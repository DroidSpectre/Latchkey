package io.latchkey.bridge;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

final class RpcHandler {
    static final class AuthException extends Exception {
        AuthException(String message) {
            super(message);
        }
    }

    static final class Result {
        final byte[] body;
        final String op;
        final String path;
        final boolean ok;

        Result(byte[] body, String op, String path, boolean ok) {
            this.body = body;
            this.op = op;
            this.path = path;
            this.ok = ok;
        }
    }

    private static final String TAG = "Latchkey";
    private static final long MAX_CLOCK_SKEW_MS = 5 * 60 * 1000L;
    private static final long REPLAY_WINDOW_MS = 5 * 60 * 1000L;
    private static final int MAX_SEEN = 16384;

    private final Context context;
    private final FileApi api;
    private final LinkedHashMap<String, Long> seen = new LinkedHashMap<String, Long>();
    private volatile byte[] key;

    RpcHandler(Context context, byte[] key, String fingerprint) {
        this.context = context;
        this.key = key;
        this.api = new FileApi(context, fingerprint);
    }

    Result handle(byte[] encryptedRequest) throws AuthException {
        return handle(encryptedRequest, null);
    }

    Result handle(byte[] encryptedRequest, String clientId) throws AuthException {
        long started = System.currentTimeMillis();
        int inbound = encryptedRequest == null ? 0 : encryptedRequest.length;
        boolean temporary = false;
        byte[] secret;
        String aad;
        if (clientId != null && clientId.length() > 0) {
            secret = PairStore.getKey(context, clientId);
            temporary = true;
            aad = "LATCHKEY/1|client:" + clientId;
            if (secret == null) {
                EventLog.warn("auth", "unknown-client",
                        "unknown or revoked paired client " + clientId);
                ServerRuntime.recordAuthFailure();
                throw new AuthException("unknown paired client");
            }
        } else {
            secret = key;
            aad = "LATCHKEY/1";
        }
        if (secret == null || encryptedRequest == null) {
            EventLog.warn("auth", "unavailable", "server key is not available");
            ServerRuntime.recordAuthFailure();
            if (temporary && secret != null) {
                Arrays.fill(secret, (byte) 0);
            }
            throw new AuthException("server key is not available");
        }

        JSONObject request;
        try {
            byte[] plaintext = Crypto.decrypt(secret, aad, encryptedRequest);
            request = new JSONObject(new String(plaintext, StandardCharsets.UTF_8));
        } catch (Exception e) {
            String message = message(e);
            EventLog.warn("auth", "decrypt-failed", message);
            ServerRuntime.recordAuthFailure();
            if (temporary) {
                Arrays.fill(secret, (byte) 0);
            }
            throw new AuthException("could not decrypt request");
        }

        String id = request.optString("id", "");
        String op = request.optString("op", "");
        String path = request.optString("path", request.optString("from", ""));

        try {
            if (request.optInt("v", 0) != 1) {
                throw new RpcError("BAD_VERSION", "unsupported protocol version");
            }
            if (id.length() < 8 || id.length() > 64) {
                throw new RpcError("BAD_REQUEST", "missing or invalid id");
            }
            if (op.length() == 0 || op.length() > 32) {
                throw new RpcError("BAD_OP", "missing or invalid op");
            }
            long timestamp = request.optLong("ts", 0L);
            if (timestamp == 0L
                    || Math.abs(System.currentTimeMillis() - timestamp) > MAX_CLOCK_SKEW_MS) {
                throw new RpcError("BAD_CLOCK", "request timestamp outside allowed window");
            }
            remember(id);

            JSONObject response;
            if ("logs-clear".equals(op)) {
                response = EventLog.clear();
            } else if ("logs".equals(op)) {
                response = EventLog.rpc(request);
            } else {
                response = api.handle(request);
            }
            Json.put(response, "ok", true);
            Json.put(response, "id", id);
            Json.put(response, "serverTime", System.currentTimeMillis());
            byte[] body = Crypto.encrypt(secret, aad, bytes(response));
            EventLog.info("rpc", op, "ok",
                    details(path, id, started, inbound, body.length, clientId));
            if (temporary) {
                Arrays.fill(secret, (byte) 0);
            }
            return new Result(body, op, path, true);
        } catch (RpcError error) {
            JSONObject response = error(id, error.code, error.getMessage());
            EventLog.warn("rpc", op, error.code + ": " + error.getMessage(),
                    details(path, id, started, inbound, 0, clientId));
            try {
                return new Result(Crypto.encrypt(secret, aad, bytes(response)),
                        op, path, false);
            } catch (Exception cryptoFailure) {
                EventLog.error("rpc", op, "could not encrypt error response");
                throw new AuthException("could not encrypt response");
            } finally {
                if (temporary) {
                    Arrays.fill(secret, (byte) 0);
                }
            }
        } catch (Exception failure) {
            Log.e(TAG, "rpc failed: " + op + " " + path, failure);
            String message = message(failure);
            JSONObject response = error(id, "INTERNAL", message);
            EventLog.error("rpc", op, message,
                    details(path, id, started, inbound, 0, clientId));
            try {
                return new Result(Crypto.encrypt(secret, aad, bytes(response)),
                        op, path, false);
            } catch (Exception cryptoFailure) {
                EventLog.error("rpc", op, "could not encrypt error response");
                throw new AuthException("could not encrypt response");
            } finally {
                if (temporary) {
                    Arrays.fill(secret, (byte) 0);
                }
            }
        }
    }

    void destroy() {
        byte[] current = key;
        key = null;
        if (current != null) {
            Arrays.fill(current, (byte) 0);
        }
        EventLog.info("auth", "destroy", "server key zeroed");
    }

    private static JSONObject details(String path, String id, long started,
                                      int inbound, int outbound, String clientId) {
        JSONObject data = Json.obj();
        Json.put(data, "path", path == null ? "" : path);
        Json.put(data, "id", id);
        if (clientId != null && clientId.length() > 0) {
            Json.put(data, "client", clientId);
        }
        Json.put(data, "ms", System.currentTimeMillis() - started);
        Json.put(data, "in", inbound);
        Json.put(data, "out", outbound);
        return data;
    }

    private static String message(Throwable failure) {
        String text = failure.getMessage();
        if (text == null || text.length() == 0) {
            text = failure.getClass().getSimpleName();
        }
        return text;
    }

    private static JSONObject error(String id, String code, String message) {
        JSONObject response = Json.obj();
        Json.put(response, "ok", false);
        Json.put(response, "id", id);
        Json.put(response, "code", code);
        Json.put(response, "error", message == null ? code : message);
        Json.put(response, "serverTime", System.currentTimeMillis());
        return response;
    }

    private static byte[] bytes(JSONObject object) {
        return object.toString().getBytes(StandardCharsets.UTF_8);
    }

    private void remember(String id) throws RpcError {
        long now = System.currentTimeMillis();
        synchronized (seen) {
            prune(now);
            if (seen.containsKey(id)) {
                throw new RpcError("REPLAY", "duplicate request id");
            }
            seen.put(id, now);
            while (seen.size() > MAX_SEEN) {
                Iterator<Map.Entry<String, Long>> iterator = seen.entrySet().iterator();
                if (iterator.hasNext()) {
                    iterator.next();
                    iterator.remove();
                }
            }
        }
    }

    private void prune(long now) {
        Iterator<Map.Entry<String, Long>> iterator = seen.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, Long> entry = iterator.next();
            if (now - entry.getValue() > REPLAY_WINDOW_MS) {
                iterator.remove();
            } else {
                break;
            }
        }
    }
}
