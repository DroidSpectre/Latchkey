package io.latchkey.bridge;

import android.content.Context;
import android.net.Uri;
import android.os.Build;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

/**
 * Issues short-lived, single-use loopback pairing links and exchanges them for
 * per-client keys. Pairing links are delivered by clipboard; the token is never
 * written to logs or storage.
 */
final class PairingManager {
    static final class PairResponse {
        final int status;
        final String body;

        PairResponse(int status, String body) {
            this.status = status;
            this.body = body;
        }
    }

    private static final Object LOCK = new Object();
    private static final long TOKEN_TTL_MS = 120000L;
    private static final long LOCKOUT_MS = 60000L;
    private static final int MAX_FAILURES = 5;
    private static final String PAIR_AAD_PREFIX = "LATCHKEY/PAIR/1|";
    static final String ACTION_PAIR = "io.latchkey.bridge.action.PAIR";

    private static byte[] tokenHash;
    private static long expiresAt;
    private static int failures;
    private static long lockoutUntil;

    private PairingManager() {
    }

    static String createLink(Context context, String appFingerprint, int port)
            throws Exception {
        synchronized (LOCK) {
            byte[] tokenBytes = Crypto.randomKey();
            String token;
            try {
                token = Crypto.encodeKey(tokenBytes);
            } finally {
                Arrays.fill(tokenBytes, (byte) 0);
            }
            byte[] nextHash = Crypto.sha256(token.getBytes(StandardCharsets.UTF_8));
            byte[] previous = tokenHash;
            tokenHash = nextHash;
            expiresAt = System.currentTimeMillis() + TOKEN_TTL_MS;
            failures = 0;
            lockoutUntil = 0L;
            if (previous != null) {
                Arrays.fill(previous, (byte) 0);
            }

            String name = (Build.MANUFACTURER + " " + Build.MODEL).trim();
            if (name.length() == 0) {
                name = "Android device";
            }
            String link = new Uri.Builder()
                    .scheme("latchkey")
                    .authority("pair")
                    .appendQueryParameter("scope", "loopback")
                    .appendQueryParameter("v", "1")
                    .appendQueryParameter("id", PairStore.hostId(context))
                    .appendQueryParameter("name", name)
                    .appendQueryParameter("host", "127.0.0.1")
                    .appendQueryParameter("port", String.valueOf(port))
                    .appendQueryParameter("fp", appFingerprint == null ? "" : appFingerprint)
                    .appendQueryParameter("tok", token)
                    .appendQueryParameter("exp", String.valueOf(expiresAt))
                    .build()
                    .toString();
            EventLog.info("pair", "link",
                    "created a single-use pairing link expiring in 120s");
            return link;
        }
    }

    static void invalidate() {
        synchronized (LOCK) {
            if (tokenHash != null) {
                Arrays.fill(tokenHash, (byte) 0);
                tokenHash = null;
            }
            expiresAt = 0L;
            failures = 0;
            lockoutUntil = 0L;
        }
    }

    static void onPairIssued(Context context) {
        LatchkeyService.refreshNotification(context);
    }

    static PairResponse pair(Context context, String body, String remote) {
        long now = System.currentTimeMillis();
        String token;
        String clientId;
        String clientName;
        try {
            JSONObject request = new JSONObject(body);
            if (request.optInt("v", 0) != 1) {
                return error(400, "BAD_VERSION", "unsupported pairing version", remote);
            }
            token = request.optString("token", "");
            if (!token.matches("[A-Za-z0-9_-]{43}")) {
                return error(400, "BAD_TOKEN", "invalid pairing token", remote);
            }
            try {
                Crypto.decodeKey(token);
            } catch (Exception invalid) {
                return error(400, "BAD_TOKEN", "invalid pairing token", remote);
            }
            JSONObject client = request.optJSONObject("client");
            if (client == null) {
                return error(400, "BAD_REQUEST", "missing client", remote);
            }
            clientId = client.optString("id", "").trim().toLowerCase();
            if (!clientId.matches("[a-f0-9]{16,64}")) {
                return error(400, "BAD_CLIENT", "invalid client id", remote);
            }
            clientName = sanitizeName(client.optString("name", "Assistant"));
        } catch (Exception failure) {
            return error(400, "BAD_REQUEST", "invalid pairing request", remote);
        }

        byte[] incomingHash;
        try {
            incomingHash = Crypto.sha256(token.getBytes(StandardCharsets.UTF_8));
        } catch (Exception failure) {
            return error(500, "PAIR_UNAVAILABLE", "pairing unavailable", remote);
        }

        PairStore.Issued issued;
        synchronized (LOCK) {
            if (lockoutUntil > now) {
                EventLog.warn("pair", "locked",
                        "pairing rejected during lockout from " + remote);
                Arrays.fill(incomingHash, (byte) 0);
                return error(429, "PAIR_LOCKED", "too many attempts; create a new link", remote);
            }
            if (tokenHash == null) {
                EventLog.warn("pair", "no-link",
                        "pairing request with no active link from " + remote);
                Arrays.fill(incomingHash, (byte) 0);
                return error(403, "NO_LINK", "no pairing link is active", remote);
            }
            if (now > expiresAt) {
                clearToken();
                EventLog.warn("pair", "expired",
                        "pairing link expired before use from " + remote);
                Arrays.fill(incomingHash, (byte) 0);
                return error(403, "EXPIRED", "pairing link expired; create a new one", remote);
            }
            if (!MessageDigest.isEqual(incomingHash, tokenHash)) {
                Arrays.fill(incomingHash, (byte) 0);
                failures++;
                if (failures >= MAX_FAILURES) {
                    lockoutUntil = now + LOCKOUT_MS;
                    clearToken();
                    EventLog.warn("pair", "lockout",
                            "pairing token rejected; locked for 60s");
                    return error(429, "PAIR_LOCKED",
                            "too many attempts; create a new link", remote);
                }
                EventLog.warn("pair", "rejected",
                        "pairing token mismatch from " + remote);
                return error(403, "BAD_TOKEN", "invalid pairing token", remote);
            }
            // Consume the token before issuing so concurrent requests cannot reuse it.
            clearToken();
            failures = 0;
            lockoutUntil = 0L;
            try {
                issued = PairStore.issue(context, clientId, clientName);
            LatchkeyService.refreshNotification(context);
            } catch (IllegalArgumentException duplicate) {
                EventLog.warn("pair", "duplicate",
                        "client is already paired: " + clientId);
                Arrays.fill(incomingHash, (byte) 0);
                return error(409, "ALREADY_PAIRED", "client is already paired", remote);
            } catch (Exception failure) {
                EventLog.error("pair", "issue-failed",
                        "could not issue client key: " + message(failure));
                Arrays.fill(incomingHash, (byte) 0);
                return error(500, "PAIR_UNAVAILABLE", "pairing is unavailable", remote);
            }
        }

        byte[] pairKey = null;
        try {
            pairKey = Crypto.sha256(token.getBytes(StandardCharsets.UTF_8));
            byte[] aad = (PAIR_AAD_PREFIX + clientId).getBytes(StandardCharsets.UTF_8);
            byte[] blob = Crypto.encrypt(pairKey, aad, issued.key);
            JSONObject response = new JSONObject();
            response.put("ok", true);
            response.put("v", 1);
            response.put("clientId", clientId);
            response.put("clientName", clientName);
            response.put("key", Base64.getUrlEncoder().withoutPadding().encodeToString(blob));
            response.put("fingerprint", issued.fingerprint);
            response.put("serverTime", System.currentTimeMillis());
            EventLog.info("pair", "success",
                    "paired client " + clientName + " (" + clientId + ") via " + remote);
            return new PairResponse(200, response.toString());
        } catch (Exception failure) {
            EventLog.error("pair", "response-failed",
                    "could not encrypt client key: " + message(failure));
            return error(500, "PAIR_UNAVAILABLE", "pairing is unavailable", remote);
        } finally {
            if (pairKey != null) {
                Arrays.fill(pairKey, (byte) 0);
            }
            Arrays.fill(issued.key, (byte) 0);
            Arrays.fill(incomingHash, (byte) 0);
        }
    }

    private static void clearToken() {
        if (tokenHash != null) {
            Arrays.fill(tokenHash, (byte) 0);
            tokenHash = null;
        }
        expiresAt = 0L;
    }

    private static String sanitizeName(String value) {
        String cleaned = value == null ? "" : value
                .replaceAll("[\\p{Cntrl}]", " ")
                .replaceAll("\\s+", " ")
                .trim();
        if (cleaned.length() == 0) {
            cleaned = "Assistant";
        }
        if (cleaned.length() > 64) {
            cleaned = cleaned.substring(0, 64);
        }
        return cleaned;
    }

    private static PairResponse error(int status, String code, String message,
                                      String remote) {
        JSONObject response = new JSONObject();
        try {
            response.put("ok", false);
            response.put("code", code);
            response.put("error", message);
            response.put("serverTime", System.currentTimeMillis());
        } catch (Exception ignored) {
        }
        return new PairResponse(status, response.toString());
    }

    private static String message(Throwable failure) {
        String text = failure.getMessage();
        if (text == null || text.length() == 0) {
            text = failure.getClass().getSimpleName();
        }
        return text;
    }
}
