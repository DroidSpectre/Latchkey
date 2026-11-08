package io.latchkey.bridge;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

final class RpcServer {
    private static final String TAG = "Latchkey";
    private static final int MAX_REQUEST = 8 * 1024 * 1024;
    private static final int MAX_HEADER = 32 * 1024;
    private static final int WORKERS = 4;
    private static final int QUEUE = 16;
    private static final long READ_TIMEOUT_MS = 30000L;
    private static final long CONNECTION_DEADLINE_MS = 60000L;

    private final Context context;
    private final int port;
    private final RpcHandler handler;
    private volatile boolean running;
    private ServerSocket serverSocket;
    private ThreadPoolExecutor pool;
    private ScheduledExecutorService deadlines;
    private Thread acceptThread;
    private final Set<Socket> connections =
            Collections.synchronizedSet(new HashSet<Socket>());

    RpcServer(Context context, int port, RpcHandler handler) {
        this.context = context.getApplicationContext();
        this.port = port;
        this.handler = handler;
    }

    void start() throws IOException {
        ServerSocket socket = new ServerSocket();
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress(
                InetAddress.getByAddress(new byte[]{127, 0, 0, 1}), port), 32);
        socket.setSoTimeout(1000);
        serverSocket = socket;
        pool = new ThreadPoolExecutor(WORKERS, WORKERS, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<Runnable>(QUEUE),
                daemonFactory("latchkey-conn"),
                new ThreadPoolExecutor.AbortPolicy());
        deadlines = Executors.newSingleThreadScheduledExecutor(
                daemonFactory("latchkey-deadline"));
        running = true;
        acceptThread = new Thread(new Runnable() {
            @Override
            public void run() {
                acceptLoop();
            }
        }, "latchkey-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
        ServerRuntime.markStarted(port);
        EventLog.info("server", "start", "listening on 127.0.0.1:" + port);
        Log.i(TAG, "listening on 127.0.0.1:" + port);
    }

    void stop() {
        running = false;
        ServerSocket socket = serverSocket;
        serverSocket = null;
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
        synchronized (connections) {
            for (Socket client : connections) {
                closeQuietly(client);
            }
            connections.clear();
        }
        ThreadPoolExecutor executor = pool;
        pool = null;
        if (executor != null) {
            executor.shutdownNow();
        }
        ScheduledExecutorService scheduler = deadlines;
        deadlines = null;
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
        Thread accept = acceptThread;
        acceptThread = null;
        if (accept != null) {
            try {
                accept.join(500L);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
        handler.destroy();
        ServerRuntime.markStopped();
        EventLog.info("server", "stop", "server stopped");
        Log.i(TAG, "stopped");
    }

    private void acceptLoop() {
        while (running) {
            ServerSocket server = serverSocket;
            if (server == null) {
                break;
            }
            try {
                final Socket socket = server.accept();
                ThreadPoolExecutor executor = pool;
                if (executor == null) {
                    closeQuietly(socket);
                    break;
                }
                try {
                    executor.execute(new Connection(socket));
                } catch (RejectedExecutionException e) {
                    EventLog.warn("server", "busy", "connection rejected: pool is full");
                    sendBusy(socket);
                }
            } catch (SocketTimeoutException ignored) {
            } catch (IOException e) {
                if (running) {
                    EventLog.warn("server", "accept-failed", message(e));
                    Log.w(TAG, "accept failed", e);
                }
            }
        }
    }

    private final class Connection implements Runnable {
        private final Socket socket;
        private int status;
        private String method = "";
        private String target = "";
        private String op = "http";
        private String path = "";
        private boolean ok;
        private long inbound;
        private long outbound;
        private String error = "";

        Connection(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            long started = System.currentTimeMillis();
            ScheduledFuture<?> deadline = null;
            try {
                connections.add(socket);
                if (!running) {
                    return;
                }
                socket.setSoTimeout((int) READ_TIMEOUT_MS);
                ScheduledExecutorService scheduler = deadlines;
                if (scheduler != null) {
                    try {
                        deadline = scheduler.schedule(new Runnable() {
                            @Override
                            public void run() {
                                closeQuietly(socket);
                            }
                        }, CONNECTION_DEADLINE_MS, TimeUnit.MILLISECONDS);
                    } catch (RejectedExecutionException ignored) {
                    }
                }

                InputStream input = new BufferedInputStream(socket.getInputStream());
                String requestLine = readLine(input);
                if (requestLine == null || requestLine.length() == 0) {
                    status = 400;
                    error = "empty request";
                    sendText(400, "{\"ok\":false,\"error\":\"bad request\"}");
                    return;
                }
                String[] parts = requestLine.split(" ");
                if (parts.length != 3) {
                    status = 400;
                    error = "malformed request line";
                    sendText(400, "{\"ok\":false,\"error\":\"bad request\"}");
                    return;
                }
                method = parts[0];
                target = parts[1];
                String version = parts[2];
                if (!"HTTP/1.1".equals(version) && !"HTTP/1.0".equals(version)) {
                    status = 400;
                    error = "unsupported HTTP version";
                    sendText(400, "{\"ok\":false,\"error\":\"bad request\"}");
                    return;
                }
                if (target.length() > 4096) {
                    status = 414;
                    error = "target too long";
                    sendText(414, "{\"ok\":false,\"error\":\"request target too long\"}");
                    return;
                }

                Map<String, String> headers = new HashMap<String, String>();
                int headerBytes = requestLine.length();
                while (true) {
                    String line = readLine(input);
                    if (line == null) {
                        status = 400;
                        error = "unterminated headers";
                        return;
                    }
                    if (line.length() == 0) {
                        break;
                    }
                    headerBytes += line.length() + 2;
                    if (headerBytes > MAX_HEADER) {
                        status = 431;
                        error = "headers too large";
                        sendText(431, "{\"ok\":false,\"error\":\"headers too large\"}");
                        return;
                    }
                    int colon = line.indexOf(':');
                    if (colon <= 0) {
                        status = 400;
                        error = "malformed header";
                        sendText(400, "{\"ok\":false,\"error\":\"bad request\"}");
                        return;
                    }
                    String name = line.substring(0, colon).trim().toLowerCase(Locale.US);
                    String value = line.substring(colon + 1).trim();
                    if (name.length() == 0 || name.length() > 64
                            || value.length() > 8192 || value.indexOf('\0') >= 0) {
                        status = 400;
                        error = "invalid header";
                        sendText(400, "{\"ok\":false,\"error\":\"bad request\"}");
                        return;
                    }
                    if (headers.put(name, value) != null) {
                        status = 400;
                        error = "duplicate header";
                        sendText(400, "{\"ok\":false,\"error\":\"duplicate header\"}");
                        return;
                    }
                }

                if (headers.containsKey("transfer-encoding")) {
                    status = 400;
                    error = "transfer-encoding not accepted";
                    sendText(400, "{\"ok\":false,\"error\":\"transfer-encoding not accepted\"}");
                    return;
                }
                String host = headers.get("host");
                if (host == null || !isLoopbackHost(host)) {
                    status = 403;
                    error = "non-loopback host header";
                    sendText(403, "{\"ok\":false,\"error\":\"forbidden\"}");
                    return;
                }
                if (headers.containsKey("expect")) {
                    status = 417;
                    error = "expectation not supported";
                    sendText(417, "{\"ok\":false,\"error\":\"expectation not supported\"}");
                    return;
                }

                if ("GET".equals(method)
                        && ("/health".equals(target) || "/".equals(target))) {
                    op = "health";
                    path = target;
                    byte[] body = health().getBytes(StandardCharsets.UTF_8);
                    sendBinary(200, "application/json; charset=utf-8", body);
                    outbound = body.length;
                    ok = true;
                    return;
                }

                if ("POST".equals(method) && "/pair".equals(target)) {
                    op = "pair";
                    path = "/pair";
                    if (!running) {
                        status = 503;
                        error = "server stopping";
                        sendText(503, "{\"ok\":false,\"error\":\"server stopping\"}");
                        return;
                    }
                    String pairLength = headers.get("content-length");
                    if (pairLength == null) {
                        status = 411;
                        error = "content-length required";
                        sendText(411, "{\"ok\":false,\"error\":\"content-length required\"}");
                        return;
                    }
                    String pairTrimmed = pairLength.trim();
                    if (!pairTrimmed.matches("[0-9]{1,6}")) {
                        status = 400;
                        error = "invalid content-length";
                        sendText(400, "{\"ok\":false,\"error\":\"bad request\"}");
                        return;
                    }
                    long pairSize = Long.parseLong(pairTrimmed);
                    if (pairSize > 16384L) {
                        status = 413;
                        error = "pairing request too large";
                        sendText(413, "{\"ok\":false,\"error\":\"request too large\"}");
                        return;
                    }
                    byte[] pairBody = new byte[(int) pairSize];
                    readFully(input, pairBody);
                    inbound = pairBody.length;
                    String remote = socket.getInetAddress() == null
                            ? "unknown" : socket.getInetAddress().getHostAddress();
                    PairingManager.PairResponse pair = PairingManager.pair(
                            context, new String(pairBody, StandardCharsets.UTF_8), remote);
                    byte[] pairResponse = pair.body.getBytes(StandardCharsets.UTF_8);
                    ok = pair.status == 200;
                    if (!ok) {
                        error = "pairing rejected";
                    }
                    sendBinary(pair.status, "application/json; charset=utf-8", pairResponse);
                    outbound = pairResponse.length;
                    return;
                }

                if (!"POST".equals(method) || !"/rpc".equals(target)) {
                    status = 404;
                    error = "not found";
                    sendText(404, "{\"ok\":false,\"error\":\"not found\"}");
                    return;
                }

                String lengthHeader = headers.get("content-length");
                if (lengthHeader == null) {
                    status = 411;
                    error = "content-length required";
                    sendText(411, "{\"ok\":false,\"error\":\"content-length required\"}");
                    return;
                }
                String trimmed = lengthHeader.trim();
                if (!trimmed.matches("[0-9]{1,9}")) {
                    status = 400;
                    error = "invalid content-length";
                    sendText(400, "{\"ok\":false,\"error\":\"invalid content-length\"}");
                    return;
                }
                long contentLength = Long.parseLong(trimmed);
                if (contentLength > MAX_REQUEST) {
                    status = 413;
                    error = "request too large";
                    sendText(413, "{\"ok\":false,\"error\":\"request too large\"}");
                    return;
                }

                byte[] request = new byte[(int) contentLength];
                readFully(input, request);
                inbound = request.length;
                if (!running) {
                    status = 503;
                    error = "server stopping";
                    return;
                }
                String clientId = headers.get("x-latchkey-client");
                if (clientId != null) {
                    clientId = clientId.trim().toLowerCase(Locale.US);
                    if (!clientId.matches("[a-f0-9]{16,64}")) {
                        status = 400;
                        error = "invalid client header";
                        sendText(400, "{\"ok\":false,\"error\":\"bad request\"}");
                        return;
                    }
                }
                RpcHandler.Result result = handler.handle(request, clientId);
                op = result.op;
                path = result.path;
                ok = result.ok;
                sendBinary(200, "application/octet-stream", result.body);
                outbound = result.body.length;
            } catch (RpcHandler.AuthException e) {
                status = 401;
                op = "auth";
                ok = false;
                error = e.getMessage();
                try {
                    sendText(401, "{\"ok\":false,\"error\":\"unauthorized\"}");
                } catch (IOException ignored) {
                }
            } catch (SocketTimeoutException e) {
                status = 408;
                error = "read timeout";
                EventLog.warn("http", "timeout", "connection timed out");
            } catch (IOException e) {
                error = message(e);
                if ("header line too long".equals(error)) {
                    status = 431;
                    try {
                        sendText(431, "{\"ok\":false,\"error\":\"headers too large\"}");
                    } catch (IOException ignored) {
                    }
                } else if (running) {
                    EventLog.warn("http", "io", error);
                }
            } catch (Exception e) {
                status = 500;
                error = message(e);
                Log.e(TAG, "unexpected connection failure", e);
                EventLog.error("http", "failed", error);
                try {
                    sendText(500, "{\"ok\":false,\"error\":\"internal error\"}");
                } catch (IOException ignored) {
                }
            } finally {
                if (deadline != null) {
                    deadline.cancel(false);
                }
                connections.remove(socket);
                closeQuietly(socket);
                long ms = System.currentTimeMillis() - started;
                JSONObject data = Json.obj();
                Json.put(data, "method", method);
                Json.put(data, "target", target);
                Json.put(data, "status", status);
                Json.put(data, "ms", ms);
                Json.put(data, "in", inbound);
                Json.put(data, "out", outbound);
                if (error.length() > 0) {
                    Json.put(data, "error", error);
                }
                String loggedPath = path.length() > 0 ? path : target;
                if (ok) {
                    EventLog.info("http", op, "ok", data);
                } else {
                    EventLog.warn("http", op, "failed", data);
                }
                ServerRuntime.recordRequest(op, loggedPath, ok, ms, inbound, outbound);
            }
        }

        private String health() {
            JSONObject out = Json.obj();
            Json.put(out, "app", "latchkey");
            Json.put(out, "ok", true);
            Json.put(out, "version", ServerRuntime.VERSION);
            Json.put(out, "port", ServerRuntime.port);
            Json.put(out, "uptimeMs", ServerRuntime.uptimeMs());
            Json.put(out, "requests", ServerRuntime.requests.get());
            return out.toString();
        }

        private void sendText(int code, String text) throws IOException {
            sendBinary(code, "application/json; charset=utf-8",
                    text.getBytes(StandardCharsets.UTF_8));
        }

        private void sendBinary(int code, String contentType, byte[] body) throws IOException {
            status = code;
            OutputStream output = socket.getOutputStream();
            String reason;
            if (code == 200) {
                reason = "OK";
            } else if (code == 400) {
                reason = "Bad Request";
            } else if (code == 401) {
                reason = "Unauthorized";
            } else if (code == 403) {
                reason = "Forbidden";
            } else if (code == 404) {
                reason = "Not Found";
            } else if (code == 409) {
                reason = "Conflict";
            } else if (code == 408) {
                reason = "Request Timeout";
            } else if (code == 411) {
                reason = "Length Required";
            } else if (code == 413) {
                reason = "Payload Too Large";
            } else if (code == 414) {
                reason = "URI Too Long";
            } else if (code == 417) {
                reason = "Expectation Failed";
            } else if (code == 429) {
                reason = "Too Many Requests";
            } else if (code == 431) {
                reason = "Request Header Fields Too Large";
            } else if (code == 503) {
                reason = "Service Unavailable";
            } else {
                reason = "Internal Server Error";
            }
            String head = "HTTP/1.1 " + code + " " + reason + "\r\n"
                    + "Content-Type: " + contentType + "\r\n"
                    + "Content-Length: " + body.length + "\r\n"
                    + "Cache-Control: no-store\r\n"
                    + "X-Content-Type-Options: nosniff\r\n"
                    + "Connection: close\r\n\r\n";
            output.write(head.getBytes(StandardCharsets.US_ASCII));
            output.write(body);
            output.flush();
        }
    }

    private static ThreadFactory daemonFactory(final String name) {
        return new ThreadFactory() {
            @Override
            public Thread newThread(Runnable runnable) {
                Thread thread = new Thread(runnable, name);
                thread.setDaemon(true);
                return thread;
            }
        };
    }

    private static String message(Throwable failure) {
        String text = failure.getMessage();
        if (text == null || text.length() == 0) {
            text = failure.getClass().getSimpleName();
        }
        return text;
    }

    private static boolean isLoopbackHost(String host) {
        String value = host.trim().toLowerCase(Locale.US);
        int colon = value.lastIndexOf(':');
        String name = colon >= 0 ? value.substring(0, colon) : value;
        return "127.0.0.1".equals(name) || "localhost".equals(name);
    }

    private static void sendBusy(Socket socket) {
        try {
            OutputStream output = socket.getOutputStream();
            String head = "HTTP/1.1 503 Service Unavailable\r\n"
                    + "Content-Length: 0\r\n"
                    + "Connection: close\r\n\r\n";
            output.write(head.getBytes(StandardCharsets.US_ASCII));
            output.flush();
        } catch (IOException ignored) {
        }
        closeQuietly(socket);
    }

    private static String readLine(InputStream input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(128);
        int value;
        while ((value = input.read()) != -1) {
            if (value == '\n') {
                byte[] bytes = out.toByteArray();
                int length = bytes.length;
                if (length > 0 && bytes[length - 1] == '\r') {
                    length--;
                }
                return new String(bytes, 0, length, StandardCharsets.US_ASCII);
            }
            out.write(value);
            if (out.size() > MAX_HEADER) {
                throw new IOException("header line too long");
            }
        }
        if (out.size() == 0) {
            return null;
        }
        return new String(out.toByteArray(), StandardCharsets.US_ASCII);
    }

    private static void readFully(InputStream input, byte[] buffer) throws IOException {
        int offset = 0;
        while (offset < buffer.length) {
            int read = input.read(buffer, offset, buffer.length - offset);
            if (read < 0) {
                throw new IOException("unexpected end of request body");
            }
            offset += read;
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }
}
