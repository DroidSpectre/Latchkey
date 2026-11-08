package io.latchkey.bridge;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

final class ServerRuntime {
    static final int PORT = 39401;
    static final String VERSION = "1.3.0-C";

    static volatile boolean running;
    static volatile int port = PORT;
    static volatile long startedAt;
    static volatile String lastError;
    static final AtomicInteger requests = new AtomicInteger();
    static final AtomicLong bytesIn = new AtomicLong();
    static final AtomicLong bytesOut = new AtomicLong();
    static final AtomicInteger authFailures = new AtomicInteger();
    static volatile String lastOp = "-";
    static volatile String lastPath = "";
    static volatile boolean lastOk = true;
    static volatile long lastMs;
    static volatile long lastAt;

    private ServerRuntime() {
    }

    static void markStarted(int boundPort) {
        port = boundPort;
        startedAt = System.currentTimeMillis();
        lastError = null;
        running = true;
    }

    static void markStopped() {
        running = false;
    }

    static void setError(String message) {
        lastError = message;
        running = false;
    }

    static void recordRequest(String op, String path, boolean ok, long ms, long in, long out) {
        requests.incrementAndGet();
        bytesIn.addAndGet(in);
        bytesOut.addAndGet(out);
        lastOp = op;
        lastPath = path;
        lastOk = ok;
        lastMs = ms;
        lastAt = System.currentTimeMillis();
    }

    static void recordAuthFailure() {
        authFailures.incrementAndGet();
        lastOp = "auth";
        lastPath = "";
        lastOk = false;
        lastMs = 0;
        lastAt = System.currentTimeMillis();
    }

    static long uptimeMs() {
        if (!running || startedAt == 0) {
            return 0;
        }
        return System.currentTimeMillis() - startedAt;
    }
}
