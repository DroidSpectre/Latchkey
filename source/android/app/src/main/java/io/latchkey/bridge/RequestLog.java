package io.latchkey.bridge;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

final class RequestLog {
    private static final int MAX = 60;
    private static final ArrayDeque<Entry> ENTRIES = new ArrayDeque<Entry>();

    static final class Entry {
        final long at;
        final String op;
        final String path;
        final boolean ok;
        final long ms;
        final long bytes;

        Entry(long at, String op, String path, boolean ok, long ms, long bytes) {
            this.at = at;
            this.op = op;
            this.path = path;
            this.ok = ok;
            this.ms = ms;
            this.bytes = bytes;
        }
    }

    private RequestLog() {
    }

    static void add(String op, String path, boolean ok, long ms, long bytes) {
        synchronized (ENTRIES) {
            ENTRIES.addFirst(new Entry(System.currentTimeMillis(), op, path, ok, ms, bytes));
            while (ENTRIES.size() > MAX) {
                ENTRIES.removeLast();
            }
        }
    }

    static List<Entry> snapshot(int limit) {
        List<Entry> out = new ArrayList<Entry>();
        synchronized (ENTRIES) {
            for (Entry entry : ENTRIES) {
                out.add(entry);
                if (out.size() >= limit) {
                    break;
                }
            }
        }
        return out;
    }

    static void clear() {
        synchronized (ENTRIES) {
            ENTRIES.clear();
        }
    }
}
