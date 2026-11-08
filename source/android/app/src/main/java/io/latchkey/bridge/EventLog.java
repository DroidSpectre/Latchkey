package io.latchkey.bridge;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Persistent, append-only activity log.
 *
 * JSONL files live in app-private storage. The log rotates through four files
 * of at most 2 MiB each, so it retains up to roughly 8 MiB of history. The
 * bridge API cannot modify these files because FileApi rejects writes into the
 * app's data directory.
 */
final class EventLog {
    static final String DEBUG = "DEBUG";
    static final String INFO = "INFO";
    static final String WARN = "WARN";
    static final String ERROR = "ERROR";

    private static final String TAG = "Latchkey";
    private static final String CURRENT_NAME = "events.log";
    private static final long MAX_BYTES = 2L * 1024L * 1024L;
    private static final int MAX_ROTATED = 3;
    private static final int RING_SIZE = 2000;
    private static final int MAX_MESSAGE = 2000;
    private static final int MAX_DATA = 4000;
    private static final String PREFS_NAME = "latchkey-meta";
    private static final String PREF_VERSION_NAME = "lastVersionName";
    private static final String PREF_VERSION_CODE = "lastVersionCode";

    private static final Object LOCK = new Object();
    private static final ArrayDeque<JSONObject> RING = new ArrayDeque<JSONObject>();
    private static File dir;
    private static File current;
    private static boolean initialized;
    private static boolean sessionLogged;
    private static volatile String versionTag;

    private EventLog() {
    }

    static void init(Context context) {
        initAt(context.getFilesDir());
        logSession(context);
    }

    static void initAt(File base) {
        synchronized (LOCK) {
            if (initialized) {
                return;
            }
            dir = base;
            current = new File(dir, CURRENT_NAME);
            if (!dir.exists() && !dir.mkdirs()) {
                Log.w(TAG, "could not create event log directory");
            }
            initialized = true;
            loadRing();
        }
    }

    private static void logSession(Context context) {
        synchronized (LOCK) {
            if (sessionLogged) {
                return;
            }
            sessionLogged = true;
        }

        String versionName = ServerRuntime.VERSION;
        long versionCode = 0L;
        long updateTime = 0L;
        String packageName = context.getPackageName();
        try {
            PackageInfo info = context.getPackageManager()
                    .getPackageInfo(packageName, 0);
            if (info.versionName != null && info.versionName.length() > 0) {
                versionName = info.versionName;
            }
            versionCode = Build.VERSION.SDK_INT >= 28
                    ? info.getLongVersionCode() : info.versionCode;
            updateTime = info.lastUpdateTime;
        } catch (Exception ignored) {
        }
        versionTag = versionName + "+" + versionCode;

        String manufacturer = Build.MANUFACTURER == null ? "" : Build.MANUFACTURER;
        String model = Build.MODEL == null ? "" : Build.MODEL;
        String deviceName = (manufacturer + " " + model).trim();
        String os = "Android " + Build.VERSION.RELEASE
                + " (SDK " + Build.VERSION.SDK_INT + ")";

        SharedPreferences prefs = context.getSharedPreferences(
                PREFS_NAME, Context.MODE_PRIVATE);
        String prevName = prefs.getString(PREF_VERSION_NAME, null);
        long prevCode = prefs.getLong(PREF_VERSION_CODE, -1L);
        if (versionCode > 0L && prevName != null && prevCode > 0L
                && (prevCode != versionCode || !prevName.equals(versionName))) {
            JSONObject data = new JSONObject();
            try {
                data.put("fromVersionName", prevName);
                data.put("fromVersionCode", prevCode);
                data.put("toVersionName", versionName);
                data.put("toVersionCode", versionCode);
                data.put("package", packageName);
                data.put("model", deviceName);
                data.put("sdk", Build.VERSION.SDK_INT);
                data.put("lastUpdateTime", updateTime);
            } catch (Exception ignored) {
            }
            log(INFO, "app", "update",
                    "app changed from " + prevName + " (" + prevCode + ") to "
                            + versionName + " (" + versionCode + ")", data);
        }

        JSONObject data = new JSONObject();
        try {
            data.put("versionName", versionName);
            data.put("versionCode", versionCode);
            data.put("package", packageName);
            data.put("manufacturer", manufacturer);
            data.put("model", model);
            data.put("release", Build.VERSION.RELEASE);
            data.put("sdk", Build.VERSION.SDK_INT);
            data.put("lastUpdateTime", updateTime);
        } catch (Exception ignored) {
        }
        log(INFO, "app", "session",
                "Latchkey " + versionName + " (" + versionCode + ") on "
                        + os + " \u2022 " + deviceName, data);

        if (versionCode > 0L) {
            prefs.edit()
                    .putString(PREF_VERSION_NAME, versionName)
                    .putLong(PREF_VERSION_CODE, versionCode)
                    .apply();
        }
    }

    static void debug(String cat, String event, String message) {
        log(DEBUG, cat, event, message, null);
    }

    static void debug(String cat, String event, String message, JSONObject data) {
        log(DEBUG, cat, event, message, data);
    }

    static void info(String cat, String event, String message) {
        log(INFO, cat, event, message, null);
    }

    static void info(String cat, String event, String message, JSONObject data) {
        log(INFO, cat, event, message, data);
    }

    static void warn(String cat, String event, String message) {
        log(WARN, cat, event, message, null);
    }

    static void warn(String cat, String event, String message, JSONObject data) {
        log(WARN, cat, event, message, data);
    }

    static void error(String cat, String event, String message) {
        log(ERROR, cat, event, message, null);
    }

    static void error(String cat, String event, String message, JSONObject data) {
        log(ERROR, cat, event, message, data);
    }

    static void log(String level, String cat, String event, String message, JSONObject data) {
        JSONObject entry = new JSONObject();
        try {
            entry.put("t", System.currentTimeMillis());
            entry.put("level", cleanLevel(level));
            entry.put("cat", truncate(cat, 32));
            entry.put("event", truncate(event, 64));
            entry.put("msg", truncate(message, MAX_MESSAGE));
            String tag = versionTag;
            if (tag != null && tag.length() > 0) {
                entry.put("v", tag);
            }
            if (data != null) {
                String serialized = data.toString();
                if (serialized.length() <= MAX_DATA) {
                    entry.put("data", data);
                } else {
                    JSONObject small = new JSONObject();
                    small.put("truncated", true);
                    small.put("size", serialized.length());
                    entry.put("data", small);
                }
            }
        } catch (Exception failure) {
            return;
        }

        synchronized (LOCK) {
            addToRing(entry);
            if (!initialized || dir == null || current == null) {
                Log.i(TAG, entry.toString());
                return;
            }
            try {
                rotateIfNeeded();
                FileOutputStream out = new FileOutputStream(current, true);
                try {
                    out.write((entry.toString() + "\n").getBytes(StandardCharsets.UTF_8));
                } finally {
                    out.close();
                }
            } catch (Exception failure) {
                Log.e(TAG, "event log write failed", failure);
            }
        }
    }

    private static void addToRing(JSONObject entry) {
        RING.addLast(entry);
        while (RING.size() > RING_SIZE) {
            RING.removeFirst();
        }
    }

    private static void loadRing() {
        RING.clear();
        for (File file : filesOldestFirst()) {
            loadFile(file);
        }
    }

    private static void loadFile(File file) {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(
                    new FileInputStream(file), StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.length() == 0) {
                    continue;
                }
                try {
                    addToRing(new JSONObject(line));
                } catch (Exception ignored) {
                }
            }
        } catch (Exception failure) {
            Log.w(TAG, "could not load event log " + file.getName(), failure);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private static void rotateIfNeeded() {
        if (current.length() < MAX_BYTES) {
            return;
        }
        File oldest = new File(dir, CURRENT_NAME + "." + MAX_ROTATED);
        if (oldest.exists()) {
            oldest.delete();
        }
        for (int i = MAX_ROTATED - 1; i >= 1; i--) {
            File from = new File(dir, CURRENT_NAME + "." + i);
            File to = new File(dir, CURRENT_NAME + "." + (i + 1));
            if (from.exists()) {
                from.renameTo(to);
            }
        }
        File first = new File(dir, CURRENT_NAME + ".1");
        if (first.exists()) {
            first.delete();
        }
        if (!current.renameTo(first)) {
            Log.w(TAG, "could not rotate event log");
        }
    }

    static List<JSONObject> snapshot(int limit) {
        synchronized (LOCK) {
            List<JSONObject> out = new ArrayList<JSONObject>();
            if (limit <= 0) {
                return out;
            }
            int skip = Math.max(0, RING.size() - limit);
            int index = 0;
            for (JSONObject entry : RING) {
                if (index++ < skip) {
                    continue;
                }
                out.add(entry);
            }
            return out;
        }
    }

    static String snapshotText(int limit, SimpleDateFormat clock) {
        List<JSONObject> entries = snapshot(limit);
        StringBuilder out = new StringBuilder();
        for (JSONObject entry : entries) {
            if (out.length() > 0) {
                out.append('\n');
            }
            out.append(format(entry, clock));
        }
        return out.toString();
    }

    static String format(JSONObject entry, SimpleDateFormat clock) {
        long timestamp = entry.optLong("t");
        String time = clock == null
                ? String.valueOf(timestamp)
                : clock.format(new Date(timestamp));
        String level = entry.optString("level");
        String cat = entry.optString("cat");
        String event = entry.optString("event");
        String message = entry.optString("msg");
        JSONObject data = entry.optJSONObject("data");

        StringBuilder out = new StringBuilder();
        out.append(time).append(' ')
                .append(pad(level, 5)).append(' ')
                .append(cat).append(' ')
                .append(event);
        if (message.length() > 0) {
            out.append(' ').append(safe(message));
        }
        if (data != null) {
            out.append(' ').append(safe(truncate(data.toString(), 600)));
        }
        return out.toString();
    }

    static JSONObject rpc(JSONObject request) throws Exception {
        int tail = clamp(request.optInt("tail", 500), 1, 5000);
        long since = request.optLong("since", 0L);
        String minLevel = request.optString("minLevel", request.optString("level", ""));
        String cat = request.optString("cat", "");
        int minRank = rank(minLevel);
        boolean tailMode = since <= 0L;

        ArrayDeque<JSONObject> kept = new ArrayDeque<JSONObject>();
        int matched = 0;
        boolean truncated = false;

        synchronized (LOCK) {
            for (File file : filesOldestFirst()) {
                BufferedReader reader = null;
                try {
                    reader = new BufferedReader(new InputStreamReader(
                            new FileInputStream(file), StandardCharsets.UTF_8));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.length() == 0) {
                            continue;
                        }
                        JSONObject entry;
                        try {
                            entry = new JSONObject(line);
                        } catch (Exception ignored) {
                            continue;
                        }
                        long timestamp = entry.optLong("t");
                        if (!tailMode && timestamp <= since) {
                            continue;
                        }
                        if (minRank > 0 && rank(entry.optString("level")) < minRank) {
                            continue;
                        }
                        if (cat.length() > 0 && !cat.equals(entry.optString("cat"))) {
                            continue;
                        }
                        matched++;
                        if (tailMode) {
                            kept.addLast(entry);
                            while (kept.size() > tail) {
                                kept.removeFirst();
                            }
                        } else if (kept.size() < tail) {
                            kept.addLast(entry);
                        } else {
                            truncated = true;
                        }
                    }
                } catch (Exception failure) {
                    Log.w(TAG, "could not read event log", failure);
                } finally {
                    if (reader != null) {
                        try {
                            reader.close();
                        } catch (Exception ignored) {
                        }
                    }
                }
            }
        }

        if (tailMode && matched > kept.size()) {
            truncated = true;
        }

        JSONObject out = new JSONObject();
        JSONArray entries = new JSONArray();
        long nextSince = since;
        for (JSONObject entry : kept) {
            entries.put(entry);
            nextSince = Math.max(nextSince, entry.optLong("t"));
        }
        out.put("entries", entries);
        out.put("count", entries.length());
        out.put("matched", matched);
        out.put("tail", tail);
        out.put("since", since);
        out.put("nextSince", nextSince);
        out.put("truncated", truncated);

        JSONArray files = new JSONArray();
        synchronized (LOCK) {
            for (File file : filesOldestFirst()) {
                JSONObject info = new JSONObject();
                info.put("name", file.getName());
                info.put("size", file.length());
                files.put(info);
            }
        }
        out.put("files", files);
        return out;
    }

    static long exportTo(File destination) throws Exception {
        File parent = destination.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("could not create " + parent);
        }
        long bytes = 0L;
        synchronized (LOCK) {
            FileOutputStream out = new FileOutputStream(destination);
            try {
                byte[] buffer = new byte[64 * 1024];
                for (File file : filesOldestFirst()) {
                    FileInputStream in = new FileInputStream(file);
                    try {
                        int read;
                        while ((read = in.read(buffer)) > 0) {
                            out.write(buffer, 0, read);
                            bytes += read;
                        }
                    } finally {
                        in.close();
                    }
                }
            } finally {
                out.close();
            }
        }
        return bytes;
    }

    static JSONObject clear() {
        synchronized (LOCK) {
            List<File> files = filesOldestFirst();
            int count = 0;
            long bytes = 0L;
            for (File file : files) {
                bytes += file.length();
                if (file.delete()) {
                    count += 1;
                }
            }
            RING.clear();
            JSONObject result = new JSONObject();
            try {
                result.put("files", count);
                result.put("bytes", bytes);
            } catch (Exception ignored) {
            }
            log(INFO, "log", "cleared", "activity log cleared", result);
            return result;
        }
    }

    private static List<File> filesOldestFirst() {
        List<File> files = new ArrayList<File>();
        if (dir == null) {
            return files;
        }
        for (int i = MAX_ROTATED; i >= 1; i--) {
            File file = new File(dir, CURRENT_NAME + "." + i);
            if (file.exists()) {
                files.add(file);
            }
        }
        if (current != null && current.exists()) {
            files.add(current);
        }
        return files;
    }

    static String safe(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\n' || c == '\r' || c == '\t') {
                out.append(' ');
                continue;
            }
            if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) {
                out.append('?');
                continue;
            }
            if (c == '\u202a' || c == '\u202b' || c == '\u202c' || c == '\u202d'
                    || c == '\u202e' || c == '\u2066' || c == '\u2067'
                    || c == '\u2068' || c == '\u2069') {
                out.append('?');
                continue;
            }
            out.append(c);
        }
        return out.toString();
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return "";
        }
        String cleaned = value.replace('\n', ' ').replace('\r', ' ');
        if (cleaned.length() <= max) {
            return cleaned;
        }
        return cleaned.substring(0, max) + "...";
    }

    private static String cleanLevel(String level) {
        if (ERROR.equals(level) || WARN.equals(level) || INFO.equals(level) || DEBUG.equals(level)) {
            return level;
        }
        return INFO;
    }

    private static int rank(String level) {
        if (DEBUG.equals(level)) {
            return 10;
        }
        if (INFO.equals(level)) {
            return 20;
        }
        if (WARN.equals(level)) {
            return 30;
        }
        if (ERROR.equals(level)) {
            return 40;
        }
        return 0;
    }

    private static String pad(String value, int width) {
        if (value.length() >= width) {
            return value;
        }
        StringBuilder out = new StringBuilder(value);
        while (out.length() < width) {
            out.append(' ');
        }
        return out.toString();
    }

    private static int clamp(int value, int min, int max) {
        if (value < min) {
            return min;
        }
        if (value > max) {
            return max;
        }
        return value;
    }
}
