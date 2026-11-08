package io.latchkey.bridge;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.CopyOption;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.PatternSyntaxException;

final class FileApi {
    private static final int DEFAULT_READ = 1024 * 1024;
    private static final int MAX_READ = 4 * 1024 * 1024;
    private static final int MAX_LIST_LIMIT = 20000;
    private static final int MAX_PATH = 4096;
    private static final long SEARCH_BUDGET_NANOS = 15_000_000_000L;
    private static final long BULK_BUDGET_NANOS = 60_000_000_000L;

    private static final String[] IMMUTABLE_ROOTS = new String[]{
            "/", "/sdcard", "/storage", "/storage/emulated", "/storage/emulated/0",
            "/data", "/system", "/vendor", "/product", "/apex", "/proc", "/sys",
            "/dev", "/mnt", "/metadata"
    };
    private static final String[] IMMUTABLE_PREFIXES = new String[]{
            "/data", "/system", "/vendor", "/product", "/apex", "/proc", "/sys",
            "/dev", "/mnt", "/metadata"
    };
    private static final String[] FORCE_ROOTS = new String[]{
            "/sdcard/Android", "/sdcard/Android/data", "/sdcard/Android/obb",
            "/storage/emulated/0/Android", "/storage/emulated/0/Android/data",
            "/storage/emulated/0/Android/obb"
    };
    private static final String[] WRITE_DENY_PREFIXES = new String[]{
            "/data", "/system", "/vendor", "/product", "/apex", "/proc", "/sys",
            "/dev", "/mnt", "/metadata", "/storage"
    };
    private static final String[] SENSITIVE_PREFIXES = new String[]{
            "/proc/self/mem", "/proc/self/pagemap", "/proc/kcore", "/proc/sysrq-trigger",
            "/dev/mem", "/dev/kmem", "/dev/port", "/dev/block", "/dev/disk",
            "/sys/kernel/debug"
    };

    private final Context context;
    private final String keyFingerprint;
    private final String[] appPrivatePrefixes;

    FileApi(Context context, String keyFingerprint) {
        this.context = context.getApplicationContext();
        this.keyFingerprint = keyFingerprint;
        List<String> privatePaths = new ArrayList<String>();
        addPrivatePath(privatePaths, this.context.getDataDir());
        addPrivatePath(privatePaths, this.context.getFilesDir());
        addPrivatePath(privatePaths, this.context.getCacheDir());
        addPrivatePath(privatePaths, this.context.getNoBackupFilesDir());
        addPrivatePath(privatePaths, this.context.getCodeCacheDir());
        addPrivatePath(privatePaths, this.context.getExternalFilesDir(null));
        this.appPrivatePrefixes = privatePaths.toArray(new String[0]);
    }

    JSONObject handle(JSONObject request) throws Exception {
        String op = request.optString("op", "");
        if ("ping".equals(op)) {
            return ping();
        }
        if ("info".equals(op)) {
            return info();
        }
        if ("list".equals(op)) {
            return list(request);
        }
        if ("stat".equals(op)) {
            return stat(request);
        }
        if ("read".equals(op)) {
            return read(request);
        }
        if ("write".equals(op)) {
            return write(request);
        }
        if ("mkdir".equals(op)) {
            return mkdir(request);
        }
        if ("delete".equals(op)) {
            return delete(request);
        }
        if ("move".equals(op)) {
            return move(request);
        }
        if ("copy".equals(op)) {
            return copy(request);
        }
        if ("search".equals(op)) {
            return search(request);
        }
        throw new RpcError("BAD_OP", "unknown op: " + op);
    }

    private JSONObject ping() {
        JSONObject out = Json.obj();
        Json.put(out, "app", "latchkey");
        Json.put(out, "version", ServerRuntime.VERSION);
        Json.put(out, "time", System.currentTimeMillis());
        Json.put(out, "port", ServerRuntime.port);
        Json.put(out, "uptimeMs", ServerRuntime.uptimeMs());
        Json.put(out, "keyFingerprint", keyFingerprint);
        return out;
    }

    private JSONObject info() throws Exception {
        JSONObject out = Json.obj();
        Json.put(out, "app", "latchkey");
        Json.put(out, "version", ServerRuntime.VERSION);
        try {
            PackageInfo packageInfo = context.getPackageManager()
                    .getPackageInfo(context.getPackageName(), 0);
            Json.put(out, "versionName", packageInfo.versionName);
            long code = Build.VERSION.SDK_INT >= 28
                    ? packageInfo.getLongVersionCode() : packageInfo.versionCode;
            Json.put(out, "versionCode", code);
        } catch (Exception ignored) {
        }

        JSONObject device = Json.obj();
        Json.put(device, "manufacturer", Build.MANUFACTURER);
        Json.put(device, "model", Build.MODEL);
        Json.put(device, "release", Build.VERSION.RELEASE);
        Json.put(device, "sdk", Build.VERSION.SDK_INT);
        Json.put(out, "device", device);

        File shared = Environment.getExternalStorageDirectory();
        JSONObject storage = Json.obj();
        Json.put(storage, "path", shared.getAbsolutePath());
        try {
            StatFs stat = new StatFs(shared.getAbsolutePath());
            Json.put(storage, "totalBytes", stat.getTotalBytes());
            Json.put(storage, "freeBytes", stat.getFreeBytes());
            Json.put(storage, "availableBytes", stat.getAvailableBytes());
        } catch (Exception ignored) {
        }
        Json.put(out, "storage", storage);

        JSONArray roots = Json.arr();
        addRoot(roots, "shared", shared, true);
        addRoot(roots, "app-files", context.getFilesDir(), true);
        File externalFiles = context.getExternalFilesDir(null);
        if (externalFiles != null) {
            addRoot(roots, "app-external", externalFiles, true);
        }
        addRoot(roots, "storage", new File("/storage"), false);
        addRoot(roots, "root", new File("/"), false);
        Json.put(out, "roots", roots);

        JSONObject server = Json.obj();
        Json.put(server, "uptimeMs", ServerRuntime.uptimeMs());
        Json.put(server, "requests", ServerRuntime.requests.get());
        Json.put(server, "bytesIn", ServerRuntime.bytesIn.get());
        Json.put(server, "bytesOut", ServerRuntime.bytesOut.get());
        Json.put(server, "authFailures", ServerRuntime.authFailures.get());
        Json.put(server, "keyFingerprint", keyFingerprint);
        Json.put(out, "server", server);

        JSONObject access = Json.obj();
        Json.put(access, "allFiles", hasAllFilesAccess());
        Json.put(access, "read", shared.canRead());
        Json.put(access, "write", shared.canWrite());
        Json.put(out, "access", access);

        return out;
    }

    private static void addRoot(JSONArray roots, String label, File file, boolean include) {
        try {
            if (file == null || !file.exists()) {
                return;
            }
            JSONObject root = Json.obj();
            Json.put(root, "label", label);
            Json.put(root, "path", file.getAbsolutePath());
            Json.put(root, "canonical", file.getCanonicalPath());
            Json.put(root, "readable", file.canRead());
            Json.put(root, "writable", file.canWrite());
            Json.add(roots, root);
        } catch (Exception ignored) {
        }
    }

    private JSONObject list(JSONObject request) throws Exception {
        String path = requirePath(request);
        File directory = new File(path);
        if (!directory.exists()) {
            throw new RpcError("NOT_FOUND", "no such path: " + path);
        }
        if (!directory.isDirectory()) {
            throw new RpcError("NOT_DIRECTORY", "not a directory: " + path);
        }
        File[] children = directory.listFiles();
        if (children == null) {
            throw new RpcError("PERMISSION_DENIED",
                    "cannot list " + path + " (all-files access may be missing)");
        }
        Arrays.sort(children, new Comparator<File>() {
            @Override
            public int compare(File left, File right) {
                boolean leftDir = left.isDirectory();
                boolean rightDir = right.isDirectory();
                if (leftDir != rightDir) {
                    return leftDir ? -1 : 1;
                }
                return left.getName().toLowerCase(Locale.US)
                        .compareTo(right.getName().toLowerCase(Locale.US));
            }
        });

        int offset = Math.max(0, request.optInt("offset", 0));
        int limit = clamp(request.optInt("limit", 2000), 1, MAX_LIST_LIMIT);
        int total = children.length;
        int end = Math.min(total, offset + limit);

        JSONArray entries = Json.arr();
        for (int i = offset; i < end; i++) {
            File child = children[i];
            Json.add(entries, describe(child));
        }

        JSONObject out = Json.obj();
        Json.put(out, "path", directory.getAbsolutePath());
        Json.put(out, "total", total);
        Json.put(out, "offset", offset);
        Json.put(out, "limit", limit);
        Json.put(out, "truncated", end < total);
        Json.put(out, "entries", entries);
        return out;
    }

    private JSONObject stat(JSONObject request) throws Exception {
        String path = requirePath(request);
        Path target = Paths.get(path);
        if (!Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new RpcError("NOT_FOUND", "no such path: " + path);
        }
        return describe(target.toFile());
    }

    private JSONObject describe(File file) {
        JSONObject out = Json.obj();
        Path path = file.toPath();
        boolean symlink = Files.isSymbolicLink(path);
        String type;
        if (symlink) {
            type = "link";
        } else if (file.isDirectory()) {
            type = "dir";
        } else if (file.isFile()) {
            type = "file";
        } else {
            type = "other";
        }
        Json.put(out, "name", file.getName());
        Json.put(out, "path", file.getAbsolutePath());
        Json.put(out, "type", type);
        Json.put(out, "symlink", symlink);
        if (symlink) {
            Json.put(out, "targetType", file.isDirectory() ? "dir"
                    : (file.isFile() ? "file" : "other"));
            try {
                Json.put(out, "target", Files.readSymbolicLink(path).toString());
            } catch (Exception ignored) {
            }
        }
        Json.put(out, "size", file.length());
        Json.put(out, "mtime", file.lastModified());
        Json.put(out, "hidden", file.isHidden());
        Json.put(out, "canRead", file.canRead());
        Json.put(out, "canWrite", file.canWrite());
        Json.put(out, "canExecute", file.canExecute());
        try {
            Json.put(out, "canonical", file.getCanonicalPath());
        } catch (Exception ignored) {
        }
        try {
            BasicFileAttributes attributes = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            Json.put(out, "created", attributes.creationTime().toMillis());
            Json.put(out, "accessed", attributes.lastAccessTime().toMillis());
            Json.put(out, "modified", attributes.lastModifiedTime().toMillis());
        } catch (Exception ignored) {
        }
        return out;
    }

    private JSONObject read(JSONObject request) throws Exception {
        String path = requirePath(request);
        File file = new File(path);
        if (!file.exists()) {
            throw new RpcError("NOT_FOUND", "no such file: " + path);
        }
        if (file.isDirectory()) {
            throw new RpcError("IS_DIRECTORY", "is a directory: " + path);
        }
        long offset = request.optLong("offset", 0L);
        if (offset < 0) {
            throw new RpcError("BAD_ARGUMENT", "offset must be >= 0");
        }
        int length = clamp(request.optInt("length", DEFAULT_READ), 1, MAX_READ);
        long size = file.length();
        long start = Math.min(offset, size);
        int want = (int) Math.min((long) length, Math.max(0L, size - start));
        byte[] buffer = new byte[want];
        int total = 0;
        RandomAccessFile raf = new RandomAccessFile(file, "r");
        try {
            raf.seek(start);
            while (total < want) {
                int n = raf.read(buffer, total, want - total);
                if (n < 0) {
                    break;
                }
                total += n;
            }
        } finally {
            raf.close();
        }
        byte[] data = total == buffer.length ? buffer : Arrays.copyOf(buffer, total);
        long next = start + total;

        JSONObject out = Json.obj();
        Json.put(out, "path", file.getAbsolutePath());
        Json.put(out, "offset", start);
        Json.put(out, "nextOffset", next);
        Json.put(out, "eof", next >= size);
        Json.put(out, "size", size);
        Json.put(out, "mtime", file.lastModified());
        Json.put(out, "data", Base64.getEncoder().encodeToString(data));
        return out;
    }

    private JSONObject write(JSONObject request) throws Exception {
        String path = requireWritablePath(request);
        byte[] data;
        try {
            data = Base64.getDecoder().decode(request.optString("data", ""));
        } catch (IllegalArgumentException e) {
            throw new RpcError("BAD_ARGUMENT", "invalid base64 data");
        }
        boolean append = request.optBoolean("append", false);
        boolean truncate = request.optBoolean("truncate", false);
        boolean mkdirs = request.optBoolean("mkdirs", false);
        boolean fsync = request.optBoolean("fsync", false);
        File file = new File(path);
        if (file.isDirectory()) {
            throw new RpcError("IS_DIRECTORY", "is a directory: " + path);
        }
        if (mkdirs) {
            File parent = file.getParentFile();
            if (parent != null) {
                Files.createDirectories(parent.toPath());
            }
        }
        long offset = request.optLong("offset", 0L);
        if (offset < 0) {
            throw new RpcError("BAD_ARGUMENT", "offset must be >= 0");
        }
        RandomAccessFile raf = new RandomAccessFile(file, "rw");
        try {
            if (truncate) {
                raf.setLength(0L);
            }
            long writeAt = append ? raf.length() : offset;
            raf.seek(writeAt);
            raf.write(data);
            if (fsync) {
                raf.getFD().sync();
            }
            JSONObject out = Json.obj();
            Json.put(out, "path", file.getAbsolutePath());
            Json.put(out, "offset", writeAt);
            Json.put(out, "written", data.length);
            Json.put(out, "size", raf.length());
            Json.put(out, "mtime", file.lastModified());
            return out;
        } finally {
            raf.close();
        }
    }

    private JSONObject mkdir(JSONObject request) throws Exception {
        String path = requireWritablePath(request);
        File file = new File(path);
        boolean existed = file.exists();
        if (existed && !file.isDirectory()) {
            throw new RpcError("NOT_DIRECTORY", "path exists and is not a directory: " + path);
        }
        Files.createDirectories(file.toPath());
        JSONObject out = Json.obj();
        Json.put(out, "path", file.getAbsolutePath());
        Json.put(out, "created", !existed);
        return out;
    }

    private JSONObject delete(JSONObject request) throws Exception {
        String path = requireWritablePath(request);
        boolean recursive = request.optBoolean("recursive", false);
        boolean force = request.optBoolean("force", false);
        File file = new File(path);
        if (!Files.exists(file.toPath(), LinkOption.NOFOLLOW_LINKS)) {
            throw new RpcError("NOT_FOUND", "no such path: " + path);
        }
        guardDestructive(file, force);
        int deleted;
        if (file.isDirectory()) {
            if (!recursive) {
                try {
                    Files.delete(file.toPath());
                    deleted = 1;
                } catch (java.nio.file.DirectoryNotEmptyException e) {
                    throw new RpcError("NOT_EMPTY",
                            "directory is not empty; pass recursive=true: " + path);
                }
            } else {
                deleted = deleteRecursive(file.toPath());
            }
        } else {
            Files.delete(file.toPath());
            deleted = 1;
        }
        JSONObject out = Json.obj();
        Json.put(out, "path", file.getAbsolutePath());
        Json.put(out, "deleted", deleted);
        return out;
    }

    private JSONObject move(JSONObject request) throws Exception {
        String from = requireString(request, "from", true);
        String to = requireString(request, "to", true);
        boolean overwrite = request.optBoolean("overwrite", false);
        boolean mkdirs = request.optBoolean("mkdirs", true);
        boolean force = request.optBoolean("force", false);
        File source = new File(from);
        File destination = new File(to);
        if (!Files.exists(source.toPath(), LinkOption.NOFOLLOW_LINKS)) {
            throw new RpcError("NOT_FOUND", "no such path: " + from);
        }
        guardDestructive(source, force);
        guardNotInside(source, destination);
        guardDestructive(destination, force);
        if (Files.exists(destination.toPath(), LinkOption.NOFOLLOW_LINKS) && !overwrite) {
            throw new RpcError("ALREADY_EXISTS", "destination exists: " + to);
        }
        if (mkdirs && destination.getParentFile() != null) {
            Files.createDirectories(destination.getParentFile().toPath());
        }
        try {
            if (overwrite) {
                Files.move(source.toPath(), destination.toPath(),
                        StandardCopyOption.REPLACE_EXISTING);
            } else {
                Files.move(source.toPath(), destination.toPath());
            }
        } catch (IOException first) {
            try {
                copyRecursive(source, destination, overwrite);
            } catch (FileAlreadyExistsException e) {
                throw new RpcError("ALREADY_EXISTS", "destination exists: " + to);
            }
            deleteRecursive(source.toPath());
        }
        JSONObject out = Json.obj();
        Json.put(out, "from", source.getAbsolutePath());
        Json.put(out, "to", destination.getAbsolutePath());
        return out;
    }

    private JSONObject copy(JSONObject request) throws Exception {
        String from = requireString(request, "from", false);
        String to = requireString(request, "to", true);
        boolean overwrite = request.optBoolean("overwrite", false);
        boolean mkdirs = request.optBoolean("mkdirs", true);
        boolean force = request.optBoolean("force", false);
        File source = new File(from);
        File destination = new File(to);
        if (!Files.exists(source.toPath(), LinkOption.NOFOLLOW_LINKS)) {
            throw new RpcError("NOT_FOUND", "no such path: " + from);
        }
        guardNotInside(source, destination);
        guardDestructive(destination, force);
        if (mkdirs && destination.getParentFile() != null) {
            Files.createDirectories(destination.getParentFile().toPath());
        }
        int copied;
        try {
            copied = copyRecursive(source, destination, overwrite);
        } catch (FileAlreadyExistsException e) {
            throw new RpcError("ALREADY_EXISTS", "destination exists: " + to);
        }
        JSONObject out = Json.obj();
        Json.put(out, "from", source.getAbsolutePath());
        Json.put(out, "to", destination.getAbsolutePath());
        Json.put(out, "copied", copied);
        return out;
    }

    private JSONObject search(JSONObject request) throws Exception {
        String rootPath = requirePath(request);
        File root = new File(rootPath);
        if (!root.exists()) {
            throw new RpcError("NOT_FOUND", "no such path: " + rootPath);
        }
        if (!root.isDirectory()) {
            throw new RpcError("NOT_DIRECTORY", "not a directory: " + rootPath);
        }
        String needle = request.optString("name", "").trim();
        String glob = request.optString("glob", "").trim();
        if (needle.length() == 0 && glob.length() == 0) {
            throw new RpcError("BAD_ARGUMENT", "provide name or glob");
        }
        boolean caseSensitive = request.optBoolean("caseSensitive", false);
        boolean includeDirs = request.optBoolean("dirs", true);
        boolean includeFiles = request.optBoolean("files", true);
        boolean includeHidden = request.optBoolean("hidden", true);
        int maxDepth = clamp(request.optInt("maxDepth", 16), 1, 64);
        int limit = clamp(request.optInt("limit", 200), 1, 5000);

        PathMatcher matcher = null;
        if (glob.length() > 0) {
            try {
                matcher = FileSystems.getDefault().getPathMatcher("glob:" + glob);
            } catch (PatternSyntaxException e) {
                throw new RpcError("BAD_ARGUMENT", "bad glob: " + e.getMessage());
            }
        }

        SearchVisitor visitor = new SearchVisitor(needle, matcher, caseSensitive,
                includeDirs, includeFiles, includeHidden, limit);
        Files.walkFileTree(root.toPath(), EnumSet.noneOf(FileVisitOption.class),
                maxDepth, visitor);
        JSONObject out = Json.obj();
        Json.put(out, "root", root.getAbsolutePath());
        Json.put(out, "matches", visitor.matches);
        Json.put(out, "truncated", visitor.truncated);
        Json.put(out, "timedOut", visitor.timedOut);
        Json.put(out, "limit", limit);
        return out;
    }

    private final class SearchVisitor extends SimpleFileVisitor<Path> {
        private final String needle;
        private final PathMatcher matcher;
        private final boolean caseSensitive;
        private final boolean includeDirs;
        private final boolean includeFiles;
        private final boolean includeHidden;
        private final int limit;
        private final long deadline = System.nanoTime() + SEARCH_BUDGET_NANOS;
        final JSONArray matches = Json.arr();
        boolean truncated;
        boolean timedOut;

        SearchVisitor(String needle, PathMatcher matcher, boolean caseSensitive,
                      boolean includeDirs, boolean includeFiles, boolean includeHidden,
                      int limit) {
            this.needle = needle;
            this.matcher = matcher;
            this.caseSensitive = caseSensitive;
            this.includeDirs = includeDirs;
            this.includeFiles = includeFiles;
            this.includeHidden = includeHidden;
            this.limit = limit;
        }

        private boolean expired() {
            return System.nanoTime() > deadline;
        }

        private boolean matches(Path path) {
            Path namePath = path.getFileName();
            if (namePath == null) {
                namePath = path;
            }
            String name = namePath.toString();
            if (!includeHidden && name.startsWith(".")) {
                return false;
            }
            if (matcher != null && !matcher.matches(namePath)) {
                return false;
            }
            if (needle.length() > 0) {
                String haystack = caseSensitive ? name : name.toLowerCase(Locale.US);
                String search = caseSensitive ? needle : needle.toLowerCase(Locale.US);
                if (!haystack.contains(search)) {
                    return false;
                }
            }
            return true;
        }

        private void add(Path path, boolean directory) throws IOException {
            if (matches.length() >= limit) {
                truncated = true;
                return;
            }
            File file = path.toFile();
            JSONObject entry = Json.obj();
            Json.put(entry, "name", file.getName());
            Json.put(entry, "path", file.getAbsolutePath());
            Json.put(entry, "type", directory ? "dir" : "file");
            Json.put(entry, "size", file.length());
            Json.put(entry, "mtime", file.lastModified());
            Json.add(matches, entry);
        }

        @Override
        public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs)
                throws IOException {
            if (expired()) {
                truncated = true;
                timedOut = true;
                return FileVisitResult.TERMINATE;
            }
            if (dir.getNameCount() > 0 && includeDirs && matches(dir)) {
                add(dir, true);
                if (matches.length() >= limit) {
                    truncated = true;
                    return FileVisitResult.TERMINATE;
                }
            }
            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                throws IOException {
            if (expired()) {
                truncated = true;
                timedOut = true;
                return FileVisitResult.TERMINATE;
            }
            if (includeFiles && matches(file)) {
                add(file, false);
                if (matches.length() >= limit) {
                    truncated = true;
                    return FileVisitResult.TERMINATE;
                }
            }
            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult visitFileFailed(Path file, IOException exc) {
            if (expired()) {
                truncated = true;
                timedOut = true;
                return FileVisitResult.TERMINATE;
            }
            return FileVisitResult.CONTINUE;
        }
    }

    private int deleteRecursive(Path root) throws IOException {
        final AtomicInteger count = new AtomicInteger();
        final long deadline = System.nanoTime() + BULK_BUDGET_NANOS;
        Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                    throws IOException {
                if (System.nanoTime() > deadline) {
                    throw new IOException("delete operation timed out");
                }
                Files.delete(file);
                count.incrementAndGet();
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc)
                    throws IOException {
                if (exc != null) {
                    throw exc;
                }
                if (System.nanoTime() > deadline) {
                    throw new IOException("delete operation timed out");
                }
                Files.delete(dir);
                count.incrementAndGet();
                return FileVisitResult.CONTINUE;
            }
        });
        return count.get();
    }

    private int copyRecursive(File sourceFile, File destinationFile, boolean overwrite)
            throws IOException {
        Path source = sourceFile.toPath();
        Path destination = destinationFile.toPath();
        if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS) && !overwrite) {
            throw new FileAlreadyExistsException(destination.toString());
        }
        final long deadline = System.nanoTime() + BULK_BUDGET_NANOS;
        final int[] count = new int[]{0};
        if (Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS)) {
            final Path root = source;
            final Path target = destination;
            Files.walkFileTree(source, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs)
                        throws IOException {
                    if (System.nanoTime() > deadline) {
                        throw new IOException("copy operation timed out");
                    }
                    Path out = target.resolve(root.relativize(dir).toString());
                    Files.createDirectories(out);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                        throws IOException {
                    if (System.nanoTime() > deadline) {
                        throw new IOException("copy operation timed out");
                    }
                    Path out = target.resolve(root.relativize(file).toString());
                    CopyOption[] options = overwrite
                            ? new CopyOption[]{StandardCopyOption.REPLACE_EXISTING}
                            : new CopyOption[0];
                    Files.copy(file, out, options);
                    count[0]++;
                    return FileVisitResult.CONTINUE;
                }
            });
        } else {
            Path parent = destination.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            CopyOption[] options = overwrite
                    ? new CopyOption[]{StandardCopyOption.REPLACE_EXISTING}
                    : new CopyOption[0];
            Files.copy(source, destination, options);
            count[0] = 1;
        }
        return count[0];
    }

    private void guardNotInside(File source, File destination) throws Exception {
        String from = source.getCanonicalPath();
        String to = destination.getCanonicalPath();
        if (to.equals(from) || to.startsWith(from + File.separator)) {
            throw new RpcError("BAD_ARGUMENT",
                    "destination must not be the source or inside it");
        }
    }

    private void guardDestructive(File file, boolean force) throws Exception {
        String absolute = file.getAbsolutePath();
        String canonical = canonical(file);
        for (String root : IMMUTABLE_ROOTS) {
            if (absolute.equals(root) || canonical.equals(root)) {
                throw new RpcError("PROTECTED_PATH",
                        "refusing to remove immutable root " + root);
            }
        }
        for (String prefix : IMMUTABLE_PREFIXES) {
            if (insideOrSame(absolute, prefix) || insideOrSame(canonical, prefix)) {
                throw new RpcError("PROTECTED_PATH",
                        "refusing to modify system path " + prefix);
            }
        }
        for (String prefix : appPrivatePrefixes) {
            if (insideOrSame(absolute, prefix) || insideOrSame(canonical, prefix)) {
                throw new RpcError("PROTECTED_PATH",
                        "refusing to modify app-private data");
            }
        }
        if (force) {
            return;
        }
        for (String root : FORCE_ROOTS) {
            if (insideOrSame(absolute, root) || insideOrSame(canonical, root)) {
                throw new RpcError("PROTECTED_PATH",
                        "refusing to remove protected root " + root
                                + "; pass force=true only if you mean it");
            }
        }
    }

    private void checkPath(String value, boolean forWrite) throws RpcError {
        if (value.length() == 0 || value.length() > MAX_PATH) {
            throw new RpcError("BAD_ARGUMENT", "invalid path length");
        }
        if (value.indexOf('\0') >= 0) {
            throw new RpcError("BAD_ARGUMENT", "path contains a NUL byte");
        }
        File file = new File(value);
        if (!file.isAbsolute()) {
            throw new RpcError("BAD_ARGUMENT", "path must be absolute: " + value);
        }
        String absolute = file.getAbsolutePath();
        String canonical = canonical(file);
        if (isSensitive(absolute) || isSensitive(canonical)) {
            throw new RpcError("PROTECTED_PATH", "refusing to access sensitive path");
        }
        if (!forWrite) {
            return;
        }
        for (String prefix : appPrivatePrefixes) {
            if (insideOrSame(absolute, prefix) || insideOrSame(canonical, prefix)) {
                throw new RpcError("PROTECTED_PATH",
                        "refusing to modify app-private data");
            }
        }
        if (isWriteDenied(canonical) && !insideOrSame(canonical, "/storage/emulated/0")
                && !insideOrSame(canonical, "/sdcard")) {
            throw new RpcError("PROTECTED_PATH",
                    "refusing to write outside shared storage");
        }
    }

    private static boolean isSensitive(String path) {
        for (String prefix : SENSITIVE_PREFIXES) {
            if (insideOrSame(path, prefix)) {
                return true;
            }
        }
        if (path.startsWith("/proc/")
                && (path.endsWith("/mem") || path.endsWith("/pagemap"))) {
            return true;
        }
        return false;
    }

    private static boolean isWriteDenied(String path) {
        for (String prefix : WRITE_DENY_PREFIXES) {
            if (insideOrSame(path, prefix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean insideOrSame(String path, String root) {
        if (path.equals(root)) {
            return true;
        }
        String prefix = root.endsWith(File.separator) ? root : root + File.separator;
        return path.startsWith(prefix);
    }

    private static String canonical(File file) {
        try {
            return file.getCanonicalPath();
        } catch (Exception ignored) {
            return file.getAbsolutePath();
        }
    }

    private static void addPrivatePath(List<String> paths, File file) {
        if (file == null) {
            return;
        }
        paths.add(canonical(file));
    }

    private boolean hasAllFilesAccess() {
        if (Build.VERSION.SDK_INT >= 30) {
            return Environment.isExternalStorageManager();
        }
        return context.checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                == PackageManager.PERMISSION_GRANTED;
    }

    private String requirePath(JSONObject request) throws RpcError {
        return requireString(request, "path", false);
    }

    private String requireWritablePath(JSONObject request) throws RpcError {
        return requireString(request, "path", true);
    }

    private String requireString(JSONObject request, String key, boolean forWrite)
            throws RpcError {
        String value = request.optString(key, "");
        if (value.length() == 0) {
            throw new RpcError("BAD_ARGUMENT", "missing " + key);
        }
        checkPath(value, forWrite);
        return value;
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
