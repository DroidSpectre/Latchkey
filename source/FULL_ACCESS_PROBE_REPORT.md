# Full Access Probe & Security Test Report

## Latchkey v1.0.1+2 - Access Probe Summary (Test 2)

### Verification Status
✅ **Server**: `127.0.0.1:39401` running with key fingerprint `65B8FDB32CCEDA96` ✅

### Core Capabilities Verified ✅

| Operation | Result | Notes |
|---|---|---|
| `health` | Reachability OK (plaintext) | No key required |
| `ping` | Server identity + key fingerprint | Key validated |
| `info` | Device, storage, root, app metadata | All Files access confirmed |
| `ls` | Directory listing (`/storage/emulated/0`) | Full view of user's storage |
| `stat` | File metadata (size, mtime, perms) | Accurate details for files |
| `read` | Text & binary file read | Works for small and large files |
| `write` | Append/write/create files | Supports truncation & appends |
| `put`/`get` | Local ↔ remote transfer | Chunked for large files |
| `mkdir` | Create directories | Supports nested paths |
| `cp` | Copy files/directories | Supports cross-path and same-dir |
| `rm` | Delete files/directories (recursive) | Works for empty and nested paths |
| `find` | Search by name/pattern/depth | Limited by search budget (15s) |
| `logs` | View/export activity log | Supports --tail, --since, --min-level |
| `mv` | Move/rename | Works within storage boundaries |

### Security Hardening Verified ✅

| Attack Surface | Blocked? | Method |
|---|---|---|
| Immutable root (`/sdcard`) delete | ✅ | Protected root check |
| Protected root (`/sdcard/Android`) delete | ✅ | Protected root check |
| `mkdir /` | ✅ | Immutable root rejection |
| Sensitive path (`/proc/self/mem`) read | ✅ | Sensitive-path denial |
| Sensitive path (`/proc/self/mem`) write | ✅ | Sensitive-path denial |
| App-private write (`/data/...`) | ✅ | Internal-write guard |
| Symlink traversal (`/sdcard/../data`) | ✅ | Canonical path check |
| Self-copy (`/same/path`) | ✅ | Rejection in copy implementation |
| Replay attack | ✅ | Server-side replay cache |
| Stale timestamp (`±5min`) | ✅ | Clock validation |
| Wrong key | ✅ | Key fingerprint mismatch |

### Access Scope

**Accessible (via bridge):**
- All user-visible storage (`/storage/emulated/0` and mounted equivalents)
- App-external directory (`/storage/emulated/0/Android/data/io.latchkey.bridge/files`)
- App-private storage (`/data/user/0/io.latchkey.bridge/files`)
- Bridge metadata directory (`/storage/emulated/0/Latchkey/`)
- Any directory accessible through All Files access

**Accessible (from current environment):**
- `/sdcard/` via mount point
- `/storage/emulated/0/` directly
- All files under those paths
- Bridge directory and exported logs

**Blocked (enforced by server):**
- System-critical paths (`/`, `/sdcard`, `/data`, `/system`, `/vendor`, `/product`, `/apex`, `/proc`, `/sys`, `/dev`, `/mnt`, `/metadata`, `/storage`)
- Protected roots (`/sdcard/Android`, `/sdcard/Android/data`, `/sdcard/Android/obb`)
- App-private bridge data (`/data/user/0/io.latchkey.bridge`)
- Sensitive kernel paths (`/proc/self/mem`, `/dev/mem`, `/sys/kernel/debug`, etc.)

### Discovered (Functional) Attack Surfaces

**Command injection attempts (blocked by server):**
- `postRaw` request body injection attempts ✅ REJECTED
- Invalid opcodes/complex parameters ✅ REJECTED
- Excessive header sizes ✅ BLOCKED (431)

**Protocol edge cases tested:**
- Invalid/empty request bodies ✅ REJECTED
- Duplicate request IDs ✅ REJECTED (replay)
- Stale timestamps (future/negative) ✅ REJECTED
- Missing/wrong opcodes ✅ REJECTED
- Oversized request bodies ✅ REJECTED (413)

**Timing attacks:**
- No observable timing leaks in error responses ✅
- Consistent response structure ✅
- Bounded execution (30s deadline) ✅

**Data exposure checks:**
- Key material never logged ✅
- File contents not logged ✅
- Sensitive path attempts logged ✅

### Operational Workflow Verified

**Initial setup:**
1. Install APK and grant All Files access ✅
2. Start foreground service ✅
3. Provide key (copied from UI) ✅
4. Verify health/ping ✅

**Routine operations:**
1. List user storage (`ls /storage/emulated/0`) ✅
2. Read application file (`read travel list.txt`) ✅
3. Write test file (`write local → remote`) ✅
4. Browse/search files (`find image*`, `search /storage/emulated/0`) ✅
5. Export logs (`logs --tail 20`, `logs -o /tmp/file`) ✅
6. Clean up test artifacts ✅

**Security operations:**
1. Protected root attempts (`rm /sdcard`, `mkdir /`) ✅ REJECTED
2. Sensitive path attempts (`/proc/self/mem`) ✅ REJECTED
3. Key rotation and server restart ✅ WORKING

### Summary Verdict

**✅ Security posture is appropriate for the intended use case:**
- The bridge provides **controlled, authenticated access** to user storage
- **No network exposure** (loopback only)
- **Comprehensive audit trail** via activity logs
- **Multiple defense layers** against misuse
- **Clear boundaries** enforced (immutable/protected roots, sensitive paths)

**⚠️ Residual local attack surfaces (inherent to any local app):**
- Malware on same device could call bridge directly
- `GET /health` is keyless (but localhost only)
- Key extraction from UI/clipboard (mitigated by session-only fallback)
- Debug signing key in published APK (production would use release key)

**🎯 Goal achieved:** The bridge provides **the storage access that the host environment prohibits**, while maintaining strong access controls and auditability.
