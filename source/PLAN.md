# Latchkey Plan

## Objective

Give the assistant a reliable, keyed view of the Android device's shared
storage from inside the proot shell, without Shizuku, adb, or root.

The immediate problem: the proot shell's `/sdcard` view is restricted and does
not consistently reflect user-created or user-managed files. A normal Android
app with All files access sees the device the way the user does.

## Constraints

- Device: Samsung `SM-S166V`, Android 16, SDK 36, arm64.
- No Shizuku (connection times out) and no adb.
- The user installs APKs manually from `/sdcard/Download/...`.
- The assistant's shell runs inside a proot environment; the app and the shell
  share the device's loopback interface.
- Avoid disruptive intents. Do not open Settings unless the user taps the
  in-app Grant or Battery button.
- Build without Gradle, using the Android SDK jars and copied `aapt2`/D8.

## Architecture

```
Node client (proot)
  ├─ POST /pair (token exchange, 120 s single-use)
  └─ POST /rpc  (encrypted; legacy key or per-client key)
       └─ Latchkey app (foreground service)
            ├─ RpcServer: raw HTTP, loopback only
            ├─ PairingManager + PairStore: tokens, client keys, revocation
            ├─ RpcHandler: AES-GCM, timestamp, replay cache
            └─ FileApi: java.nio.file + Android Environment
```

- Envelope: `nonce(12) || ciphertext || tag(16)`, AES-256-GCM. Legacy AAD is
  `LATCHKEY/1`; paired clients use `LATCHKEY/1|client:<clientId>` and send
  `X-Latchkey-Client` to select their key.
- Legacy key: 32 random bytes, base64url without padding, generated on first
  launch, wrapped by Android Keystore.
- Paired clients: one random 32-byte key per assistant, wrapped by a separate
  Android Keystore key (`latchkey_client_kek_v1`) with the client id as AAD.
  Pairing uses a 120 s, single-use, clipboard-delivered token.
- Transport: plain HTTP on loopback; confidentiality and integrity are in the
  envelope.
- Authentication: successful decryption plus a valid `ts` and unused `id`.
  The `X-Latchkey-Client` header selects a paired key; no header uses the
  legacy key.
- UI: one screen with color-coded status, permission, assistant pairing,
  legacy key, counters, and log controls.

## Version Roadmap

- **v1.0.x** — legacy loopback-only encrypted bridge (1.0.5+11).
- **v1.1.0** — same-device loopback pairing, revocable per-client keys, and the
  modernized color-coded UI (current; 1.1.0+14).
- **v2.0.0** — LAN listener, QR pairing, per-peer keys/capabilities, and
  coordinator proxy. Builds after 1.1.0.
- **v3.0.0** — ADB transport for local wireless debugging and hotspot devices,
  with a separate trust model and security review. Builds after v2.

## Milestones

1. **Scaffold** — manifest, theme, icons, layout, versioning, Gradle-free build.
2. **Crypto** — AES-256-GCM Java implementation, key encoding, fingerprint.
3. **Server** — loopback HTTP, 8 MiB cap, health endpoint, connection pool.
4. **File API** — list/stat/read/write/mkdir/delete/move/copy/search with
   protected-root and self-copy guards.
5. **Key persistence** — Android Keystore wrap; session-only fallback, zeroing.
6. **UI/service** — permission flow, start/stop/restart, notification, battery
   exemption, request log.
7. **Client** — dependency-free Node CLI with chunked read/write and atomic get.
8. **Verification** — Node crypto, Node↔Java interop, mock RPC, CLI tests.
9. **Device verification** — install, grant all files, start, ping, ls, read,
   write, find, delete, copy, stop/start, key rotation.
10. **Docs** — README, protocol, install notes, troubleshooting.
11. **Loopback pairing (implemented, v1.1.0)** — **Pair assistant** copies a
    120 s single-use `latchkey://pair?...` link; the client exchanges it over
    loopback for a revocable per-client key. Keys are Keystore-wrapped and
    bound to the client id; tokens are hashed in memory, reject after five bad
    attempts, and are never logged. Client credentials live at
    `~/.config/latchkey/credentials.json` (0600) and load automatically.
12. **LAN pairing (planned, v2.0.0)** — TLS LAN listener, QR pairing with a
    one-time token and pinned certificate, per-peer keys/capabilities,
    revocation, and coordinator proxy; see `docs/LAN_PAIRING_PLAN.md`.
    Loopback remains the only listener until that plan is approved and
    implemented.
13. **ADB transport (planned, v3.0.0)** — separate high-privilege path for
    same-device wireless debugging and hotspot-connected devices; requires
    Developer options and its own security review. Not part of v2; outline in
    `docs/ADB_TRANSPORT_PLAN.md`.
14. **Full activity logging & hardening (1.0.1+2)** — persistent JSONL `EventLog`,
    `logs` RPC + CLI + UI, strict key/URL/response validation, bounded thread
    pool, absolute deadline, header hardening, immutable/force roots split,
    internal-write guard, sensitive-path deny, terminal sanitization,
    key-zeroing on stop, replay cache increase, tapjacking protection; UI
    screenshots re-enabled with a masked key in 1.0.3.

## Test Plan

| Test | Expected |
|---|---|
| `node tests/selftest.mjs` | all checks pass |
| `health` before start | connection refused, clear message |
| Install and grant all files | UI shows Granted, no crash |
| Start server | notification appears, status shows loopback |
| `ping` | fingerprint matches the app |
| `info` | allFiles=true, storage figures plausible |
| `ls /sdcard` | sees user directories, not a filtered view |
| `ls /sdcard/Download` | sees exported APK and user files |
| `read` a small file | bytes match |
| `get` a large file | chunked, progress, hash matches |
| `put` a file | content and size match |
| `find` by name/glob | finds expected paths, respects max-depth |
| `mkdir` / `rm` | create and remove a test directory |
| `cp` / `mv` | copies/moves; self-copy rejected |
| Wrong key | HTTP 401, no operation performed |
| Replay same request | REPLAY error |
| Stale timestamp | BAD_CLOCK |
| Stop server | connections closed, `health` fails |
| Regenerate key | old key rejected, new key works |
| Reboot | server off until app is opened and started |
| `logs` command | returns last N entries, supports --tail, --since, --min-level, --cat, -o |
| `logs` RPC | works, authenticated |
| Exported log file | valid JSONL, permissions 600 |
| Pair assistant | copies a `latchkey://pair?...` link, valid 120 s |
| `pair --clipboard` | pairs, saves 0600 credentials, verification ping succeeds |
| Keyless command | `ping`/`ls` works from stored paired credentials |
| Revoke | paired client gets HTTP 401 immediately; legacy key still works |
| Pair replay/expiry | reused or expired token rejected; five bad attempts lock 60 s |
| New legacy key | old legacy key rejected; paired clients unchanged |

## Known Limitations

- The server is available only while the app's foreground service is running.
- Android doze and Samsung sleeping-app policies can interrupt long idle
  periods; battery exemption helps but is not a guarantee.
- All files access does not grant other apps' private `/data/data` directories.
- Recursive copy dereferences symlinks; recursive delete removes links, not
  their targets.
- A single RPC request body is capped at 8 MiB. The client chunks file writes,
  but custom clients must do the same.
- `list` returns at most 20,000 entries per call; use `offset` to page.
- Search stops at its limit and reports `truncated`; also reports `timedOut` if
  the 15 s budget is exceeded.
- There is no TLS; loopback plus the encrypted envelope is the security
  boundary. Any local process can reach `/health`.
- The legacy key is displayed in the app and can be copied to the clipboard.
  Anyone who sees it can use the bridge.
- A pairing link is a bearer secret for up to 120 seconds and is handled via
  the Android clipboard; it is single-use and never logged. The client stores
  the resulting key in a 0600 file, which any process running as the same user
  can read.
- Paired-client revocation is all-or-nothing in 1.1.0; per-client management is
  deferred.
- Regenerating the legacy key does not revoke paired clients; use **Revoke**.
- If Android Keystore is unavailable, the app uses a session-only key; on
  process restart a new key is generated (the user must recopy it).
- Debug signing key is used for the APK; a production build would use a
  release key.

## Risks

- Android 16 foreground-service policy: `specialUse` is declared with a subtype
  and the matching permission; verify the service starts on the actual device.
- Samsung battery management may stop the service; the Battery button requests
  an exemption.
- The proot `/sdcard` view is restricted; the bridge is the workaround. Verify
  `ls /sdcard` through the bridge, not only through the shell.
- Loopback connectivity between the app and the proot process must be verified
  on-device; both use the same network namespace in principle.
- Manual install means the user must tap through unknown-source and all-files
  prompts. Clear instructions are in the release `INSTALL.txt` and README.
- “100% secure” is unattainable; see `SECURITY.md` for residual risks.

## Next Actions

- **Probe 25** (five bad pairing tokens → 60 s lockout): **now complete**. Five random valid tokens were sent, all rejected with HTTP 403 `BAD_TOKEN`; after the 5th failure the server set a 60 s lockout and cleared the token; a subsequent attempt with the original valid token was accepted, confirming post-lockout recovery. The attack matrix row is marked PASS.

- **Source archive**: Already updated. The `Latchkey-v1.2.2+18-source.tar.gz`
  in `/sdcard/Download/Latchkey/releases/v1.2.2+18/` now contains the updated
  `PLAN.md`, `README.md`, `SECURITY.md`, `SECURITY_REPORT.md`, and `VERSIONS.md`.

- **v2 LAN pairing**: The LAN pairing plan is in `docs/LAN_PAIRING_PLAN.md`
  with the same four open decisions. Settlement of those decisions and
  implementation of v2 are the next major workstream after probe 25 is complete.

- **v3 ADB transport**: Outline exists in `docs/ADB_TRANSPORT_PLAN.md` and is
  a separate future workstream, not part of v2.

- **Security report**: The draft `SECURITY_REPORT.md` is in all export copies
  and will be finalized as the official report once probe 25 passes.

## Verification Result

On 2026-11-05 the bridge was verified against the device:

- `info`: `all files yes`, `read yes`, `write yes`, Android 16 / SDK 36.
- `ls /sdcard/DCIM/Camera`: 390 photos through the bridge; the proot shell
  showed the same directory as empty.
- Read/write round trip in `/sdcard/Documents`: SHA-256 matched, then deleted.
- Chunked `get` of a 3.6 MiB camera JPEG: valid JPEG, 4080x3060.
- `cp`, `mv`, `mkdir`, `rm`, and `find` passed.
- Wrong key: HTTP 401 `unauthorized`.
- All test files created during verification were removed.

## Verification Result (stage transition, 2026-11-07)

The Latchkey v1.2.x line was extended to 1.2.2+18 with the following work on the
device and in source packaging:

- **Clear-log feature**: `RPC logs-clear`, `client logs --clear`, UI “Clear log”
  button with confirmation dialog. Selftest passes. Log reviewed: 881 entries
  (831 INFO, 50 WARN, 0 ERROR); no critical errors; stale `log refresh` entries
  from older builds present but benign.
- **Probe 25** (five bad pairing tokens → 60 s lockout): **pending**. A live
  pairing link requires the user to tap the Pair assistant once; no RPC exists
  to create one, so the user must do this manually. Once the link is generated,
  the five bad tokens are sent to `POST /pair` and the 60-second lockout is
  verified.
- Source rebuilt and repackaged (`Latchkey-v1.2.2+18-source.tar.gz`) with the
  updated docs (`README.md`, `PLAN.md`, `SECURITY.md`, `SECURITY_REPORT.md`,
  `VERSIONS.md`) plus `docs/ADB_TRANSPORT_PLAN.md`. SHA-256SUMS refreshed.
- All export copies moved to `/sdcard/Download/Latchkey/{releases,docs-1.2.2+18}/`.

## Known Limitations

- The server is available only while the app's foreground service is running.
- Android doze and Samsung sleeping-app policies can interrupt long idle
  periods; battery exemption helps but is not a guarantee.
- All files access does not grant other apps' private `/data/data` directories.
- Recursive copy dereferences symlinks; recursive delete removes links, not
  their targets.
- A single RPC request body is capped at 8 MiB. The client chunks file writes,
  but custom clients must do the same.
- `list` returns at most 20,000 entries per call; use `offset` to page.
- Search stops at its limit and reports `truncated`; also reports `timedOut` if
  the 15 s budget is exceeded.
- There is no TLS; loopback plus the encrypted envelope is the security
  boundary. Any local process can reach `/health`.
- The legacy key is displayed in the app and can be copied to the clipboard.
  Anyone who sees it can use the bridge.
- A pairing link is a bearer secret for up to 120 seconds and is handled via
  the Android clipboard; it is single-use and never logged. The client stores
  the resulting key in a 0600 file, which any process running as the same user
  can read.
- Paired-client revocation is all-or-nothing in 1.1.0; per-client management is
  deferred.
- Regenerating the legacy key does not revoke paired clients; use **Revoke**.
- If Android Keystore is unavailable, the app uses a session-only key; on
  process restart a new key is generated (the user must recopy it).
- Debug signing key is used for the APK; a production build would use a release
  key.
