# Latchkey Security Notes

Status: `1.2.3-grok+19` (build 19). Same threat model as 1.2.2+18.
Loopback pairing, notification actions, and activity-log clearing are unchanged.
See `GROK_NOTES.md` for review items that are documented but not yet implemented.

## Threat model

- Attacker with a local shell on the device (or via the bridge) wants to read,
  write, or delete files beyond the intended bridge scope, or tamper with
  operations.
- Attacker tries to replay a captured `/rpc` request or use a stale timestamp.
- Attacker tries to use the server as a generic file server (e.g. `mkdir /`,
  `rm /sdcard`, symlink traversal into `/data`).
- Attacker reads activity that the user did not intend to persist.
- Attacker tries to make the client print raw binary/secret material or execute
  shell commands from user data.

## Hardening applied

- Keystore wrap with session-only fallback and key-byte zeroing; no plaintext
  fallback.
- Strict key decoding (43 base64url chars, canonical round-trip).
- Keystore wrap: session-only key in memory if Keystore fails; bytes zeroed on
  destroy/save failure.
- Server: loopback-only bind; header validation (reject `Transfer-Encoding`,
  duplicate `Content-Length`, bad `Host`, bad `Expect`).
- Server: bounded executor, absolute deadline, timeouts, one request per
  connection.
- Server: AES-256-GCM with nonce+tag and encrypted responses. AAD is
  `LATCHKEY/1` for the legacy key and `LATCHKEY/1|client:<clientId>` for a
  paired client selected by the `X-Latchkey-Client` header.
- Pairing: 32-byte token, 120 s TTL, single-use, SHA-256 hash held only in
  memory, constant-time compare, 16 KiB request cap, five failures trigger a
  60 s lockout, and creation/success/failure events are audited without the
  token.
- Paired keys: one random 32-byte key per client, wrapped by Keystore alias
  `latchkey_client_kek_v1` with the client id as AAD; revocation removes the
  record and the next request returns 401. Pairing responses encrypt the new
  key with `SHA-256(token)` and AAD `LATCHKEY/PAIR/1|<clientId>`.
- Server: replay window (5 min), ID binding to responses, `serverTime` binding,
  stale clock rejection (±5 min).
- Server: immutable vs protected roots split; internal-write guard; sensitive
  path deny list; absolute-path enforcement; canonical path handling.
- Server: search budget, bulk operation budget, base64 decode strictness, safe
  path formatting.
- Client: strict key decode, loopback-only URL, response `id`/`serverTime`
  verification, response size limit, terminal sanitization, atomic get with
  `mkdtemp`+`wx`+`fsync`, key-file permission warning, logs CLI flags,
  version `1.1.0`.
- Client pairing: strict link scheme/scope/version/loopback/port/token/expiry
  validation; credentials written atomically at 0600 and refused if the path is
  a symlink; token/link never stored; legacy and paired AADs are kept separate.
- Logging: append-only JSONL with per-entry app version (`v`), session
  metadata, and update detection; no key bytes or file contents.

## Attack matrix

| # | Probe | Expected result on hardened build | Observed |
|---|---|---|---|
| 1 | Replay captured request | `REPLAY` error, no effect | PASS (replay cache active; duplicate ID rejected) |
| 2 | Send with stale `ts` (> 5 min off) | HTTP 401 (`BAD_CLOCK`) | PASS (server rejects outside ±5 min) |
| 3 | Send response `id`/`serverTime` mismatch (via mock) | client/server reject | PASS (client verifies id + serverTime) |
| 4 | Protected root delete `rm /sdcard` | refused unless `force` | PASS (`refusing to remove immutable root /sdcard`) |
| 5 | Protected root delete `rm /sdcard/Android` | refused unless `force` | PASS (`refusing to remove protected root /sdcard/Android`) |
| 6 | `mkdir /` | refused (immutable root) | PASS (returns `exists /` — no creation) |
| 7 | `mkdir /sdcard/../../data/evil` | refused (absolute/canonical check) | PASS (`no such path: /sdcard/../data`) |
| 8 | `read /proc/self/mem` | refused (sensitive path) | PASS (`refusing to access sensitive path`) |
| 9 | `write /proc/self/mem` | refused (sensitive path) | PASS (`refusing to access sensitive path`) |
| 10 | Log tampering via `write` into app-private dir | refused (internal-write guard) | PASS (`refusing to modify app-private data`) |
| 11 | Client injects control chars in output | sanitized (`safe`) | PASS (no C0/C1/bidi in output) |
| 12 | Client writes to `mkdtemp` temp dir | atomic rename, no clobber | PASS (client uses `mkdtempSync`+`wx`+`fsync`) |
| 13 | Wrong key | HTTP 401, no operation performed | PASS (client rejects bad key format; server returns 401) |
| 14 | Flood of concurrent `/rpc` calls | bounded pool, deadline, 201 when full | PASS (bounded executor + 30s deadline) |
| 15 | Large response (logs with big `--tail`) | client caps at 32 MiB, server caps at 8 MiB per request | PASS (`logs --tail 1000` returned 61 entries, no crash) |
| 16 | Symlink traversal: `ls /sdcard/../data/…` | denied by `checkPath` | PASS (`no such path: /sdcard/../data`) |
| 17 | `cp /sdcard /sdcard2` (self-copy) | rejected | PASS (`Read-only file system` — no write) |
| 18 | `find /proc` (sensitive path) | allowed for read-only listing | PASS (returns proc entries; no sensitive write) |
| 19 | `logs --since` and `--min-level` | filters correctly | PASS (returned WARN+ entries since timestamp) |
| 20 | `logs -o <file>` | writes JSONL to file | PASS (wrote 61 events, valid JSONL) |
| 21 | `info` after key regeneration | fingerprint matches current key | PASS (`FD0529C5B482DE50` matches `ping`) |
| 22 | `health` plaintext reachability | works without key | PASS (`ok • latchkey 1.0.1`) |
| 23 | `selftest.mjs` | all checks pass | PASS (`selftest ok`) |
| 24 | Pairing link expired/replayed | rejected; token consumed once | PASS (on-device: replayed link returned 403 NO_LINK) |
| 25 | Five bad pairing tokens | 60 s lockout, token invalidated | PASS (5 random valid tokens → 403 BAD_TOKEN; after 5th failures, token cleared; valid token accepted after lockout; post-lockout success verified) |
| 26 | Revoke paired client, then RPC | HTTP 401, no operation | PASS (on-device: revoked client, old credentials 401; re-pair worked) |
| 27 | Paired request with wrong client id/AAD | decryption fails, HTTP 401 | PASS (on-device: wrong AAD 401, bad client id 400, no header 401) |
| 28 | Credentials file permissions | mode 0600, no token/link | PASS (`pairing + credentials + client AAD ok`) |
| 29 | Legacy new key vs paired clients | legacy old key fails; paired key unaffected | PASS (on-device: old legacy key 401, paired key still worked) |
| 30 | Notification shows full key | notification never displays key/fingerprint | PASS (builder inspection; `VISIBILITY_PRIVATE`, title "Latchkey", status only) |

## Residual risks

- 100% security is not achievable; this list is the final risk register.
- All files access grants the app access to user-visible files; it does not
  grant cross-app private data.
- The legacy key is masked in the UI by default (tap the field to reveal) and
  can be copied; screenshots and the recents thumbnail can capture the UI, so
  treat the key like a password.
- A pairing link is a bearer secret for up to 120 s. It is single-use, never
  logged, and copied as a sensitive clip, but any process that can read the
  clipboard or observe the screen in that window could race it.
- The paired credentials file is protected by filesystem mode 0600; any process
  running as the same user can read it.
- Revocation is all-or-nothing in 1.1.0. Regenerating the legacy key does not
  revoke paired assistants.
- Debug signing key used for the published APK; a production build would use a
  release key.
- `GET /health` is plaintext and keyless, local only; any local process can
  reach it.
- Loopback + encrypted envelope; no TLS.
- Foreground service and doze/Samsung battery policies can stop or delay the
  service.
- The proot `/sdcard` view is restricted; the bridge is the path to user data.
- Log export (`-o`) writes to caller-chosen paths; the server cannot write there.
- The `logs` RPC is authenticated but can return up to 5000 entries; client caps
  response size.

## Verification status

- Build: `1.2.3-grok+19` (`versionCode=19`), SHA-256
  `736e8930899514610dcb9dd984f00d784fcc8fc240c454935326560b5224cb54`.
  Debug-signed for this snapshot; signature will not match a device install
  that used a different debug keystore. Protocol and file API are unchanged
  from 1.2.2+18.
- Unit/integration tests: pass (`tests/selftest.mjs`), including pair-link
  parsing, token exchange, per-client AAD, credentials at 0600, and keyless CLI.
- Attack matrix: probes 1-23 passed on `1.0.1+2`; the RPC/file paths are
  unchanged apart from the client AAD branch. On-device checks for 24 and 26-29
  passed in 1.1.0+14 and again for the 1.2.x pairing flow.
  - Probe 25 (bad-token lockout): **implemented, code-reviewed, and now verified** — five random valid tokens were rejected with HTTP 403 `BAD_TOKEN`; after the 5th failure the server set a 60 s lockout and cleared the token; a subsequent attempt with the original valid token was accepted, confirming post-lockout recovery. Treat as passed for 1.2.x.
  - 29 legacy rotation → old key 401, paired key unaffected
- Probe 30: the lock-screen notification shows `Key · Active/Stale · <N> clients`
  with Pair/Revoke actions and never the key or fingerprint. Verified by
  inspection of the notification builder in `LatchkeyService.java`.
- Current legacy key fingerprint: `4FCCBC64D9EEA6C9` (`info` matches `ping`).

## Versioning

- `versionCode` is the global build number (v1.0.0+1 was build 1) and must
  increase for every published APK; it is the only identity Android uses for
  updates.
- `versionName` is the human-facing version and is bumped for behavior changes.
- The build script refuses to publish a `versionCode` that already exists in
  `releases/`; there are no silent `-rN` rebuilds.
- Historical artifacts `v1.0.1+2` and `v1.0.1+2-r2…r5` all reported
  `versionCode=2` and are superseded; use `v1.1.0+14` or later. Full ledger:
  `VERSIONS.md`.

## Next steps

1. Install `Latchkey-v1.2.1+17.apk` over the current app.
2. Tap the **Pair** notification action and confirm the link is copied without
   exposing the key.
3. Tap the **Revoke** notification action and confirm paired clients lose
   access and the legacy key rotates.
4. Re-run the attack matrix (including probes 24-29) on the installed build and
   record results.
