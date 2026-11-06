# Latchkey

**A keyed door to this device.**

Latchkey is a small Android app that exposes a local, encrypted file API on
`127.0.0.1:39401`. It is meant for this setup, where the assistant runs inside a
proot environment and needs a reliable view of the phone's shared storage.

The proot shell can see some shared-storage paths, but its view is restricted
and does not always reflect what the device actually contains. Latchkey runs as
a normal Android app with **All files access**, so it sees the same storage the
user sees, and it serves that view to a dependency-free Node client over
loopback.

## Status

- Version: `1.2.0` (`versionCode=15`, build 15)
- APK: `/root/Latchkey/build/nogradle/Latchkey-v1.2.0+15.apk`
- SHA-256: `07ddda58050266435ea2856d8546cbcc9b48f85acf28ebf2dd76b7420900cc15`
- Size: 104,471 bytes
- Published for manual install:
  - `/sdcard/Download/Latchkey/Latchkey-v1.2.0+15.apk`
  - `/sdcard/Download/Latchkey/releases/v1.2.0+15/`
- Versioning: `versionCode` is the global build number and must increase for
  every published APK; the build script refuses a reused code. See `VERSIONS.md`.
- Device check (1.0.5): All files access granted; the bridge listed 390 photos
  in `/sdcard/DCIM/Camera` while the proot shell saw that directory as empty.
- Verified operations (1.0.5): `health`, `ping`, `info`, `ls`, `stat`,
  `read`/`get` (3.6 MiB photo, chunked), `write`/`put`, `mkdir`, `cp`, `mv`,
  `rm`, `find`, `logs`, and wrong-key rejection (HTTP 401).
- 1.1.0 adds loopback pairing with revocable per-client keys and a redesigned
  UI. Verified on-device: `pair --link`/`pair --clipboard`, keyless `ping`/`info`/`ls`,
  replayed link (403 NO_LINK), unknown client (401), wrong AAD (401), revoke +
  re-pair, legacy key rotation (old key 401), credentials 0600, and no token or
  key in the activity log.
- 1.2.0 adds notification actions: the lock-screen notification now shows
  `Key · Active/Stale · <N> clients connected` with **Pair** / **Revoke**
  buttons and never exposes the key or fingerprint. **Revoke** regenerates the
  legacy key and revokes all paired clients in one step; the same action is
  available in the app.
- Test key fingerprint: `00B1CA0D4B85009E` (the key itself is not stored in this
  repository). Paired clients do not use this key.

## Components

| Piece | Path | Purpose |
|---|---|---|
| Android app | `android/app/` | Single-screen UI, key display, permission and service controls |
| Foreground service | `LatchkeyService.java` | Keeps the loopback server alive |
| RPC server | `RpcServer.java` | Raw HTTP on `127.0.0.1:39401` |
| RPC dispatch | `RpcHandler.java` | Decrypt, timestamp/replay checks, dispatch, encrypt |
| File operations | `FileApi.java` | list/stat/read/write/mkdir/delete/move/copy/search |
| Event log | `EventLog.java` | persistent JSONL activity log, `logs` RPC, View/Export UI |
| Crypto | `Crypto.java` | AES-256-GCM, key encoding, fingerprint |
| Key storage | `KeyStoreManager.java` | Wraps the legacy key with Android Keystore; session-only key if Keystore fails |
| Pair store | `PairStore.java` | Per-client keys wrapped by Android Keystore; list/count/revoke |
| Pairing | `PairingManager.java` | 120 s single-use tokens, link generation, token exchange |
| Node client | `client/latchkey.mjs` | Encrypted CLI |
| Build | `scripts/build-apk-nogradle.sh` | aapt2 + javac + D8 + zipalign + apksigner |
| Tests | `tests/selftest.mjs` | Node crypto, Java interop, CLI get/put/health |

## Security model

- The server binds only to `127.0.0.1`; it is not reachable from the network.
- Every `/rpc` request and response is AES-256-GCM with a 12-byte nonce and a
  16-byte tag.
- AAD is `LATCHKEY/1` for the legacy key, or `LATCHKEY/1|client:<clientId>`
  for a paired client.
- The legacy key is 32 random bytes, shown as 43 base64url characters without
  padding. It is wrapped by Android Keystore; if Keystore is unavailable, a
  **session-only key** is used in memory only (no SharedPreferences fallback).
- **Pairing:** tapping **Pair assistant** creates a 120-second, single-use
  `latchkey://pair?...` link and copies it to the clipboard as a sensitive
  clip. The client exchanges the token over loopback for a random 32-byte
  per-client key. The app stores only a Keystore-wrapped copy, bound to the
  client id with AAD; the token is stored in memory only as a SHA-256 hash.
  Five bad attempts lock pairing for 60 seconds. Pairing links and keys are
  never logged.
- Paired keys are independent of the legacy key and are revoked with
  **Revoke** (all at once in this build). Regenerating the legacy key does not
  revoke them. Clearing app data removes the wrapped records; Keystore key
  invalidation also makes them fail closed.
- The client stores its paired key in
  `~/.config/latchkey/credentials.json` with mode 0600. Later commands load it
  automatically; no key is pasted or copied repeatedly.
- Persistent events are stored in a **JSONL activity log** in app-private storage,
  rotated across up to 4 files of 2 MiB each; the `logs` RPC queries this log.
  Entries written by 1.0.5+ carry the app version as `v` (for example
  `1.0.5+11`).
  Each process start records an `app/session` entry with version, package,
  device model/manufacturer, Android release, and SDK. The first start after an
  update also records `app/update` with the from/to versions.
- Requests carry a UUID and a millisecond timestamp. The server rejects
  timestamps outside a 5‑minute window and remembers IDs for 5 minutes to stop
  replay. HTTP responses also verify that the `id` and `serverTime` match the
  request.
- The server enforces an absolute connection deadline of 60 seconds and a
  30‑second read timeout; it also rejects `Transfer-Encoding` and duplicate
  `Content-Length` headers, and validates that the `Host` header is loopback only.
- `GET /health` is plaintext and keyless so the client can check reachability.
  It reveals only app version, port, uptime, and request counter.
- Anyone who can read the key can use the bridge. Treat the key like a password.
- The app has All files access. It cannot read other apps' private data (for
  example `/data/data/<other app>`), and it does not use root.
- The server enforces immutable root protection and a split `IMMUTABLE_ROOTS`
  vs `PROTECTED_ROOTS` model with `force=true` for deletion/move operations.
- The app never logs key bytes, file contents, or base64 payloads; it logs
  metadata, paths, counts, fingerprints, and status only.
- Screenshots are allowed for UI review. The access key is masked by default
  (tap the key field to reveal it); `android:filterTouchesWhenObscured` still
  protects against tapjacking.
- The activity log (`EventLog`) records every in‑app and server event; it can be
  viewed and exported from the UI.
- The `logs` RPC returns the last N entries (up to 5000)
  with timestamps, levels, categories, events, and (optionally) data; it does
  not expose raw file contents.

## Install

The device is a Samsung `SM-S166V` on Android 16 (SDK 36). Shizuku and adb are
not used. Install manually:

1. Open `/sdcard/Download/Latchkey/` in the device's file manager.
2. Tap `Latchkey-v1.2.0+15.apk` and allow installs from that source if prompted.
3. Open **Latchkey**.
4. Tap **Grant** and enable **Allow access to manage all files**.
5. Optionally tap **Battery** and allow Latchkey to run without battery
   optimization.
6. Tap **Start server**. The status card should say **Listening on loopback**.
7. Tap **Pair assistant**. This copies a 2-minute, single-use link.
8. In the proot shell, run:

   ```sh
   node /root/Latchkey/client/latchkey.mjs pair --clipboard
   ```

Later commands use the saved per-client credentials without a key. The legacy
key is still available for older clients; tap **Copy key** only if needed.

The legacy key is generated on first launch and persists. Tapping **New key**
replaces it and restarts the server; paired assistants keep access until
**Revoke** is tapped.

## Client quick start

```sh
# Pair once: tap "Pair assistant" in the app first
node /root/Latchkey/client/latchkey.mjs pair --clipboard

# Later commands need no key
node /root/Latchkey/client/latchkey.mjs health
node /root/Latchkey/client/latchkey.mjs ping
node /root/Latchkey/client/latchkey.mjs info
node /root/Latchkey/client/latchkey.mjs ls /sdcard
node /root/Latchkey/client/latchkey.mjs ls /sdcard/Download
```

The paired key lives in `~/.config/latchkey/credentials.json` (0600). Override
the path with `--credentials <file>` or `LATCHKEY_CREDENTIALS`. The legacy key
still works via `--key`, `LATCHKEY_KEY`, or `--key-file`:

```sh
export LATCHKEY_KEY='<legacy-key>'
export LATCHKEY_URL='http://127.0.0.1:39401'
node /root/Latchkey/client/latchkey.mjs info
```

A small wrapper is available at `/root/Latchkey/bin/latchkey`.

### Commands

```text
pair [--clipboard|--link <uri>] pair a client and save revocable credentials
health                          plaintext reachability check (no key)
ping                            authenticated round-trip
info                            app, device, storage, roots, counters
ls <path> [--limit N] [--offset N]
stat <path>
read <path> [-o file] [--offset N] [--length N] [--chunk-size N]
get <remote> <local>            alias for read -o
write <path> --from <file> [--append] [--chunk-size N] [--no-mkdirs]
put <local> <remote>            alias for write --from
mkdir <path>
rm <path> [--recursive] [--force]
mv <from> <to> [--overwrite] [--force]
cp <from> <to> [--overwrite]
find <path> [--name text] [--glob pattern] [--max-depth N] [--limit N]
              [--dirs-only|--files-only] [--hidden] [--case-sensitive]
  logs [--tail N] [--since ms] [--min-level LEVEL] [--cat name] [-o file]
                                    read the persistent activity log

Global options: `--key`, `--key-file`, `--url`, `--credentials`, `--json`.

Examples:

```sh
# Download a camera photo
node /root/Latchkey/client/latchkey.mjs \
  get /sdcard/DCIM/Camera/photo.jpg ./photo.jpg

# Upload a note
node /root/Latchkey/client/latchkey.mjs \
  put ./notes.txt /sdcard/Documents/notes.txt

# Find files by name
node /root/Latchkey/client/latchkey.mjs \
  find /sdcard --name invoice --max-depth 6

# Read the last 200 activity events
node /root/Latchkey/client/latchkey.mjs logs --tail 200
```

`get` writes to a temporary file in the destination directory and renames it
only after the full read succeeds, so a failed download does not clobber an
existing local file. The client validates that every response carries the same
`id` and a `serverTime` within ±5 minutes of the request.

## Protocol

See `docs/PROTOCOL.md` for the wire format and operation list.

Same-device loopback pairing is implemented in **1.1.0** via a
clipboard-delivered one-time token. LAN/QR pairing remains **planned for
v2.0.0** (builds after 1.1.0). The design and threat model are in
`docs/LAN_PAIRING_PLAN.md`; loopback remains the only listener until the LAN
work is approved. ADB transport is deferred to **v3.0.0**
(`docs/ADB_TRANSPORT_PLAN.md`, outline).

Short version: `POST /rpc` with a body of
`nonce(12) || ciphertext || tag(16)`, AES-256-GCM. The AAD is `LATCHKEY/1` for
the legacy key or `LATCHKEY/1|client:<id>` for a paired client. The decrypted
payload is JSON with `v`, `id`, `ts`, `op`, and operation parameters. The
response uses the same envelope and AAD. `POST /pair` is the plaintext
single-use token exchange; `GET /health` is plaintext JSON.

## Build

No Gradle. The build uses the copied toolchain:

```sh
cd /root/Latchkey
bash scripts/build-apk-nogradle.sh
```

Toolchain:

- JDK 17 at `/usr/lib/jvm/java-17-openjdk-arm64`
- `aapt2` and `r8.jar` in `/root/Latchkey/tools/`
- `android.jar` at `/opt/android-sdk/platforms/android-35/android.jar`
- `zipalign` and `apksigner` from the Android SDK build tools
- Debug signing key: `/root/Latchkey/debug.keystore` (password `latchkey`)

The script publishes to `/sdcard/Download/Latchkey/` and creates an
`INSTALL.txt` plus `SHA256SUMS` in the release directory.

Version bumps must update both `next-version.properties` and
`AndroidManifest.xml`; the build fails if they disagree.

## Tests

```sh
cd /root/Latchkey
node tests/selftest.mjs
```

The self-test covers:

- Node AES-GCM round trip and tamper rejection
- Node -> Java and Java -> Node ciphertext interop
- Encrypted RPC ping/list against a local mock server
- Client CLI `health`, `get`, and `put`
- Atomic `get` behavior (existing output preserved on failure)
- Pair-link parsing, 120 s expiry, single-use token exchange, per-client AAD,
  credentials at 0600, and keyless follow-up commands

## Troubleshooting

| Symptom | Check |
|---|---|
| `cannot connect to 127.0.0.1:39401` | Is the server started? Is the notification visible? |
| `unauthorized` | Credentials were revoked or app data was cleared. Tap **Pair assistant** and run `pair --clipboard` again. For a legacy key, copy it again. |
| `PERMISSION_DENIED` / empty listing | All files access is not granted, or the path is not readable. |
| Server stops when screen is off | Tap **Battery** and allow the app to ignore battery optimization; Samsung may also have sleeping-app controls. |
| App won't install | Allow installs from the file manager, or use the release folder's `INSTALL.txt`. |
| Server error on start | Port in use or Keystore failure. Read the status card and logcat if available. |

## Design notes

- `specialUse` foreground service type was chosen because Android 15 imposes
  time limits on `dataSync`. The subtype is `local_loopback_file_bridge`.
- The app does not use `VpnService`, a local socket via adb, or Shizuku. It is a
  plain app plus a loopback HTTP server.
- Request bodies are capped at 8 MiB; read responses are capped at 4 MiB per
  chunk by default. The client chunks reads and writes.
- Protected roots (`/`, `/sdcard`, `/data`, `/system`, etc.) require
  `force=true` to delete. Copy and move reject a destination inside the source.
- Symlinks are reported but not followed during recursive search or delete.
