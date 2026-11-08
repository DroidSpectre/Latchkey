# Latchkey 1.2.3-grok notes

Review of **1.2.2+18** (source archive, the 1.2.0 APK in the repo, and the
LocalKey / LocalBridge archives that sat next to it). This snapshot records
that review. The APK built from this tree is **1.2.3-grok, versionCode 19**.

What changed in the binary:

- `versionName` / `ServerRuntime.VERSION` / client `CLIENT_VERSION` are
  `1.2.3-grok`. `versionCode` is 19.
- The no-Gradle build discovers JDK 17 and Android SDK 35 instead of
  hard-coding `/usr/lib/jvm/java-17-openjdk-arm64`, `/root/Latchkey/tools`,
  and `/opt/android-sdk`.
- `scripts/fetch-toolchain.sh` and `Dockerfile` install command-line tools
  build **15859902**, `platforms;android-35`, and `build-tools;35.0.0`.

What did **not** change: protocol, pairing, path checks, notification actions,
the activity log, or the single-screen UI. The items below are the backlog.

The published APK is **debug-signed** with a keystore generated for this
build (`debug.keystore`, alias `latchkey`, password `latchkey`). That key is
not the one used for 1.2.2+18, and it is not in this archive. Android will
refuse an update over the installed app. Uninstall first. Uninstalling drops
paired clients and the legacy key.

## Ten weaknesses

1. **No reproducible build in the repo.**  
   1.2.2 shipped source plus a script that assumed one absolute SDK layout.
   **This snapshot:** path-agnostic discovery, `fetch-toolchain.sh`, and a
   `Dockerfile`. Still missing: a CI job that publishes the APK, the source
   archive, and `SHA256SUMS` as a GitHub Release. The GitHub repo is still an
   archive dump rather than the app tree.

2. **Legacy key stays first-class.**  
   The original 32-byte key is still generated, shown (masked), and accepted.
   Once copied it is a permanent shared secret.  
   **Next:** hide it after a client is paired, add a “Disable legacy key”
   toggle that rejects it after a grace period, then remove the code path.

3. **Clipboard pairing is convenient and leaky.**  
   Other apps can read a sensitive clip, especially with accessibility
   services or on older Android. The 120 s window is not zero.  
   **Next:** prefer an in-app QR or a short numeric code plus loopback
   confirmation. Keep clipboard as fallback. Clear the clip after a successful
   exchange.

4. **Path guarding is mostly prefix / string based.**  
   Immutable and protected roots are real, but `realpath`, bind mounts,
   multi-user storage, and Samsung paths can still surprise. Symlinks are
   reported; recursive ops need to keep refusing to follow them.  
   **Next:** resolve with `toRealPath(NOFOLLOW_LINKS)` before every check,
   keep an allow-list of real roots, and add a self-test for
   `/sdcard/Android/data`, bind mounts, and `..` sequences.

5. **Notification actions are a high-privilege surface.**  
   Pair / Revoke from the lock-screen notification is good UX and a large
   capability.  
   **Next:** confirmation (dialog, short PIN, or biometric) for Revoke-all.
   A “notification actions enabled” setting that defaults off on first install
   is worth considering.

6. **Concurrency limits are fixed.**  
   4 workers, a small queue, and a 60 s connection deadline are fine for one
   proot client. A buggy or hostile local process can still saturate them.  
   **Next:** make the limits configurable and add per-client rate limiting
   before any LAN listener exists.

7. **EventLog can accumulate sensitive metadata.**  
   Paths, counts, and status are logged. Rotation exists. Long retention plus
   export still widens the blast radius of a compromised app-data directory.  
   **Next:** shorter default retention, “clear on revoke”, and a written list
   of what is never logged (keys, file contents, tokens). 1.2.2 already has
   Clear log; it is manual.

8. **No production signing story.**  
   This snapshot still uses a debug keystore.  
   **Next:** document a release-keystore workflow (or Play App Signing) and
   never commit private key material. This archive does not contain a keystore.

9. **Client language lock-in.**  
   The Node client is the right primary (zero dependencies). LocalKey’s Python
   client was dropped.  
   **Next:** a thin Python client that speaks the same protocol, generated or
   ported, so both ecosystems work. Do not fork the protocol.

10. **History lives in tarballs.**  
    `DroidSpectre/Latchkey` holds archives, not the app’s git history. Diffs
    and bisect are painful.  
    **Next:** unpack the current tree at the repo root (or `src/`), keep
    release tarballs as artifacts, and treat git as the canonical history.

## LocalKey UI to borrow

LocalKey’s useful pieces, without taking its weaker security model:

- Multi-page information architecture: Home / Connect / Audit / Settings,
  instead of one long scroll.
- An explicit readiness checklist: storage permission, notification permission,
  battery exemption, server running, at least one client paired.
- A small visual system: cyan / violet / amber / red / green tokens, section
  headers, status pills, cards. Latchkey 1.1+ already uses part of this.
- Layout flexibility and UI helpers kept out of the RPC and file code.
- A dedicated Audit page so EventLog is not a secondary button.

Adaptation that preserves the single-activity model:

1. Bottom navigation or top tabs: **Status · Pair · Log · Settings**.
2. Status page: current status, permissions, key, clients, readiness checklist.
3. Pair page: large Pair button, live token countdown, paired clients with
   individual revoke, and a clear legacy-vs-paired explanation.
4. Log page: filter by level and category, search, export, clear.
5. Settings: battery, notifications, advanced options.
6. Keep notification actions, key masking, and the color-coded live status.

Do this as layout and activity structure first. Do not change `/rpc` or
`/pair` in the same change.

## Signing and install

- `versionCode` 19 is higher than 18, so Android would accept the upgrade
  **if** the signing certificate matched. It does not.
- Uninstall the installed Latchkey, then install
  `Latchkey-v1.2.3-grok+19.apk`.
- Pair the assistant again. The previous `~/.config/latchkey/credentials.json`
  will 401.

## Rebuild

```sh
sh scripts/fetch-toolchain.sh
sh scripts/build-apk-nogradle.sh
```

Hashes of the published APK and of the source archive are in `SHA256SUMS`
next to those files. The hash lines inside `README.md`, `SECURITY.md`, and
`VERSIONS.md` were filled in after signing. Those markdown files are not
compiler inputs.
