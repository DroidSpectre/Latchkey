# ADB Transport Plan (v3, Outline)

Status: outline only, 2026-11-06. Not designed, not approved, not scheduled
before v2.0.0. This file records the v3 direction so v2 does not accidentally
depend on it.

## Goal

Add an optional ADB-based transport for:

1. Same-device access ("loopback") via Android wireless debugging, when the
   device's adbd is reachable from the proot shell.
2. Other devices on the hotspot (or a trusted LAN) with wireless debugging
   enabled.

ADB would complement, not replace, the v2 Latchkey LAN/QR path. It is for users
who have enabled Developer options and accept a debug-level trust boundary.
Latchkey v2 remains the path for devices without ADB.

## Why this is a separate major version

ADB is fundamentally different from the Latchkey bridge:

- It requires Developer options, wireless debugging, and (on Android 11+) a
  pairing code; it is a debug interface, not a normal app feature.
- `adbd` runs as the `shell` UID with broad device access. It is not scoped by
  Latchkey's per-peer capability model.
- Enabling it exposes the device to anyone who can reach the ADB port and
  complete pairing; it must be off by default and easy to revoke.
- Tooling is external: no `adb` binary is present in the current proot
  environment. v3 must either ship/provide an arm64 adb client or rely on the
  user's platform-tools installation.
- It has its own update/reliability concerns (wireless debugging resets on
  reboot, port changes, pairing codes expire).

## Candidate architecture (to be validated)

```
Assistant (proot)
  └─ adb client ── TCP ──► adbd on this device (wireless debugging)
                 └──────► adbd on hotspot peer (wireless debugging)
                              └─ adb shell / pull / push / install
```

The Latchkey app may only act as a helper: show wireless-debugging status,
surface the pairing address/code (including a QR for a second screen), guide the
user to Developer options, and store non-secret profiles. File operations and
shell commands would be executed by the agent's adb client, not by the app.
No Latchkey v2 key or TLS identity is reused for ADB.

## Required spikes

1. Is `adbd` reachable at `127.0.0.1:<port>` from the proot shell when wireless
   debugging is on? Test on the SM-S166V and S20 FE.
2. Can a static arm64 `adb` binary run in the proot environment? If not, what
   is the smallest reliable alternative?
3. Android 11+ wireless-debugging pairing from the shell: code entry, mDNS
   discovery, port changes, and behavior after reboot/screen lock.
4. Hotspot reachability: can the assistant's adb client reach a peer's adbd on
   the hotspot, and does the peer's Developer options survive reboot?
5. Permissions: what can `shell` read/write under `/sdcard` on Samsung Android
   16? What is blocked (app-private data, protected directories)?
6. Security: ADB port exposure, pairing-code brute force, host key verification
   (`adb` known_hosts vs `-o StrictHostKeyChecking`), and revocation (disable
   wireless debugging, change port, reboot).

## Security requirements (draft)

- Off by default; explicit user setup; never auto-enable Developer options.
- No internet exposure; bind/connect only over the hotspot or loopback.
- Verify the peer's ADB host key/fingerprint and show it for confirmation.
- Pairing codes are short-lived and single-use; rate-limit attempts.
- Never log keys, pairing codes, or file contents.
- Provide a one-tap "Disable ADB" / "Forget device" path and clear warnings.
- Treat ADB access as broader than Latchkey v2 capabilities; do not imply the
  v2 read-only default applies.
- Audit connections and commands at a metadata level; export on request.
- Document that USB debugging/wireless debugging is a user-owned risk and can
  be used by other tools on the same network.

## Phases (after v2 ships)

1. Feasibility report from the spikes above; decide whether v3 is viable.
2. Local ADB profile: detect wireless debugging, connect, basic `ls`/`pull`/
   `push`, health check, clear errors.
3. Hotspot peer profile: discover/enter address and pairing code, verify host
   key, connect, transfer; reconnect after reboot/port change.
4. UI/helper and docs; security review and red-team tests.
5. Optional: v2/v3 unified device list in the assistant, without sharing keys.

## Open questions

- Does "loopback ADB" mean adbd over 127.0.0.1, or ADB to the same device via
  its Wi-Fi address?
- Is the goal file access only, or also shell/package management?
- Should Latchkey ship an adb client, or is it acceptable to require the user
  to install platform-tools in the proot environment?
- How should v3 interact with v2's coordinator proxy (separate commands,
  unified device list, or both)?
- What is the acceptable UX for enabling Developer options and wireless
  debugging? (This is a significant user hurdle and a support burden.)
