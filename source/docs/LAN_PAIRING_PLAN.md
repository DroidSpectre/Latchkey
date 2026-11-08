# LAN Pairing Plan (v2, Draft)

Status: LAN design is a draft for review, 2026-11-06. The same-device loopback
pairing companion in section 5.6 is **implemented in v1.1.0 (build 14)**; the
LAN/QR parts are planned for **v2.0.0**, builds after 14. ADB transport is
deferred to v3.0.0 (separate document; see section 5.7).

Scope: let a Latchkey app on one Android device reach the Latchkey bridge on
another device over a hotspot or trusted LAN, paired by scanning a QR code,
without exposing the bridge to the internet and without handing the assistant
long-term peer keys. It also covers a **same-device loopback pairing companion**
so the assistant no longer needs the user to keep copying the loopback key by
hand. This plan does **not** cover the local helper model (dropped; separate
project).

## 1. Goals and non-goals

Goals:

- Add a second, explicitly enabled LAN listener. Loopback remains the default
  and continues to work exactly as it does today.
- Pair two devices in under 30 seconds by scanning a QR code shown by the host.
- Give every paired device its own credential and capability set that can be
  revoked independently.
- Keep the coordinator/agent model: the app holds peer keys; the assistant
  addresses devices by name through the local bridge. The assistant never needs
  raw peer keys.
- Make the safe path the default: LAN off, pairing mode time-limited, new peers
  read-only until the user grants more.
- Pass a security review of the pairing protocol, key storage, network
  exposure, and Android platform behavior.

Non-goals (v2.0.0):

- Internet exposure, port forwarding, NAT traversal, UPnP, or cloud rendezvous.
- Desktop/iOS clients.
- Automatic file sync or a global index. "Organize and sort" means remote
  browse/copy/move through the existing file operations plus a device list.
- Replacing TLS with a custom handshake. (A PAKE such as SPAKE2/CPace is a
  possible future refinement, not protocol v1.)
- Root, adb, Shizuku, or other apps' private data.

## 2. Current state

- Server: raw HTTP on `127.0.0.1:39401` only. `Host` must be loopback.
- Envelope: `nonce(12) || ciphertext || tag(16)`, AES-256-GCM. Legacy AAD is
  `LATCHKEY/1`; paired clients use `LATCHKEY/1|client:<clientId>`,
  timestamp + replay cache.
- Legacy key: generated on first launch, wrapped by Android Keystore,
  displayed masked in the UI.
- Loopback pairing (v1.1.0): **Pair assistant** copies a 120 s single-use link;
  the client exchanges it for a revocable per-client key. Keys are wrapped by
  `latchkey_client_kek_v1`, and credentials are stored at 0600.
- Client: dependency-free Node CLI; stores paired credentials and rejects
  non-loopback URLs.
- No TLS. Loopback plus the encrypted envelope is the security boundary.
- All-files access is granted to the app; every RPC caller with the key can
  read/write broadly.
- Manifest: `targetSdk 35`, `minSdk 26`, FGS type `specialUse`, no camera or
  network-state permission yet.

Why LAN needs more than "bind to 0.0.0.0": the loopback key is a bearer token
with no per-device identity. On a shared network it would be a single shared
password with no revocation, no audit identity, and no protection for the
pairing exchange. The LAN path needs TLS, per-peer keys, and an approval step.

## 3. Threat model

### Assets

- File contents and the ability to read/write/delete them.
- The loopback access key and the new per-peer keys.
- Pairing tokens and the TLS private key.
- Peer list, device names, activity logs.
- Availability of the host device/service.

### Adversaries and scenarios

| # | Adversary / scenario | Notes |
|---|---|---|
| T1 | Passive network eavesdropper on the LAN/hotspot | Sees plaintext today if LAN were added naively |
| T2 | Active MITM / rogue AP / ARP or DNS spoofing | Can redirect traffic, present its own cert |
| T3 | Nearby unauthorized device | Can reach the LAN port, try pairing or brute force |
| T4 | QR thief / shoulder surfer / screenshot malware | Wants the pairing secret or a reusable credential |
| T5 | Compromised or lost paired device | Has a valid peer key, may act until revoked |
| T6 | Malicious local app on either phone | Can reach `/health` on loopback today; wants keys/files |
| T7 | Malformed/malicious requests | Path traversal, oversized bodies, slowloris, replay |
| T8 | User error | Pairs the wrong device, leaves LAN on in public |
| T9 | Host phone lost/stolen | Attacker has host files/cert; peers must re-pair after rotation |
| T10 | Android platform change | Local-network permission enforcement, doze, FGS limits |

### Assumptions

- Android app sandbox and Keystore behave as documented; devices are not rooted;
  the OS/firmware is not malicious.
- The hotspot uses WPA2/WPA3; a public/open Wi-Fi is hostile and is discouraged.
- The user can see both screens during pairing and can compare a fingerprint.
- TLS 1.2+ implementations on both devices are sound.
- Another app with all-files access can already read shared storage; LAN must
  not make app-private data readable.

### In scope

LAN listener, TLS identity and pinning, QR pairing, per-peer credentials,
capability policy, revocation, rate limiting, audit logging, network-change
handling, Android 17 local-network permission readiness, and their tests.

### Out of scope

Rooted/compromised OS, physical coercion, traffic-analysis resistance, LAN
denial-of-service beyond basic limits, IPv6 in v1, multi-user/work profiles,
and cryptographic side channels.

## 4. Architecture

```
Assistant (proot, no peer keys)
  └─ HTTP 127.0.0.1:39401/rpc  (existing envelope + loopback key)
       └─ Coordinator app A
            ├─ PeerStore / PeerPolicy (keys wrapped by Keystore)
            └─ TLS client (pinned) ── LAN ──► Host app B
                                              ├─ LanServer :39403 (TLS 1.2+)
                                              ├─ PeerAuthenticator (peer ID → key)
                                              ├─ PairingManager (token, approval)
                                              └─ FileApi (same operations)
```

- **Loopback listener (existing, unchanged):** plain HTTP + app-layer AEAD.
  Only the local assistant/coordinator uses it.
- **LAN listener (new):** TLS on a separate port, bound to one selected private
  IPv4 address. It never uses wildcard binds. The app-layer envelope is kept on
  top of TLS for replay/timestamp protection and defense in depth.
- **Separate port:** `39403` proposed (`39401` loopback, `39402` reserved).
  Putting LAN on a separate port avoids weakening the loopback path, makes the
  exposure visible in the UI, and allows the LAN listener to be stopped
  independently.
- **Why TLS:** the pairing exchange issues a per-peer key. It cannot be sent
  over plaintext or protected only by a token that travels in the same exchange.
  TLS with cert pinning authenticates the host to the guest; the QR token
  authenticates the guest to the host; approval closes the loop.
- **Why keep the envelope on LAN:** identical request semantics, replay cache,
  timestamps, and audit on both paths. Cost is double encryption; measure it.
  If throughput is unacceptable, revisit only with a written security review.

### Components

| Component | Responsibility |
|---|---|
| `LanServer` | Accept TLS sockets on one private address; handshake/connection caps; route `/pair` vs `/rpc` |
| `TlsIdentity` | Generate/persist self-signed P-256 cert + key; fingerprint; rotation |
| `PeerStore` | Persist peer ID, name, wrapped key, caps, timestamps; atomic writes |
| `PeerAuthenticator` | Map `X-Latchkey-Peer` to key; enforce revocation and AAD binding |
| `PeerPolicy` | Enforce read/write/destructive/root capabilities per peer |
| `PairingManager` | Token TTL/single-use/attempts; QR payload; approval state; rate limits |
| `NetworkMonitor` | Enumerate candidate private addresses; detect changes; reboot listener |
| `MdnsAdvertiser` (phase 3) | Advertise host ID/fingerprint/port; never the token |
| `QrDisplay` / `QrScanner` | FLAG_SECURE QR dialog; Camera2 + ZXing decoding |
| `CoordinatorProxy` | Loopback op to address paired devices by ID; holds peer keys |
| `PeerSettings` UI | Peers, capabilities, revoke, last seen, LAN status |

### Ports and protocols

| Port | Bind | Transport | Auth | Purpose |
|---|---|---|---|---|
| 39401 | 127.0.0.1 | HTTP + AEAD | Loopback key | Existing assistant access |
| 39403 | selected private IPv4 | TLS 1.2+ + AEAD | Peer key | LAN file access |
| 39403 `/pair` | same | TLS 1.2+ | One-time token + approval | Pairing only while active |

`/health` is **not** served on LAN. Unknown paths and all RPC without a valid
peer return generic auth errors. The LAN listener is enabled only while the
foreground service is running and LAN mode is on.

## 5. Pairing protocol v1

Roles: **host B** (shows the QR, owns the files), **guest A** (scans, wants
access). Pairing is initiated by B; A must be physically present.

### 5.1 QR payload

Compact JSON (no whitespace), encoded in the QR in byte mode:

```json
{"v":1,"t":"pair","id":"<host-id>","name":"<host-name>","host":"192.168.43.1","port":39403,"fp":"<64 lowercase hex>","tok":"<base64url 32 bytes>","exp":1762345678}
```

- `v`: protocol version, must be `1`.
- `t`: `"pair"`; reject anything else.
- `id`: host device ID, 16–64 hex chars, random at first LAN enable.
- `name`: host display name, max 64 printable characters; sanitized for UI.
- `host`: **IPv4 literal only**, must be private (10/8, 172.16/12,
  192.168/16). Reject hostnames to avoid DNS rebinding and search-domain
  surprises. IPv6 is out of scope v1.
- `port`: 1024–65535; must match the listener actually started.
- `fp`: SHA-256 of the host's leaf certificate DER, lowercase hex, in the UI
  shown as `SHA256:AB12 CD34 …`.
- `tok`: 32 random bytes, base64url without padding, valid for 120 seconds,
  single use. This is **not** the long-term key and is never reused as one.
- `exp`: unix seconds, advisory to the guest; the host enforces expiry.

The QR contains no long-term secret. A screenshot of it is useless after the
token is used or expires, and screenshots of the QR dialog are blocked anyway.

### 5.2 Flow

1. **Enable.** B: LAN on and a private address selected. Tapping "Pair a
   device" starts pairing mode. If LAN is off, prompt to enable it.
2. **Token.** B generates `tok` (32 random bytes), stores only
   `SHA-256(tok)` in memory with `expiresAt = now + 120s`, `attempts = 0`,
   and a fresh `pairingId`. Any previous token is invalidated.
3. **Display.** B shows the QR in a `FLAG_SECURE` dialog with a countdown,
   the short fingerprint, and "Never share this screen." The screen is kept on.
   Pairing mode ends at expiry, Hide, success, denial, or service stop.
4. **Scan.** A scans and strictly validates every field (section 5.4). It
   refuses public/non-literal hosts, bad lengths, unknown version, and a
   fingerprint that is not 64 hex chars.
5. **TLS.** A connects to `host:port` with a custom trust manager that computes
   SHA-256 of the leaf DER and compares it to `fp` in constant time. Hostname
   verification is replaced by pinning, not disabled globally. Only TLS 1.2/1.3
   with AEAD ciphers; no fallback, no redirects, no system-CA fallback.
6. **Request.** A sends `POST /pair` (max 4 KiB, 10 s timeout):
   ```json
   {"v":1,"token":"…","client":{"id":"<guest-id>","name":"Pixel 8","model":"…","app":"2.0.0+12"},"nonce":"<16 random bytes b64url>"}
   ```
   The token is the only credential in this request; the TLS pin already
   authenticates B to A.
7. **Host checks.** B accepts only if pairing mode is active and the request is
   TLS. It compares the token hash in constant time, checks expiry, single use,
   attempt count, global/per-IP rate limits, and body/schema limits. All
   failures return a generic 403/429 (no token oracle) and are logged locally
   without the token.
8. **Approval.** B shows: guest name, model, source IP, and capabilities
   (default **read-only**; optional "Allow changes"). The dialog expires after
   60 s and has Deny/Allow. A 6-digit confirmation code is optional (see 5.5).
   Overlay/tapjacking protections apply to this dialog.
9. **Issue key.** On Allow, B generates peer ID (guest-supplied if valid and
   unique, otherwise random) and a fresh 32-byte peer key `K`. It stores:
   peer ID, name, model, `K` wrapped by Keystore (AAD binds the peer ID),
   capabilities, roots, created/last-seen, and a random key ID. It returns over
   TLS:
   ```json
   {"v":1,"ok":true,"peerId":"…","key":"<b64url K>","hostId":"…","hostName":"…","serverTime":1762345678,"caps":{"read":true,"write":false,"delete":false,"roots":["/sdcard"]}}
   ```
   B zeroes the `K` byte array after wrapping/sending, closes pairing mode, and
   destroys the token. Pairing success/failure is logged without `K`.
10. **Store.** A wraps `K` with its own Keystore key (AAD binds host ID + peer
    ID), stores host ID/name/host/port/fp/caps, and optionally verifies with a
    `ping` over LAN. If the response is lost, the token is already consumed:
    re-pair. (Do not cache `K` for replay; simplicity beats a 10-second grace.)
11. **Use.** A sends LAN RPCs with header `X-Latchkey-Peer: <peerId>` and an
    envelope whose AAD is `LATCHKEY/1|peer:<peerId>`. B looks up `K`, verifies
    caps, processes, and audits. Loopback requests keep AAD `LATCHKEY/1` and
    never carry a peer header.

### 5.3 Token and approval rules

- 120 s TTL, one active token, 32 random bytes, stored hashed, constant-time
  compare, single use including after success.
- Max 5 failed attempts per token and per source IP per minute; then a 60 s
  lockout and token invalidation. The user must regenerate the QR. Log rate is
  capped to avoid log flooding.
- Every pairing requires explicit Allow. No auto-approve, no "remember this
  device" shortcut, and no approval while the screen is locked.
- Pairing mode cannot be started while the device is locked if the UI is not
  reachable; no background auto-start.
- Deny/timeout invalidates the token. The guest sees "Host denied" or
  "Approval timed out" without details.

### 5.4 QR validation (guest)

Reject unless all are true:

- Scheme/type/version exactly v1/pair; object has no unknown critical fields.
- `host` is a private IPv4 literal; not 0.0.0.0, broadcast, multicast, or
  loopback (loopback pairing is meaningless and hints at a misconfigured QR).
- `port` is an integer in 1024–65535 and not 39401.
- `id` is 16–64 hex; `name` is 1–64 printable, no control characters; `fp` is
  64 lowercase hex; `tok` decodes to exactly 32 bytes; `exp` is a plausible
  unix time (warn if more than 5 minutes in the past, but let the host decide).
- The QR was scanned from a live screen, not imported from an image file. No
  gallery/file import in v1 (a stored QR image is a stored token).

The guest does not log the token, and does not display it after scanning.

### 5.5 Optional confirmation code (SAS)

The pinned TLS channel already authenticates B to A, and approval plus the
one-time token authenticate A to B. A SAS adds protection mainly against a
user approving the wrong request or a QR substituted before scanning; it does
not protect against a compromised host screen. Proposed v1: show the guest name
and IP, require explicit Allow, and display the host fingerprint on both
success screens for out-of-band comparison. A 6-digit code derived from
`SHA-256(token || clientNonce || serverNonce || certFp)` can be added as a
"high-security pairing" option later if user testing shows confusion.

### 5.6 Same-device loopback pairing (implemented in v1.1.0)

The QR flow is cross-device: the guest camera scans the host screen. The
same-device assistant cannot use it: the camera faces away from the screen, the
agent has no trusted screen-capture path, and the QR dialog is `FLAG_SECURE`.
Copying the long-term key remains possible but is the pain point. v1.1.0 adds a
loopback pairing flow that reuses the one-time-token primitive, delivered
through the clipboard instead of a QR; v2 will reuse the same client identity
and AAD binding.

Concrete flow (implemented):

```
Phone app:   [Pair assistant]  ── copies one-time link to clipboard
Assistant:   latchkey pair --clipboard
Assistant:   latchkey ls /sdcard        # key is loaded automatically
```

`latchkey` here is the CLI (today `node /root/Latchkey/client/latchkey.mjs`); a
small wrapper/alias makes it a single word. The user taps once in the app; the
assistant reads the clipboard and runs the exchange. The clipboard carries only
the 120 s token, never the long-term key.

1. In the app, tap **Pair assistant**. It generates a 32-byte token with a
   120 s TTL, stores only its hash, and copies a link to the clipboard:
   `latchkey://pair?scope=loopback&v=1&id=<hostId>&name=<device>&host=127.0.0.1&port=39401&fp=<app-cert>&tok=<...>&exp=<...>`.
   It logs the event without the token and does not auto-copy on launch.
2. The user runs `latchkey pair --clipboard` (or asks the agent to do it). The
   CLI reads the clipboard, strictly validates scheme, scope, version, loopback
   host, port, token, host id, and expiry, then POSTs the token to
   `http://127.0.0.1:39401/pair` with a random client ID and display name.
3. The app verifies the hash (constant-time), TTL, single use, and rate limits
   (five bad attempts trigger a 60 s lockout). It issues a **per-client key**
   (32 bytes), stores it wrapped by the Keystore key
   `latchkey_client_kek_v1` with the client ID as AAD, and returns it
   encrypted with `SHA-256(token)` and AAD
   `LATCHKEY/PAIR/1|<clientId>`. The legacy loopback key stays valid unless the
   user rotates it.
4. The CLI verifies `clientId` and the short key fingerprint, stores
   `{url, clientId, key, name, hostId, fingerprint, pairedAt}` at
   `~/.config/latchkey/credentials.json` (mode 0600, atomic write), and uses it
   automatically on later commands. The key is never echoed, logged, or put in
   shell history. It can be revoked independently of the legacy key.
5. Fallback: `--link <uri>` accepts a link directly if clipboard access is
   unavailable. A typed-code fallback is deferred.

Same-device pairing does not use TLS; loopback already uses the encrypted
envelope. The pairing request itself is plaintext JSON containing only the
short-lived token, client ID/name, and platform; the issued key is returned
encrypted. A local process that can read the clipboard within 120 s could race
the token, so link creation and pairing success are audited (without secrets),
and the token is single-use with a short TTL and failure lockout. This is no
weaker than the existing **Copy key** button (an app with
accessibility/clipboard access could already capture the long-term key); the
difference is that the issued key is revocable, and the long-term key can
eventually be retired.

The app must never auto-copy a token on launch; the user gesture is the
consent. Loopback client keys use the same client-header/AAD binding as LAN
peers, so audit logs identify the agent and revocation is per client.

**Why not QR for loopback?** A QR needs a second screen/camera or a trusted
screen capture. The app and the agent are on the same phone; the agent cannot
photograph the screen it is displayed on, and `FLAG_SECURE` blocks capture.
Writing the token to a shared-storage image would turn a short-lived secret
into a file readable by other apps. Clipboard is the narrowest channel already
available to the agent.

### 5.7 Relationship to v3 ADB

ADB is a separate, higher-privilege transport planned for **v3.0.0**. It is not
part of v2 and must not share key material or trust decisions with the Latchkey
listeners. v3 will target:

- ADB over loopback/wireless debugging on the same device, if the device's
  adbd is reachable from the proot shell.
- ADB over the hotspot to other devices with wireless debugging enabled.
- A guided setup with explicit warnings, since ADB requires Developer options,
  a pairing code, and shell-level access; it must be off by default and easy to
  revoke.

v2's coordinator/peer model remains the non-ADB path. A v3 design document will
cover feasibility, tooling, pairing, security, and tests.

## 6. Keys, capabilities, and lifecycle

### Per-peer keys

- New random 32-byte `K` per pairing; never derived from the loopback key and
  never accepted on loopback. Loopback key is never accepted on LAN.
- Encrypted at rest with an AES-256-GCM Keystore key (separate alias), AAD
  binding the peer ID. Stored in app-private storage. `allowBackup=false`.
- Never logged, never shown in the UI, never included in exports. Only a
  non-secret key ID/fingerprint may be shown for support.
- If Keystore is unavailable, pairing fails closed. Do **not** fall back to a
  plaintext or session-only peer key (the loopback path has its own documented
  session fallback; that is different).

### Capabilities

Default new peer: read-only on `/sdcard`. The host can grant, per peer:

| Capability | Operations |
|---|---|
| read | `info`, `list`, `stat`, `read`, `search`, `ping` |
| write | `write`, `mkdir`, `copy` destination, `move` destination |
| delete | `delete`, `move` source, overwrite delete |
| roots | Canonical allowlist; default `/sdcard`; reject escapes/symlinks |
| logs | **Denied** to LAN peers in v1 (host activity is not peer data) |

Capability checks happen before path work and are audited. Revocation deletes
the peer record and closes active sockets; subsequent requests get
`401 PEER_REVOKED`. Capability changes take effect on the next request.
Max 8 peers by default, configurable.

### Lifecycle

- App update: peer keys/cert persist (same app signing key). Peers stay paired.
- Uninstall/clear data: keys lost; re-pair.
- Host cert rotation (fingerprint change): all peers must re-pair. Provide a
  "Rotate identity" action with a warning and a new QR; old peer records are
  invalidated.
- Revoke one/all peers; "Forget all" clears peer keys.
- Lost guest: revoke on host. Lost host: rotate identity after recovery; a lost
  host's files are already exposed to whoever holds it.
- Timestamps: last seen, created, last IP; no location history.

## 7. TLS details

- Identity: ECDSA P-256, self-signed X.509 v3, SHA-256; validity 365 days;
  CN `Latchkey <hostId>`; SAN `IP:<current LAN IP>`, `DNS:latchkey.local`.
  Regenerate SANs when the IP changes **without** changing the key/fingerprint
  if possible; otherwise the fingerprint changes and re-pairing is required.
  Decision needed: build certs with a long validity and update SANs by issuing
  a new cert from the same key (fingerprint of the **key**, not the cert, would
  then be the pin). Simpler v1: pin the SPKI (public key) SHA-256, not the
  whole cert, so IP/SAN changes do not force re-pairing. The QR/UI still shows
  a fingerprint; define it as the SPKI fingerprint. A cert reissue with the same
  key keeps the pin. This is a recommended refinement; see open decisions.
- Key storage: private key in a PKCS12 keystore in app-private files, password
  random and wrapped by Android Keystore; or an AndroidKeyStore EC key with a
  generated certificate. A no-Gradle X.509 self-signed cert builder is the
  main implementation risk (see section 13).
- Server: TLS 1.2 minimum, TLS 1.3 when the API supports it; AEAD cipher
  suites; no client certificates; no 0-RTT; handshake timeout 10 s; connection
  cap (16 global, 4 per peer); idle/absolute deadlines; TLS session resumption
  allowed (no security state in the session beyond the cert).
- Client pinning: custom `X509TrustManager` computes the SPKI/cert SHA-256 and
  compares with the stored/QR value in constant time; checks validity with a
  small clock skew allowance; no system CA fallback; no redirects; hostname
  verification is intentionally replaced by pinning (documented).
- The pairing endpoint is TLS-only; there is no plaintext fallback. Loopback
  remains plaintext+AEAD, unchanged.

## 8. Network and lifecycle behavior

- LAN mode is off by default and is independent of the loopback server.
- Candidate addresses come from `NetworkInterface`/`LinkProperties`: private
  IPv4 only, exclude cellular, VPN, loopback, and link-local. Show interface
  name and address; let the user pick when there is more than one. Do not
  hardcode `192.168.43.1`; AOSP tethering commonly uses 192.168.42–48.x, but
  vendors differ.
- Bind the selected address, never `0.0.0.0`/`::`. Refuse public addresses.
- Detect address loss/change while LAN is on: stop the listener, update the UI
  ("LAN offline — reconnect Wi-Fi/hotspot"), and rebind when a private address
  returns. Existing peers keep their stored host until rediscovery; phase 3
  mDNS resolves by host ID + fingerprint.
- Port 39403 fixed. If bind fails (in use), show a clear error; keep loopback
  running; do not silently choose another port.
- Public/open Wi-Fi: show a warning the first time; default read-only limits
  damage; TLS still protects credentials.
- AP/client isolation: some routers block client-to-client traffic. The
  supported topology is the host's hotspot (or a trusted LAN with isolation
  off). Detect unreachable peers and explain.
- FGS/notification: persistent notification includes LAN state, address, peer
  count, and a Stop LAN action. Stopping the service stops LAN. Keep the
  service in `specialUse`; update the subtype string to `local_file_bridge`.
- Doze/battery: battery exemption already requested; optionally hold a partial
  Wi-Fi lock only while LAN is on and a peer is connected; make the battery
  tradeoff explicit. Test Samsung sleeping-app behavior.
- Reboot: LAN remains off until the user opens the app and starts the service
  (same as loopback today).
- IPv4 only in v1. IPv6-only networks are unsupported and documented.

## 9. Android platform constraints

- Permissions to add: `ACCESS_NETWORK_STATE` (address/transport detection),
  `CAMERA` (scanner; runtime), `CHANGE_WIFI_MULTICAST_STATE` (mDNS phase 3).
  Keep `INTERNET`, FGS, notifications, all-files as-is.
- Android 17 (API 37) enforces a local-network permission for raw sockets and
  `NsdManager`. Current `targetSdk 35` is unaffected; do not declare
  `ACCESS_LOCAL_NETWORK` until the targetSdk 37 migration, then add the
  declaration and a runtime request/denial flow. Loopback is exempt. Add a
  targetSdk 37 test track even before shipping it.
- Android 16 has an opt-in local-network permission; track it but do not rely
  on it at targetSdk 35.
- Camera: Camera2 + ZXing core (no Play Services, no CameraX) is the likely
  scanner. If camera permission is denied, allow manual/pasted pairing text as
  an advanced debug path only; no gallery QR import.
- Keystore: peer key wrapping must fail closed. No plaintext fallback.
- Cleartext policy/network security config: raw TLS sockets are unaffected by
  `usesCleartextTraffic`; do not add user CAs or a global trust-all.
- App standby/doze, FGS limits, and Samsung battery policy can interrupt LAN;
  test and document.
- Work profile/multi-user: out of scope; app data is per user.

## 10. UX outline

Host (B):

- LAN card: Off/On, address:port, interface, fingerprint, "Pair a device",
  peers list (name, last seen, read-only/write, Revoke), "Forget all",
  "Rotate identity".
- Pairing dialog: QR, countdown (120 s), "Hide", short fingerprint, warning.
  `FLAG_SECURE`, keep screen on, tapjacking protection.
- Approval: "Pixel 8 (192.168.43.23) wants to access files." Capabilities
  radio: Read only (default) / Read and change. Deny/Allow, 60 s auto-deny.
- Errors: no private address ("Connect to Wi-Fi or turn on hotspot"), port in
  use, TLS init failed, Keystore unavailable (pairing disabled), network lost.

Guest (A):

- "Add device": camera permission rationale, scanner, "Connecting…",
  "Waiting for approval…", success (host name, fingerprint), failures
  (expired/used QR, wrong network, host denied, unreachable).
- Devices list: name, address, status, last seen, Test connection, Remove,
  capability summary. "Use with assistant" is on by default for the proxy.
- Advanced: paste pairing text/manual entry for debugging; token field is
  masked and never logged.

Assistant (via coordinator):

- `latchkey devices` lists coordinator peers and status.
- Existing commands accept `--device <id>`; the coordinator forwards the same
  operations over LAN and returns results. Peer keys never enter the shell.
- Direct key export is disabled by default; if ever added, it requires a loud
  warning and a separate release decision (it moves keys into the proot).

## 11. Implementation phases

### Phase 1 — LAN transport foundation (internal only, v2)

- Refactor `RpcServer` into transport + handler; add `LanServer` skeleton with
  TLS, selected-address bind, connection caps, and per-peer authentication hook.
- Cert/SPKI generation spike; persist identity; fingerprint in UI.
- Address enumeration/selection; LAN toggle; notification state.
- Host header allowlist for LAN (`Host` must equal the bound `ip:port`);
  disable `/health` on LAN.
- No release with an unauthenticated LAN listener. Development builds may use
  a debug-only test peer that is never shipped.

### Phase 2 — Pairing and per-peer auth (release 2.0.0, builds after 14)

- `PeerStore` with Keystore wrapping; `PeerPolicy`; `PairingManager`.
- `POST /pair`, token rules, approval UI, QR display, scanner.
- LAN RPC header/AAD binding; revocation; audit events (`pair`, `peer`,
  `lan`) without secrets.
- Two-device end-to-end test and negative tests.
- Docs: README, PROTOCOL, SECURITY, PLAN, VERSIONS.

### Phase 3 — Coordinator proxy and discovery (v2.x)

- Loopback `devices`/`peer` operations; CLI `--device`.
- mDNS advertise/resolve with fingerprint validation; auto-reconnect after
  address changes. Never advertise the token.
- Optional SAS/high-security pairing; peer capability editing; connection
  status.

### Phase 4 — Hardening and platform readiness (v2.x; v3 groundwork)

- Rate limits/lockout tuning, log throttling, red-team matrix.
- Android 17 targetSdk track and local-network permission flow.
- Cert/SPKI rotation UX; backup/migration docs; performance measurements.
- Final security report and release gate.

### Release gates

- G1: LAN listener cannot start without per-peer auth.
- G2: Pairing works on two physical devices over a hotspot; all negative tests
  pass.
- G3: Assistant can use a paired device through the coordinator with no peer
  key in the shell.
- G4: Security review sign-off (threat matrix, key handling, logs, network
  exposure) and docs updated.

## 12. Test plan and acceptance criteria

### Unit

- QR parse: valid; wrong version/type; public/loopback/multicast host; hostname;
  bad port; short/long fp/token; non-hex; expired; unknown critical fields;
  hostile names/control characters.
- Token: hash comparison, TTL, single use, attempt counter, lockout, clock
  skew, concurrent requests (one wins).
- PeerStore: wrap/unwrap with AAD; tamper/corruption fails closed; no plaintext
  in files/prefs/logs; revocation removes material.
- PeerPolicy: op matrix for read-only/write/delete; root escape via `..`,
  absolute paths, symlinks, weird Unicode; `logs` denied; cross-peer ID/key
  confusion rejected.
- TLS pinning: correct SPKI accepted; wrong cert/key, expired cert, self-signed
  other cert rejected; no system-CA fallback.
- Network selection: private-only; excludes cellular/VPN/loopback; address
  change handling.

### Integration / two-device

- Happy path pairing <30 s; QR screenshot blocked; countdown/Hide; approval
  Deny/timeout; token reuse/expiry; 6th attempt lockout; lost response.
- Rogue cert/MITM fails; DNS/host header tricks fail; public address refused.
- LAN RPC with peer key works; loopback key over LAN rejected; peer key over
  loopback rejected; revoked peer 401; capability violation 403; replay/stale
  timestamp still rejected; oversized body/slowloris bounded.
- Network change (Wi-Fi off/on, hotspot toggle, DHCP change); listener rebind;
  peer offline/rediscovery (phase 3).
- Service stop/start, reboot, app update (peer persists), uninstall (gone),
  doze/battery.
- Android 16 device; Android 17 targetSdk 37 track with permission grant/deny.
- Regression: all existing `tests/selftest.mjs` and loopback acceptance tests.

### Acceptance criteria

- No LAN socket exists when LAN mode is off; no wildcard bind ever.
- No long-term key in a QR, log, notification, or crash output. Pairing tokens
  are short-lived and appear only in the QR (LAN) or clipboard link (loopback);
  they are never stored long-term. QR screenshots are blocked; tokens expire
  and are single use.
- Every LAN request maps to one peer ID and one key; revocation is immediate;
  the loopback key cannot be used on LAN and vice versa.
- New peers are read-only by default; `logs` is not exposed to LAN peers.
- Pairing cannot succeed without TLS pin match, unexpired token, and explicit
  host Allow.
- Assistant access works through the coordinator without peer keys in the
  shell.
- Android 17 local-network permission plan is documented and testable.

## 13. Risks and open decisions

Already decided:

- **Version split:** network/QR pairing is v2.0.0 (builds after 14); ADB is
  v3.0.0 with a separate trust model and design.
- **Loopback token delivery:** clipboard pairing link (`latchkey pair
  --clipboard`), chosen 2026-11-06 and implemented in 1.1.0. A 6-digit code
  fallback may be added later
  but is not required.

Decisions still needed before implementation:

1. **Coordinator proxy vs direct key export.** Recommendation: proxy (keys stay
   in the app; assistant gets device names). Direct export is riskier and
   should require a separate decision.
2. **SPKI pin vs cert pin.** Recommendation: SPKI SHA-256 so an IP/SAN change
   does not force re-pairing; certificate reissue must reuse the key. Cert pin
   is simpler to explain but more re-pairing.
3. **Default capabilities.** Recommendation: read-only; user opts into write.
   Alternative: read/write by default for convenience.
4. **mDNS in v2 or phase 3.** Recommendation: phase 3; QR-only first, accept
   re-scan after DHCP changes.
5. **SAS now or later.** Recommendation: later; name+IP+approval+fingerprint
   comparison first.
6. **Scanner implementation.** Camera2 + ZXing core vs a small dependency.
   Prototype early; no Play Services/CameraX unless justified.
7. **Self-signed cert generation.** Minimal DER builder vs bundling
   BouncyCastle. Both are work; pick based on the spike and APK size.
8. **Port 39403.** Confirm no conflict with user's other tools.
9. **TargetSdk 37 timing.** When to take the local-network permission and how
   to test without breaking current Android 16 use.
10. **Hotspot vs home Wi-Fi policy.** Allow both with a warning, or hotspot
    only by default.
11. **v3 ADB scope.** Separate design: local wireless debugging and hotspot
    peers, tooling/binary availability in the proot shell, and a security model
    for Developer options. Not part of v2.

Implementation risks:

- Android 17 permission behavior and NsdManager restrictions may change before
  release; keep QR pairing independent of mDNS.
- TLS/self-signed cert generation on a no-Gradle build is the largest technical
  unknown.
- Camera2/ZXing integration on Samsung devices and rotation/permission edge
  cases.
- Double encryption (TLS + AEAD) throughput on large file copies.
- Samsung battery/doze behavior with Wi-Fi/hotspot idle.
- Router AP isolation breaks device-to-device access; hotspot-host topology is
  the supported fallback.
- Token/QR shoulder surfing cannot be fully prevented; TTL, approval, and
  optional SAS reduce it.
- A compromised paired device with write access can damage files until revoked;
  read-only default and capability scopes limit blast radius.

## 14. Prior art and references

Patterns reviewed: PocketCmd/Crosslink/Surf/Clash-style QR pairing (user opcode +
short-lived token, TLS fingerprint pinning, per-device keys), Android NSD/mDNS
service discovery, and self-signed TLS pinning guidance. No code is copied;
these are protocol patterns only.

References:

- Android local network permission: `developer.android.com/privacy-and-security/local-network-permission`
- Android 16/17 behavior changes: `developer.android.com/about/versions`
- `NsdManager`: `developer.android.com/develop/connectivity/wifi/use-nsd`
- Network interfaces: `developer.android.com/reference/java/net/NetworkInterface`
- Android Keystore: `developer.android.com/privacy-and-security/keystore`
- OWASP certificate pinning: `owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning`
- TLS 1.3: RFC 8446; X.509: RFC 5280
- ZXing core: `github.com/zxing/zxing` (Apache-2.0)
- Samsung/FGS/doze behavior: vendor documentation and on-device testing

## 15. Proposed next actions

1. Review and settle the decisions above (especially proxy vs direct, SPKI
   pin, default capabilities, and the loopback clipboard pairing flow).
2. Run a one-day TLS identity spike: generate a self-signed EC cert in a
   no-Gradle APK, start a TLS listener on a private address, connect with a
   pinned client, verify fingerprint mismatch rejection.
3. Prototype the QR scanner (Camera2 + ZXing) and FLAG_SECURE QR dialog.
4. Implement phase 1 behind an internal flag; then pairing and the coordinator
   proxy in builds after 14.
5. Update `PLAN.md`, `README.md`, `SECURITY.md`, `PROTOCOL.md`, and `VERSIONS.md`
   as each phase lands.
6. Start the separate v3 ADB feasibility outline after v2 pairing is stable:
   local wireless debugging reachability, hotspot peers, adb binary/tooling in
   the proot shell, and the Developer-options security model.
