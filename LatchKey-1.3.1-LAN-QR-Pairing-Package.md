# LatchKey LAN QR Pairing — v1.3.1 drop-in package

Target: **LatchKey 1.3.0-C (versionCode 20)**, nogradle build, package `io.latchkey.bridge`.

Scope: bidirectional **LAN-only** pairing (phone hotspot / Wi-Fi, never cell/internet) via QR code — Device A scans Device B's QR → Agent-A can access Device-B; Device B later scans Device-A's QR → Agent-B can access Device-A. Loopback pairing is untouched.

Camera permission policy per your revision: `CAMERA` is declared in the manifest with the other permissions (no runtime request dialog anywhere). The LAN pairing section is disabled with a settings hint unless `checkSelfPermission(CAMERA) == GRANTED`.

---

## Contents

| # | File | Kind |
|---|------|------|
| 1 | `LanQrPayload.java` | new |
| 2 | `LanNetwork.java` | new |
| 3 | `LanIdentity.java` | new |
| 4 | `LanStore.java` | new |
| 5 | `LanPairingManager.java` | new |
| 6 | `LanServer.java` | new |
| 7 | `ScanActivity.java` | new |
| 8 | `RpcHandler.java` | patch (one block) |
| 9 | `AndroidManifest.xml` | patch |
| 10 | `MainActivity.java` | patch (additive methods) |
| 11 | `LatchkeyService.java` | patch (LAN server lifecycle) |
| 12 | `Dockerfile` / `build-apk-nogradle.sh` | patch (zxing vendoring) |
| 13 | `next-version.properties` | patch |

All new files go in `android/app/src/main/java/io/latchkey/bridge/`.

---

## Design summary (mirrors your loopback model 1:1)

- **Token**: 32 random bytes → 43-char base64url, single-use, 120 s TTL, stored **only as SHA-256 hash** in memory, 5 failures → 60 s lockout (same constants as `PairingManager`).
- **Keys**: ECDH P-256 (`secp256r1`) with a persisted long-term identity keypair (PKCS#8 wrapped by a dedicated Android Keystore KEK, alias `latchkey_lan_id_kek_v1`), then `HKDF-SHA256(shared, salt=sha256(token), info="LatchKey/LAN/1", 32)` → AES-256-GCM session key per direction.
- **clientId**: `sha256("LAN/1|" + hostId + "|" + peerDeviceId)` hex (64 hex chars — passes your existing `[a-f0-9]{16,64}` header check). Re-pairing the same peer replaces the record (no duplicate error).
- **AAD**: `LATCHKEY/LAN/1|client:<clientId>` — distinct from the loopback `LATCHKEY/1|client:` namespace.
- **MITM pin**: the claim response's server pubkey must byte-equal the `pk` embedded in the QR (constant-time) — the gap in the original plan, closed.
- **Transport**: separate `ServerSocket` on the **hotspot interface only**, port `39402`, never `0.0.0.0`. Every connection's remote address must be in the same subnet (real prefix length, no /24 assumption). The loopback server on 39401 is not touched.
- **QR**: `LK1:<base64url(JSON)>`, validated on decode: version, expiry, **private-range IPv4 only** (10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10), port range, canonical token, parseable EC pubkey.
- Burn-before-crypto: the token offer is consumed before any ECDH work, so a replayed token hits `NO_LINK`.
- Nothing sensitive is ever logged (EventLog gets paths/counts/names only).

---

## 1. `LanQrPayload.java`

```java
package io.latchkey.bridge;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Versioned LAN pairing QR payload: "LK1:<base64url(JSON)>". Decode refuses
 * anything that is not a current-version, unexpired, private-range-LAN
 * payload. The token never appears in logs or persistent storage.
 */
final class LanQrPayload {
    static final int VERSION = 1;
    private static final String PREFIX = "LK1:";

    // 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10 (CGNAT)
    private static final Pattern PRIVATE_V4 = Pattern.compile(
            "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|169\\.254\\."
                    + "|100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.)");

    final String deviceId;
    final String ip;
    final int port;
    final byte[] token;
    final byte[] pubKey;
    final long expiresAt;
    final String name;

    private LanQrPayload(String deviceId, String ip, int port, byte[] token,
                         long expiresAt, byte[] pubKey, String name) {
        this.deviceId = deviceId;
        this.ip = ip;
        this.port = port;
        this.token = token;
        this.expiresAt = expiresAt;
        this.pubKey = pubKey;
        this.name = name;
    }

    static LanQrPayload create(String deviceId, String ip, int port,
                               byte[] token, long ttlMs, byte[] pubKey,
                               String name) {
        return new LanQrPayload(deviceId, ip, port, token,
                System.currentTimeMillis() + ttlMs, pubKey, name);
    }

    String encode() {
        try {
            JSONObject o = new JSONObject();
            o.put("v", VERSION);
            o.put("id", deviceId);
            o.put("ip", ip);
            o.put("port", port);
            o.put("tok", b64(token));
            o.put("exp", expiresAt);
            o.put("pk", b64(pubKey));
            o.put("nm", name == null ? "" : name);
            return PREFIX + Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(o.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("could not encode QR payload", e);
        }
    }

    static LanQrPayload decode(String scanned) throws LanPairingManager.LanException {
        if (scanned == null || !scanned.startsWith(PREFIX)) {
            throw new LanPairingManager.LanException("not a LatchKey LAN QR code");
        }
        try {
            byte[] raw = Base64.getUrlDecoder().decode(scanned.substring(PREFIX.length()));
            JSONObject o = new JSONObject(new String(raw, StandardCharsets.UTF_8));
            if (o.optInt("v", 0) != VERSION) {
                throw new LanPairingManager.LanException("unsupported QR version");
            }
            String id = o.optString("id", "");
            if (!id.matches("[a-f0-9]{16,64}")) {
                throw new LanPairingManager.LanException("bad device id");
            }
            String ip = o.optString("ip", "");
            if (!PRIVATE_V4.matcher(ip).find()) {
                throw new LanPairingManager.LanException("refusing non-LAN address: " + ip);
            }
            int port = o.optInt("port", 0);
            if (port < 1024 || port > 65535) {
                throw new LanPairingManager.LanException("bad port");
            }
            long exp = o.optLong("exp", 0L);
            if (exp < System.currentTimeMillis()) {
                throw new LanPairingManager.LanException("QR code expired");
            }
            byte[] token = unb64(o.optString("tok", ""));
            byte[] pub = unb64(o.optString("pk", ""));
            if (token == null || token.length != Crypto.KEY_BYTES) {
                throw new LanPairingManager.LanException("bad token");
            }
            if (pub == null || pub.length < 32 || pub.length > 1024) {
                throw new LanPairingManager.LanException("bad key");
            }
            String name = sanitize(o.optString("nm", "Android device"));
            return new LanQrPayload(id, ip, port, token, exp, pub, name);
        } catch (LanPairingManager.LanException e) {
            throw e;
        } catch (Exception e) {
            throw new LanPairingManager.LanException("malformed QR code", e);
        }
    }

    /** Constant-time token comparison. */
    boolean tokenEquals(byte[] other) {
        return other != null && MessageDigest.isEqual(token, other);
    }

    /** Constant-time pubkey comparison (MITM pin on the claim response). */
    boolean pubKeyEquals(byte[] other) {
        return other != null && MessageDigest.isEqual(pubKey, other);
    }

    static byte[] newToken() {
        byte[] t = new byte[Crypto.KEY_BYTES];
        new SecureRandom().nextBytes(t);
        return t;
    }

    static String b64(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static byte[] unb64(String s) {
        try {
            byte[] out = Base64.getUrlDecoder().decode(s);
            return out.length == 0 ? null : out;
        } catch (Exception e) {
            return null;
        }
    }

    private static String sanitize(String value) {
        String cleaned = value == null ? "" : value
                .replaceAll("[\\p{Cntrl}]", " ")
                .replaceAll("\\s+", " ")
                .trim();
        if (cleaned.length() == 0) {
            cleaned = "Android device";
        }
        return cleaned.substring(0, Math.min(cleaned.length(), 64));
    }

    void wipe() {
        Arrays.fill(token, (byte) 0);
    }
}
```

---

## 2. `LanNetwork.java`

```java
package io.latchkey.bridge;

import android.content.Context;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.List;

/**
 * LAN interface discovery and subnet checks. Hotspot interfaces are
 * preferred (ap/swlan/wlan naming); loopback and non-site-local addresses
 * are never returned, so LAN pairing cannot bind or accept off-LAN traffic.
 */
final class LanNetwork {

    private LanNetwork() {
    }

    /** Site-local IPv4 address of the hotspot/LAN interface, or null. */
    static String hotspotAddress(Context context) {
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback()) {
                    continue;
                }
                String n = ni.getName().toLowerCase();
                if (!(n.startsWith("ap") || n.startsWith("swlan")
                        || n.startsWith("wlan"))) {
                    continue;
                }
                for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                    if (a instanceof Inet4Address && a.isSiteLocalAddress()) {
                        return a.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /** Prefix length of the interface carrying {@code selfIp}, or -1. */
    static int prefixLength(String selfIp) {
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                for (java.net.InterfaceAddress ia : ni.getInterfaceAddresses()) {
                    InetAddress a = ia.getAddress();
                    if (a instanceof Inet4Address
                            && a.getHostAddress().equals(selfIp)) {
                        return (int) ia.getNetworkPrefixLength();
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return -1;
    }

    /** True when {@code peer} is inside the same subnet as {@code selfIp}. */
    static boolean sameSubnet(String peer, String selfIp) {
        if (peer == null || selfIp == null) {
            return false;
        }
        int prefix = prefixLength(selfIp);
        if (prefix < 0 || prefix > 32) {
            return false;
        }
        int a = toInt(peer);
        int b = toInt(selfIp);
        if (a == 0 || b == 0) {
            return false;
        }
        if (prefix == 0) {
            return true;
        }
        int mask = (int) ((0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL);
        return (a & mask) == (b & mask);
    }

    private static int toInt(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return 0;
        }
        try {
            int out = 0;
            for (String p : parts) {
                int v = Integer.parseInt(p);
                if (v < 0 || v > 255) {
                    return 0;
                }
                out = (out << 8) | v;
            }
            return out;
        } catch (Exception e) {
            return 0;
        }
    }
}
```

---

## 3. `LanIdentity.java`

```java
package io.latchkey.bridge;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Long-term EC P-256 identity used for LAN pairing ECDH. The private key is
 * generated in memory and persisted only as a Keystore-wrapped PKCS#8 blob.
 * If the Keystore is unavailable the identity fails closed.
 */
final class LanIdentity {
    private static final String PREFS = "latchkey-lan-identity";
    private static final String PREF_BLOB = "identity";
    private static final String ALIAS = "latchkey_lan_id_kek_v1";
    private static final Object LOCK = new Object();
    private static KeyPair cached;

    private LanIdentity() {
    }

    static KeyPair getOrCreate(Context context) throws Exception {
        synchronized (LOCK) {
            if (cached != null) {
                return cached;
            }
            SharedPreferences prefs = context.getSharedPreferences(
                    PREFS, Context.MODE_PRIVATE);
            String blob = prefs.getString(PREF_BLOB, null);
            if (blob != null && blob.length() > 0) {
                byte[] priv = unwrap(Base64.getDecoder().decode(blob));
                PrivateKey privateKey = KeyFactory.getInstance("EC")
                        .generatePrivate(new PKCS8EncodedKeySpec(priv));
                // Public key is re-derived from the private point via the store
                // below: we persist the public half alongside for simplicity.
                byte[] pubBytes = Base64.getDecoder().decode(
                        prefs.getString(PREF_BLOB + ".pub", ""));
                PublicKey publicKey = KeyFactory.getInstance("EC")
                        .generatePublic(new X509EncodedKeySpec(pubBytes));
                Arrays.fill(priv, (byte) 0);
                cached = new KeyPair(publicKey, privateKey);
                return cached;
            }
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"),
                    new SecureRandom());
            KeyPair fresh = g.generateKeyPair();
            byte[] priv = fresh.getPrivate().getEncoded();
            byte[] pub = fresh.getPublic().getEncoded();
            byte[] wrapped = wrap(priv);
            prefs.edit()
                    .putString(PREF_BLOB, Base64.getEncoder().encodeToString(wrapped))
                    .putString(PREF_BLOB + ".pub", Base64.getEncoder().encodeToString(pub))
                    .commit();
            Arrays.fill(priv, (byte) 0);
            Arrays.fill(wrapped, (byte) 0);
            cached = fresh;
            EventLog.info("lan", "identity", "created a LAN pairing identity");
            return fresh;
        }
    }

    private static SecretKey kek() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (!keyStore.containsAlias(ALIAS)) {
            KeyGenerator generator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(
                    ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setUserAuthenticationRequired(false)
                    .build());
            generator.generateKey();
            keyStore.load(null);
        }
        return (SecretKey) keyStore.getKey(ALIAS, null);
    }

    private static byte[] wrap(byte[] priv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, kek());
        cipher.updateAAD("latchkey-lan-identity".getBytes(StandardCharsets.UTF_8));
        byte[] iv = cipher.getIV();
        byte[] ct = cipher.doFinal(priv);
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return out;
    }

    private static byte[] unwrap(byte[] blob) throws Exception {
        byte[] iv = Arrays.copyOfRange(blob, 0, Crypto.NONCE_BYTES);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, kek(), new GCMParameterSpec(Crypto.TAG_BITS, iv));
        cipher.updateAAD("latchkey-lan-identity".getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(blob, Crypto.NONCE_BYTES, blob.length - Crypto.NONCE_BYTES);
    }
}
```

---

## 4. `LanStore.java`

```java
package io.latchkey.bridge;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Stores LAN pairing records, wrapped by a dedicated Android Keystore KEK
 * (alias latchkey_lan_kek_v1) with the clientId as AAD — same fail-closed
 * model as PairStore.
 *
 * Two record kinds:
 *  - inbound:  a LAN peer that can call THIS device (issued during /pair/claim)
 *  - outbound: a LAN peer THIS device can call (stored after scanning a QR)
 * A peer can be both (mutual pairing). Records are keyed by peer device id;
 * re-pairing the same peer replaces the record instead of duplicating it.
 */
final class LanStore {
    static final class Peer {
        final String peerId;
        final String name;
        final String clientId;
        final byte[] key;

        Peer(String peerId, String name, String clientId, byte[] key) {
            this.peerId = peerId;
            this.name = name;
            this.clientId = clientId;
            this.key = key;
        }
    }

    static final String AAD_PREFIX = "LATCHKEY/LAN/1|client:";

    private static final String PREFS = "latchkey-lan";
    private static final String PREF_IN = "lan_inbound";
    private static final String PREF_OUT = "lan_outbound";
    private static final String ALIAS = "latchkey_lan_kek_v1";
    private static final Object LOCK = new Object();

    private LanStore() {
    }

    static String aadFor(String clientId) {
        return AAD_PREFIX + clientId;
    }

    /** Inbound record for a peer that just claimed a token. Replaces any prior record for the peer. */
    static void issueInbound(Context context, String peerId, String name,
                             String clientId, byte[] key) throws Exception {
        synchronized (LOCK) {
            JSONArray list = load(context, PREF_IN);
            removePeer(list, peerId);
            JSONObject record = record(peerId, name, clientId, key);
            list.put(record);
            save(context, PREF_IN, list);
            EventLog.info("lan", "paired-in",
                    "LAN peer can now access this device: " + name);
        }
    }

    /** Outbound record for a peer this device just scanned. */
    static void putOutbound(Context context, String peerId, String name,
                            String clientId, byte[] key) throws Exception {
        synchronized (LOCK) {
            JSONArray list = load(context, PREF_OUT);
            removePeer(list, peerId);
            JSONObject record = record(peerId, name, clientId, key);
            list.put(record);
            save(context, PREF_OUT, list);
            EventLog.info("lan", "paired-out",
                    "this device can now access LAN peer: " + name);
        }
    }

    /** Inbound session key for an RPC caller, or null. */
    static byte[] getInboundKey(Context context, String clientId) {
        synchronized (LOCK) {
            JSONArray list = load(context, PREF_IN);
            for (int i = 0; i < list.length(); i++) {
                JSONObject r = list.optJSONObject(i);
                if (r != null && clientId.equals(r.optString("cid", ""))) {
                    return unwrapKey(r, clientId);
                }
            }
            return null;
        }
    }

    /** Outbound record for calling a peer, or null. */
    static Peer getOutbound(Context context, String peerId) {
        synchronized (LOCK) {
            JSONArray list = load(context, PREF_OUT);
            for (int i = 0; i < list.length(); i++) {
                JSONObject r = list.optJSONObject(i);
                if (r == null || !peerId.equals(r.optString("id", ""))) {
                    continue;
                }
                String cid = r.optString("cid", "");
                byte[] key = unwrapKey(r, cid);
                return key == null
                        ? null : new Peer(peerId, r.optString("nm", ""), cid, key);
            }
            return null;
        }
    }

    static List<Peer> list(Context context) {
        synchronized (LOCK) {
            List<Peer> out = new ArrayList<Peer>();
            for (String pref : new String[] {PREF_IN, PREF_OUT}) {
                JSONArray list = load(context, pref);
                for (int i = 0; i < list.length(); i++) {
                    JSONObject r = list.optJSONObject(i);
                    if (r == null) {
                        continue;
                    }
                    String cid = r.optString("cid", "");
                    out.add(new Peer(r.optString("id", ""),
                            r.optString("nm", ""), cid, null));
                }
            }
            return out;
        }
    }

    /** Revokes a peer in both directions. Returns how many records were removed. */
    static int revoke(Context context, String peerId) {
        synchronized (LOCK) {
            int removed = 0;
            for (String pref : new String[] {PREF_IN, PREF_OUT}) {
                JSONArray list = load(context, pref);
                JSONArray kept = new JSONArray();
                for (int i = 0; i < list.length(); i++) {
                    JSONObject r = list.optJSONObject(i);
                    if (r != null && peerId.equals(r.optString("id", ""))) {
                        removed++;
                    } else if (r != null) {
                        kept.put(r);
                    }
                }
                save(context, pref, kept);
            }
            if (removed > 0) {
                EventLog.warn("lan", "revoked", "revoked LAN peer " + peerId);
            }
            return removed;
        }
    }

    // ---------- internals ----------

    private static JSONObject record(String peerId, String name,
                                    String clientId, byte[] key) throws Exception {
        String wrapped = Base64.getEncoder().encodeToString(wrap(key, clientId));
        JSONObject r = new JSONObject();
        r.put("id", peerId);
        r.put("nm", name);
        r.put("cid", clientId);
        r.put("fp", Crypto.fingerprint(key));
        r.put("created", System.currentTimeMillis());
        r.put("blob", wrapped);
        return r;
    }

    private static void removePeer(JSONArray list, String peerId) {
        for (int i = list.length() - 1; i >= 0; i--) {
            JSONObject r = list.optJSONObject(i);
            if (r != null && peerId.equals(r.optString("id", ""))) {
                list.remove(i);
            }
        }
    }

    private static JSONArray load(Context context, String pref) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String raw = prefs.getString(pref, "");
        if (raw == null || raw.length() == 0) {
            return new JSONArray();
        }
        try {
            return new JSONArray(raw);
        } catch (Exception e) {
            EventLog.error("lan", "store-corrupt", "LAN store is corrupt: " + e.getMessage());
            return new JSONArray();
        }
    }

    private static void save(Context context, String pref, JSONArray list) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        if (!prefs.edit().putString(pref, list.toString()).commit()) {
            throw new IllegalStateException("could not save LAN pairing record");
        }
    }

    private static byte[] unwrapKey(JSONObject record, String clientId) {
        String wrapped = record.optString("blob", "");
        try {
            return unwrap(Base64.getDecoder().decode(wrapped), clientId);
        } catch (Exception e) {
            EventLog.error("auth", "lan-unwrap-failed",
                    "could not unwrap LAN key for client " + clientId);
            return null;
        }
    }

    private static SecretKey kek() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (!keyStore.containsAlias(ALIAS)) {
            KeyGenerator generator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(
                    ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setUserAuthenticationRequired(false)
                    .build());
            generator.generateKey();
            keyStore.load(null);
        }
        return (SecretKey) keyStore.getKey(ALIAS, null);
    }

    private static byte[] wrap(byte[] key, String clientId) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, kek());
        cipher.updateAAD(clientId.getBytes(StandardCharsets.UTF_8));
        byte[] iv = cipher.getIV();
        byte[] ct = cipher.doFinal(key);
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return out;
    }

    private static byte[] unwrap(byte[] blob, String clientId) throws Exception {
        if (blob.length <= Crypto.NONCE_BYTES) {
            throw new IllegalArgumentException("wrapped key too short");
        }
        byte[] iv = Arrays.copyOfRange(blob, 0, Crypto.NONCE_BYTES);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, kek(), new GCMParameterSpec(Crypto.TAG_BITS, iv));
        cipher.updateAAD(clientId.getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(blob, Crypto.NONCE_BYTES, blob.length - Crypto.NONCE_BYTES);
    }
}
```

---

## 5. `LanPairingManager.java`

```java
package io.latchkey.bridge;

import android.content.Context;
import android.os.Build;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * LAN pairing: issues single-use QR offers and consumes them over the LAN.
 * Mirrors PairingManager policy exactly: 120s single-use tokens held only as
 * SHA-256 hashes, 5 failures -> 60s lockout, burn-before-crypto.
 */
final class LanPairingManager {
    static final class LanException extends Exception {
        LanException(String message) { super(message); }
        LanException(String message, Throwable cause) { super(message, cause); }
    }

    static final class Offer {
        final String qr;
        final long expiresAt;

        Offer(String qr, long expiresAt) {
            this.qr = qr;
            this.expiresAt = expiresAt;
        }
    }

    private static final Object LOCK = new Object();
    private static final long TOKEN_TTL_MS = 120000L;
    private static final long LOCKOUT_MS = 60000L;
    private static final int MAX_FAILURES = 5;
    private static final String HKDF_INFO = "LatchKey/LAN/1";

    private static byte[] tokenHash;
    private static long expiresAt;
    private static int failures;
    private static long lockoutUntil;

    private LanPairingManager() {
    }

    // ---------- OFFER SIDE (this device shows the QR) ----------

    static Offer createOffer(Context context, int lanPort) throws Exception {
        synchronized (LOCK) {
            String ip = LanNetwork.hotspotAddress(context);
            if (ip == null) {
                throw new LanException("not on a LAN (join the hotspot or Wi-Fi first)");
            }
            byte[] token = LanQrPayload.newToken();
            byte[] hash;
            String qr;
            try {
                KeyPair identity = LanIdentity.getOrCreate(context);
                String name = (Build.MANUFACTURER + " " + Build.MODEL).trim();
                qr = LanQrPayload.create(PairStore.hostId(context), ip, lanPort,
                        token, TOKEN_TTL_MS, identity.getPublic().getEncoded(), name)
                        .encode();
                hash = Crypto.sha256(token);
            } finally {
                Arrays.fill(token, (byte) 0);
            }
            byte[] previous = tokenHash;
            tokenHash = hash;
            expiresAt = System.currentTimeMillis() + TOKEN_TTL_MS;
            failures = 0;
            lockoutUntil = 0L;
            if (previous != null) {
                Arrays.fill(previous, (byte) 0);
            }
            EventLog.info("lan", "offer",
                    "created a single-use LAN pairing QR expiring in 120s");
            return new Offer(qr, expiresAt);
        }
    }

    static void invalidate() {
        synchronized (LOCK) {
            clearToken();
            failures = 0;
            lockoutUntil = 0L;
        }
    }

    /**
     * Consumes a claim request on the LAN server. Returns the JSON response.
     */
    static String claim(Context context, String body, String remote) {
        long now = System.currentTimeMillis();
        String token;
        byte[] peerPub;
        String peerId;
        String peerName;
        try {
            JSONObject request = new JSONObject(body);
            if (request.optInt("v", 0) != 1) {
                return error(400, "BAD_VERSION", "unsupported pairing version");
            }
            token = request.optString("tok", "");
            if (!token.matches("[A-Za-z0-9_-]{43}")) {
                return error(400, "BAD_TOKEN", "invalid pairing token");
            }
            peerPub = LanQrPayload.unb64(request.optString("pk", ""));
            if (peerPub == null || peerPub.length < 32 || peerPub.length > 1024) {
                return error(400, "BAD_REQUEST", "invalid key");
            }
            peerId = request.optString("id", "").trim().toLowerCase();
            if (!peerId.matches("[a-f0-9]{16,64}")) {
                return error(400, "BAD_CLIENT", "invalid client id");
            }
            peerName = sanitize(request.optString("nm", "Android device"));
        } catch (Exception e) {
            return error(400, "BAD_REQUEST", "invalid pairing request");
        }

        byte[] incomingHash;
        try {
            incomingHash = Crypto.sha256(token.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return error(500, "PAIR_UNAVAILABLE", "pairing unavailable");
        }

        byte[] shared = null;
        byte[] key = null;
        KeyPair identity = null;
        synchronized (LOCK) {
            if (lockoutUntil > now) {
                EventLog.warn("lan", "locked", "LAN pairing rejected during lockout");
                Arrays.fill(incomingHash, (byte) 0);
                return error(429, "PAIR_LOCKED", "too many attempts; create a new QR");
            }
            if (tokenHash == null) {
                EventLog.warn("lan", "no-link", "LAN pairing request with no active QR");
                Arrays.fill(incomingHash, (byte) 0);
                return error(403, "NO_LINK", "no pairing QR is active");
            }
            if (now > expiresAt) {
                clearToken();
                EventLog.warn("lan", "expired", "LAN pairing QR expired before use");
                Arrays.fill(incomingHash, (byte) 0);
                return error(403, "EXPIRED", "pairing QR expired; create a new one");
            }
            if (!MessageDigest.isEqual(incomingHash, tokenHash)) {
                Arrays.fill(incomingHash, (byte) 0);
                failures++;
                if (failures >= MAX_FAILURES) {
                    lockoutUntil = now + LOCKOUT_MS;
                    clearToken();
                    EventLog.warn("lan", "lockout", "LAN token rejected; locked for 60s");
                    return error(429, "PAIR_LOCKED", "too many attempts; create a new QR");
                }
                EventLog.warn("lan", "rejected", "LAN pairing token mismatch");
                return error(403, "BAD_TOKEN", "invalid pairing token");
            }
            // Burn before crypto: a replay cannot reuse this token.
            clearToken();
            failures = 0;
            lockoutUntil = 0L;
            try {
                identity = LanIdentity.getOrCreate(context);
                PublicKey peer = KeyFactory.getInstance("EC")
                        .generatePublic(new X509EncodedKeySpec(peerPub));
                shared = ecdh(identity.getPrivate(), peer);
                key = hkdfSha256(shared, incomingHash, HKDF_INFO, Crypto.KEY_BYTES);
                String clientId = clientIdFor(PairStore.hostId(context), peerId);
                LanStore.issueInbound(context, peerId, peerName, clientId, key);
                LatchkeyService.refreshNotification(context);
                JSONObject ok = new JSONObject();
                ok.put("ok", true);
                ok.put("cid", clientId);
                ok.put("spk", LanQrPayload.b64(identity.getPublic().getEncoded()));
                EventLog.info("lan", "success",
                        "LAN peer can now access this device: " + peerName);
                return ok.toString();
            } catch (Exception e) {
                EventLog.error("lan", "claim-failed",
                        "LAN pairing failed: " + message(e));
                return error(500, "PAIR_UNAVAILABLE", "pairing is unavailable");
            } finally {
                if (shared != null) Arrays.fill(shared, (byte) 0);
                if (key != null) Arrays.fill(key, (byte) 0);
                Arrays.fill(incomingHash, (byte) 0);
            }
        }
    }

    // ---------- SCAN SIDE (this device scanned a peer's QR) ----------

    /**
     * Claims the scanned offer and stores the outbound record. Runs on a
     * background thread. Throws LanException with a user-readable message.
     */
    static void performClaim(Context context, LanQrPayload payload,
                              String myName) throws LanException {
        KeyPair identity;
        try {
            identity = LanIdentity.getOrCreate(context);
        } catch (Exception e) {
            throw new LanException("pairing identity unavailable", e);
        }
        HttpURLConnection connection = null;
        byte[] shared = null;
        byte[] key = null;
        try {
            JSONObject body = new JSONObject();
            body.put("v", 1);
            body.put("tok", LanQrPayload.b64(payload.token));
            body.put("pk", LanQrPayload.b64(identity.getPublic().getEncoded()));
            body.put("id", PairStore.hostId(context));
            body.put("nm", myName);

            URL url = new URL("http://" + payload.ip + ":" + payload.port + "/pair/claim");
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(8000);
            connection.setReadTimeout(8000);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
            connection.setFixedLengthStreamingMode(bytes.length);
            OutputStream out = connection.getOutputStream();
            out.write(bytes);
            out.close();

            int status = connection.getResponseCode();
            String responseText = readFully(status < 400
                    ? connection.getInputStream() : connection.getErrorStream());
            JSONObject response = new JSONObject(responseText);
            if (status != 200 || !response.optBoolean("ok", false)) {
                throw new LanException("peer rejected: "
                        + response.optString("error", "unknown error"));
            }

            // MITM pin: the server pubkey must match the QR, constant-time.
            byte[] serverPub = LanQrPayload.unb64(response.optString("spk", ""));
            if (serverPub == null || !payload.pubKeyEquals(serverPub)) {
                throw new LanException("server key does not match the QR code");
            }
            String clientId = response.optString("cid", "");
            if (!clientId.matches("[a-f0-9]{16,64}")) {
                throw new LanException("peer returned an invalid client id");
            }

            PublicKey server = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(serverPub));
            shared = ecdh(identity.getPrivate(), server);
            byte[] tokenHash = Crypto.sha256(payload.token);
            key = hkdfSha256(shared, tokenHash, HKDF_INFO, Crypto.KEY_BYTES);
            Arrays.fill(tokenHash, (byte) 0);

            LanStore.putOutbound(context, payload.deviceId, payload.name,
                    clientId, key);
        } catch (LanException e) {
            throw e;
        } catch (Exception e) {
            throw new LanException("could not reach the peer on this LAN", e);
        } finally {
            if (shared != null) Arrays.fill(shared, (byte) 0);
            if (key != null) Arrays.fill(key, (byte) 0);
            if (connection != null) connection.disconnect();
        }
    }

    // ---------- shared helpers ----------

    static String clientIdFor(String hostId, String peerId) throws Exception {
        byte[] hash = Crypto.sha256(("LAN/1|" + hostId + "|" + peerId)
                .getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder(hash.length * 2);
        for (byte value : hash) {
            String hex = Integer.toHexString(value & 0xff);
            if (hex.length() == 1) {
                out.append('0');
            }
            out.append(hex);
        }
        return out.toString();
    }

    static boolean hasActiveOffer() {
        synchronized (LOCK) {
            return tokenHash != null && expiresAt > System.currentTimeMillis();
        }
    }

    private static byte[] ecdh(java.security.PrivateKey mine, PublicKey peer)
            throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(mine);
        ka.doPhase(peer, true);
        return ka.generateSecret();
    }

    private static byte[] hkdfSha256(byte[] ikm, byte[] salt, String info, int len)
            throws Exception {
        byte[] saltCopy = salt == null ? new byte[32] : salt;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(saltCopy, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] out = new byte[len];
        byte[] t = new byte[0];
        int pos = 0;
        int counter = 1;
        while (pos < len) {
            mac.update(t);
            mac.update(info.getBytes(StandardCharsets.UTF_8));
            mac.update((byte) counter++);
            t = mac.doFinal();
            int n = Math.min(t.length, len - pos);
            System.arraycopy(t, 0, out, pos, n);
            pos += n;
        }
        Arrays.fill(prk, (byte) 0);
        return out;
    }

    private static void clearToken() {
        if (tokenHash != null) {
            Arrays.fill(tokenHash, (byte) 0);
            tokenHash = null;
        }
        expiresAt = 0L;
    }

    private static String sanitize(String value) {
        String cleaned = value == null ? "" : value
                .replaceAll("[\\p{Cntrl}]", " ")
                .replaceAll("\\s+", " ")
                .trim();
        if (cleaned.length() == 0) {
            cleaned = "Android device";
        }
        return cleaned.substring(0, Math.min(cleaned.length(), 64));
    }

    private static String readFully(InputStream in) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int n;
        while ((n = in.read(chunk)) > 0) {
            buffer.write(chunk, 0, n);
            if (buffer.size() > 16384) {
                throw new IllegalStateException("response too large");
            }
        }
        return new String(buffer.toByteArray(), StandardCharsets.UTF_8);
    }

    private static String error(int status, String code, String message) {
        JSONObject r = new JSONObject();
        try {
            r.put("ok", false);
            r.put("code", code);
            r.put("error", message);
            r.put("serverTime", System.currentTimeMillis());
        } catch (Exception ignored) {
        }
        return r.toString();
    }

    private static String message(Throwable failure) {
        String text = failure.getMessage();
        return text == null || text.length() == 0
                ? failure.getClass().getSimpleName() : text;
    }
}
```

---

## 6. `LanServer.java`

```java
package io.latchkey.bridge;

import android.content.Context;
import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Raw-HTTP LAN server bound to the hotspot interface only. Routes:
 *   GET  /health        plaintext reachability check (same shape as loopback)
 *   POST /pair/claim    LAN pairing (see LanPairingManager.claim)
 *   POST /rpc           encrypted RPC with x-latchkey-client (LAN keys)
 * Every connection's remote address must be in the same subnet as the
 * bound interface. The loopback server on 39401 is unaffected.
 */
final class LanServer {
    private static final String TAG = "LatchkeyLan";
    private static final int MAX_PAIR_BODY = 16384;
    private static final int MAX_RPC_BODY = 8 * 1024 * 1024;
    private static final int MAX_HEADER = 32 * 1024;
    private static final long READ_TIMEOUT_MS = 30000L;

    private final Context context;
    private final String bindIp;
    private final int port;
    private final RpcHandler handler;
    private volatile boolean running;
    private ServerSocket serverSocket;
    private ExecutorService pool;
    private Thread acceptThread;

    LanServer(Context context, String bindIp, int port, RpcHandler handler) {
        this.context = context.getApplicationContext();
        this.bindIp = bindIp;
        this.port = port;
        this.handler = handler;
    }

    void start() throws IOException {
        ServerSocket socket = new ServerSocket();
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress(InetAddress.getByName(bindIp), port), 16);
        socket.setSoTimeout(1000);
        serverSocket = socket;
        running = true;
        pool = Executors.newFixedThreadPool(2, daemonFactory("latchkey-lan"));
        acceptThread = new Thread(new Runnable() {
            @Override
            public void run() {
                acceptLoop();
            }
        }, "latchkey-lan-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
        EventLog.info("lan", "start", "listening on " + bindIp + ":" + port);
        Log.i(TAG, "listening on " + bindIp + ":" + port);
    }

    void stop() {
        running = false;
        ServerSocket socket = serverSocket;
        serverSocket = null;
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
        if (pool != null) {
            pool.shutdownNow();
            pool = null;
        }
        EventLog.info("lan", "stop", "LAN server stopped");
    }

    private void acceptLoop() {
        while (running) {
            try {
                final Socket socket = serverSocket.accept();
                if (!running) {
                    socket.close();
                    return;
                }
                final String remote = socket.getInetAddress() == null
                        ? "unknown" : socket.getInetAddress().getHostAddress();
                if (!LanNetwork.sameSubnet(remote, bindIp)) {
                    EventLog.warn("lan", "off-subnet",
                            "rejected off-subnet connection from " + remote);
                    socket.close();
                    continue;
                }
                final Runnable job = new Runnable() {
                    @Override
                    public void run() {
                        try {
                            socket.setSoTimeout((int) READ_TIMEOUT_MS);
                            handle(socket, remote);
                        } catch (Exception e) {
                            EventLog.warn("lan", "connection",
                                    "LAN connection failed: " + e.getMessage());
                        } finally {
                            try {
                                socket.close();
                            } catch (IOException ignored) {
                            }
                        }
                    }
                };
                try {
                    pool.execute(job);
                } catch (Exception rejected) {
                    try {
                        socket.close();
                    } catch (IOException ignored) {
                    }
                }
            } catch (java.net.SocketTimeoutException expected) {
                // accept timeout: loop and re-check running
            } catch (Exception e) {
                if (running) {
                    Log.w(TAG, "accept failed: " + e.getMessage());
                }
            }
        }
    }

    private void handle(Socket socket, String remote) throws Exception {
        InputStream in = socket.getInputStream();
        String requestLine = readLine(in);
        if (requestLine == null) {
            return;
        }
        String[] parts = requestLine.split(" ");
        if (parts.length < 3) {
            sendText(socket, 400, "{\"ok\":false,\"error\":\"bad request\"}");
            return;
        }
        String method = parts[0];
        String target = parts[1].indexOf('?') >= 0
                ? parts[1].substring(0, parts[1].indexOf('?')) : parts[1];

        Map<String, String> headers = new HashMap<String, String>();
        int total = 0;
        while (total < MAX_HEADER) {
            String line = readLine(in);
            if (line == null || line.length() == 0) {
                break;
            }
            total += line.length();
            int colon = line.indexOf(':');
            if (colon > 0) {
                headers.put(line.substring(0, colon).trim().toLowerCase(Locale.US),
                        line.substring(colon + 1).trim());
            }
        }

        String host = headers.get("host");
        if (host == null || !isLanHost(host)) {
            sendText(socket, 403, "{\"ok\":false,\"error\":\"forbidden\"}");
            return;
        }
        if (headers.containsKey("transfer-encoding")) {
            sendText(socket, 400, "{\"ok\":false,\"error\":\"bad request\"}");
            return;
        }

        if ("GET".equals(method) && "/health".equals(target)) {
            org.json.JSONObject health = new org.json.JSONObject();
            health.put("ok", true);
            health.put("scope", "lan");
            health.put("version", BuildInfo.versionName);
            health.put("port", port);
            health.put("uptime", ServerRuntime.uptime());
            sendText(socket, 200, health.toString());
            return;
        }

        if ("POST".equals(method) && "/pair/claim".equals(target)) {
            long length = contentLength(headers, MAX_PAIR_BODY);
            if (length < 0) {
                sendText(socket, length == -411 ? 411 : 400,
                        "{\"ok\":false,\"error\":\"bad request\"}");
                return;
            }
            byte[] body = new byte[(int) length];
            readFully(in, body);
            String response = LanPairingManager.claim(
                    context, new String(body, StandardCharsets.UTF_8), remote);
            sendText(socket, 200, response);
            return;
        }

        if ("POST".equals(method) && "/rpc".equals(target)) {
            long length = contentLength(headers, MAX_RPC_BODY);
            if (length < 0) {
                sendText(socket, length == -411 ? 411 : 400,
                        "{\"ok\":false,\"error\":\"bad request\"}");
                return;
            }
            byte[] request = new byte[(int) length];
            readFully(in, request);
            String clientId = headers.get("x-latchkey-client");
            if (clientId != null) {
                clientId = clientId.trim().toLowerCase(Locale.US);
                if (!clientId.matches("[a-f0-9]{16,64}")) {
                    sendText(socket, 400, "{\"ok\":false,\"error\":\"bad request\"}");
                    return;
                }
            }
            try {
                RpcHandler.Result result = handler.handle(request, clientId);
                sendBinary(socket, 200, "application/octet-stream", result.body);
            } catch (RpcHandler.AuthException e) {
                sendText(socket, 401, "{\"ok\":false,\"error\":\"unauthorized\"}");
            }
            return;
        }

        sendText(socket, 404, "{\"ok\":false,\"error\":\"not found\"}");
    }

    /** Host must be "<bindIp>" or "<bindIp>:<port>". */
    private boolean isLanHost(String host) {
        String bare = host;
        int colon = host.lastIndexOf(':');
        if (colon >= 0 && host.indexOf(']') < 0) {
            bare = host.substring(0, colon);
        }
        return bindIp.equals(bare);
    }

    /** Returns length, or negative error codes (-400 bad, -411 missing). */
    private static long contentLength(Map<String, String> headers, long max) {
        String value = headers.get("content-length");
        if (value == null) {
            return -411L;
        }
        String trimmed = value.trim();
        if (!trimmed.matches("[0-9]{1,9}")) {
            return -400L;
        }
        long length = Long.parseLong(trimmed);
        if (length > max) {
            return -400L;
        }
        return length;
    }

    private static void sendText(Socket socket, int status, String body)
            throws IOException {
        sendBinary(socket, status, "application/json; charset=utf-8",
                body.getBytes(StandardCharsets.UTF_8));
    }

    private static void sendBinary(Socket socket, int status,
                                   String contentType, byte[] body) throws IOException {
        OutputStream out = socket.getOutputStream();
        String head = "HTTP/1.1 " + status + " " + reason(status) + "\r\n"
                + "Content-Type: " + contentType + "\r\n"
                + "Content-Length: " + body.length + "\r\n"
                + "Connection: close\r\n"
                + "Cache-Control: no-store\r\n\r\n";
        out.write(head.getBytes(StandardCharsets.US_ASCII));
        out.write(body);
        out.flush();
    }

    private static String reason(int status) {
        switch (status) {
            case 200: return "OK";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 411: return "Length Required";
            default: return "Error";
        }
    }

    private static String readLine(InputStream in) throws IOException {
        StringBuilder out = new StringBuilder();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') {
                break;
            }
            if (c != '\r') {
                out.append((char) c);
            }
            if (out.length() > MAX_HEADER) {
                throw new IOException("header too long");
            }
        }
        return c < 0 && out.length() == 0 ? null : out.toString();
    }

    private static void readFully(InputStream in, byte[] buffer) throws IOException {
        int off = 0;
        while (off < buffer.length) {
            int n = in.read(buffer, off, buffer.length - off);
            if (n < 0) {
                throw new IOException("truncated body");
            }
            off += n;
        }
    }

    private static ThreadFactory daemonFactory(final String name) {
        return new ThreadFactory() {
            private final AtomicInteger counter = new AtomicInteger(1);

            @Override
            public Thread newThread(Runnable runnable) {
                Thread thread = new Thread(runnable, name + "-" + counter.getAndIncrement());
                thread.setDaemon(true);
                return thread;
            }
        };
    }
}
```

**Note:** `LanServer` calls two helpers that already exist or need tiny additions:
- `ServerRuntime.uptime()` — if your `ServerRuntime` tracks the start time, expose an `uptime()` (or inline your own value here).
- `BuildInfo.versionName` — if you don't have a `BuildInfo` helper, replace with your existing version constant (the one your `/health` route returns).

---

## 7. `ScanActivity.java` (Camera2 + zxing decode)

```java
package io.latchkey.bridge;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.graphics.SurfaceTexture;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.media.Image;
import android.media.ImageReader;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.util.Size;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.widget.FrameLayout;
import android.widget.Toast;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * In-app QR scanner for LAN pairing. Camera permission is declared in the
 * manifest only (no runtime request flow): if it is not granted, the activity
 * explains how to enable it in system settings and exits. Decoding runs on a
 * camera handler thread, throttled; the claim runs on its own worker.
 */
public final class ScanActivity extends Activity {
    private SurfaceView preview;
    private CameraDevice camera;
    private CameraCaptureSession session;
    private ImageReader reader;
    private Handler cameraHandler;
    private HandlerThread cameraThread;
    private String cameraId;
    private int sensorRotation;
    private final AtomicBoolean claiming = new AtomicBoolean(false);
    private long lastDecodeAt = 0L;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Camera permission is manifest-declared only; no runtime request.
        if (checkSelfPermission(Manifest.permission.CAMERA)
                != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(this,
                    "Camera access is off. Enable it for Latchkey in system "
                            + "settings (Apps → Latchkey → Permissions), then try again.",
                    Toast.LENGTH_LONG).show();
            finish();
            return;
        }
        FrameLayout root = new FrameLayout(this);
        preview = new SurfaceView(this);
        root.addView(preview, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));
        setContentView(root);
        preview.getHolder().addCallback(new SurfaceHolder.Callback() {
            @Override
            public void surfaceCreated(SurfaceHolder holder) {
                openCamera(holder.getSurface());
            }

            @Override
            public void surfaceChanged(SurfaceHolder holder, int format,
                                       int width, int height) {
            }

            @Override
            public void surfaceDestroyed(SurfaceHolder holder) {
                closeCamera();
            }
        });
    }

    private void openCamera(Surface surface) {
        try {
            CameraManager manager = (CameraManager) getSystemService(CAMERA_SERVICE);
            for (String id : manager.getCameraIdList()) {
                CameraCharacteristics chars = manager.getCameraCharacteristics(id);
                if (chars.get(CameraCharacteristics.LENS_FACING)
                        != CameraCharacteristics.LENS_FACING_BACK) {
                    continue;
                }
                cameraId = id;
                sensorRotation = chars.get(CameraCharacteristics.SENSOR_ORIENTATION);
                StreamConfigurationMap map = chars.get(
                        CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
                Size size = chooseSize(map.getOutputSizes(SurfaceTexture.class));
                preview.getHolder().setFixedSize(size.getWidth(), size.getHeight());
                Size yuv = chooseSize(map.getOutputSizes(ImageFormat.YUV_420_888));
                reader = ImageReader.newInstance(yuv.getWidth(), yuv.getHeight(),
                        ImageFormat.YUV_420_888, 2);
                reader.setOnImageAvailableListener(new ImageReader.OnImageAvailableListener() {
                    @Override
                    public void onImageAvailable(ImageReader r) {
                        Image image = r.acquireLatestImage();
                        if (image != null) {
                            try {
                                decode(image);
                            } finally {
                                image.close();
                            }
                        }
                    }
                }, cameraHandler);
                if (cameraThread == null) {
                    cameraThread = new HandlerThread("latchkey-scan");
                    cameraThread.start();
                    cameraHandler = new Handler(cameraThread.getLooper());
                }
                manager.openCamera(id, new CameraDevice.StateCallback() {
                    @Override
                    public void onOpened(CameraDevice device) {
                        camera = device;
                        startSession(surface);
                    }

                    @Override
                    public void onDisconnected(CameraDevice device) {
                        device.close();
                    }

                    @Override
                    public void onError(CameraDevice device, int error) {
                        toast("Camera error");
                        finish();
                    }
                }, cameraHandler);
                return;
            }
            toast("No back-facing camera");
            finish();
        } catch (SecurityException e) {
            toast("Camera access is off");
            finish();
        } catch (Exception e) {
            toast("Could not open the camera");
            finish();
        }
    }

    private void startSession(Surface surface) {
        try {
            final CaptureRequest.Builder builder =
                    camera.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
            builder.addTarget(surface);
            builder.addTarget(reader.getSurface());
            camera.createCaptureSession(java.util.Arrays.asList(surface, reader.getSurface()),
                    new CameraCaptureSession.StateCallback() {
                        @Override
                        public void onConfigured(CameraCaptureSession s) {
                            session = s;
                            try {
                                builder.set(CaptureRequest.CONTROL_AF_MODE,
                                        CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);
                                session.setRepeatingRequest(builder.build(), null, cameraHandler);
                            } catch (Exception e) {
                                toast("Could not start the preview");
                            }
                        }

                        @Override
                        public void onConfigureFailed(CameraCaptureSession s) {
                            toast("Could not start the preview");
                        }
                    }, cameraHandler);
        } catch (Exception e) {
            toast("Could not start the preview");
        }
    }

    private void decode(Image image) {
        long now = System.currentTimeMillis();
        if (claiming.get() || now - lastDecodeAt < 200) {
            return;
        }
        lastDecodeAt = now;
        Image.Plane[] planes = image.getPlanes();
        int width = image.getWidth();
        int height = image.getHeight();
        int rowStride = planes[0].getRowStride();
        ByteBuffer buffer = planes[0].getBuffer();
        byte[] data;
        if (rowStride == width) {
            data = new byte[buffer.remaining()];
            buffer.get(data);
        } else {
            data = new byte[width * height];
            for (int row = 0; row < height; row++) {
                buffer.position(row * rowStride);
                buffer.get(data, row * width, width);
            }
        }
        boolean rotate = sensorRotation == 90 || sensorRotation == 270;
        byte[] rotated = rotate ? rotate90(data, width, height) : data;
        int rw = rotate ? height : width;
        int rh = rotate ? width : height;
        try {
            PlanarYUVLuminanceSource source = new PlanarYUVLuminanceSource(
                    rotated, rw, rh, 0, 0, rw, rh, false);
            Result result = new QRCodeReader().decode(new BinaryBitmap(
                    new HybridBinarizer(source)), hints());
            onQr(result.getText());
        } catch (Exception notFound) {
            // no QR in this frame; keep scanning
        }
    }

    private static Map<DecodeHintType, Object> hints() {
        Map<DecodeHintType, Object> hints = new HashMap<DecodeHintType, Object>();
        hints.put(DecodeHintType.POSSIBLE_FORMATS,
                java.util.Collections.singletonList(
                        com.google.zxing.BarcodeFormat.QR_CODE));
        return hints;
    }

    private static byte[] rotate90(byte[] data, int width, int height) {
        byte[] out = new byte[data.length];
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                out[x * height + (height - 1 - y)] = data[y * width + x];
            }
        }
        return out;
    }

    private void onQr(String text) {
        if (!claiming.compareAndSet(false, true)) {
            return;
        }
        vibrate();
        closeCamera();
        final LanQrPayload payload;
        try {
            payload = LanQrPayload.decode(text);
        } catch (LanPairingManager.LanException e) {
            claiming.set(false);
            toast("Not a valid LatchKey LAN QR: " + e.getMessage());
            reopen();
            return;
        }
        final String myName = (Build.MANUFACTURER + " " + Build.MODEL).trim();
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    LanPairingManager.performClaim(getApplicationContext(), payload, myName);
                    payload.wipe();
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            toast("Paired with " + payload.name
                                    + " — this device can now access it");
                            finish();
                        }
                    });
                } catch (Exception e) {
                    final String message = e.getMessage() == null
                            ? "pairing failed" : e.getMessage();
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            claiming.set(false);
                            toast("Pairing failed: " + message);
                            reopen();
                        }
                    });
                }
            }
        }, "latchkey-lan-claim").start();
    }

    private void reopen() {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (preview.getHolder().getSurface() != null
                        && checkSelfPermission(Manifest.permission.CAMERA)
                                == PackageManager.PERMISSION_GRANTED) {
                    openCamera(preview.getHolder().getSurface());
                }
            }
        });
    }

    private static Size chooseSize(Size[] sizes) {
        Size best = sizes[0];
        for (Size s : sizes) {
            if (s.getWidth() <= 1280 && s.getHeight() <= 1280
                    && s.getWidth() * s.getHeight() > best.getWidth() * best.getHeight()) {
                best = s;
            }
        }
        return best;
    }

    private void vibrate() {
        try {
            Vibrator vibrator = (Vibrator) getSystemService(VIBRATOR_SERVICE);
            if (vibrator == null) {
                return;
            }
            vibrator.vibrate(60);
        } catch (Exception ignored) {
        }
    }

    private void toast(final String text) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(ScanActivity.this, text, Toast.LENGTH_LONG).show();
            }
        });
    }

    private void closeCamera() {
        try {
            if (session != null) {
                session.close();
                session = null;
            }
        } catch (Exception ignored) {
        }
        try {
            if (camera != null) {
                camera.close();
                camera = null;
            }
        } catch (Exception ignored) {
        }
        try {
            if (reader != null) {
                reader.close();
                reader = null;
            }
        } catch (Exception ignored) {
        }
    }

    @Override
    protected void onDestroy() {
        closeCamera();
        if (cameraThread != null) {
            cameraThread.quitSafely();
            cameraThread = null;
            cameraHandler = null;
        }
        super.onDestroy();
    }
}
```

---

## 8. `RpcHandler.java` — patch (one block)

Replace the client-key resolution inside `handle(byte[] encryptedRequest, String clientId)`:

```java
// BEFORE
if (clientId != null && clientId.length() > 0) {
    secret = PairStore.getKey(context, clientId);
    temporary = true;
    aad = "LATCHKEY/1|client:" + clientId;
    if (secret == null) {
```

```java
// AFTER
if (clientId != null && clientId.length() > 0) {
    temporary = true;
    secret = LanStore.getInboundKey(context, clientId);
    if (secret != null) {
        aad = LanStore.aadFor(clientId);          // LATCHKEY/LAN/1|client:<id>
    } else {
        secret = PairStore.getKey(context, clientId);
        aad = "LATCHKEY/1|client:" + clientId;    // loopback client
    }
    if (secret == null) {
```

Everything below (`unknown paired client`, decrypt, replay window, dispatch) is unchanged — LAN requests get the same timestamp/replay/size protections as loopback clients.

---

## 9. `AndroidManifest.xml` — patch

Add the camera permission **in the existing permission block** (no runtime request is ever made), and register the scanner:

```xml
<!-- existing block, add alongside the others -->
<uses-permission android:name="android.permission.CAMERA" />
<uses-feature android:name="android.hardware.camera" android:required="false" />
```

```xml
<!-- inside <application> -->
<activity
    android:name=".ScanActivity"
    android:exported="false"
    android:screenOrientation="portrait" />
```

---

## 10. `MainActivity.java` — additive patch

Add these fields and methods, then call `root.addView(buildLanSection())` in `buildConnectPage()` (your programmatic layout). The whole section is **disabled with a settings hint unless the camera permission is granted** — no runtime request dialog.

```java
// fields
private TextView lanStatusText;
private Button lanQrBtn;
private Button lanScanBtn;
private static final int LAN_PORT = 39402;

private boolean lanReady() {
    return checkSelfPermission(android.Manifest.permission.CAMERA)
            == android.content.pm.PackageManager.PERMISSION_GRANTED;
}

private View buildLanSection() {
    LinearLayout box = new LinearLayout(this);
    box.setOrientation(LinearLayout.VERTICAL);
    int pad = (int) (12 * getResources().getDisplayMetrics().density);
    box.setPadding(pad, pad, pad, pad);

    TextView title = new TextView(this);
    title.setText("Pair on LAN (QR)");
    title.setTypeface(Typeface.DEFAULT_BOLD);
    box.addView(title);

    lanStatusText = new TextView(this);
    box.addView(lanStatusText);

    lanQrBtn = new Button(this);
    lanQrBtn.setText("Show LAN QR");
    lanQrBtn.setOnClickListener(new View.OnClickListener() {
        @Override
        public void onClick(View v) {
            showLanQr();
        }
    });
    box.addView(lanQrBtn);

    lanScanBtn = new Button(this);
    lanScanBtn.setText("Scan to pair");
    lanScanBtn.setOnClickListener(new View.OnClickListener() {
        @Override
        public void onClick(View v) {
            startActivity(new android.content.Intent(
                    MainActivity.this, ScanActivity.class));
        }
    });
    box.addView(lanScanBtn);

    refreshLanSection();
    return box;
}

private void refreshLanSection() {
    if (lanStatusText == null) {
        return;
    }
    boolean ready = lanReady();
    lanQrBtn.setEnabled(ready);
    lanScanBtn.setEnabled(ready);
    if (!ready) {
        lanStatusText.setText("Camera access is off. Enable it for Latchkey in "
                + "system settings (Apps → Latchkey → Permissions) to use LAN pairing.");
        return;
    }
    String ip = LanNetwork.hotspotAddress(this);
    lanStatusText.setText(ip == null
            ? "Not on a LAN yet — join the hotspot or Wi-Fi first."
            : "LAN address: " + ip + ":" + LAN_PORT);
}

@Override
protected void onResume() {
    super.onResume();
    refreshLanSection();   // settings changes (camera grant) are picked up here
    // ... keep your existing onResume body
}

private void showLanQr() {
    final LanPairingManager.Offer offer;
    try {
        offer = LanPairingManager.createOffer(this, LAN_PORT);
    } catch (Exception e) {
        toast("Could not create a LAN pairing QR: "
                + (e.getMessage() == null ? "unknown error" : e.getMessage()));
        return;
    }
    try {
        com.google.zxing.qrcode.QRCodeWriter writer =
                new com.google.zxing.qrcode.QRCodeWriter();
        java.util.Map<com.google.zxing.EncodeHintType, Object> hints =
                new java.util.HashMap<com.google.zxing.EncodeHintType, Object>();
        hints.put(com.google.zxing.EncodeHintType.MARGIN, 1);
        hints.put(com.google.zxing.EncodeHintType.ERROR_CORRECTION,
                com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.M);
        com.google.zxing.common.BitMatrix matrix = writer.encode(
                offer.qr, com.google.zxing.BarcodeFormat.QR_CODE, 720, 720, hints);
        int width = matrix.getWidth();
        int height = matrix.getHeight();
        int[] pixels = new int[width * height];
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                pixels[y * width + x] = matrix.get(x, y)
                        ? 0xFF000000 : 0xFFFFFFFF;
            }
        }
        android.graphics.Bitmap bitmap = android.graphics.Bitmap.createBitmap(
                pixels, width, height, android.graphics.Bitmap.Config.ARGB_8888);

        android.widget.ImageView image = new android.widget.ImageView(this);
        image.setImageBitmap(bitmap);
        new android.app.AlertDialog.Builder(this)
                .setTitle("Let the other device scan this")
                .setView(image)
                .setNegativeButton("Close",
                        new android.content.DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(android.content.DialogInterface d, int w) {
                                LanPairingManager.invalidate();
                                d.dismiss();
                            }
                        })
                .show();

        // Auto-cancel at token expiry (120s), matching the offer lifecycle.
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                LanPairingManager.invalidate();
            }
        }, LanPairingManager.hasActiveOffer() ? 120000L : 0L);
    } catch (Exception e) {
        LanPairingManager.invalidate();
        toast("Could not render the QR code");
    }
}
```

If your `onResume` already exists, just add the single `refreshLanSection()` line to it. Adjust the dialog/timer wiring if you keep references to the dialog — the point is: **closing the dialog or 120 s passing invalidates the offer**.

---

## 11. `LatchkeyService.java` — patch (LAN server lifecycle)

Wherever you currently construct and start the loopback server (inside your start logic, next to `rpcServer.start()`):

```java
// after the loopback RpcServer is started
String lanIp = LanNetwork.hotspotAddress(this);
lanServer = null;
if (lanIp != null) {
    try {
        lanServer = new LanServer(this, lanIp, 39402, handler);  // same RpcHandler instance
        lanServer.start();
    } catch (Exception e) {
        EventLog.warn("lan", "start-failed",
                "LAN server not started: " + e.getMessage());
        lanServer = null;
    }
}
```

And in `stopServer()`:

```java
if (lanServer != null) {
    lanServer.stop();
    lanServer = null;
}
```

Add the field `private LanServer lanServer;`. If the hotspot appears **after** the service started (common: server started before tethering), call `LatchkeyService.restart(context)` from the UI, or re-check `LanNetwork.hotspotAddress()` in your existing status ticker and start the LAN server lazily when an IP first appears.

---

## 12. Build integration (vendored zxing-core)

**Dockerfile** (once, at the top with your other setup):

```dockerfile
RUN mkdir -p /opt/latchkey/libs \
 && curl -fsSL -o /opt/latchkey/libs/core-3.5.3.jar \
      https://repo1.maven.org/maven2/com/google/zxing/core/3.5.3/core-3.5.3.jar
```

**`scripts/build-apk-nogradle.sh`** — two changes:

```bash
# 1) javac: put the jar on the compile classpath
javac -classpath "$ANDROID_JAR:libs/core-3.5.3.jar" -d "$OBJ" \
    $(find android/app/src/main/java -name '*.java')

# 2) d8: dex the jar INTO classes.dex (not --classpath)
"$D8" --release --lib "$ANDROID_JAR" --min-api 26 \
    --output "$DEX_OUT" "$OBJ_DIR"/*.class libs/core-3.5.3.jar
```

(Keep whatever variable names your script already uses — the point is: jar on `javac -classpath`, jar as a D8 **input**. zxing-core is pure Java, minSdk 26-compatible, no AndroidX.)

---

## 13. `next-version.properties`

```
version=1.3.1
versionCode=21
note=LAN QR pairing: bidirectional hotspot/Wi-Fi pairing, LAN-only, ECDH P-256 per-direction keys, vendored zxing-core, manifest-only CAMERA permission with disabled-feature gating
```

---

## Client side (calling a LAN peer)

Your Node client (`client/latchkey.mjs`) needs one small extension: the LAN variant sends the same encrypted RPC, but to `http://<peerIp>:39402/rpc` with header `x-latchkey-client: <cid>` and encrypts with AAD `LATCHKEY/LAN/1|client:<cid>`. `LanStore.getOutbound()` on the Android side exposes the record your on-device agent bridge would use. Since the wire format is otherwise identical to loopback paired clients, only the **host/port** and the **AAD prefix** differ — a flag like `--lan <peerId>` (reading the saved LAN credentials) is enough.

---

## Integration checklist

1. Drop the 7 new `.java` files into `android/app/src/main/java/io/latchkey/bridge/`.
2. Apply the `RpcHandler` patch (LAN key/AAD resolution).
3. Apply the manifest patch (permission block + `ScanActivity`).
4. Add the `MainActivity` methods and hook `buildLanSection()` into the Connect page.
5. Wire `LanServer` start/stop into `LatchkeyService`.
6. Vendor zxing-core in the Dockerfile and fix the two build-script lines.
7. Bump to 1.3.1/21, build with `build-apk-nogradle.sh`.
8. On-device verification: pair A→B over the hotspot, confirm Agent-A reaches Device-B (`ls`/`read`), confirm B→A fails until B scans A's QR, confirm cell-data pairing fails (QR with a public IP is refused at decode), revoke a LAN peer and confirm 401, replay a used QR token (403 NO_LINK), 5 bad tokens (429 lockout).