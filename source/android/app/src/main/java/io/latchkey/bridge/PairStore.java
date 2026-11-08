package io.latchkey.bridge;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Stores per-client loopback keys issued by the pairing flow.
 *
 * Each key is wrapped by an Android Keystore AES key with the client ID as
 * AAD. If the Keystore is unavailable, issuing a key fails closed: client keys
 * are never written in plaintext.
 */
final class PairStore {
    static final class Issued {
        final String clientId;
        final String name;
        final byte[] key;
        final String fingerprint;

        Issued(String clientId, String name, byte[] key, String fingerprint) {
            this.clientId = clientId;
            this.name = name;
            this.key = key;
            this.fingerprint = fingerprint;
        }
    }

    static final class Client {
        final String id;
        final String name;
        final String fingerprint;
        final long createdAt;

        Client(String id, String name, String fingerprint, long createdAt) {
            this.id = id;
            this.name = name;
            this.fingerprint = fingerprint;
            this.createdAt = createdAt;
        }
    }

    private static final String TAG = "Latchkey";
    private static final String PREFS = "latchkey-pairing";
    private static final String PREF_CLIENTS = "clients";
    private static final String PREF_HOST_ID = "host_id";
    private static final String ALIAS = "latchkey_client_kek_v1";
    private static final Object LOCK = new Object();
    private static final SecureRandom RNG = new SecureRandom();

    private PairStore() {
    }

    static String hostId(Context context) {
        synchronized (LOCK) {
            SharedPreferences prefs = context.getSharedPreferences(
                    PREFS, Context.MODE_PRIVATE);
            String existing = prefs.getString(PREF_HOST_ID, null);
            if (existing != null && existing.matches("[a-f0-9]{32}")) {
                return existing;
            }
            byte[] id = new byte[16];
            RNG.nextBytes(id);
            String value = hex(id);
            prefs.edit().putString(PREF_HOST_ID, value).apply();
            return value;
        }
    }

    static Issued issue(Context context, String clientId, String name) throws Exception {
        synchronized (LOCK) {
            JSONArray clients = load(context);
            for (int i = 0; i < clients.length(); i++) {
                JSONObject record = clients.optJSONObject(i);
                if (record != null && clientId.equals(record.optString("id", ""))) {
                    throw new IllegalArgumentException("client is already paired");
                }
            }
            byte[] key = Crypto.randomKey();
            try {
                String fingerprint = Crypto.fingerprint(key);
                String wrapped = Base64.getEncoder().encodeToString(wrap(key, clientId));
                JSONObject record = new JSONObject();
                record.put("id", clientId);
                record.put("name", name);
                record.put("fp", fingerprint);
                record.put("created", System.currentTimeMillis());
                record.put("blob", wrapped);
                clients.put(record);
                SharedPreferences prefs = context.getSharedPreferences(
                        PREFS, Context.MODE_PRIVATE);
                if (!prefs.edit().putString(PREF_CLIENTS, clients.toString()).commit()) {
                    throw new IllegalStateException("could not save paired client");
                }
                EventLog.info("pair", "issued",
                        "issued a client key for " + name + " (" + clientId + ")");
                return new Issued(clientId, name, key, fingerprint);
            } catch (Exception failure) {
                Arrays.fill(key, (byte) 0);
                throw failure;
            }
        }
    }

    static byte[] getKey(Context context, String clientId) {
        synchronized (LOCK) {
            JSONArray clients = load(context);
            for (int i = 0; i < clients.length(); i++) {
                JSONObject record = clients.optJSONObject(i);
                if (record == null || !clientId.equals(record.optString("id", ""))) {
                    continue;
                }
                String wrapped = record.optString("blob", "");
                try {
                    return unwrap(Base64.getDecoder().decode(wrapped), clientId);
                } catch (Exception failure) {
                    EventLog.error("auth", "client-unwrap-failed",
                            "could not unwrap client key " + clientId + ": "
                                    + message(failure));
                    return null;
                }
            }
            return null;
        }
    }

    static List<Client> list(Context context) {
        synchronized (LOCK) {
            List<Client> out = new ArrayList<Client>();
            JSONArray clients = load(context);
            for (int i = 0; i < clients.length(); i++) {
                JSONObject record = clients.optJSONObject(i);
                if (record == null) {
                    continue;
                }
                out.add(new Client(record.optString("id", ""),
                        record.optString("name", "Assistant"),
                        record.optString("fp", ""),
                        record.optLong("created", 0L)));
            }
            return out;
        }
    }

    static int count(Context context) {
        return load(context).length();
    }

    static int revokeAll(Context context) {
        synchronized (LOCK) {
            int count = load(context).length();
            SharedPreferences prefs = context.getSharedPreferences(
                    PREFS, Context.MODE_PRIVATE);
            prefs.edit().remove(PREF_CLIENTS).apply();
            if (count > 0) {
                EventLog.warn("pair", "revoked", "revoked " + count + " paired client(s)");
            }
            return count;
        }
    }

    private static JSONArray load(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(
                PREFS, Context.MODE_PRIVATE);
        String raw = prefs.getString(PREF_CLIENTS, "");
        if (raw == null || raw.length() == 0) {
            return new JSONArray();
        }
        try {
            JSONArray parsed = new JSONArray(raw);
            return parsed == null ? new JSONArray() : parsed;
        } catch (Exception failure) {
            EventLog.error("pair", "store-corrupt",
                    "paired-client store is corrupt: " + message(failure));
            return new JSONArray();
        }
    }

    private static SecretKey getOrCreateKek() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (!keyStore.containsAlias(ALIAS)) {
            KeyGenerator generator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setUserAuthenticationRequired(false)
                    .build();
            generator.init(spec);
            generator.generateKey();
            keyStore.load(null);
        }
        return (SecretKey) keyStore.getKey(ALIAS, null);
    }

    private static byte[] wrap(byte[] key, String clientId) throws Exception {
        SecretKey kek = getOrCreateKek();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, kek);
        cipher.updateAAD(clientId.getBytes(StandardCharsets.UTF_8));
        byte[] iv = cipher.getIV();
        byte[] ciphertext = cipher.doFinal(key);
        byte[] out = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ciphertext, 0, out, iv.length, ciphertext.length);
        return out;
    }

    private static byte[] unwrap(byte[] blob, String clientId) throws Exception {
        if (blob.length <= Crypto.NONCE_BYTES) {
            throw new IllegalArgumentException("wrapped key too short");
        }
        SecretKey kek = getOrCreateKek();
        byte[] iv = Arrays.copyOfRange(blob, 0, Crypto.NONCE_BYTES);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, kek,
                new GCMParameterSpec(Crypto.TAG_BITS, iv));
        cipher.updateAAD(clientId.getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(blob, Crypto.NONCE_BYTES, blob.length - Crypto.NONCE_BYTES);
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            String hex = Integer.toHexString(value & 0xff);
            if (hex.length() == 1) {
                out.append('0');
            }
            out.append(hex);
        }
        return out.toString();
    }

    private static String message(Throwable failure) {
        String text = failure.getMessage();
        if (text == null || text.length() == 0) {
            text = failure.getClass().getSimpleName();
        }
        return text;
    }
}
