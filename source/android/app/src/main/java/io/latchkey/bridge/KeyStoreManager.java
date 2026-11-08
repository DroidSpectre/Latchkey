package io.latchkey.bridge;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyStore;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class KeyStoreManager {
    private static final String PREFS = "latchkey";
    private static final String PREF_WRAPPED = "wrapped_key";
    private static final String PREF_LEGACY_PLAIN = "plain_key_fallback";
    private static final String ALIAS = "latchkey_access_key_v1";
    private static final Object LOCK = new Object();

    private static volatile boolean persisted = true;
    private static volatile String storageWarning = "";
    private static String sessionEncoded;

    private KeyStoreManager() {
    }

    static boolean isPersisted() {
        return persisted;
    }

    static String storageWarning() {
        return storageWarning;
    }

    static String getOrCreateKey(Context context) {
        synchronized (LOCK) {
            String encoded = load(context);
            if (encoded != null) {
                return encoded;
            }
            if (sessionEncoded != null) {
                return sessionEncoded;
            }
            byte[] key = Crypto.randomKey();
            try {
                encoded = Crypto.encodeKey(key);
                if (save(context, key)) {
                    persisted = true;
                    storageWarning = "";
                    sessionEncoded = null;
                    EventLog.info("key", "create", "generated and wrapped a new access key");
                } else {
                    sessionEncoded = encoded;
                    markSessionOnly();
                }
                return encoded;
            } finally {
                Arrays.fill(key, (byte) 0);
            }
        }
    }

    static String regenerate(Context context) {
        synchronized (LOCK) {
            byte[] key = Crypto.randomKey();
            try {
                String encoded = Crypto.encodeKey(key);
                if (save(context, key)) {
                    persisted = true;
                    storageWarning = "";
                    sessionEncoded = null;
                    EventLog.warn("key", "regenerate", "access key regenerated and wrapped");
                } else {
                    sessionEncoded = encoded;
                    markSessionOnly();
                }
                return encoded;
            } finally {
                Arrays.fill(key, (byte) 0);
            }
        }
    }

    private static String load(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String wrapped = prefs.getString(PREF_WRAPPED, null);
        if (wrapped != null) {
            byte[] key = null;
            try {
                byte[] blob = Base64.getDecoder().decode(wrapped);
                key = unwrap(blob);
                String encoded = Crypto.encodeKey(key);
                persisted = true;
                storageWarning = "";
                sessionEncoded = null;
                EventLog.info("key", "load", "loaded wrapped access key");
                return encoded;
            } catch (Exception failure) {
                EventLog.warn("key", "unwrap-failed",
                        "could not unwrap stored key: " + message(failure));
                prefs.edit().remove(PREF_WRAPPED).apply();
            } finally {
                if (key != null) {
                    Arrays.fill(key, (byte) 0);
                }
            }
        }

        String legacy = prefs.getString(PREF_LEGACY_PLAIN, null);
        if (legacy != null) {
            byte[] key = null;
            try {
                key = Crypto.decodeKey(legacy);
                String encoded = Crypto.encodeKey(key);
                if (save(context, key)) {
                    persisted = true;
                    storageWarning = "";
                    sessionEncoded = null;
                    EventLog.warn("key", "migrate",
                            "migrated legacy plaintext key into Android Keystore");
                    return encoded;
                }
                prefs.edit().remove(PREF_LEGACY_PLAIN).apply();
                markSessionOnly();
                EventLog.error("key", "migrate-failed",
                        "removed legacy plaintext key; using a session-only key");
                return encoded;
            } catch (Exception failure) {
                EventLog.warn("key", "legacy-invalid",
                        "could not decode legacy key: " + message(failure));
                prefs.edit().remove(PREF_LEGACY_PLAIN).apply();
            } finally {
                if (key != null) {
                    Arrays.fill(key, (byte) 0);
                }
            }
        }
        return null;
    }

    private static boolean save(Context context, byte[] key) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        try {
            byte[] blob = wrap(key);
            prefs.edit()
                    .putString(PREF_WRAPPED, Base64.getEncoder().encodeToString(blob))
                    .remove(PREF_LEGACY_PLAIN)
                    .apply();
            return true;
        } catch (Exception failure) {
            prefs.edit()
                    .remove(PREF_WRAPPED)
                    .remove(PREF_LEGACY_PLAIN)
                    .apply();
            EventLog.error("key", "wrap-failed",
                    "Android Keystore unavailable: " + message(failure));
            return false;
        }
    }

    private static void markSessionOnly() {
        persisted = false;
        storageWarning = "Keystore unavailable; this key is session-only";
        EventLog.error("key", "session-only", storageWarning);
    }

    private static String message(Throwable failure) {
        String text = failure.getMessage();
        if (text == null || text.length() == 0) {
            text = failure.getClass().getSimpleName();
        }
        return text;
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

    private static byte[] wrap(byte[] key) throws Exception {
        SecretKey kek = getOrCreateKek();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, kek);
        byte[] iv = cipher.getIV();
        byte[] ciphertext = cipher.doFinal(key);
        byte[] out = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ciphertext, 0, out, iv.length, ciphertext.length);
        return out;
    }

    private static byte[] unwrap(byte[] blob) throws Exception {
        SecretKey kek = getOrCreateKek();
        if (blob.length <= Crypto.NONCE_BYTES) {
            throw new IllegalArgumentException("wrapped key too short");
        }
        byte[] iv = Arrays.copyOfRange(blob, 0, Crypto.NONCE_BYTES);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, kek, new GCMParameterSpec(Crypto.TAG_BITS, iv));
        return cipher.doFinal(blob, Crypto.NONCE_BYTES, blob.length - Crypto.NONCE_BYTES);
    }
}
