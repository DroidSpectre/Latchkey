package io.latchkey.bridge;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class Crypto {
    static final int KEY_BYTES = 32;
    static final int NONCE_BYTES = 12;
    static final int TAG_BITS = 128;
    static final byte[] AAD = "LATCHKEY/1".getBytes(StandardCharsets.UTF_8);
    private static final SecureRandom RNG = new SecureRandom();

    private Crypto() {
    }

    static byte[] randomKey() {
        byte[] key = new byte[KEY_BYTES];
        RNG.nextBytes(key);
        return key;
    }

    static String encodeKey(byte[] key) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(key);
    }

    static byte[] decodeKey(String text) {
        if (text == null) {
            throw new IllegalArgumentException("missing key");
        }
        String cleaned = text.trim();
        if (!cleaned.matches("[A-Za-z0-9_-]{43}")) {
            throw new IllegalArgumentException("key must be 43 base64url characters");
        }
        byte[] key = Base64.getUrlDecoder().decode(cleaned);
        if (key.length != KEY_BYTES || !encodeKey(key).equals(cleaned)) {
            throw new IllegalArgumentException("key is not canonical 32-byte base64url");
        }
        return key;
    }

    static byte[] encrypt(byte[] key, byte[] plaintext) throws Exception {
        return encrypt(key, AAD, plaintext);
    }

    static byte[] encrypt(byte[] key, String aad, byte[] plaintext) throws Exception {
        return encrypt(key, aad == null ? AAD : aad.getBytes(StandardCharsets.UTF_8), plaintext);
    }

    static byte[] encrypt(byte[] key, byte[] aad, byte[] plaintext) throws Exception {
        byte[] nonce = new byte[NONCE_BYTES];
        RNG.nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(aad == null ? AAD : aad);
        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] out = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, out, 0, nonce.length);
        System.arraycopy(ciphertext, 0, out, nonce.length, ciphertext.length);
        return out;
    }

    static byte[] decrypt(byte[] key, byte[] blob) throws Exception {
        return decrypt(key, AAD, blob);
    }

    static byte[] decrypt(byte[] key, String aad, byte[] blob) throws Exception {
        return decrypt(key, aad == null ? AAD : aad.getBytes(StandardCharsets.UTF_8), blob);
    }

    static byte[] decrypt(byte[] key, byte[] aad, byte[] blob) throws Exception {
        if (blob == null || blob.length < NONCE_BYTES + 16) {
            throw new IllegalArgumentException("ciphertext too short");
        }
        byte[] nonce = Arrays.copyOfRange(blob, 0, NONCE_BYTES);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(aad == null ? AAD : aad);
        return cipher.doFinal(blob, NONCE_BYTES, blob.length - NONCE_BYTES);
    }

    static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    static String fingerprint(byte[] key) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(key);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            String hex = Integer.toHexString(hash[i] & 0xff);
            if (hex.length() == 1) {
                out.append('0');
            }
            out.append(hex);
        }
        return out.toString().toUpperCase();
    }
}
