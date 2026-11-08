package io.latchkey.bridge;

import android.content.Context;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;

import java.util.Arrays;

/**
 * Thin public API for the notification and activity actions. The old
 * PairingManager/PairStore/KeyStoreManager classes are package-private, so
 * the foreground service and the UI talk through this class.
 */
final class PairManager {
    private PairManager() {
    }

    static String createLink(Context context, String appFingerprint, int port) {
        try {
            return PairingManager.createLink(context, appFingerprint, port);
        } catch (Exception e) {
            return "";
        }
    }

    static void invalidate() {
        PairingManager.invalidate();
    }

    static String pair(Context context, String body, String remote) {
        PairingManager.PairResponse response = PairingManager.pair(context, body, remote);
        return response.body;
    }

    static int count(Context context) {
        return PairStore.count(context);
    }

    static int revokeAll(Context context) {
        PairingManager.invalidate();
        return PairStore.revokeAll(context);
    }

    static String regenerateKey(Context context) {
        return KeyStoreManager.regenerate(context);
    }

    static String currentFingerprint(Context context) {
        try {
            byte[] key = Crypto.decodeKey(KeyStoreManager.getOrCreateKey(context));
            try {
                return Crypto.fingerprint(key);
            } finally {
                Arrays.fill(key, (byte) 0);
            }
        } catch (Exception ignored) {
            return "";
        }
    }

    static String appFingerprint(Context context) {
        try {
            int flags = Build.VERSION.SDK_INT >= 28
                    ? PackageManager.GET_SIGNING_CERTIFICATES
                    : PackageManager.GET_SIGNATURES;
            PackageInfo info = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), flags);
            Signature[] signatures = null;
            if (Build.VERSION.SDK_INT >= 28 && info.signingInfo != null) {
                signatures = info.signingInfo.getApkContentsSigners();
            } else if (info.signatures != null) {
                signatures = info.signatures;
            }
            if (signatures != null && signatures.length > 0) {
                return Crypto.fingerprint(signatures[0].toByteArray());
            }
        } catch (Exception ignored) {
        }
        return "";
    }

    static void copyLink(Context context, String link) {
        ClipboardManager clipboard =
                (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null) {
            return;
        }
        ClipData clip = ClipData.newPlainText("Latchkey pairing link", link);
        if (Build.VERSION.SDK_INT >= 33) {
            android.os.PersistableBundle extras = new android.os.PersistableBundle();
            extras.putBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE, true);
            clip.getDescription().setExtras(extras);
        }
        clipboard.setPrimaryClip(clip);
    }
}