package io.latchkey.bridge;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import io.latchkey.bridge.PairManager;
import io.latchkey.bridge.PairStore;
import io.latchkey.bridge.KeyStoreManager;

public final class LatchkeyService extends Service {
    private static final String TAG = "Latchkey";
    private static final String CHANNEL_ID = "latchkey_service";
    private static final int NOTIFICATION_ID = 39401;

    static final String ACTION_START = "io.latchkey.bridge.action.START";
    static final String ACTION_STOP = "io.latchkey.bridge.action.STOP";
    static final String ACTION_RESTART = "io.latchkey.bridge.action.RESTART";
    static final String ACTION_PAIR = "io.latchkey.bridge.action.PAIR";
    static final String ACTION_REVOKE = "io.latchkey.bridge.action.REVOKE";

    private RpcServer server;
    private String keyFingerprint = "";

    static void start(Context context) {
        Intent intent = new Intent(context, LatchkeyService.class).setAction(ACTION_START);
        if (Build.VERSION.SDK_INT >= 26) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
    }

    static void stop(Context context) {
        Intent intent = new Intent(context, LatchkeyService.class).setAction(ACTION_STOP);
        context.startService(intent);
    }

    static void restart(Context context) {
        Intent intent = new Intent(context, LatchkeyService.class).setAction(ACTION_RESTART);
        if (Build.VERSION.SDK_INT >= 26) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        EventLog.init(this);
        EventLog.info("service", "create", "foreground service created");
        createChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_START : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            EventLog.info("service", "stop", "server stop requested; keeping controls");
            stopServer();
            notifyStatus(this, statusText(this), false);
            return START_STICKY;
        }

        EventLog.info("service", "start", "action=" + action);
        startForegroundCompat(notification(this, statusText(this), ServerRuntime.running));

        if (ACTION_RESTART.equals(action)) {
            EventLog.info("service", "restart", "restarting server with current key");
            stopServer();
        }

        if (ACTION_PAIR.equals(action)) {
            EventLog.info("pair", "link", "pairing link requested from notification");
            try {
                String link = PairManager.createLink(this, appFingerprint(),
                        ServerRuntime.port);
                PairManager.copyLink(this, link);
                EventLog.info("pair", "link-copied",
                        "pairing link copied from notification");
                notifyStatus(this, "Pairing link copied", ServerRuntime.running);
            } catch (Exception e) {
                EventLog.error("pair", "link-failed", e.getMessage());
                notifyStatus(this, "Could not create pairing link", ServerRuntime.running);
            }
            return START_STICKY;
        }

        if (ACTION_REVOKE.equals(action)) {
            EventLog.info("pair", "revoke", "revoke requested from notification");
            int revoked = PairManager.revokeAll(this);
            String newKey = PairManager.regenerateKey(this);
            EventLog.warn("key", "regenerate",
                    "access key regenerated from notification revoke");
            keyFingerprint = PairManager.currentFingerprint(this);
            EventLog.info("service", "revoke",
                    "revoked " + revoked + " client(s) and regenerated the legacy key");
            notifyStatus(this, statusText(this), ServerRuntime.running);
            return START_STICKY;
        }

        if (server == null) {
            try {
                String encodedKey = KeyStoreManager.getOrCreateKey(this);
                byte[] key = Crypto.decodeKey(encodedKey);
                keyFingerprint = Crypto.fingerprint(key);
                RpcHandler handler = new RpcHandler(this, key, keyFingerprint);
                RpcServer newServer = new RpcServer(this, ServerRuntime.PORT, handler);
                newServer.start();
                server = newServer;
                EventLog.info("service", "started", "server is listening",
                        Json.put(Json.put(Json.obj(), "port", ServerRuntime.port),
                                "keyFingerprint", keyFingerprint));
                notifyStatus(this, statusText(this), true);
            } catch (Exception e) {
                Log.e(TAG, "could not start server", e);
                String message = e.getMessage();
                if (message == null || message.length() == 0) {
                    message = e.getClass().getSimpleName();
                }
                ServerRuntime.setError(message);
                EventLog.error("service", "start-failed", message);
                notifyStatus(this, "Could not start: " + message, false);
                return START_STICKY;
            }
        } else {
            notifyStatus(this, statusText(this), ServerRuntime.running);
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        EventLog.info("service", "destroy", "foreground service destroyed");
        stopServer();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void stopServer() {
        RpcServer current = server;
        server = null;
        if (current != null) {
            current.stop();
        }
    }

    private void startForegroundCompat(Notification notification) {
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    private void createChannel() {
        NotificationManager manager =
                (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager == null) {
            return;
        }
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "Latchkey server", NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Keeps the loopback file bridge running");
        channel.setShowBadge(false);
        manager.createNotificationChannel(channel);
    }

private static void notifyStatus(Context context, String text, boolean running) {
        NotificationManager manager =
                (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, notification(context, text, running));
        }
    }

    static void refreshNotification(Context context) {
        notifyStatus(context, statusText(context), ServerRuntime.running);
    }

    private static String statusText(Context context) {
        int clients = PairManager.count(context);
        String state = ServerRuntime.running ? "Active" : "Stale";
        return "Key · " + state + " · "
                + clients + " client" + (clients == 1 ? "" : "s") + " connected";
    }

    private String appFingerprint() {
        return PairManager.appFingerprint(this);
    }

    private static Notification notification(Context context, String text, boolean running) {
        Intent openIntent = new Intent(context, MainActivity.class);
        PendingIntent open = PendingIntent.getActivity(context, 1, openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder builder = new Notification.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_key)
                .setContentTitle("Latchkey")
                .setContentText(text)
                .setContentIntent(open)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setCategory(Notification.CATEGORY_SERVICE)
                .setVisibility(Notification.VISIBILITY_PRIVATE);

        if (!running) {
            Intent startIntent = new Intent(context, LatchkeyService.class).setAction(ACTION_START);
            PendingIntent start = PendingIntent.getService(context, 6, startIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            builder.addAction(new Notification.Action.Builder(
                    android.R.drawable.ic_media_play, "Start", start).build());
        } else {
            Intent stopIntent = new Intent(context, LatchkeyService.class).setAction(ACTION_STOP);
            PendingIntent stop = PendingIntent.getService(context, 2, stopIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            builder.addAction(new Notification.Action.Builder(
                    android.R.drawable.ic_menu_close_clear_cancel, "Stop", stop).build());

            Intent pairIntent = new Intent(context, LatchkeyService.class).setAction(ACTION_PAIR);
            PendingIntent pair = PendingIntent.getService(context, 4, pairIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            builder.addAction(new Notification.Action.Builder(
                    android.R.drawable.ic_menu_add, "Pair", pair).build());
        }

        Intent revokeIntent = new Intent(context, LatchkeyService.class).setAction(ACTION_REVOKE);
        PendingIntent revoke = PendingIntent.getService(context, 5, revokeIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        builder.addAction(new Notification.Action.Builder(
                android.R.drawable.ic_menu_delete, "Revoke", revoke).build());

        Intent deleteIntent = new Intent(context, LatchkeyService.class).setAction(ACTION_RESTART);
        PendingIntent delete = PendingIntent.getService(context, 3, deleteIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        builder.setDeleteIntent(delete);
        return builder.build();
    }
}
