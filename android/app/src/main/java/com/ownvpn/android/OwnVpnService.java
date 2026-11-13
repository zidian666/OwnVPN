package com.ownvpn.android;
import android.app.*;
import android.content.*;
import android.net.*;
import android.os.*;
import android.system.OsConstants;
import java.util.concurrent.*;

public final class OwnVpnService extends VpnService {
    static final String START = "com.ownvpn.android.START", STOP = "com.ownvpn.android.STOP";
    private static final int NOTIFICATION = 10;
    static final class Request {
        final String profile, username, password, otp;
        final boolean automatic, reconnect, fallback;
        Request(String profile, String username, String password, String otp, boolean automatic,
                boolean reconnect, boolean fallback) {
            this.profile = profile;
            this.username = username;
            this.password = password;
            this.otp = otp;
            this.automatic = automatic;
            this.reconnect = reconnect;
            this.fallback = fallback;
        }
    }
    static final class Snapshot {
        final String state, message, ip, diagnostic;
        final boolean active;
        Snapshot(String state, String message, String ip, String diagnostic, boolean active) {
            this.state = state;
            this.message = message;
            this.ip = ip;
            this.diagnostic = diagnostic;
            this.active = active;
        }
    }
    final class LocalBinder extends Binder {
        OwnVpnService service() {
            return OwnVpnService.this;
        }
    }
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final StringBuilder diagnostic = new StringBuilder();
    private volatile Snapshot snapshot = new Snapshot("IDLE", "未连接", "", "", false);
    private volatile boolean wanted;
    private long handle;
    private Request request;
    private int retries;
    private long connectedAt;
    private boolean foreground;
    private Runnable pendingRetry;
    private Builder builder;
    private int routes;
    Snapshot snapshot() {
        return snapshot;
    }
    @Override
    public void onCreate() {
        super.onCreate();
        getSystemService(NotificationManager.class)
            .createNotificationChannel(
                new NotificationChannel("vpn", "VPN 连接", NotificationManager.IMPORTANCE_LOW));
    }
    @Override
    public IBinder onBind(Intent intent) {
        return "local".equals(intent.getAction()) ? new LocalBinder() : super.onBind(intent);
    }
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && STOP.equals(intent.getAction()))
            disconnect();
        else if (request == null) {
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
        } else
            showNotification();
        return START_NOT_STICKY;
    }
    void connect(Request value) {
        if (snapshot.active)
            return;
        request = value;
        wanted = true;
        retries = 0;
        connectedAt = 0;
        diagnostic.setLength(0);
        update("STARTING", "正在准备连接", "", true);
        attempt();
    }
    void disconnect() {
        wanted = false;
        if (pendingRetry != null) {
            main.removeCallbacks(pendingRetry);
            pendingRetry = null;
        }
        if (handle != 0) {
            update("STOPPING", "正在断开", "", true);
            NativeBridge.stop(handle);
        } else
            finish("IDLE", "未连接");
    }
    private void attempt() {
        if (!wanted || request == null)
            return;
        update("STARTING", "正在启动", "", true);
        final Request current = request;
        try {
            handle = NativeBridge.newSession(this);
        } catch (RuntimeException error) {
            wanted = false;
            finish("ERROR", "无法启动 VPN 引擎");
            return;
        }
        final long session = handle;
        worker.execute(() -> {
            String result;
            try {
                result = NativeBridge.run(session, current.profile, current.username, current.password,
                                          current.otp, current.automatic, current.fallback);
            } catch (RuntimeException error) {
                result = "FAILED";
            }
            final String ended = result;
            main.post(() -> completed(session, ended));
        });
    }
    private void completed(long session, String result) {
        if (handle != session)
            return;
        handle = 0;
        builder = null;
        if (!wanted) {
            finish("ERROR".equals(snapshot.state) ? "ERROR" : "IDLE",
                   "ERROR".equals(snapshot.state) ? snapshot.message : "未连接");
            return;
        }
        if ("AUTH_FAILED".equals(result) || "CONFIG_ERROR".equals(result)) {
            wanted = false;
            finish("ERROR", "AUTH_FAILED".equals(result) ? "认证失败，请核对密码和验证码" : "配置检查失败");
            return;
        }
        if (request.reconnect && request.automatic) {
            if (connectedAt != 0 && SystemClock.elapsedRealtime() - connectedAt >= 60000)
                retries = 0;
            connectedAt = 0;
            int seconds = NativeBridge.retrySeconds(retries++);
            update("RETRYING", seconds + " 秒后重连", "", true);
            pendingRetry = () -> {
                pendingRetry = null;
                attempt();
            };
            main.postDelayed(pendingRetry, seconds * 1000L);
        } else {
            wanted = false;
            finish("ERROR",
                   request.reconnect ? "连接已断开，自动重连需要绑定自动验证码" : "连接已断开，请重试");
        }
    }
    private void finish(String state, String message) {
        request = null;
        update(state, message, "", false);
        stopForeground(STOP_FOREGROUND_REMOVE);
        foreground = false;
        stopSelf();
    }
    private void update(String state, String message, String ip, boolean active) {
        android.util.Log.i("OwnVPNState", state);
        snapshot = new Snapshot(state, message, ip, diagnostic.toString(), active);
        if (active)
            showNotification();
    }
    private void record(String text) {
        if (text.isEmpty())
            return;
        diagnostic
            .append(new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.ROOT)
                        .format(new java.util.Date()))
            .append(' ')
            .append(text)
            .append('\n');
        if (diagnostic.length() > 16000)
            diagnostic.delete(0, diagnostic.indexOf("\n", diagnostic.length() - 12000) + 1);
        snapshot = new Snapshot(snapshot.state, snapshot.message, snapshot.ip, diagnostic.toString(),
                                snapshot.active);
    }
    private void showNotification() {
        PendingIntent open =
            PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class),
                                      PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop =
            PendingIntent.getService(this, 1, new Intent(this, OwnVpnService.class).setAction(STOP),
                                     PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification notification =
            new Notification.Builder(this, "vpn")
                .setSmallIcon(R.drawable.ic_ownvpn)
                .setContentTitle("OwnVPN")
                .setContentText(snapshot.message)
                .setContentIntent(open)
                .setOngoing(true)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .setColor("CONNECTED".equals(snapshot.state) ? 0xff327560 : 0xff777777)
                .addAction(new Notification.Action.Builder(null, "断开", stop).build())
                .build();
        if (!foreground) {
            startForeground(NOTIFICATION, notification);
            foreground = true;
        } else
            getSystemService(NotificationManager.class).notify(NOTIFICATION, notification);
    }
    // JNI callbacks run on the engine worker. All state/UI updates are posted to main.
    public void nativeEvent(String name, String text) {
        main.post(() -> {
            if ("DIAGNOSTIC".equals(name)) {
                record
                (text);
                return;
            }
            if (!wanted)
                return;
            record
            (name);
            switch (name) {
            case "PREPARING_CONFIG":
                update("STARTING", "正在读取配置", "", true);
                break;
            case "PREPARING_OTP":
                update("STARTING", "正在准备验证码", "", true);
                break;
            case "STARTING_ENGINE":
                update("CONNECTING", "正在连接服务器", "", true);
                break;
            case "SETUP_ERROR":
                record
                (text);
                wanted = false;
                update("ERROR", "VPN 启动失败，请查看诊断", "", true);
                break;
            case "CONNECTED":
                connectedAt = SystemClock.elapsedRealtime();
                update("CONNECTED", "已连接", text, true);
                break;
            case "AUTH_FAILED":
                wanted = false;
                update("ERROR", "认证失败，请核对密码和验证码", "", true);
                if (handle != 0)
                    NativeBridge.stop(handle);
                break;
            case "CONFIG_ERROR":
                wanted = false;
                update("ERROR", text, "", true);
                break;
            case "RECONNECTING":
                update("CONNECTING", "连接中断，准备重新连接", "", true);
                break;
            case "RESOLVE":
                update("CONNECTING", "正在解析服务器", "", true);
                break;
            case "CONNECTING":
            case "WAIT":
                update("CONNECTING", "正在连接服务器", "", true);
                break;
            case "GET_CONFIG":
            case "ASSIGN_IP":
                update("CONNECTING", "正在建立 VPN 隧道", "", true);
                break;
            case "FAILED":
                record
                (text);
                break;
            default:
                break;
            }
        });
    }
    public boolean protectSocket(int fd) {
        return wanted && protect(fd);
    }
    public synchronized boolean newTunnel() {
        if (!wanted)
            return false;
        builder = new Builder().setSession("OwnVPN").setMtu(1500);
        builder.allowFamily(OsConstants.AF_INET);
        builder.allowFamily(OsConstants.AF_INET6);
        routes = 0;
        return true;
    }
    public synchronized boolean addAddress(String address, int prefix) {
        builder.addAddress(address, prefix);
        return wanted;
    }
    public synchronized boolean addRoute(String address, int prefix) {
        if (prefix > 1) {
            builder.addRoute(address, prefix);
            routes++;
        }
        return wanted;
    }
    public synchronized boolean excludeRoute(String address, int prefix) {
        if (Build.VERSION.SDK_INT >= 33)
            builder.excludeRoute(new IpPrefix(InetAddresses.parseNumericAddress(address), prefix));
        else
            throw new IllegalStateException("此配置的排除路由需要 Android 13 或更新版本");
        return wanted;
    }
    public synchronized boolean addDns(String address) {
        builder.addDnsServer(address);
        builder.addRoute(address, address.contains(":") ? 128 : 32);
        return wanted;
    }
    public synchronized boolean allowFamily(int family) {
        builder.allowFamily(family);
        return wanted;
    }
    public synchronized boolean setMtu(int mtu) {
        builder.setMtu(mtu);
        return wanted;
    }
    public synchronized int establish() {
        if (!wanted || routes == 0)
            throw new IllegalStateException("配置没有公司内网路由");
        ParcelFileDescriptor tunnel = builder.establish();
        if (tunnel == null)
            return -1;
        return tunnel.detachFd(); // OpenVPN owns and closes this fd.
    }
    @Override
    public void onRevoke() {
        main.post(this::disconnect);
    }
    @Override
    public void onDestroy() {
        wanted = false;
        if (handle != 0)
            NativeBridge.stop(handle);
        main.removeCallbacksAndMessages(null);
        worker.shutdown();
        super.onDestroy();
    }
}
