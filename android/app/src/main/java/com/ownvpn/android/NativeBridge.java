package com.ownvpn.android;
import android.content.Context;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.concurrent.*;
final class NativeBridge {
    static {
        System.loadLibrary("ownvpn_android");
    }
    private static SecretStore secrets;
    private static final ExecutorService DNS = Executors.newFixedThreadPool(2);
    static void initialize(Context context) {
        secrets = new SecretStore(context);
        init(context.getFilesDir().getAbsolutePath());
    }
    static String readSecret(String group, String field) {
        return secrets.read(group, field);
    }
    static void writeSecret(String group, String field, String value) {
        secrets.write(group, field, value);
    }
    static String[] resolve(String host, int family) {
        Future<String[]> task = DNS.submit(() -> {
            ArrayList<String> result = new ArrayList<>();
            for (InetAddress address : InetAddress.getAllByName(host)) {
                if (family == 0 || address.getAddress().length == (family == 4 ? 4 : 16))
                    result.add(address.getHostAddress());
            }
            return result.toArray(new String[0]);
        });
        try {
            return task.get(10, TimeUnit.SECONDS);
        } catch (Exception error) {
            task.cancel(true);
            return new String[0];
        }
    }
    private static native void init(String root);
    static native String[] profiles();
    static native String importProfile(String ovpn, String pem);
    static native void bindTotp(String profile, String username, String input);
    static native String totp(String profile, String username);
    static native String decodeQr(int[] pixels, int width, int height);
    static native String selfTest();
    static native String evaluateConfig(String input);
    static native String validateProfile(String id);
    static native String probeProfile(OwnVpnService service, String id);
    static native int retrySeconds(int attempt);
    static native long newSession(OwnVpnService service);
    static native String run(long handle, String profile, String username, String password, String otp,
                             boolean automatic, boolean fallback);
    static native void stop(long handle);
}
