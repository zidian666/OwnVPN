package com.ownvpn.android;
import android.app.*;
import android.content.*;
import android.graphics.*;
import android.os.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;

public final class SmokeInstrumentation extends Instrumentation {
    private Bundle arguments;
    private int checks;
    @Override
    public void onCreate(Bundle args) {
        arguments = args;
        super.onCreate(args);
        start();
    }
    private void check(boolean condition, String name) {
        if (!condition)
            throw new AssertionError(name);
        checks++;
        android.util.Log.i("OwnVPNSmoke", name);
        Bundle progress = new Bundle();
        progress.putString("stream", "PASS: " + name + "\n");
        sendStatus(1, progress);
    }
    @Override
    public void onStart() {
        Bundle result = new Bundle();
        try {
            android.util.Log.i("OwnVPNSmoke", "waiting for app initialization");
            waitForIdleSync();
            if (arguments != null && "true".equals(arguments.getString("prepareCredentialImport"))) {
                CredentialTransfer.prepare(getTargetContext());
                result.putString("stream", "IMPORT_PUBLIC_KEY_READY\n");
                finish(Activity.RESULT_OK, result);
                return;
            }
            if (arguments != null && "true".equals(arguments.getString("importCredentials"))) {
                int imported = CredentialTransfer.apply(getTargetContext());
                result.putString("stream", "IMPORTED_LOGIN_PROFILES: " + imported + "\n");
                finish(Activity.RESULT_OK, result);
                return;
            }
            check(NativeBridge.selfTest().contains("18 RFC6238"), "production crypto RFC vectors");
            NativeBridge.writeSecret("__selftest__", "value", "公开测试中文🔒");
            check("公开测试中文🔒".equals(NativeBridge.readSecret("__selftest__", "value")),
                  "Keystore encrypted UTF8 roundtrip");
            NativeBridge.writeSecret("__selftest__", "value", "");
            check(NativeBridge.readSecret("__selftest__", "value").isEmpty(), "secret deletion");
            check(NativeBridge.retrySeconds(0) == 3 && NativeBridge.retrySeconds(1) == 6 &&
                      NativeBridge.retrySeconds(5) == 30,
                  "shared reconnect policy");
            try (InputStream stream = getContext().getAssets().open("totp-standard.png")) {
                Bitmap image = BitmapFactory.decodeStream(stream);
                int[] pixels = new int[image.getWidth() * image.getHeight()];
                image.getPixels(pixels, 0, image.getWidth(), 0, 0, image.getWidth(), image.getHeight());
                check(NativeBridge.decodeQr(pixels, image.getWidth(), image.getHeight())
                          .startsWith("otpauth://totp/"),
                      "real QR decoding");
                image.recycle();
            }
            CountDownLatch ready = new CountDownLatch(1);
            OwnVpnService[] service = new OwnVpnService[1];
            ServiceConnection binding = new ServiceConnection() {
                public void onServiceConnected(ComponentName n, IBinder binder) {
                    service[0] = ((OwnVpnService.LocalBinder)binder).service();
                    ready.countDown();
                }
                public void onServiceDisconnected(ComponentName n) {}
            };
            check(getTargetContext().bindService(
                      new Intent(getTargetContext(), OwnVpnService.class).setAction("local"), binding,
                      Context.BIND_AUTO_CREATE),
                  "local service binding");
            try {
                check(ready.await(10, TimeUnit.SECONDS), "service becomes ready");
                for (int i = 0; i < 8; i++) {
                    long handle = NativeBridge.newSession(service[0]);
                    NativeBridge.stop(handle);
                    check("CANCELLED".equals(NativeBridge.run(handle, "", "public-user", "public-password",
                                                                "123456", false, false)),
                          "cancel before engine start");
                }
                String[] profiles = NativeBridge.profiles();
                for (int p = 0; p < profiles.length; p += 2)
                    check("OK".equals(NativeBridge.probeProfile(service[0], profiles[p])),
                          "full profile startup with loopback override and synthetic credentials");
            } finally {
                getTargetContext().unbindService(binding);
            }
            if (arguments != null && "true".equals(arguments.getString("companyConfig"))) {
                for (int i = 1; i <= 2; i++) {
                    File file = new File(getTargetContext().getFilesDir(), "compatibility-" + i + ".txt");
                    try {
                        check("OK".equals(NativeBridge.evaluateConfig(new String(
                                  java.nio.file.Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8))),
                              "company profile compatibility " + i);
                    } finally {
                        file.delete();
                    }
                }
            }
            if (arguments != null && "true".equals(arguments.getString("importFromComputer"))) {
                File directory = new File(getTargetContext().getFilesDir(), "transfer");
                File[] files = directory.listFiles((dir, name) -> name.endsWith(".ovpn"));
                check(files != null && files.length > 0, "computer configuration transfer available");
                String selected = "";
                for (File file : files) {
                    try {
                        String id = NativeBridge.importProfile(file.getAbsolutePath(), "");
                        check("OK".equals(NativeBridge.validateProfile(id)),
                              "imported configuration accepted by engine");
                        if (file.getName().equals("knownsec.ovpn") || selected.isEmpty())
                            selected = id;
                    } finally {
                        file.delete();
                    }
                }
                directory.delete();
                getTargetContext()
                    .getSharedPreferences("ui", Context.MODE_PRIVATE)
                    .edit()
                    .putString("profile", selected)
                    .commit();
            }
            ActivityMonitor monitor = addMonitor(MainActivity.class.getName(), null, false);
            try (ParcelFileDescriptor command =
                     getUiAutomation().executeShellCommand("am start -W -n com.ownvpn.android/.MainActivity");
                 InputStream output = new ParcelFileDescriptor.AutoCloseInputStream(command)) {
                output.readAllBytes();
            }
            Activity launched = waitForMonitorWithTimeout(monitor, 10000);
            removeMonitor(monitor);
            check(launched instanceof MainActivity, "activity starts within timeout");
            MainActivity activity = (MainActivity)launched;
            runOnMainSync(() -> {
                check(activity.findViewById(MainActivity.CONNECT_ID) != null, "connect UI available");
                check(activity.findViewById(MainActivity.USER_ID) != null, "username UI available");
                check(activity.findViewById(MainActivity.PASSWORD_ID) != null, "password UI available");
                check(activity.findViewById(MainActivity.OTP_ID) != null, "OTP UI available");
            });
            result.putString("stream",
                             "OWNVPN_TESTS_PASSED: " + checks + " checks; no VPN authentication submitted\n");
            finish(Activity.RESULT_OK, result);
        } catch (Throwable error) {
            result.putString("stream", "OWNVPN_TESTS_FAILED: " + error.getClass().getSimpleName() + ": " +
                                           error.getMessage() + "\n");
            finish(Activity.RESULT_CANCELED, result);
        }
    }
}
