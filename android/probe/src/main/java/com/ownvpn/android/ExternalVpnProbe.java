package com.ownvpn.android;
import android.app.*;
import android.content.*;
import android.net.*;
import android.os.*;
import android.view.accessibility.AccessibilityNodeInfo;
import java.io.*;
import java.net.*;

// Runs in a separate probe APK so finishing the probe leaves the VPN service running.
public final class ExternalVpnProbe extends Instrumentation {
    private Bundle arguments;
    private String targetHost;
    private int targetPort;
    private String targetUrl;
    @Override
    public void onCreate(Bundle args) {
        arguments = args;
        super.onCreate(args);
        start();
    }
    private void progress(String text) {
        Bundle status = new Bundle();
        status.putString("stream", text + "\n");
        sendStatus(1, status);
    }
    private boolean reachable() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(targetHost, targetPort), 2500);
            return true;
        } catch (IOException error) {
            return false;
        }
    }
    private boolean hasText(UiAutomation ui, String value) {
        AccessibilityNodeInfo root = ui.getRootInActiveWindow();
        if (root == null || !"com.ownvpn.android".contentEquals(root.getPackageName()))
            return false;
        for (AccessibilityNodeInfo node : root.findAccessibilityNodeInfosByText(value))
            if (node.getText() != null && value.contentEquals(node.getText()))
                return true;
        return false;
    }
    @Override
    public void onStart() {
        Bundle result = new Bundle();
        try {
            targetHost = arguments.getString("targetHost");
            targetPort = Integer.parseInt(arguments.getString("targetPort", "0"));
            targetUrl = arguments.getString("targetUrl");
            if (targetUrl != null) {
                URL url = new URL(targetUrl);
                if (!"https".equals(url.getProtocol()))
                    throw new IllegalArgumentException("HTTPS required");
                targetHost = url.getHost();
                targetPort = url.getPort() < 0 ? 443 : url.getPort();
            }
            boolean disconnectOnly = "true".equals(arguments.getString("disconnectOnly"));
            if (!disconnectOnly &&
                (targetHost == null || targetHost.isEmpty() || targetPort < 1 || targetPort > 65535))
                throw new IllegalArgumentException("Pass the authorized internal targetHost and targetPort");
            UiAutomation ui = getUiAutomation(UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES);
            android.accessibilityservice.AccessibilityServiceInfo info = ui.getServiceInfo();
            info.flags |= android.accessibilityservice.AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS;
            ui.setServiceInfo(info);
            if (!disconnectOnly && targetUrl == null)
                progress("BASELINE_TARGET_REACHABLE: " + reachable());
            try (ParcelFileDescriptor command =
                     ui.executeShellCommand("am start -W -n com.ownvpn.android/.MainActivity");
                 InputStream input = new ParcelFileDescriptor.AutoCloseInputStream(command)) {
                byte[] buffer = new byte[1024];
                while (input.read(buffer) != -1) {
                }
            }
            if (disconnectOnly || "true".equals(arguments.getString("resetConnection"))) {
                AccessibilityNodeInfo root = ui.getRootInActiveWindow();
                if (root != null && "com.ownvpn.android".contentEquals(root.getPackageName()))
                    for (AccessibilityNodeInfo node : root.findAccessibilityNodeInfosByText("断开连接"))
                        if ("断开连接".contentEquals(node.getText()) && node.isEnabled()) {
                            node.performAction(AccessibilityNodeInfo.ACTION_CLICK);
                            break;
                        }
                Thread.sleep(1000);
            }
            if (disconnectOnly) {
                long deadline = SystemClock.elapsedRealtime() + 15000;
                while (SystemClock.elapsedRealtime() < deadline && !hasText(ui, "连接 VPN"))
                    Thread.sleep(200);
                if (!hasText(ui, "连接 VPN"))
                    throw new IllegalStateException("Phone disconnect did not finish");
                result.putString("stream", "OWNVPN_DISCONNECTED\n");
                finish(Activity.RESULT_OK, result);
                return;
            }
            boolean clicked = false;
            for (int retry = 0; retry < 30 && !clicked; retry++) {
                AccessibilityNodeInfo root = ui.getRootInActiveWindow();
                if (root != null && "com.ownvpn.android".contentEquals(root.getPackageName())) {
                    boolean ready = false;
                    for (AccessibilityNodeInfo code :
                         root.findAccessibilityNodeInfosByViewId("com.ownvpn.android:id/otp"))
                        if (code.getText() != null && code.getText().length() == 6)
                            ready = true;
                    if (!ready) {
                        Thread.sleep(500);
                        continue;
                    }
                    for (AccessibilityNodeInfo node : root.findAccessibilityNodeInfosByText("连接 VPN"))
                        if ("连接 VPN".contentEquals(node.getText()) && node.isEnabled())
                            clicked = node.performAction(AccessibilityNodeInfo.ACTION_CLICK);
                }
                if (!clicked)
                    Thread.sleep(500);
            }
            if (!clicked)
                throw new IllegalStateException("Connect button not available");
            progress("CONNECT_REQUESTED: confirm Android VPN and notification prompts on the phone");
            long end = SystemClock.elapsedRealtime() + 180000;
            while (SystemClock.elapsedRealtime() < end && !hasText(ui, "已连接"))
                Thread.sleep(500);
            if (!hasText(ui, "已连接"))
                throw new IllegalStateException("VPN did not report connected within 180 seconds");
            progress("OWNVPN_VPN_CONNECTED");
            InetAddress[] resolved = InetAddress.getAllByName(targetHost);
            progress("DNS_OK: " + resolved.length + " addresses");
            ConnectivityManager connectivity = getTargetContext().getSystemService(ConnectivityManager.class);
            boolean vpnFound = false, defaultRoute = false, targetRoute = false;
            for (Network network : connectivity.getAllNetworks()) {
                NetworkCapabilities capabilities = connectivity.getNetworkCapabilities(network);
                if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    vpnFound = true;
                    LinkProperties properties = connectivity.getLinkProperties(network);
                    if (properties != null)
                        for (RouteInfo route : properties.getRoutes()) {
                            if (route.isDefaultRoute() && route.getType() == RouteInfo.RTN_UNICAST)
                                defaultRoute = true;
                            for (InetAddress address : resolved)
                                if (route.getType() == RouteInfo.RTN_UNICAST && route.matches(address))
                                    targetRoute = true;
                        }
                }
            }
            progress("ANDROID_VPN_NETWORK: " + vpnFound + "; DEFAULT_ROUTE_PRESENT: " + defaultRoute +
                     "; TARGET_ROUTE_IN_VPN: " + targetRoute);
            boolean target = reachable();
            progress("TARGET_TCP_REACHABLE: " + target);
            if (!vpnFound || defaultRoute || !target || !targetRoute)
                throw new IllegalStateException("VPN route or internal target verification failed");
            if (targetUrl != null) {
                javax.net.ssl.HttpsURLConnection connection =
                    (javax.net.ssl.HttpsURLConnection) new URL(targetUrl).openConnection();
                try {
                    connection.setConnectTimeout(6000);
                    connection.setReadTimeout(6000);
                    connection.setInstanceFollowRedirects(false);
                    connection.setRequestMethod("HEAD");
                    int code = connection.getResponseCode();
                    String location = connection.getHeaderField("Location");
                    boolean login =
                        location != null && (location.contains("sign_in") || location.contains("login") ||
                                             location.contains("oauth"));
                    progress("HTTPS_CERTIFICATE_VERIFIED: true; HTTP_STATUS: " + code +
                             "; LOGIN_REDIRECT: " + login);
                } finally {
                    connection.disconnect();
                }
            }
            Thread.sleep(15000);
            if (!hasText(ui, "已连接") || !reachable())
                throw new IllegalStateException("VPN did not remain stable during observation");
            result.putString("stream", "OWNVPN_VPN_PROBE_PASSED; app connection left running\n");
            finish(Activity.RESULT_OK, result);
        } catch (Throwable error) {
            result.putString("stream", "OWNVPN_VPN_PROBE_FAILED: " + error.getClass().getSimpleName() + ": " +
                                           error.getMessage() + "\n");
            finish(Activity.RESULT_CANCELED, result);
        }
    }
}
