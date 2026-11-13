package com.ownvpn.android;
import android.app.Application;
public final class OwnVpnApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        NativeBridge.initialize(this);
    }
}
