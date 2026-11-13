package com.ownvpn.android;
import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
final class SecretStore {
    private final SharedPreferences preferences;
    private static final String ALIAS = "OwnVPN.Secrets.v1";
    SecretStore(Context context) {
        preferences = context.getSharedPreferences("protected-secrets", Context.MODE_PRIVATE);
    }
    private SecretKey key() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (!store.containsAlias(ALIAS)) {
            KeyGenerator generator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            generator.init(new KeyGenParameterSpec
                               .Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                               .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                               .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                               .setKeySize(256)
                               .build());
            generator.generateKey();
        }
        return (SecretKey)store.getKey(ALIAS, null);
    }
    private String name(String group, String field) {
        return group.length() + ":" + group + field;
    }
    synchronized String read(String group, String field) {
        String name = name(group, field), value = preferences.getString(name, "");
        if (value.isEmpty())
            return "";
        byte[] plain = null;
        try {
            String[] parts = value.split(":", -1);
            if (parts.length != 2)
                throw new IllegalStateException("Invalid secret format");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key(),
                        new GCMParameterSpec(128, Base64.decode(parts[0], Base64.NO_WRAP)));
            cipher.updateAAD(name.getBytes(StandardCharsets.UTF_8));
            plain = cipher.doFinal(Base64.decode(parts[1], Base64.NO_WRAP));
            return new String(plain, StandardCharsets.UTF_8);
        } catch (Exception error) {
            throw new IllegalStateException("无法读取受保护数据，请重新填写或绑定", error);
        } finally {
            if (plain != null)
                java.util.Arrays.fill(plain, (byte)0);
        }
    }
    synchronized void write(String group, String field, String value) {
        String name = name(group, field);
        if (value.isEmpty()) {
            if (!preferences.edit().remove(name).commit())
                throw new IllegalStateException("无法删除受保护数据");
            return;
        }
        byte[] plain = value.getBytes(StandardCharsets.UTF_8);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key());
            cipher.updateAAD(name.getBytes(StandardCharsets.UTF_8));
            String encoded = Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP) + ":" +
                             Base64.encodeToString(cipher.doFinal(plain), Base64.NO_WRAP);
            if (!preferences.edit().putString(name, encoded).commit())
                throw new IllegalStateException("无法保存受保护数据");
        } catch (Exception error) {
            throw new IllegalStateException("无法保存受保护数据", error);
        } finally {
            java.util.Arrays.fill(plain, (byte)0);
        }
    }
}
