package com.ownvpn.android;
import android.content.Context;
import android.security.keystore.*;
import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.json.*;

// Instrumentation-only helper. The production APK does not expose a credential import endpoint.
final class CredentialTransfer {
    private static final String ALIAS = "OwnVPN.DebugTransfer.v1";
    private static KeyStore store() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        return store;
    }
    static void prepare(Context context) throws Exception {
        KeyStore store = store();
        if (store.containsAlias(ALIAS))
            store.deleteEntry(ALIAS);
        KeyPairGenerator generator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        generator.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_DECRYPT)
                                 .setKeySize(3072)
                                 .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                                 .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                                 .build());
        KeyPair pair = generator.generateKeyPair();
        try (OutputStream output = context.openFileOutput("import-public.der", Context.MODE_PRIVATE)) {
            output.write(pair.getPublic().getEncoded());
        }
    }
    static int apply(Context context) throws Exception {
        File input = new File(context.getFilesDir(), "credential-transfer.bin");
        byte[] aes = null, plain = null;
        try {
            byte[] encoded = java.nio.file.Files.readAllBytes(input.toPath());
            ByteBuffer buffer = ByteBuffer.wrap(encoded);
            byte[] magic = new byte[8];
            buffer.get(magic);
            if (!"OWNVPNI1".equals(new String(magic, StandardCharsets.US_ASCII)))
                throw new SecurityException("Transfer format mismatch");
            int length = buffer.getInt();
            if (length != 384 || buffer.remaining() < length + 12 + 16)
                throw new SecurityException("Transfer size mismatch");
            byte[] wrapped = new byte[length], iv = new byte[12];
            buffer.get(wrapped);
            buffer.get(iv);
            byte[] ciphertext = new byte[buffer.remaining()];
            buffer.get(ciphertext);
            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
            rsa.init(
                Cipher.DECRYPT_MODE, store().getKey(ALIAS, null),
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
            aes = rsa.doFinal(wrapped);
            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aes, "AES"), new GCMParameterSpec(128, iv));
            gcm.updateAAD("ownvpn-import-v1".getBytes(StandardCharsets.US_ASCII));
            plain = gcm.doFinal(ciphertext);
            JSONArray entries = new JSONArray(new String(plain, StandardCharsets.UTF_8));
            String[] profiles = NativeBridge.profiles();
            int count = 0;
            for (int index = 0; index < entries.length(); index++) {
                JSONObject entry = entries.getJSONObject(index);
                String id = "";
                for (int p = 0; p < profiles.length; p += 2)
                    if (profiles[p + 1].equals(entry.getString("name")))
                        id = profiles[p];
                if (id.isEmpty())
                    throw new IllegalStateException("Transferred profile is missing");
                NativeBridge.writeSecret(id, "ui.username", entry.getString("username"));
                NativeBridge.writeSecret(id, "ui.password", entry.getString("password"));
                context.getSharedPreferences("ui", Context.MODE_PRIVATE)
                    .edit()
                    .putBoolean("remember." + id, !entry.getString("password").isEmpty())
                    .commit();
                String seed = entry.optString("seed", "");
                if (!seed.isEmpty()) {
                    String uri = "otpauth://totp/OwnVPN?secret=" + seed +
                                 "&algorithm=" + entry.getString("algorithm") +
                                 "&digits=" + entry.getInt("digits") + "&period=" + entry.getInt("period");
                    NativeBridge.bindTotp(id, entry.getString("username"), uri);
                    if (id.equals(context.getSharedPreferences("ui", Context.MODE_PRIVATE)
                                      .getString("profile", "")))
                        context.getSharedPreferences("ui", Context.MODE_PRIVATE)
                            .edit()
                            .putBoolean("automatic", entry.optBoolean("automatic", true))
                            .commit();
                }
                count++;
            }
            return count;
        } finally {
            if (aes != null)
                java.util.Arrays.fill(aes, (byte)0);
            if (plain != null)
                java.util.Arrays.fill(plain, (byte)0);
            input.delete();
            new File(context.getFilesDir(), "import-public.der").delete();
            KeyStore store = store();
            if (store.containsAlias(ALIAS))
                store.deleteEntry(ALIAS);
        }
    }
}
