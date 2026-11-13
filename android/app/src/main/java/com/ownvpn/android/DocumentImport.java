package com.ownvpn.android;
import android.content.Context;
import android.graphics.*;
import android.net.Uri;
import android.provider.OpenableColumns;
import java.io.*;
final class DocumentImport {
    static String displayName(Context context, Uri uri) {
        try (android.database.Cursor cursor = context.getContentResolver().query(
                 uri, new String[] {OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (cursor != null && cursor.moveToFirst())
                return cursor.getString(0);
        }
        return "profile.ovpn";
    }
    static File copy(Context context, Uri uri, String filename) throws IOException {
        File dir = new File(context.getCacheDir(), "import");
        if (!dir.exists() && !dir.mkdir())
            throw new IOException("无法创建导入目录");
        String name = new File(filename).getName();
        if (name.isEmpty() || name.equals(".") || name.equals(".."))
            throw new IOException("文件名无效");
        File target = new File(dir, name);
        try (InputStream input = context.getContentResolver().openInputStream(uri);
             OutputStream output = new FileOutputStream(target)) {
            if (input == null)
                throw new IOException("无法读取文件");
            byte[] buffer = new byte[8192];
            int read;
            long total = 0;
            while ((read = input.read(buffer)) != -1) {
                total += read;
                if (total > 16 * 1024 * 1024)
                    throw new IOException("配置文件过大");
                output.write(buffer, 0, read);
            }
        }
        return target;
    }
    static String qr(Context context, Uri uri) throws IOException {
        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inJustDecodeBounds = true;
        try (InputStream stream = context.getContentResolver().openInputStream(uri)) {
            BitmapFactory.decodeStream(stream, null, options);
        }
        if (options.outWidth <= 0 || options.outHeight <= 0)
            throw new IOException("无法读取二维码图片");
        options.inSampleSize = 1;
        while (options.outWidth / options.inSampleSize > 2048 ||
               options.outHeight / options.inSampleSize > 2048)
            options.inSampleSize *= 2;
        options.inJustDecodeBounds = false;
        options.inPreferredConfig = Bitmap.Config.ARGB_8888;
        Bitmap image;
        try (InputStream stream = context.getContentResolver().openInputStream(uri)) {
            image = BitmapFactory.decodeStream(stream, null, options);
        }
        if (image == null)
            throw new IOException("无法读取二维码图片");
        int[] pixels = new int[image.getWidth() * image.getHeight()];
        try {
            image.getPixels(pixels, 0, image.getWidth(), 0, 0, image.getWidth(), image.getHeight());
            return NativeBridge.decodeQr(pixels, image.getWidth(), image.getHeight());
        } finally {
            java.util.Arrays.fill(pixels, 0);
            image.recycle();
        }
    }
}
