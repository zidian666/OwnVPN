package com.ownvpn.android;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

// One import owns one private workspace. ZIP paths stay relative to source/;
// explicitly selected dependencies are mapped by directive, never by guessing
// that a PEM can substitute for a TLS authentication key or CA certificate.
final class ImportWorkspace implements AutoCloseable {
    private static final long FILE_LIMIT = 16L * 1024 * 1024, ARCHIVE_LIMIT = 32L * 1024 * 1024;
    private final Path root, source, selected;
    private final List<Path> configurations = new ArrayList<>();
    private final LinkedHashMap<String, Path> dependencies = new LinkedHashMap<>();
    private Path configuration, pem;
    private boolean closed;
    ImportWorkspace(File cache) throws IOException {
        root = Files.createTempDirectory(cache.toPath(), "ownvpn-import-").toRealPath();
        source = Files.createDirectory(root.resolve("source"));
        selected = Files.createDirectory(root.resolve("selected"));
    }
    private static void copy(InputStream input, Path destination, long limit) throws IOException {
        if (input == null)
            throw new IOException("无法读取文件");
        try (OutputStream output = Files.newOutputStream(destination, StandardOpenOption.CREATE_NEW)) {
            byte[] buffer = new byte[8192];
            long total = 0;
            int count;
            while ((count = input.read(buffer)) != -1) {
                total += count;
                if (total > limit)
                    throw new IOException("导入文件过大");
                output.write(buffer, 0, count);
            }
        } catch (IOException error) {
            Files.deleteIfExists(destination);
            throw error;
        }
    }
    void document(String name, InputStream input) throws IOException {
        if (!name.equals(new File(name).getName()) || name.contains("\\") ||
            !name.toLowerCase(Locale.ROOT).endsWith(".ovpn"))
            throw new IOException("配置文件名无效");
        Path file = source.resolve(name);
        copy(input, file, FILE_LIMIT);
        configurations.add(file);
        configuration = file;
    }
    void archive(InputStream input) throws IOException {
        if (input == null)
            throw new IOException("无法读取压缩包");
        long total = 0;
        int entries = 0;
        try (ZipInputStream zip = new ZipInputStream(input)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (++entries > 128)
                    throw new IOException("压缩包文件数量过多");
                String name = entry.getName().replace('\\', '/');
                if (name.startsWith("/") || name.matches("^[A-Za-z]:.*"))
                    throw new IOException("压缩包路径无效");
                Path path = source.resolve(name).normalize();
                if (!path.startsWith(source) || path.equals(source))
                    throw new IOException("压缩包路径超出导入目录");
                if (Files.exists(path)) {
                    if (entry.isDirectory() && Files.isDirectory(path))
                        continue;
                    throw new IOException("压缩包包含重复文件");
                }
                if (entry.isDirectory())
                    Files.createDirectories(path);
                else {
                    Files.createDirectories(path.getParent());
                    long remaining = ARCHIVE_LIMIT - total;
                    copy(zip, path, Math.min(FILE_LIMIT, remaining));
                    total += Files.size(path);
                    if (name.toLowerCase(Locale.ROOT).endsWith(".ovpn"))
                        configurations.add(path);
                }
                zip.closeEntry();
            }
        }
        if (configurations.isEmpty())
            throw new IOException("压缩包中没有 .ovpn 配置");
        configurations.sort(Comparator.comparing(Path::toString));
        if (configurations.size() == 1)
            configuration = configurations.get(0);
    }
    String[] configurations() {
        String[] names = new String[configurations.size()];
        for (int i = 0; i < names.length; i++)
            names[i] = source.relativize(configurations.get(i)).toString();
        return names;
    }
    void choose(int index) {
        configuration = configurations.get(index);
    }
    void pem(InputStream input) throws IOException {
        pem = selected.resolve("users.pem");
        Files.deleteIfExists(pem);
        copy(input, pem, FILE_LIMIT);
    }
    void dependency(String option, InputStream input) throws IOException {
        if (!Arrays
                 .asList("ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "extra-certs",
                         "pkcs12", "crl-verify")
                 .contains(option))
            throw new IOException("不支持该依赖类型");
        Path file = selected.resolve(option + ".bin");
        Files.deleteIfExists(file);
        copy(input, file, FILE_LIMIT);
        dependencies.put(option, file);
    }
    String configurationPath() {
        if (configuration == null)
            throw new IllegalStateException("请先选择配置");
        return configuration.toString();
    }
    String pemPath() {
        return pem == null ? "" : pem.toString();
    }
    String referenceRoot() {
        return source.toString();
    }
    String[] dependencyOptions() {
        return dependencies.keySet().toArray(new String[0]);
    }
    String[] dependencyPaths() {
        return dependencies.values().stream().map(Path::toString).toArray(String[] ::new);
    }
    @Override
    public void close() throws IOException {
        if (closed)
            return;
        closed = true;
        if (Files.isSymbolicLink(root))
            throw new IOException("导入目录已变化");
        Path[] items;
        try (java.util.stream.Stream<Path> paths = Files.walk(root)) {
            items = paths.sorted(Comparator.reverseOrder()).toArray(Path[] ::new);
        }
        for (Path path : items)
            Files.deleteIfExists(path);
    }
}
