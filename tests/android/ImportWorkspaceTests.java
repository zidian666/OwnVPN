package com.ownvpn.android;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

public final class ImportWorkspaceTests {
    private static int checks;
    private static void check(boolean ok, String name) {
        if (!ok)
            throw new AssertionError(name);
        checks++;
    }
    private static InputStream text(String value) {
        return new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
    }
    private static byte[] zip(String[][] entries) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream output = new ZipOutputStream(bytes)) {
            for (String[] entry : entries) {
                output.putNextEntry(new ZipEntry(entry[0]));
                output.write(entry[1].getBytes(StandardCharsets.UTF_8));
                output.closeEntry();
            }
        }
        return bytes.toByteArray();
    }
    private static void rejected(File cache, String[][] entries) throws Exception {
        Path root;
        try (ImportWorkspace workspace = new ImportWorkspace(cache)) {
            root = Paths.get(workspace.referenceRoot()).getParent();
            boolean failed = false;
            try {
                workspace.archive(new ByteArrayInputStream(zip(entries)));
            } catch (IOException error) {
                failed = true;
            }
            check(failed, "invalid archive rejected");
        }
        check(!Files.exists(root), "failed archive workspace cleaned");
    }
    public static void main(String[] args) throws Exception {
        Path cache = Files.createTempDirectory("ownvpn-import-tests-");
        try {
            Path root;
            try (ImportWorkspace workspace = new ImportWorkspace(cache.toFile())) {
                root = Paths.get(workspace.referenceRoot()).getParent();
                workspace.archive(new ByteArrayInputStream(
                    zip(new String[][] {{"company/ca.crt", "public CA fixture"},
                                        {"company/key", "public TLS auth fixture"},
                                        {"office.ovpn", "tls-auth company/key 1\nca company/ca.crt\ncert " +
                                                        "company/users.pem\nkey company/users.pem\n"},
                                        {"second.ovpn", "public second configuration"}})));
                check(workspace.configurations().length == 2, "both archive configurations discovered");
                workspace.choose(0);
                check(Paths.get(workspace.configurationPath()).getFileName().toString().equals("office.ovpn"),
                      "selected archive configuration retained");
                check(Files.readString(Paths.get(workspace.referenceRoot()).resolve("company/key"))
                          .equals("public TLS auth fixture"),
                      "nested TLS key retained with original bytes");
                check(Files.readString(Paths.get(workspace.referenceRoot()).resolve("company/ca.crt"))
                          .equals("public CA fixture"),
                      "nested CA retained with original bytes");
                workspace.pem(text("public client PEM fixture"));
                check(Files.readString(Paths.get(workspace.pemPath())).equals("public client PEM fixture"),
                      "selected PEM separate from archive dependencies");
            }
            check(!Files.exists(root), "successful archive workspace cleaned");
            try (ImportWorkspace workspace = new ImportWorkspace(cache.toFile())) {
                workspace.document("办公.ovpn", text("public configuration"));
                workspace.pem(text("public client PEM fixture"));
                workspace.dependency("tls-auth", text("public selected TLS key"));
                workspace.dependency("ca", text("public selected CA"));
                check(workspace.dependencyOptions().length == 2,
                      "multiple document dependencies retained across selections");
                check(workspace.dependencyOptions()[0].equals("tls-auth") &&
                          Files.readString(Paths.get(workspace.dependencyPaths()[0]))
                              .equals("public selected TLS key"),
                      "directive maps to the explicitly selected file");
                check(workspace.configurationPath().endsWith("办公.ovpn"),
                      "document import supports Unicode names");
                boolean failed = false;
                try {
                    workspace.dependency("up", text("not executable"));
                } catch (IOException error) {
                    failed = true;
                }
                check(failed, "executable directive cannot be supplied as a dependency");
            }
            rejected(cache.toFile(), new String[][] {{"../outside.ovpn", "public fixture"}});
            rejected(cache.toFile(), new String[][] {{"/outside.ovpn", "public fixture"}});
            rejected(cache.toFile(), new String[][] {{"C:\\outside.ovpn", "public fixture"}});
            rejected(cache.toFile(),
                     new String[][] {{"office.ovpn", "one"}, {"folder/../office.ovpn", "two"}});
            rejected(cache.toFile(), new String[][] {{"ca.crt", "no configuration"}});
            try (ImportWorkspace workspace = new ImportWorkspace(cache.toFile())) {
                InputStream oversized = new InputStream() {
                    long left = 16L * 1024 * 1024 + 1;
                    public int read() {
                        return left-- > 0 ? 0 : -1;
                    }
                    public int read(byte[] bytes, int start, int size) {
                        if (left <= 0)
                            return -1;
                        int count = (int)Math.min(left, size);
                        Arrays.fill(bytes, start, start + count, (byte)0);
                        left -= count;
                        return count;
                    }
                };
                boolean failed = false;
                try {
                    workspace.pem(oversized);
                } catch (IOException error) {
                    failed = true;
                }
                check(failed, "oversized selected file rejected");
            }
            try (java.util.stream.Stream<Path> entries = Files.list(cache)) {
                check(entries.count() == 0, "all temporary workspaces removed");
            }
            System.out.println("PASS: " + checks + " Android import workspace checks");
        } finally {
            Files.deleteIfExists(cache);
        }
    }
}
