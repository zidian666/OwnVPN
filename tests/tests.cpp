#include "credential_store.h"
#include "dns_fallback.h"
#include "engine.h"
#include "ipc.h"
#include "management_commands.h"
#include "management_startup.h"
#include "support/core_cases.h"
#include "ui_text.h"
#include <iostream>
#include <sstream>
#include <thread>

using namespace ownvpn;
namespace {
int checks = 0;
void Check(bool value, const char* text) {
    ++checks;
    if (!value) {
        throw std::runtime_error(text);
    }
}
template <class F> void Throws(F action, const char* text) {
    bool failed = false;
    try {
        action();
    } catch (const std::exception&) {
        failed = true;
    }
    Check(failed, text);
}
void ProtocolTests() {
    ownvpn::testing::ProtocolCases(Check, [](auto action, const char* message) { Throws(action, message); });
}
void ProfileTests(const fs::path& root) {
    auto source = root / L"source files";
    fs::create_directories(source);
    WriteFile(source / L"ca.crt", "dummy CA");
    WriteFile(source / L"users.pem", "dummy PEM");
    WriteFile(source / L"tls.key", "dummy TLS key");
    auto input = source / L"office.ovpn";
    WriteFile(input, "client\ndev tun\nremote vpn.example.invalid 1194\nca ca.crt\ncert users.pem\nkey "
                     "users.pem\ntls-auth tls.key 1\nns-cert-type server\nauth-user-pass "
                     "secret.txt\nredirect-gateway def1\nroute 10.20.0.0 255.255.0.0\n");
    auto before = ReadFile(input);
    ProfileRepository repo(root / L"managed");
    auto profile = repo.Import(input);
    Check(ReadFile(input) == before, "original config untouched");
    auto config = ReadFile(profile.config);
    Check(config.starts_with(SplitTunnelPolicy()), "split tunnel policy first");
    Check(config.find("remote-cert-tls server") != config.npos && config.find("ns-cert-type") == config.npos,
          "legacy server verification migrated");
    Check(config.find("secret.txt") == config.npos, "credential file reference removed");
    Check(config.find("route \"10.20.0.0\" \"255.255.0.0\"") != config.npos, "company route retained");
    Check(config.find("redirect-gateway def1") == config.npos, "local default gateway removed");
    Check(repo.List().size() == 1, "profile inventory");
    repo.Validate(profile);
    ++checks;
    WriteFile(input, "client\ndev tun\nremote x\nup arbitrary-script.exe\n");
    Throws([&] { repo.Import(input); }, "profile cannot execute arbitrary scripts");
    WriteFile(input, "client\ndev tun\nremote x\nconfig nested.ovpn\n");
    Throws([&] { repo.Import(input); }, "nested config forbidden");
    WriteFile(input, "client\ndev tun\nremote x\n<connection>\nremote y\n</connection>\n");
    Throws([&] { repo.Import(input); }, "unsupported blocks rejected");
    WriteFile(input, "client\ndev tun\nremote x\ncert missing/users.pem\nkey missing/users.pem\n");
    auto fallback = repo.Import(input, source / L"users.pem");
    repo.Validate(fallback);
    ++checks;
    auto changed = config + "\nmanagement 0.0.0.0 1234\n";
    WriteFile(profile.config, changed);
    Throws([&] { repo.Validate(profile); }, "managed configs revalidated before elevation");
    Check(IsDefaultRoute({"route", "0.0.0.0", "0.0.0.0"}), "IPv4 default route");
    Check(IsDefaultRoute({"route-ipv6", "::/0"}), "IPv6 default route");
    Check(!IsDefaultRoute({"route", "10.0.0.0", "255.0.0.0"}), "private route accepted");
    auto tokens = ConfigTokens("ca \"C:/dir with spaces/ca.crt\" # comment");
    Check(tokens.size() == 2 && tokens[1] == "C:/dir with spaces/ca.crt", "quoted config paths");
    Throws([] { ConfigTokens("ca \"unterminated"); }, "malformed quoting rejected");
}
void CredentialTests() {
    auto id = L"test-" + Wide(RandomHex());
    Credentials c{L"synthetic-user", L"synthetic-password", L"001234", true};
    try {
        SaveCredentials(id, c);
        auto loaded = LoadCredentials(id);
        Check(loaded.username == c.username && loaded.password == c.password && loaded.otp.empty(),
              "remember username/password but never persist OTP");
        loaded.ClearSecrets();
        c.rememberPassword = false;
        SaveCredentials(id, c);
        loaded = LoadCredentials(id);
        Check(loaded.password.empty() && loaded.otp.empty(), "unremember password and keep OTP transient");
        loaded.ClearSecrets();
        StoreProtectedValue(id, L"otp", L"legacy-saved-OTP");
        loaded = LoadCredentials(id);
        Check(loaded.otp.empty() && ReadProtectedValue(id, L"otp").empty(),
              "loading migrates and removes old saved OTP");
        loaded.ClearSecrets();
    } catch (...) {
        DeleteCredentials(id);
        throw;
    }
    DeleteCredentials(id);
    c.ClearSecrets();
}
void DnsFallbackTests(const fs::path& root) {
    ownvpn::testing::DnsCases(root, Check, [](auto action, const char* message) { Throws(action, message); });
}
void IpcTests() {
    auto name = L"\\\\.\\pipe\\OwnVPN-test-" + Wide(RandomHex());
    Handle server(
        CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX,
                         PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
                         65536, 65536, 0, nullptr));
    Check(server.valid(), "create test pipe");
    bool received = false;
    std::thread client([&] {
        Handle pipe(
            CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
        uint32_t type = 0;
        std::vector<std::string> fields;
        received = ReceivePacket(pipe.value, type, fields) && type == 100 &&
                   fields == std::vector<std::string>{"abc", "\xe4\xb8\xad", "012345"};
        SendPacket(pipe.value, 9, {});
    });
    BOOL ok = ConnectNamedPipe(server.value, nullptr);
    Check(ok || GetLastError() == ERROR_PIPE_CONNECTED, "connect test pipe");
    SendPacket(server.value, 100, {"abc", "\xe4\xb8\xad", "012345"});
    uint32_t type = 0;
    std::vector<std::string> fields;
    ReceivePacket(server.value, type, fields);
    client.join();
    Check(received, "length-prefixed IPC roundtrip");
}
} // namespace
int main(int argc, char** argv) {
    auto root = fs::temp_directory_path() / PathFromUtf8("ownvpn-tests-" + RandomHex());
    try {
        ProtocolTests();
        Check(FormatTrafficBytes(0) == L"0 KB", "zero traffic format");
        Check(FormatTrafficBytes(512) == L"0.5 KB", "small traffic preserves fraction");
        Check(FormatTrafficBytes(1024) == L"1.0 KB", "kilobyte traffic format");
        Check(FormatTrafficBytes(1048576) == L"1.0 MB", "megabyte threshold changes unit");
        Check(FormatTrafficBytes(1572864) == L"1.5 MB", "megabyte fraction format");
        Check(CleanUiText(L"OwnVPN · 正在连接…") == L"OwnVPN   正在连接",
              "decorative separator and progress dots removed");
        Check(CleanUiText(L"10.255.252.73  1.5 MB") == L"10.255.252.73  1.5 MB",
              "IP and numeric decimal points preserved");
        ProfileTests(root);
        DnsFallbackTests(root / L"dns");
        CredentialTests();
        IpcTests();
        if (argc > 1 && (std::string(argv[1]) == "--probe" || std::string(argv[1]) == "--probe-startup" ||
                         std::string(argv[1]) == "--probe-startup-repeat")) {
            bool repeat = std::string(argv[1]) == "--probe-startup-repeat";
            for (int i = 0; i < (repeat ? 8 : 1); ++i) {
                Check(ProbeManagement(
                          [&](Event e) {
                              if (!repeat) {
                                  std::cout << Utf8(e.text) << '\n';
                              }
                          },
                          std::string(argv[1]) != "--probe"),
                      "real OpenVPN management startup probe");
                if (repeat) {
                    std::cout << "loopback-startup-cycle=" << i + 1 << ": passed\n";
                }
            }
        }
        fs::remove_all(root);
        std::cout << "PASS: " << checks << " checks\n";
        return 0;
    } catch (const std::exception& e) {
        std::error_code ec;
        fs::remove_all(root, ec);
        std::cerr << "FAIL: " << e.what() << '\n';
        return 1;
    }
}
