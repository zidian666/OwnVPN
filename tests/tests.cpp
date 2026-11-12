#include "credential_store.h"
#include "dns_fallback.h"
#include "engine.h"
#include "ipc.h"
#include "management_commands.h"
#include "management_startup.h"
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
    const std::vector<std::string> expectedStartup{"state on", "bytecount 1", "hold off", "hold release"};
    ManagementCommands queue;
    queue.Enqueue(expectedStartup);
    const std::vector<std::string> acknowledgments{
        "SUCCESS: real-time state notification set to ON", "SUCCESS: bytecount interval changed",
        "SUCCESS: hold flag set to OFF", "SUCCESS: hold release succeeded"};
    for (size_t i = 0; i < expectedStartup.size(); ++i) {
        Check(queue.TakeNext() == expectedStartup[i], "send next startup command");
        Check(!queue.TakeNext(), "one in-flight management command only");
        Check(!queue.OnLine(">HOLD:Waiting for hold release:0"), "notification cannot acknowledge command");
        Check(queue.OnLine(acknowledgments[i]), "matching command response advances queue");
    }
    Check(!queue.waiting() && !queue.TakeNext(), "completed commands are never replayed");
    auto now = std::chrono::system_clock::now();
    queue.Enqueue({"username \"Auth\" \"synthetic-user\"", "password \"Auth\" \"synthetic-password000000\""},
                  now + std::chrono::seconds(2));
    Check(queue.TakeNext(now).has_value(), "username sent first");
    Check(!queue.TakeNext(now), "password waits for username acknowledgment");
    queue.OnLine("SUCCESS: 'Auth' username entered, but not yet verified");
    Throws([&] { queue.TakeNext(now + std::chrono::seconds(2)); },
           "expired OTP is never sent after waiting for command response");
    ManagementStartup noHold;
    Check(noHold.OnLine("SUCCESS: password is correct") == expectedStartup,
          "authentication releases startup even with no HOLD notification");
    Check(noHold.OnLine("SUCCESS: password is correct").empty(), "startup commands issued only once");
    noHold.OnLine("SUCCESS: hold release succeeded");
    Check(noHold.releaseConfirmed() && !noHold.progressed(),
          "release acknowledgment distinct from tunnel progress");
    noHold.OnLine(">PASSWORD:Need 'Auth' username/password");
    Check(noHold.progressed(), "authentication prompt proves startup progress");
    ManagementStartup earlyHold;
    Check(earlyHold.OnLine(">HOLD:Waiting for hold release:0").empty(),
          "no commands before management authentication");
    Check(earlyHold.OnLine("SUCCESS: password is correct") == expectedStartup,
          "HOLD before authentication cannot strand startup");
    ManagementStartup heldProbe(true);
    heldProbe.OnLine(">HOLD:Waiting for hold release:0");
    Check(!heldProbe.heldProbeReady(), "probe waits for both authentication and HOLD");
    Check(heldProbe.OnLine("SUCCESS: password is correct") ==
                  std::vector<std::string>{"state on", "bytecount 1"} &&
              heldProbe.heldProbeReady(),
          "offline probe never releases startup even with early HOLD");
    std::vector<Event> events;
    auto sink = [&](Event e) { events.push_back(std::move(e)); };
    ManagementProtocol p("alice", "p\\\"ass", std::make_unique<ManualOtpProvider>("012345"), sink);
    auto commands = p.OnLine(">PASSWORD:Need 'Auth' username/password");
    Check(commands.size() == 2, "two auth commands");
    Check(commands[0] == "username \"Auth\" \"alice\"", "username command");
    Check(commands[1] == "password \"Auth\" \"p\\\\\\\"ass012345\"",
          "password and OTP concatenate and escape");
    Check(p.OnLine(">PASSWORD:Need 'Auth' username/password").empty() && p.terminal(),
          "never automatically reuse an OTP");
    ManagementProtocol sc("alice", "password", std::make_unique<ManualOtpProvider>("123456"), sink);
    auto staticCommands = sc.OnLine(">PASSWORD:Need 'Auth' username/password SC:0,Token");
    Check(staticCommands[1] == "password \"Auth\" \"SCRV1:cGFzc3dvcmQ=:MTIzNDU2\"",
          "static challenge encoding");
    ManagementProtocol failed("alice", "pw", std::make_unique<ManualOtpProvider>("123456"), sink);
    failed.OnLine(">PASSWORD:Verification Failed: 'Auth'");
    Check(failed.terminal(), "auth failure terminal");
    Check(events.size() >= 2 && events[events.size() - 2].type == EventType::RetryBlocked,
          "server rejection blocks automatic retry");
    ManagementProtocol state("alice", "pw", std::make_unique<ManualOtpProvider>("123456"), sink);
    state.OnLine(">STATE:42,CONNECTED,SUCCESS,10.8.0.2,192.0.2.1");
    Check(state.connected() && events.back().type == EventType::Connected,
          "connected only on actual core state");
    state.OnLine(">STATE:43,RECONNECTING,ping-restart,,");
    Check(!state.connected(), "reconnecting clears connected state");
    Check(events.size() >= 2 && events[events.size() - 2].type == EventType::ConnectionLost,
          "core reconnect state reports lost connection");
    Throws([] { ManagementQuote("pass\nmanagement-command"); }, "block management command injection");
    ManualOtpProvider invalid("12345a");
    Throws([&] { invalid.GetCode({}, {}); }, "OTP digits enforced");
    ManualOtpProvider valid("000123");
    auto code = valid.GetCode({}, {});
    Check(code.value == "000123", "leading zeros preserved");
    Throws([&] { valid.GetCode({}, {}); }, "manual OTP single use");
    Check(Base64Decode(Base64("Chinese UTF8: \xe4\xb8\xad")) == "Chinese UTF8: \xe4\xb8\xad",
          "base64 roundtrip");
    struct FakeProvider final : IOtpProvider {
        bool& observed;
        bool expired;
        FakeProvider(bool& seen, bool isExpired) : observed(seen), expired(isExpired) {}
        OneTimeCode GetCode(const OtpRequest& request, std::stop_token cancel) override {
            observed = request.profileId == L"test-profile" && request.username == L"alice" &&
                       request.challenge == L"Token" && cancel.stop_possible();
            return {"123456", expired
                                  ? std::optional(std::chrono::system_clock::now() - std::chrono::minutes(1))
                                  : std::nullopt};
        }
    };
    bool observed = false;
    std::stop_source cancel;
    ManagementProtocol future("alice", "pw", std::make_unique<FakeProvider>(observed, false), sink,
                              {L"test-profile", L"", L""}, cancel.get_token());
    Check(future.OnLine(">PASSWORD:Need 'Auth' username/password SC:0,Token").size() == 2 && observed,
          "provider receives profile, username, challenge and cancellation token");
    ManagementProtocol expired("alice", "pw", std::make_unique<FakeProvider>(observed, true), sink,
                               {L"test-profile", L"", L""}, cancel.get_token());
    Check(expired.OnLine(">PASSWORD:Need 'Auth' username/password").empty() && expired.terminal(),
          "expired provider code never submitted");
    cancel.request_stop();
    ManualOtpProvider cancelled("123456");
    Throws([&] { cancelled.GetCode({}, cancel.get_token()); }, "OTP retrieval cancellation");
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
    fs::create_directories(root);
    auto cache = root / L"dns-cache.txt";
    auto stop = [] { return false; };
    std::vector<Event> events;
    auto sink = [&](Event event) { events.push_back(std::move(event)); };
    const std::string config =
        "client\nremote vpn.example.test 57 udp\nremote-cert-tls server\nverify-x509-name CompanyVPN "
        "name\n<ca>\nremote fake.example.test 1\n</ca>\n";
    auto success = [](const std::string&, int) { return std::vector<std::string>{"192.0.2.10"}; };
    auto failure = [](const std::string&, int) { return std::vector<std::string>{}; };
    Check(PrepareDnsFallback(config, cache, false, success, sink, stop).empty(),
          "DNS success preserves original config");
    Check(fs::exists(cache), "successful DNS persists history with fallback disabled");
    Check(PrepareDnsFallback(config, cache, false, failure, sink, stop).empty(),
          "unchecked fallback never uses history");
    auto fallback = PrepareDnsFallback(config, cache, true, failure, sink, stop);
    Check(fallback.find("192.0.2.10") != fallback.npos, "DNS failure uses previous address");
    Check(fallback.find("verify-x509-name CompanyVPN name") != fallback.npos &&
              fallback.find("remote-cert-tls server") != fallback.npos,
          "DNS fallback preserves certificate identity checks");
    Check(fallback.find("remote fake.example.test 1") != fallback.npos,
          "inline certificate data never resolved or rewritten");
    Check(PrepareDnsFallback(config, root / L"other-profile.txt", true, failure, sink, stop).empty(),
          "profile caches stay isolated");
    Check(
        PrepareDnsFallback("remote another.example.test 57 udp\n", cache, true, failure, sink, stop).empty(),
        "host mismatch cannot reuse another server address");
    Check(PrepareDnsFallback("remote vpn.example.test 57 udp6\n", cache, true, failure, sink, stop).empty(),
          "IPv6-only connection rejects cached IPv4");
    Check(PrepareDnsFallback(config, cache, true, success, sink, stop).empty(),
          "recovered DNS takes precedence over cache");
    Check(PrepareDnsFallback(
              "remote 192.0.2.1 57 udp\n", cache, true,
              [](const std::string&, int) -> std::vector<std::string> {
                  throw std::runtime_error("numeric lookup");
              },
              sink, stop)
              .empty(),
          "numeric remotes do not query DNS");
    WriteFile(cache, "vpn.example.test 4 --evil-option 9999999999\n");
    Check(PrepareDnsFallback(config, cache, true, failure, sink, stop).empty(),
          "invalid cache cannot inject OpenVPN options");
    WriteFile(cache, "vpn.example.test 4 192.0.2.10 1\n");
    Check(PrepareDnsFallback(config, cache, true, failure, sink, stop).find("192.0.2.10") !=
              std::string::npos,
          "historical addresses remain usable without expiration");
    auto changedAddress = [](const std::string&, int) { return std::vector<std::string>{"192.0.2.20"}; };
    Check(PrepareDnsFallback(config, cache, true, changedAddress, sink, stop).empty(),
          "successful DNS refresh still preserves domain connection");
    auto refreshedFallback = PrepareDnsFallback(config, cache, true, failure, sink, stop);
    Check(refreshedFallback.find("192.0.2.20") != std::string::npos &&
              refreshedFallback.find("192.0.2.10") == std::string::npos,
          "DNS success replaces old address for later fallback");
    Throws([&] { PrepareDnsFallback(config, cache, true, failure, sink, [] { return true; }); },
           "DNS preparation supports cancellation");
    Check(!events.empty(), "DNS decisions emit diagnostics");
    auto initialCache = root / L"initial.txt";
    const std::string seededConfig = "remote vpn.knownsec.com 57 udp\nremote-cert-tls server\n";
    Check(PrepareDnsFallback(seededConfig, initialCache, true, failure, sink, stop).find("123.125.242.132") !=
              std::string::npos,
          "first connection can fall back to built-in vpn address");
    Check(PrepareDnsFallback("remote ksvpn.knownsec.com 57 udp\n", root / L"initial-other.txt", true, failure,
                             sink, stop)
                  .find("106.39.24.170") != std::string::npos,
          "first connection uses correct built-in ksvpn address");
    Check(PrepareDnsFallback(seededConfig, initialCache, true, changedAddress, sink, stop).empty(),
          "DNS success takes precedence over built-in address");
    Check(PrepareDnsFallback(seededConfig, initialCache, true, failure, sink, stop).find("192.0.2.20") !=
              std::string::npos,
          "new resolution replaces built-in address and is not reset later");
    Check(
        PrepareDnsFallback(seededConfig, root / L"initial-disabled.txt", false, failure, sink, stop).empty(),
        "built-in address does not enable fallback when unchecked");
    Check(PrepareDnsFallback("remote vpn.knownsec.com 57 udp6\n", root / L"initial-ipv6.txt", true, failure,
                             sink, stop)
              .empty(),
          "built-in IPv4 address never overrides IPv6-only profiles");
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
