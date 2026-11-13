#pragma once
#include "dns_fallback.h"
#include "management_commands.h"
#include "management_startup.h"
#include "protocol.h"
#include <algorithm>
#include <sstream>
namespace ownvpn::testing {
template <class Check, class Throws> void ProtocolCases(Check check, Throws throws) {
    const std::vector<std::string> expectedStartup{"state on", "bytecount 1", "hold off", "hold release"};
    ManagementCommands queue;
    queue.Enqueue(expectedStartup);
    const std::vector<std::string> acknowledgments{
        "SUCCESS: real-time state notification set to ON", "SUCCESS: bytecount interval changed",
        "SUCCESS: hold flag set to OFF", "SUCCESS: hold release succeeded"};
    for (size_t i = 0; i < expectedStartup.size(); ++i) {
        check(queue.TakeNext() == expectedStartup[i], "send next startup command");
        check(!queue.TakeNext(), "one in-flight management command only");
        check(!queue.OnLine(">HOLD:Waiting for hold release:0"), "notification cannot acknowledge command");
        check(queue.OnLine(acknowledgments[i]), "matching command response advances queue");
    }
    check(!queue.waiting() && !queue.TakeNext(), "completed commands are never replayed");
    auto now = std::chrono::system_clock::now();
    queue.Enqueue({"username \"Auth\" \"synthetic-user\"", "password \"Auth\" \"synthetic-password000000\""},
                  now + std::chrono::seconds(2));
    check(queue.TakeNext(now).has_value(), "username sent first");
    check(!queue.TakeNext(now), "password waits for username acknowledgment");
    queue.OnLine("SUCCESS: 'Auth' username entered, but not yet verified");
    throws([&] { queue.TakeNext(now + std::chrono::seconds(2)); },
           "expired OTP is never sent after waiting for command response");
    ManagementStartup noHold;
    check(noHold.OnLine("SUCCESS: password is correct") == expectedStartup,
          "authentication releases startup even with no HOLD notification");
    check(noHold.OnLine("SUCCESS: password is correct").empty(), "startup commands issued only once");
    noHold.OnLine("SUCCESS: hold release succeeded");
    check(noHold.releaseConfirmed() && !noHold.progressed(),
          "release acknowledgment distinct from tunnel progress");
    noHold.OnLine(">PASSWORD:Need 'Auth' username/password");
    check(noHold.progressed(), "authentication prompt proves startup progress");
    ManagementStartup earlyHold;
    check(earlyHold.OnLine(">HOLD:Waiting for hold release:0").empty(),
          "no commands before management authentication");
    check(earlyHold.OnLine("SUCCESS: password is correct") == expectedStartup,
          "HOLD before authentication cannot strand startup");
    ManagementStartup heldProbe(true);
    heldProbe.OnLine(">HOLD:Waiting for hold release:0");
    check(!heldProbe.heldProbeReady(), "probe waits for both authentication and HOLD");
    check(heldProbe.OnLine("SUCCESS: password is correct") ==
                  std::vector<std::string>{"state on", "bytecount 1"} &&
              heldProbe.heldProbeReady(),
          "offline probe never releases startup even with early HOLD");
    std::vector<Event> events;
    auto sink = [&](Event e) { events.push_back(std::move(e)); };
    ManagementProtocol p("alice", "p\\\"ass", std::make_unique<ManualOtpProvider>("012345"), sink);
    auto commands = p.OnLine(">PASSWORD:Need 'Auth' username/password");
    check(commands.size() == 2, "two auth commands");
    check(commands[0] == "username \"Auth\" \"alice\"", "username command");
    check(commands[1] == "password \"Auth\" \"p\\\\\\\"ass012345\"",
          "password and OTP concatenate and escape");
    check(p.OnLine(">PASSWORD:Need 'Auth' username/password").empty() && p.terminal(),
          "never automatically reuse an OTP");
    ManagementProtocol sc("alice", "password", std::make_unique<ManualOtpProvider>("123456"), sink);
    auto staticCommands = sc.OnLine(">PASSWORD:Need 'Auth' username/password SC:0,Token");
    check(staticCommands[1] == "password \"Auth\" \"SCRV1:cGFzc3dvcmQ=:MTIzNDU2\"",
          "static challenge encoding");
    ManagementProtocol failed("alice", "pw", std::make_unique<ManualOtpProvider>("123456"), sink);
    failed.OnLine(">PASSWORD:Verification Failed: 'Auth'");
    check(failed.terminal(), "auth failure terminal");
    check(events.size() >= 2 && events[events.size() - 2].type == EventType::RetryBlocked,
          "server rejection blocks automatic retry");
    ManagementProtocol state("alice", "pw", std::make_unique<ManualOtpProvider>("123456"), sink);
    state.OnLine(">STATE:42,CONNECTED,SUCCESS,10.8.0.2,192.0.2.1");
    check(state.connected() && events.back().type == EventType::Connected,
          "connected only on actual core state");
    state.OnLine(">STATE:43,RECONNECTING,ping-restart,,");
    check(!state.connected(), "reconnecting clears connected state");
    check(events.size() >= 2 && events[events.size() - 2].type == EventType::ConnectionLost,
          "core reconnect state reports lost connection");
    throws([] { ManagementQuote("pass\nmanagement-command"); }, "block management command injection");
    ManualOtpProvider invalid("12345a");
    throws([&] { invalid.GetCode({}, {}); }, "OTP digits enforced");
    ManualOtpProvider valid("000123");
    auto code = valid.GetCode({}, {});
    check(code.value == "000123", "leading zeros preserved");
    throws([&] { valid.GetCode({}, {}); }, "manual OTP single use");
    check(Base64Decode(Base64("Chinese UTF8: \xe4\xb8\xad")) == "Chinese UTF8: \xe4\xb8\xad",
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
    check(future.OnLine(">PASSWORD:Need 'Auth' username/password SC:0,Token").size() == 2 && observed,
          "provider receives profile, username, challenge and cancellation token");
    ManagementProtocol expired("alice", "pw", std::make_unique<FakeProvider>(observed, true), sink,
                               {L"test-profile", L"", L""}, cancel.get_token());
    check(expired.OnLine(">PASSWORD:Need 'Auth' username/password").empty() && expired.terminal(),
          "expired provider code never submitted");
    cancel.request_stop();
    ManualOtpProvider cancelled("123456");
    throws([&] { cancelled.GetCode({}, cancel.get_token()); }, "OTP retrieval cancellation");
}
template <class Check, class Throws> void DnsCases(const fs::path& root, Check check, Throws throws) {
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
    check(PrepareDnsFallback(config, cache, false, success, sink, stop).empty(),
          "DNS success preserves original config");
    check(fs::exists(cache), "successful DNS persists history with fallback disabled");
    check(PrepareDnsFallback(config, cache, false, failure, sink, stop).empty(),
          "unchecked fallback never uses history");
    auto fallback = PrepareDnsFallback(config, cache, true, failure, sink, stop);
    check(fallback.find("192.0.2.10") != fallback.npos, "DNS failure uses previous address");
    check(fallback.find("verify-x509-name CompanyVPN name") != fallback.npos &&
              fallback.find("remote-cert-tls server") != fallback.npos,
          "DNS fallback preserves certificate identity checks");
    check(fallback.find("remote fake.example.test 1") != fallback.npos,
          "inline certificate data never resolved or rewritten");
    check(PrepareDnsFallback(config, root / L"other-profile.txt", true, failure, sink, stop).empty(),
          "profile caches stay isolated");
    check(
        PrepareDnsFallback("remote another.example.test 57 udp\n", cache, true, failure, sink, stop).empty(),
        "host mismatch cannot reuse another server address");
    check(PrepareDnsFallback("remote vpn.example.test 57 udp6\n", cache, true, failure, sink, stop).empty(),
          "IPv6-only connection rejects cached IPv4");
    check(PrepareDnsFallback(config, cache, true, success, sink, stop).empty(),
          "recovered DNS takes precedence over cache");
    check(PrepareDnsFallback(
              "remote 192.0.2.1 57 udp\n", cache, true,
              [](const std::string&, int) -> std::vector<std::string> {
                  throw std::runtime_error("numeric lookup");
              },
              sink, stop)
              .empty(),
          "numeric remotes do not query DNS");
    WriteFile(cache, "vpn.example.test 4 --evil-option 9999999999\n");
    check(PrepareDnsFallback(config, cache, true, failure, sink, stop).empty(),
          "invalid cache cannot inject OpenVPN options");
    WriteFile(cache, "vpn.example.test 4 192.0.2.10 1\n");
    check(PrepareDnsFallback(config, cache, true, failure, sink, stop).find("192.0.2.10") !=
              std::string::npos,
          "historical addresses remain usable without expiration");
    auto changedAddress = [](const std::string&, int) { return std::vector<std::string>{"192.0.2.20"}; };
    check(PrepareDnsFallback(config, cache, true, changedAddress, sink, stop).empty(),
          "successful DNS refresh still preserves domain connection");
    auto refreshedFallback = PrepareDnsFallback(config, cache, true, failure, sink, stop);
    check(refreshedFallback.find("192.0.2.20") != std::string::npos &&
              refreshedFallback.find("192.0.2.10") == std::string::npos,
          "DNS success replaces old address for later fallback");
    throws([&] { PrepareDnsFallback(config, cache, true, failure, sink, [] { return true; }); },
           "DNS preparation supports cancellation");
    check(!events.empty(), "DNS decisions emit diagnostics");
    auto initialCache = root / L"initial.txt";
    const std::string seededConfig = "remote vpn.knownsec.com 57 udp\nremote-cert-tls server\n";
    check(PrepareDnsFallback(seededConfig, initialCache, true, failure, sink, stop).find("123.125.242.132") !=
              std::string::npos,
          "first connection can fall back to built-in vpn address");
    check(PrepareDnsFallback("remote ksvpn.knownsec.com 57 udp\n", root / L"initial-other.txt", true, failure,
                             sink, stop)
                  .find("106.39.24.170") != std::string::npos,
          "first connection uses correct built-in ksvpn address");
    check(PrepareDnsFallback(seededConfig, initialCache, true, changedAddress, sink, stop).empty(),
          "DNS success takes precedence over built-in address");
    check(PrepareDnsFallback(seededConfig, initialCache, true, failure, sink, stop).find("192.0.2.20") !=
              std::string::npos,
          "new resolution replaces built-in address and is not reset later");
    check(
        PrepareDnsFallback(seededConfig, root / L"initial-disabled.txt", false, failure, sink, stop).empty(),
        "built-in address does not enable fallback when unchecked");
    check(PrepareDnsFallback("remote vpn.knownsec.com 57 udp6\n", root / L"initial-ipv6.txt", true, failure,
                             sink, stop)
              .empty(),
          "built-in IPv4 address never overrides IPv6-only profiles");
}
} // namespace ownvpn::testing
