#include "credential_store.h"
#include "protocol.h"
#include "qr_import.h"
#include "totp.h"
#include "totp_detection.h"
#include "totp_preview.h"
#include "totp_store.h"
#include <array>
#include <iostream>
#include <objbase.h>

using namespace ownvpn;
namespace {
int checks = 0;
void Check(bool value, const char* label) {
    ++checks;
    if (!value) {
        throw std::runtime_error(label);
    }
}
template <class F> void Throws(F action, const char* label) {
    bool failed = false;
    try {
        action();
    } catch (const std::exception&) {
        failed = true;
    }
    Check(failed, label);
}
constexpr auto publicSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
std::string Uri() {
    return std::string("otpauth://totp/Test:alice?secret=") + publicSeed + "&issuer=Test";
}
void StandardVectors() {
    // RFC 6238 Appendix B, all three algorithms including a time beyond 2038.
    const std::array<int64_t, 6> times{59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000};
    const char* expected[3][6] = {{"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"},
                                  {"46119246", "68084774", "67062674", "91819424", "90698825", "77737706"},
                                  {"90693936", "25091201", "99943326", "93441116", "38618901", "47863826"}};
    const std::array<std::string, 3> keys{"12345678901234567890", "12345678901234567890123456789012",
                                          "1234567890123456789012345678901234567890123456789012345678901234"};
    for (int algorithm = 0; algorithm < 3; ++algorithm) {
        TotpConfig config;
        config.secretBase32 = EncodeBase32(std::span(
            reinterpret_cast<const unsigned char*>(keys[algorithm].data()), keys[algorithm].size()));
        config.algorithm = static_cast<TotpAlgorithm>(algorithm);
        config.digits = 8;
        for (size_t i = 0; i < times.size(); ++i) {
            Check(GenerateTotp(config, times[i]) == expected[algorithm][i], "RFC 6238 vector");
        }
    }
    auto config = ParseTotpUri(Uri());
    Check(GenerateTotp(config, 59) == "287082", "six-digit truncation");
    Check(GenerateTotp(config, 29) == GenerateTotp(config, 0), "same window stable");
    Check(GenerateTotp(config, 30) != GenerateTotp(config, 29), "window boundary changes");
    Check(GenerateTotp(config, 1111111109) == "081804", "six-digit leading zero preserved");
    auto wrongParameters = WithTotpParameters(config, TotpAlgorithm::Sha256, 60);
    Check(wrongParameters.secretBase32 == config.secretBase32 &&
              wrongParameters.algorithm == TotpAlgorithm::Sha256 && wrongParameters.periodSeconds == 60,
          "editing parameters preserves the existing seed");
    auto matches = FindTotpMatches(wrongParameters, GenerateTotp(config, 1234567890), 1234567890);
    Check(matches.size() == 1 && matches.front().algorithm == TotpAlgorithm::Sha1 &&
              matches.front().periodSeconds == 30 && matches.front().windowOffset == 0,
          "local phone check identifies algorithm and period mismatch");
    auto shifted = FindTotpMatches(config, GenerateTotp(config, 1234567920), 1234567890);
    Check(shifted.size() == 1 && shifted.front().windowOffset == 1,
          "local phone check tolerates the adjacent time window");
    Check(FindTotpMatches(config, "000000", 1234567890).empty(),
          "unmatched phone code does not change configuration");
    Throws([&] { FindTotpMatches(config, "12345a", 1234567890); }, "phone check rejects malformed codes");
}
void Parsing() {
    auto config = ParseTotpUri(Uri());
    Check(config.periodSeconds == 30 && config.digits == 6 && config.algorithm == TotpAlgorithm::Sha1,
          "URI standard defaults");
    Check(config.issuer == L"Test" && config.account == L"alice", "URI account metadata");
    auto custom = ParseTotpUri(Uri() + "&algorithm=SHA256&period=60");
    Check(custom.periodSeconds == 60 && custom.algorithm == TotpAlgorithm::Sha256, "explicit URI parameters");
    Throws([] { ParseTotpUri("phonefactor://activate-account?code=not-a-secret"); },
           "Microsoft push enrollment rejected");
    Throws([] { ParseTotpUri("https://example.invalid"); }, "arbitrary URL rejected without fetching");
    Throws([] { ParseTotpUri("otpauth://hotp/account?secret=ABC&counter=0"); }, "HOTP rejected");
    Throws([] { ParseTotpUri(Uri() + "&secret=ABC"); }, "duplicate secret rejected");
    Throws([] { ParseTotpUri(Uri() + "&period=0"); }, "zero period rejected");
    Throws([] { ParseTotpUri(Uri() + "&algorithm=MD5"); }, "unknown hash rejected");
    Throws([] { ParseTotpUri(Uri() + "&digits=7"); }, "invalid digit count");
    Throws(
        [] {
            auto c = ParseTotpUri(Uri() + "&digits=8");
            ValidateTotp(c, true);
        },
        "eight-digit binding rejected for this VPN");
    Throws([] { ParseTotpUri("otpauth://totp/account?secret=ABC%0aDEF"); }, "encoded controls rejected");
    Throws([] { ParseTotpUri("otpauth://totp/account?secret=%GG"); }, "malformed percent encoding rejected");
    Throws([] { DecodeBase32("A"); }, "incomplete base32 rejected");
    Throws([] { DecodeBase32("MZ"); }, "nonzero padding bits rejected");
    Throws([] { DecodeBase32("AA=AA"); }, "embedded padding rejected");
    Throws([] { DecodeBase32("0123456789"); }, "invalid base32 alphabet rejected");
    auto lower = ParseTotpInput("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", TotpAlgorithm::Sha1, 30);
    Check(lower.secretBase32 == publicSeed, "manual lowercase/spaces normalized");
    Throws([] { GenerateTotp(ParseTotpUri(Uri()), -1); }, "negative UTC time rejected");
}
class FakeClock final : public ITotpClock {
  public:
    std::chrono::system_clock::time_point now{std::chrono::seconds(59)};
    int waits = 0;
    bool cancelOnWait = false;
    std::stop_source source;
    auto Now() const -> std::chrono::system_clock::time_point override {
        return now;
    }
    void WaitFor(std::chrono::milliseconds duration, std::stop_token) override {
        ++waits;
        now += duration;
        if (cancelOnWait) {
            source.request_stop();
        }
    }
};
void ProviderTests() {
    auto clock = std::make_shared<FakeClock>();
    TotpOtpProvider provider([](const OtpRequest&) { return ParseTotpUri(Uri()); }, clock);
    auto code = provider.GetCode({}, {});
    Check(clock->waits == 1, "near-expiry code waits for rollover");
    Check(code.value == GenerateTotp(ParseTotpUri(Uri()), 60), "fresh code generated after rollover");
    Check(code.expiresAt == std::chrono::system_clock::time_point(std::chrono::seconds(90)),
          "real expiration returned");
    auto next = provider.GetCode({}, {});
    Check(clock->waits == 2 && next.expiresAt > code.expiresAt, "provider does not reuse same counter");
    auto reconnectClock = std::make_shared<FakeClock>();
    reconnectClock->now = std::chrono::system_clock::time_point(std::chrono::seconds(60));
    std::optional<int64_t> issued = 2;
    TotpOtpProvider reconnect([](const OtpRequest&) { return ParseTotpUri(Uri()); }, reconnectClock,
                              [&](const OtpRequest&) { return issued; },
                              [&](const OtpRequest&, int64_t counter) { issued = counter; });
    auto fresh = reconnect.GetCode({}, {});
    Check(reconnectClock->waits == 1 && issued == 3 && fresh.value == GenerateTotp(ParseTotpUri(Uri()), 90),
          "new connection does not reuse previously issued counter");
    reconnectClock->now = std::chrono::system_clock::time_point(std::chrono::seconds(30));
    Throws([&] { reconnect.GetCode({}, {}); }, "clock rollback fails without reusing older codes");
    auto cancelled = std::make_shared<FakeClock>();
    cancelled->cancelOnWait = true;
    TotpOtpProvider cancellable([](const OtpRequest&) { return ParseTotpUri(Uri()); }, cancelled);
    Throws([&] { cancellable.GetCode({}, cancelled->source.get_token()); },
           "waiting for rollover responds to cancellation");
    auto pipelineClock = std::make_shared<FakeClock>();
    pipelineClock->now = std::chrono::system_clock::time_point(std::chrono::seconds(60));
    auto automatic = std::make_unique<TotpOtpProvider>(
        [](const OtpRequest& r) {
            if (r.profileId != L"test-profile") {
                throw std::runtime_error("missing binding context");
            }
            return ParseTotpUri(Uri());
        },
        pipelineClock);
    ManagementProtocol protocol(
        "alice", "pw", std::move(automatic), [](Event) {}, {L"test-profile", L"", L""}, {},
        [pipelineClock] { return pipelineClock->Now(); });
    auto commands = protocol.OnLine(">PASSWORD:Need 'Auth' username/password");
    Check(commands.size() == 2 &&
              commands[1] == "password \"Auth\" \"pw" + GenerateTotp(ParseTotpUri(Uri()), 60) + "\"",
          "automatic provider integrated with VPN password concatenation");
}
void StoreTests() {
    TotpRepository store;
    auto id = L"totp-test-" + Wide(RandomHex());
    auto config = ParseTotpUri(Uri());
    try {
        store.Bind(id, L"alice", config);
        Check(store.Metadata(id, L"alice").automatic, "saved binding enables automatic mode");
        Check(store.Load(id, L"alice").secretBase32 == publicSeed,
              "seed roundtrip through Windows credentials");
        Check(!store.Metadata(id, L"bob").bound, "different username isolated");
        Check(!store.Metadata(id + L"other", L"alice").bound, "different profile isolated");
        store.MarkIssued(id, L"alice", 123);
        Check(store.LastIssuedCounter(id, L"alice") == 123 && !store.LastIssuedCounter(id, L"bob"),
              "issued counter persisted and isolated by account");
        store.Bind(id, L"alice", config);
        Check(store.LastIssuedCounter(id, L"alice") == 123,
              "saving unchanged parameters preserves replay protection");
        auto changed = WithTotpParameters(store.Load(id, L"alice"), TotpAlgorithm::Sha256, 60);
        store.Bind(id, L"alice", changed);
        auto metadata = store.Metadata(id, L"alice");
        Check(metadata.algorithm == TotpAlgorithm::Sha256 && metadata.periodSeconds == 60 &&
                  store.Load(id, L"alice").secretBase32 == config.secretBase32,
              "new algorithm and period are actually saved with an existing key");
        Check(!store.LastIssuedCounter(id, L"alice"), "changed token parameters reset their old counter");
        store.Bind(id, L"alice", config);
        store.MarkIssued(id, L"alice", 123);
        int loads = 0;
        TotpPreview preview([&](const OtpRequest& request) {
            ++loads;
            return store.Load(request.profileId, request.username);
        });
        OtpRequest context{id, L"alice", L""};
        auto first = preview.Code(context, 30, 1111111109);
        Check(first == L"081804", "automatic preview displays all six digits including leading zeros");
        Check(preview.Code(context, 30, 1111111109) == first && loads == 1,
              "preview does not reload or repaint a stable code");
        auto updated = preview.Code(context, 30, 1111111110);
        Check(updated != first && loads == 2, "preview refreshes at the actual period boundary");
        Check(store.LastIssuedCounter(id, L"alice") == 123,
              "preview does not consume an authentication code");
        preview.Reset();
        preview.Code(context, 30, 1111111110);
        Check(loads == 3, "binding changes explicitly invalidate preview cache");
        store.SetAutomatic(id, L"alice", false);
        Check(store.Metadata(id, L"alice").bound && !store.Metadata(id, L"alice").automatic,
              "manual mode retains seed");
        Credentials c{L"alice", L"synthetic", L"123456", true};
        SaveCredentials(id, c);
        c.otp.clear();
        SaveCredentials(id, c);
        auto remembered = LoadCredentials(id);
        Check(remembered.otp.empty(), "manual and automatic modes never persist OTP values");
        remembered.ClearSecrets();
        c.ClearSecrets();
        store.Remove(id, L"alice");
        Check(!store.Metadata(id, L"alice").bound, "explicit removal deletes binding");
    } catch (...) {
        store.Remove(id, L"alice");
        DeleteCredentials(id);
        throw;
    }
    store.Remove(id, L"alice");
    DeleteCredentials(id);
}
void DetectionTests() {
    auto config = ParseTotpUri(Uri());
    auto phone = WithTotpParameters(config, TotpAlgorithm::Sha256, 60);
    TotpParameterDetector detector;
    constexpr int64_t time = 1234567890;
    auto first = detector.Observe(config, GenerateTotp(phone, time), time);
    Check(first.state == DetectionState::AwaitNextCode,
          "parameter detector requires a second independent round");
    auto repeated = detector.Observe(config, GenerateTotp(phone, time), time + 1);
    Check(repeated.state == DetectionState::SameWindow,
          "retyping the same phone window does not confirm parameters");
    auto next = detector.Observe(config, GenerateTotp(phone, time + 60), time + 60);
    Check(next.state == DetectionState::Confirmed &&
              next.candidates.front().algorithm == TotpAlgorithm::Sha256 &&
              next.candidates.front().periodSeconds == 60,
          "two rounds identify the actual phone algorithm and period");
    detector.Reset();
    detector.Observe(config, GenerateTotp(config, 60), 59);
    Check(detector.Observe(config, GenerateTotp(config, 60), 60).state == DetectionState::SameWindow,
          "PC boundary crossing does not count unchanged phone code as a second round");
    Check(detector.Observe(config, GenerateTotp(config, 90), 90).state == DetectionState::Confirmed,
          "following phone window confirms parameters after boundary mismatch");
    Check(detector.Observe(config, "000000", time).state == DetectionState::NoMatch,
          "unmatched observation clears pending candidates");
}
void QrTests() {
    fs::path root = PathFromUtf8(OWNVPN_TEST_FIXTURES);
    auto normal = ImportTotpQrImage(root / L"totp-standard.png");
    Check(normal.secretBase32 == publicSeed, "local PNG QR decoding");
    auto rotated = ImportTotpQrImage(root / L"totp-rotated.png");
    Check(rotated.secretBase32 == publicSeed, "rotated QR decoding");
    Throws([&] { ImportTotpQrImage(root / L"not-totp.png"); }, "non-enrollment QR rejected");
    Throws([&] { ImportTotpQrImage(root / L"multiple-qr.png"); }, "ambiguous multiple QR image rejected");
    Throws([&] { ImportTotpQrImage(root / L"blank.png"); }, "blank image rejected");
}
} // namespace
int main() {
    auto initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    try {
        StandardVectors();
        Parsing();
        ProviderTests();
        StoreTests();
        DetectionTests();
        QrTests();
        if (SUCCEEDED(initialized)) {
            CoUninitialize();
        }
        std::cout << "PASS: " << checks << " TOTP/QR checks\n";
        return 0;
    } catch (const std::exception& e) {
        if (SUCCEEDED(initialized)) {
            CoUninitialize();
        }
        std::cerr << "FAIL: " << e.what() << '\n';
        return 1;
    }
}
