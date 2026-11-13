#include "credential_store.h"
#include "dns_fallback.h"
#include "management_commands.h"
#include "management_startup.h"
#include "protocol.h"
#include "reconnect_policy.h"
#include "support/core_cases.h"
#include "support/test_platform.h"
#include "totp.h"
#include "ui_text.h"
#include <iostream>
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
void DnsFallbackTests(const fs::path& root) {
    ownvpn::testing::DnsCases(root, Check, [](auto action, const char* message) { Throws(action, message); });
}

} // namespace
int main() {
    auto root =
        fs::temp_directory_path() /
        ("ownvpn-portable-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    SetTestDataDirectory(root);
    try {
        fs::create_directories(root);
        ProtocolTests();
        Check(Base64("") == "" && Base64Decode("") == "", "empty Base64 roundtrip");
        Check(Base64("f") == "Zg==" && Base64("fo") == "Zm8=" && Base64("foo") == "Zm9v",
              "RFC4648 encoding vectors");
        Check(Base64Decode("Zg==") == "f" && Base64Decode("Zm8=") == "fo" && Base64Decode("Zm9v") == "foo",
              "RFC4648 decoding vectors");
        Check(Base64Decode("Zg") == "f", "unpadded challenge interoperability");
        Throws([] { Base64Decode("Z==="); }, "excess Base64 padding rejected");
        Throws([] { Base64Decode("Zg==Zm8="); }, "embedded Base64 padding rejected");
        Throws([] { Base64Decode("Zm9*"); }, "invalid Base64 alphabet rejected");
        Throws([] { Base64Decode("Zh=="); }, "noncanonical Base64 trailing bits rejected");
        DnsFallbackTests(root / "dns");
        const std::string unicode = "OwnVPN \xe4\xb8\xad\xe6\x96\x87 \xf0\x9f\x94\x92";
        Check(Utf8(Wide(unicode)) == unicode, "UTF8 roundtrip includes Chinese and supplementary characters");
        Check(Wide("\xc0\xaf") == L"无法解码文本", "overlong UTF8 rejected");
        Check(Wide("\xed\xa0\x80") == L"无法解码文本", "UTF8 surrogate rejected");
        Check(Wide("\xf4\x90\x80\x80") == L"无法解码文本", "out-of-range Unicode rejected");
        Check(Wide("\xe4\xb8") == L"无法解码文本", "truncated UTF8 rejected");
        Throws([] { Utf8(std::wstring(1, static_cast<wchar_t>(0xd800))); },
               "unpaired wide surrogate rejected");
        auto path = root / PathFromUtf8("\xe4\xb8\xad\xe6\x96\x87.txt");
        WriteFile(path, unicode);
        Check(ReadFile(path) == unicode && Utf8(PathText(path.filename())) == "\xe4\xb8\xad\xe6\x96\x87.txt",
              "portable UTF8 file path roundtrip");
        TotpConfig config;
        config.secretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        config.digits = 8;
        Check(GenerateTotp(config, 59) == "94287082",
              "TOTP uses injected HMAC and RFC6238 counter/truncation");
        Credentials saved{L"test-user", L"test-password", L"012345", true};
        SaveCredentials(L"portable-test", saved);
        auto loaded = LoadCredentials(L"portable-test");
        Check(loaded.username == saved.username && loaded.password == saved.password && loaded.otp.empty(),
              "credentials use isolated store with transient OTP");
        loaded.ClearSecrets();
        saved.ClearSecrets();
        DeleteCredentials(L"portable-test");
        Check(LoadCredentials(L"portable-test").password.empty(), "isolated credential deletion");
        ReconnectPolicy retry;
        auto now = ReconnectPolicy::Clock::now();
        Check(retry.Schedule(now) && !retry.Due(now + std::chrono::seconds(2)) &&
                  retry.Due(now + std::chrono::seconds(3)),
              "portable reconnect timing");
        Check(FormatTrafficBytes(1572864) == L"1.5 MB", "portable traffic formatting");
        std::string secret = "temporary";
        Wipe(secret);
        Check(secret.empty(), "portable memory wipe clears string");
        fs::remove_all(root);
        std::cout << "PASS: " << checks << " portable checks\n";
        return 0;
    } catch (const std::exception& error) {
        std::error_code ignored;
        fs::remove_all(root, ignored);
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
