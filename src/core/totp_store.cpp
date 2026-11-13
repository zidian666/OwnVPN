#include "totp_store.h"
#include "credential_store.h"
#include "platform.h"
#include <array>
#include <sstream>

namespace ownvpn {
namespace {
std::wstring Field(std::wstring_view username) {
    if (username.empty() || username.size() > 256) {
        throw std::runtime_error("请先填写有效的 VPN 用户名");
    }
    auto input = Utf8(username);
    struct InputGuard {
        std::string& value;
        ~InputGuard() {
            Wipe(value);
        }
    } guard{input};
    auto digest = Platform().crypto.Digest(
        HashAlgorithm::Sha256, {reinterpret_cast<const unsigned char*>(input.data()), input.size()});
    Wipe(input);
    if (digest.size() != 32) {
        throw std::runtime_error("Invalid SHA256 result length");
    }
    constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring field = L"totp/";
    for (auto b : digest) {
        field += hex[b >> 4];
        field += hex[b & 15];
    }
    return field;
}
std::wstring Serialize(const TotpConfig& config) {
    auto uri = L"otpauth://totp/OwnVPN?secret=" + Wide(config.secretBase32) + L"&algorithm=" +
               Wide(AlgorithmName(config.algorithm)) + L"&digits=" + std::to_wstring(config.digits) +
               L"&period=" + std::to_wstring(config.periodSeconds);
    return uri; // Labels are optional and deliberately not persisted.
}
} // namespace
TotpConfig TotpRepository::Load(std::wstring_view profileId, std::wstring_view username) const {
    auto text = ReadProtectedValue(profileId, Field(username));
    struct Guard {
        std::wstring& s;
        ~Guard() {
            Wipe(s);
        }
    } guard{text};
    if (text.empty()) {
        throw std::runtime_error("该账号尚未绑定自动验证码，请先导入二维码或密钥");
    }
    auto uri = Utf8(text);
    struct Guard8 {
        std::string& s;
        ~Guard8() {
            Wipe(s);
        }
    } guard8{uri};
    auto config = ParseTotpUri(uri);
    ValidateTotp(config, true);
    return config;
}
TotpMetadata TotpRepository::Metadata(std::wstring_view id, std::wstring_view username) const {
    if (username.empty()) {
        return {};
    }
    auto field = Field(username);
    auto seed = ReadProtectedValue(id, field);
    bool bound = !seed.empty();
    Wipe(seed);
    if (!bound) {
        return {};
    }
    auto config = Load(id, username);
    return {true, ReadProtectedValue(id, field + L"/mode") == L"auto", config.periodSeconds,
            config.algorithm};
}
void TotpRepository::Bind(std::wstring_view id, std::wstring_view username, const TotpConfig& config) const {
    ValidateTotp(config, true);
    auto field = Field(username);
    auto text = Serialize(config);
    auto previous = ReadProtectedValue(id, field);
    bool sameParameters = previous == text;
    Wipe(previous);
    struct Guard {
        std::wstring& s;
        ~Guard() {
            Wipe(s);
        }
    } guard{text};
    StoreProtectedValue(id, field, text);
    StoreProtectedValue(id, field + L"/mode", L"auto");
    if (!sameParameters) {
        StoreProtectedValue(id, field + L"/counter", L"");
    }
}
void TotpRepository::SetAutomatic(std::wstring_view id, std::wstring_view username, bool enabled) const {
    if (enabled) {
        auto config = Load(id, username);
        (void)config;
    }
    StoreProtectedValue(id, Field(username) + L"/mode", enabled ? L"auto" : L"manual");
}
void TotpRepository::Remove(std::wstring_view id, std::wstring_view username) const {
    auto field = Field(username);
    StoreProtectedValue(id, field, L"");
    StoreProtectedValue(id, field + L"/mode", L"");
    StoreProtectedValue(id, field + L"/counter", L"");
}
std::optional<int64_t> TotpRepository::LastIssuedCounter(std::wstring_view id,
                                                         std::wstring_view username) const {
    auto text = ReadProtectedValue(id, Field(username) + L"/counter");
    if (text.empty()) {
        return std::nullopt;
    }
    if (text.size() > 18 || text.find_first_not_of(L"0123456789") != text.npos) {
        throw std::runtime_error("验证码使用记录无效，请重新绑定");
    }
    return std::stoll(text);
}
void TotpRepository::MarkIssued(std::wstring_view id, std::wstring_view username, int64_t counter) const {
    if (counter < 0) {
        throw std::runtime_error("验证码计数器无效");
    }
    StoreProtectedValue(id, Field(username) + L"/counter", std::to_wstring(counter));
}
} // namespace ownvpn
