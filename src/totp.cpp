#include "totp.h"
#include <array>
#include <bcrypt.h>
#include <charconv>
#include <condition_variable>
#include <map>
#include <mutex>
#include <set>

namespace ownvpn {
namespace {
struct SecureBytes {
    std::vector<unsigned char> data;
    ~SecureBytes() {
        if (!data.empty()) {
            SecureZeroMemory(data.data(), data.size());
        }
    }
};
struct AlgorithmHandle {
    BCRYPT_ALG_HANDLE value = nullptr;
    ~AlgorithmHandle() {
        if (value) {
            BCryptCloseAlgorithmProvider(value, 0);
        }
    }
};
struct HashHandle {
    BCRYPT_HASH_HANDLE value = nullptr;
    ~HashHandle() {
        if (value) {
            BCryptDestroyHash(value);
        }
    }
};
void RequireCrypto(NTSTATUS status) {
    if (status < 0) {
        throw std::runtime_error("Windows HMAC operation failed");
    }
}
int Digit(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}
std::string PercentDecode(std::string_view input) {
    std::string out;
    for (size_t i = 0; i < input.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (c == '%') {
            if (i + 2 >= input.size() || Digit(input[i + 1]) < 0 || Digit(input[i + 2]) < 0) {
                throw std::runtime_error("绑定链接包含无效的百分号编码");
            }
            c = static_cast<unsigned char>(Digit(input[i + 1]) * 16 + Digit(input[i + 2]));
            i += 2;
        }
        if (c < 32 || c == 127) {
            throw std::runtime_error("绑定链接包含无效控制字符");
        }
        out += static_cast<char>(c);
    }
    return out;
}
int Number(std::string_view text) {
    int number = 0;
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), number);
    if (error != std::errc{} || end != text.data() + text.size()) {
        throw std::runtime_error("验证码参数必须是整数");
    }
    return number;
}
int64_t UnixSeconds(std::chrono::system_clock::time_point now) {
    return std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
}
class SystemClock final : public ITotpClock {
  public:
    std::chrono::system_clock::time_point Now() const override {
        return std::chrono::system_clock::now();
    }
    void WaitFor(std::chrono::milliseconds duration, std::stop_token cancel) override {
        std::mutex mutex;
        std::condition_variable_any condition;
        std::unique_lock lock(mutex);
        condition.wait_for(lock, cancel, duration, [] { return false; });
    }
};
} // namespace
std::vector<unsigned char> DecodeBase32(std::string_view text) {
    if (text.empty() || text.size() > 512) {
        throw std::runtime_error("绑定密钥长度无效");
    }
    std::vector<unsigned char> out;
    uint32_t bits = 0;
    int bitCount = 0;
    bool padding = false;
    size_t count = 0, pad = 0;
    for (unsigned char c : text) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            continue;
        }
        if (c == '=') {
            padding = true;
            ++pad;
            continue;
        }
        if (padding) {
            throw std::runtime_error("Base32 密钥填充位置无效");
        }
        if (c >= 'a' && c <= 'z') {
            c = static_cast<unsigned char>(c - 'a' + 'A');
        }
        int value = (c >= 'A' && c <= 'Z') ? c - 'A' : (c >= '2' && c <= '7') ? c - '2' + 26 : -1;
        if (value < 0) {
            throw std::runtime_error("密钥必须是 Base32 字符（A–Z、2–7）");
        }
        ++count;
        bits = (bits << 5) | static_cast<uint32_t>(value);
        bitCount += 5;
        if (bitCount >= 8) {
            bitCount -= 8;
            out.push_back(static_cast<unsigned char>((bits >> bitCount) & 255));
        }
    }
    auto rem = count % 8;
    if (rem == 1 || rem == 3 || rem == 6 || count == 0 ||
        (bitCount && (bits & ((1u << bitCount) - 1)) != 0) || (pad && (count + pad) % 8 != 0) || pad > 6) {
        throw std::runtime_error("Base32 密钥编码不完整");
    }
    return out;
}
std::string EncodeBase32(std::span<const unsigned char> bytes) {
    constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string out;
    uint32_t bits = 0;
    int count = 0;
    for (auto b : bytes) {
        bits = (bits << 8) | b;
        count += 8;
        while (count >= 5) {
            count -= 5;
            out += alphabet[(bits >> count) & 31];
        }
    }
    if (count) {
        out += alphabet[(bits << (5 - count)) & 31];
    }
    return out;
}
std::string AlgorithmName(TotpAlgorithm algorithm) {
    switch (algorithm) {
    case TotpAlgorithm::Sha1:
        return "SHA1";
    case TotpAlgorithm::Sha256:
        return "SHA256";
    case TotpAlgorithm::Sha512:
        return "SHA512";
    }
    throw std::runtime_error("不支持的 TOTP 算法");
}
void ValidateTotp(const TotpConfig& config, bool forVpn) {
    SecureBytes key{DecodeBase32(config.secretBase32)};
    if (key.data.size() < 10 || key.data.size() > 128) {
        throw std::runtime_error("绑定密钥必须包含 10–128 字节");
    }
    AlgorithmName(config.algorithm);
    if (config.digits != 6 && config.digits != 8) {
        throw std::runtime_error("仅支持 6 位或 8 位 TOTP");
    }
    if (forVpn && config.digits != 6) {
        throw std::runtime_error("当前公司 VPN 要求 6 位验证码，该绑定为其他位数");
    }
    if (config.periodSeconds < 10 || config.periodSeconds > 300) {
        throw std::runtime_error("验证码周期必须为 10–300 秒");
    }
}
TotpConfig ParseTotpUri(std::string_view input) {
    if (input.size() > 4096) {
        throw std::runtime_error("绑定链接过长");
    }
    if (!input.starts_with("otpauth://totp/")) {
        throw std::runtime_error("二维码不是标准 TOTP 绑定；不支持微软推送注册链接或 HOTP");
    }
    auto query = input.find('?');
    if (query == input.npos || query <= 15 || input.find('#') != input.npos) {
        throw std::runtime_error("TOTP 绑定链接格式无效");
    }
    TotpConfig config;
    auto label = PercentDecode(input.substr(15, query - 15));
    auto colon = label.find(':');
    if (colon != label.npos) {
        config.issuer = Wide(label.substr(0, colon));
        config.account = Wide(label.substr(colon + 1));
    } else {
        config.account = Wide(label);
    }
    std::map<std::string, std::string> parameters;
    struct Guard {
        std::map<std::string, std::string>& p;
        ~Guard() {
            for (auto& [k, v] : p) {
                (void)k;
                Wipe(v);
            }
        }
    } guard{parameters};
    size_t begin = query + 1;
    while (begin < input.size()) {
        auto end = input.find('&', begin);
        if (end == input.npos) {
            end = input.size();
        }
        auto pair = input.substr(begin, end - begin);
        auto equals = pair.find('=');
        if (equals == pair.npos || equals == 0) {
            throw std::runtime_error("TOTP 参数格式无效");
        }
        auto key = PercentDecode(pair.substr(0, equals)), value = PercentDecode(pair.substr(equals + 1));
        if (!parameters.emplace(key, value).second) {
            Wipe(value);
            throw std::runtime_error("TOTP 绑定包含重复参数");
        }
        Wipe(value);
        begin = end + 1;
    }
    if (!parameters.contains("secret")) {
        throw std::runtime_error("绑定中缺少验证码密钥");
    }
    SecureBytes key{DecodeBase32(parameters.at("secret"))};
    config.secretBase32 = EncodeBase32(key.data);
    if (parameters.contains("algorithm")) {
        const auto& algorithm = parameters.at("algorithm");
        if (algorithm == "SHA1") {
            config.algorithm = TotpAlgorithm::Sha1;
        } else if (algorithm == "SHA256") {
            config.algorithm = TotpAlgorithm::Sha256;
        } else if (algorithm == "SHA512") {
            config.algorithm = TotpAlgorithm::Sha512;
        } else {
            throw std::runtime_error("绑定使用了不支持的 TOTP 算法");
        }
    }
    if (parameters.contains("digits")) {
        config.digits = Number(parameters.at("digits"));
    }
    if (parameters.contains("period")) {
        config.periodSeconds = Number(parameters.at("period"));
    }
    if (parameters.contains("issuer")) {
        auto issuer = Wide(parameters.at("issuer"));
        if (!config.issuer.empty() && config.issuer != issuer) {
            throw std::runtime_error("绑定中的发行方信息不一致");
        }
        config.issuer = std::move(issuer);
    }
    ValidateTotp(config);
    return config;
}
TotpConfig ParseTotpInput(std::string_view input, TotpAlgorithm algorithm, int periodSeconds) {
    auto clean = Trim(input);
    struct Guard {
        std::string& s;
        ~Guard() {
            Wipe(s);
        }
    } guard{clean};
    if (clean.starts_with("otpauth:") || clean.find("://") != clean.npos) {
        return ParseTotpUri(clean);
    }
    TotpConfig config;
    SecureBytes key{DecodeBase32(clean)};
    config.secretBase32 = EncodeBase32(key.data);
    config.algorithm = algorithm;
    config.periodSeconds = periodSeconds;
    ValidateTotp(config, true);
    return config;
}
TotpConfig WithTotpParameters(const TotpConfig& existing, TotpAlgorithm algorithm, int periodSeconds) {
    auto updated = existing;
    updated.algorithm = algorithm;
    updated.periodSeconds = periodSeconds;
    ValidateTotp(updated, true);
    return updated;
}
std::vector<TotpMatch> FindTotpMatches(const TotpConfig& config, std::string_view phoneCode,
                                       int64_t unixSeconds) {
    if (phoneCode.size() != 6 || phoneCode.find_first_not_of("0123456789") != phoneCode.npos) {
        throw std::runtime_error("请输入手机上的当前 6 位数字验证码");
    }
    std::vector<TotpMatch> matches;
    for (auto algorithm : {TotpAlgorithm::Sha1, TotpAlgorithm::Sha256, TotpAlgorithm::Sha512}) {
        for (int period : std::set<int>{config.periodSeconds, 30, 60}) {
            auto candidate = WithTotpParameters(config, algorithm, period);
            for (int offset = -1; offset <= 1; ++offset) {
                auto time = unixSeconds + static_cast<int64_t>(offset) * period;
                if (time < 0) {
                    continue;
                }
                auto code = GenerateTotp(candidate, time);
                if (code == phoneCode) {
                    matches.push_back({algorithm, period, offset});
                }
                Wipe(code);
            }
        }
    }
    return matches;
}
std::string GenerateTotp(const TotpConfig& config, int64_t unixSeconds) {
    ValidateTotp(config);
    if (unixSeconds < 0) {
        throw std::runtime_error("系统时间早于 Unix 起点");
    }
    SecureBytes key{DecodeBase32(config.secretBase32)};
    uint64_t counter = static_cast<uint64_t>(unixSeconds / config.periodSeconds);
    std::array<unsigned char, 8> message{};
    for (int i = 7; i >= 0; --i) {
        message[i] = static_cast<unsigned char>(counter & 255);
        counter >>= 8;
    }
    const wchar_t* name = config.algorithm == TotpAlgorithm::Sha1     ? BCRYPT_SHA1_ALGORITHM
                          : config.algorithm == TotpAlgorithm::Sha256 ? BCRYPT_SHA256_ALGORITHM
                                                                      : BCRYPT_SHA512_ALGORITHM;
    AlgorithmHandle algorithm;
    RequireCrypto(BCryptOpenAlgorithmProvider(&algorithm.value, name, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG));
    DWORD objectSize = 0, hashSize = 0, resultSize = 0;
    RequireCrypto(BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH,
                                    reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &resultSize,
                                    0));
    RequireCrypto(BCryptGetProperty(algorithm.value, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashSize),
                                    sizeof(hashSize), &resultSize, 0));
    SecureBytes object{std::vector<unsigned char>(objectSize)}, digest{std::vector<unsigned char>(hashSize)};
    HashHandle hash;
    RequireCrypto(BCryptCreateHash(algorithm.value, &hash.value, object.data.data(), objectSize,
                                   key.data.data(), static_cast<ULONG>(key.data.size()), 0));
    RequireCrypto(BCryptHashData(hash.value, message.data(), static_cast<ULONG>(message.size()), 0));
    RequireCrypto(BCryptFinishHash(hash.value, digest.data.data(), hashSize, 0));
    size_t offset = digest.data.back() & 15;
    uint32_t binary = (static_cast<uint32_t>(digest.data[offset] & 127) << 24) |
                      (static_cast<uint32_t>(digest.data[offset + 1]) << 16) |
                      (static_cast<uint32_t>(digest.data[offset + 2]) << 8) | digest.data[offset + 3];
    auto code = std::to_string(binary % (config.digits == 6 ? 1000000u : 100000000u));
    return std::string(static_cast<size_t>(config.digits) - code.size(), '0') + code;
}
std::chrono::system_clock::time_point TotpExpiry(const TotpConfig& config, int64_t unixSeconds) {
    if (config.periodSeconds < 10 || config.periodSeconds > 300 || unixSeconds < 0) {
        throw std::runtime_error("验证码时间参数无效");
    }
    return std::chrono::system_clock::time_point(
        std::chrono::seconds((unixSeconds / config.periodSeconds + 1) * config.periodSeconds));
}
std::shared_ptr<ITotpClock> SystemTotpClock() {
    return std::make_shared<SystemClock>();
}
TotpOtpProvider::TotpOtpProvider(ConfigLoader loader, std::shared_ptr<ITotpClock> clock,
                                 CounterReader counterReader, CounterWriter counterWriter)
    : loader_(std::move(loader)), clock_(std::move(clock)), counterReader_(std::move(counterReader)),
      counterWriter_(std::move(counterWriter)) {
    if (!loader_ || !clock_) {
        throw std::runtime_error("Missing TOTP dependencies");
    }
}
OneTimeCode TotpOtpProvider::GetCode(const OtpRequest& request, std::stop_token cancel) {
    auto config = loader_(request);
    ValidateTotp(config, true);
    if (counterReader_) {
        lastCounter_ = counterReader_(request);
    }
    for (int attempts = 0; attempts < 3; ++attempts) {
        if (cancel.stop_requested()) {
            throw std::runtime_error("验证码生成已取消");
        }
        auto now = clock_->Now();
        auto unixSeconds = UnixSeconds(now);
        auto counter = unixSeconds / config.periodSeconds;
        if (lastCounter_ && counter < *lastCounter_) {
            throw std::runtime_error("系统时间已回退，请校准时间后重试");
        }
        auto expiry = TotpExpiry(config, unixSeconds);
        if (expiry - now <= std::chrono::seconds(5) || (lastCounter_ && counter <= *lastCounter_)) {
            auto wait = std::chrono::duration_cast<std::chrono::milliseconds>(expiry - now) +
                        std::chrono::milliseconds(50);
            clock_->WaitFor(wait, cancel);
            continue;
        }
        auto code = GenerateTotp(config, unixSeconds);
        if (clock_->Now() >= expiry) {
            Wipe(code);
            continue;
        }
        lastCounter_ = counter;
        if (counterWriter_) {
            counterWriter_(request, counter);
        }
        return {std::move(code), expiry};
    }
    throw std::runtime_error("系统时间发生变化，请校准时间后重试");
}
} // namespace ownvpn
