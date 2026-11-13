#pragma once
#include "otp_provider.h"
#include <cstdint>
#include <memory>
#include <span>

namespace ownvpn {
enum class TotpAlgorithm { Sha1, Sha256, Sha512 };
struct TotpConfig {
    std::string secretBase32;
    TotpAlgorithm algorithm = TotpAlgorithm::Sha1;
    int digits = 6;
    int periodSeconds = 30;
    std::wstring issuer;
    std::wstring account;
    ~TotpConfig() {
        Wipe(secretBase32);
    }
};

std::vector<unsigned char> DecodeBase32(std::string_view input);
std::string EncodeBase32(std::span<const unsigned char> bytes);
TotpConfig ParseTotpUri(std::string_view uri);
TotpConfig ParseTotpInput(std::string_view input, TotpAlgorithm algorithm, int periodSeconds);
TotpConfig WithTotpParameters(const TotpConfig& existing, TotpAlgorithm algorithm, int periodSeconds);
struct TotpMatch {
    TotpAlgorithm algorithm;
    int periodSeconds;
    int windowOffset;
};
std::vector<TotpMatch> FindTotpMatches(const TotpConfig& config, std::string_view phoneCode,
                                       int64_t unixSeconds);
void ValidateTotp(const TotpConfig& config, bool forVpn = false);
std::string GenerateTotp(const TotpConfig& config, int64_t unixSeconds);
std::chrono::system_clock::time_point TotpExpiry(const TotpConfig& config, int64_t unixSeconds);
std::string AlgorithmName(TotpAlgorithm algorithm);

// Production uses UTC system time. Tests inject a deterministic clock and wait
// implementation to cover rollover/cancellation without sleeping.
class ITotpClock {
  public:
    virtual ~ITotpClock() = default;
    virtual std::chrono::system_clock::time_point Now() const = 0;
    virtual void WaitFor(std::chrono::milliseconds duration, std::stop_token cancel) = 0;
};
std::shared_ptr<ITotpClock> SystemTotpClock();

class TotpOtpProvider final : public IOtpProvider {
  public:
    using ConfigLoader = std::function<TotpConfig(const OtpRequest&)>;
    using CounterReader = std::function<std::optional<int64_t>(const OtpRequest&)>;
    using CounterWriter = std::function<void(const OtpRequest&, int64_t)>;
    explicit TotpOtpProvider(ConfigLoader loader, std::shared_ptr<ITotpClock> clock = SystemTotpClock(),
                             CounterReader counterReader = {}, CounterWriter counterWriter = {});
    OneTimeCode GetCode(const OtpRequest& request, std::stop_token cancel) override;

  private:
    ConfigLoader loader_;
    std::shared_ptr<ITotpClock> clock_;
    std::optional<int64_t> lastCounter_;
    CounterReader counterReader_;
    CounterWriter counterWriter_;
};
} // namespace ownvpn
