#pragma once
#include "core.h"
#include <chrono>
#include <stop_token>

namespace ownvpn {
struct OtpRequest {
    std::wstring profileId;
    std::wstring username;
    std::wstring challenge;
};
struct OneTimeCode {
    std::string value;
    ~OneTimeCode() {
        Wipe(value);
    }
    // A future provider can supply its real expiry; a manually entered code has
    // no known expiry. Never invent a 30/60-second validity period.
    std::optional<std::chrono::system_clock::time_point> expiresAt;
};
class IOtpProvider {
  public:
    virtual ~IOtpProvider() = default;
    virtual OneTimeCode GetCode(const OtpRequest& request, std::stop_token cancel) = 0;
};
class ManualOtpProvider final : public IOtpProvider {
  public:
    explicit ManualOtpProvider(std::string code) : code_(std::move(code)) {}
    ~ManualOtpProvider() override {
        Wipe(code_);
    }
    OneTimeCode GetCode(const OtpRequest&, std::stop_token cancel) override {
        if (cancel.stop_requested()) {
            throw std::runtime_error("OTP request cancelled");
        }
        if (used_) {
            throw std::runtime_error("A fresh OTP is required; reconnect with a new code");
        }
        if (code_.size() != 6 || code_.find_first_not_of("0123456789") != code_.npos) {
            throw std::runtime_error("OTP must contain exactly six digits");
        }
        used_ = true;
        OneTimeCode result{code_, std::nullopt};
        Wipe(code_);
        return result;
    }

  private:
    std::string code_;
    bool used_ = false;
};
} // namespace ownvpn
