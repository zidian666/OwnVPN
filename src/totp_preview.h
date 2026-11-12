#pragma once
#include "totp.h"
namespace ownvpn {
// A read-only preview: never reserves/consumes an authentication counter.
class TotpPreview {
  public:
    using Loader = std::function<TotpConfig(const OtpRequest&)>;
    explicit TotpPreview(Loader loader) : loader_(std::move(loader)) {}
    std::wstring Code(const OtpRequest& request, int periodSeconds, int64_t unixSeconds);
    void Reset();
    ~TotpPreview() {
        Reset();
    }

  private:
    Loader loader_;
    std::wstring profile_, username_, code_;
    std::optional<int64_t> counter_;
    int period_ = 0;
};
} // namespace ownvpn
