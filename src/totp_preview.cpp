#include "totp_preview.h"
namespace ownvpn {
std::wstring TotpPreview::Code(const OtpRequest& request, int periodSeconds, int64_t unixSeconds) {
    if (periodSeconds < 10 || periodSeconds > 300 || unixSeconds < 0) {
        throw std::runtime_error("Invalid preview time parameters");
    }
    auto counter = unixSeconds / periodSeconds;
    if (!counter_ || *counter_ != counter || profile_ != request.profileId || username_ != request.username ||
        period_ != periodSeconds) {
        auto config = loader_(request);
        ValidateTotp(config, true);
        auto value = GenerateTotp(config, unixSeconds);
        Wipe(code_);
        code_ = Wide(value);
        Wipe(value);
        profile_ = request.profileId;
        username_ = request.username;
        period_ = periodSeconds;
        counter_ = counter;
    }
    return code_;
}
void TotpPreview::Reset() {
    Wipe(code_);
    profile_.clear();
    username_.clear();
    counter_.reset();
    period_ = 0;
}
} // namespace ownvpn
