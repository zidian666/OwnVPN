#include "reconnect_policy.h"
#include <algorithm>

namespace ownvpn {
bool ReconnectPolicy::Schedule(Clock::time_point now) {
    if (next_) {
        return false;
    }
    if (connected_ && now - *connected_ >= std::chrono::seconds(60)) {
        failures_ = 0;
    }
    connected_.reset();
    auto delay = std::chrono::seconds(std::min(30u, 3u << std::min(failures_, 4u)));
    failures_ = std::min(failures_ + 1, 5u);
    next_ = now + delay;
    return true;
}
void ReconnectPolicy::Cancel() {
    next_.reset();
    connected_.reset();
    failures_ = 0;
}
void ReconnectPolicy::Connected(Clock::time_point now) {
    next_.reset();
    connected_ = now;
}
void ReconnectPolicy::AttemptStarted() {
    next_.reset();
}
bool ReconnectPolicy::Due(Clock::time_point now) const {
    return next_ && now >= *next_;
}
int ReconnectPolicy::Remaining(Clock::time_point now) const {
    if (!next_ || now >= *next_) {
        return 0;
    }
    return static_cast<int>(std::chrono::ceil<std::chrono::seconds>(*next_ - now).count());
}
} // namespace ownvpn
