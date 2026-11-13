#pragma once
#include <chrono>
#include <optional>

namespace ownvpn {
// Connection-independent retry timing. User disconnect and authentication
// rejection cancel the policy; every retry obtains fresh credentials/OTP.
class ReconnectPolicy {
  public:
    using Clock = std::chrono::steady_clock;
    bool Schedule(Clock::time_point now);
    void Cancel();
    void Connected(Clock::time_point now);
    void AttemptStarted();
    bool pending() const {
        return next_.has_value();
    }
    bool Due(Clock::time_point now) const;
    int Remaining(Clock::time_point now) const;

  private:
    unsigned failures_ = 0;
    std::optional<Clock::time_point> next_, connected_;
};
} // namespace ownvpn
