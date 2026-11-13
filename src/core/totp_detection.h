#pragma once
#include "totp.h"
namespace ownvpn {
enum class DetectionState { NoMatch, AwaitNextCode, SameWindow, Confirmed, Ambiguous };
struct TotpDetection {
    DetectionState state;
    std::vector<TotpMatch> candidates;
};
// Two local observations identify parameters; no OTP text is retained. A PC
// boundary crossing alone does not turn the same phone counter into a new round.
class TotpParameterDetector {
  public:
    TotpDetection Observe(const TotpConfig& config, std::string_view code, int64_t unixSeconds);
    void Reset();
    ~TotpParameterDetector() {
        Reset();
    }

  private:
    struct Observation {
        TotpMatch match;
        int64_t phoneCounter;
    };
    std::string seed_;
    std::vector<Observation> previous_;
};
} // namespace ownvpn
