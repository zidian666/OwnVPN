#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace ownvpn {
// Owns management startup sequencing, independently of TCP packet boundaries
// and the timing of the asynchronous HOLD notification.
class ManagementStartup {
  public:
    explicit ManagementStartup(bool keepHeld = false) : keepHeld_(keepHeld) {}
    std::vector<std::string> OnLine(std::string_view line);
    bool authenticated() const {
        return authenticated_;
    }
    bool heldProbeReady() const {
        return keepHeld_ && authenticated_ && holdSeen_;
    }
    bool progressed() const {
        return progressed_;
    }
    bool releaseConfirmed() const {
        return releaseConfirmed_;
    }

  private:
    bool keepHeld_, authenticated_ = false, holdSeen_ = false, progressed_ = false, releaseConfirmed_ = false;
};
} // namespace ownvpn
