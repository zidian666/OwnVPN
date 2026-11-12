#include "management_startup.h"

namespace ownvpn {
std::vector<std::string> ManagementStartup::OnLine(std::string_view line) {
    if (line.starts_with(">HOLD:")) {
        holdSeen_ = true;
    }
    if (line == "SUCCESS: password is correct" && !authenticated_) {
        authenticated_ = true;
        std::vector<std::string> commands{"state on", "bytecount 1"};
        if (!keepHeld_) {
            // Do not wait for HOLD: its notification may already have been
            // emitted. Clearing the flag also covers HOLD not yet entered.
            commands.push_back("hold off");
            commands.push_back("hold release");
        }
        return commands;
    }
    if (authenticated_) {
        if (line == "SUCCESS: hold release succeeded") {
            releaseConfirmed_ = true;
        }
        if (line.starts_with(">PASSWORD:Need ") || line.starts_with(">STATE:")) {
            progressed_ = true;
        }
    }
    return {};
}
} // namespace ownvpn
