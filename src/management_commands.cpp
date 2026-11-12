#include "management_commands.h"

namespace ownvpn {
namespace {
std::string ExpectedAck(std::string_view command) {
    if (command == "state on") {
        return "SUCCESS: real-time state notification set to ON";
    }
    if (command == "bytecount 1") {
        return "SUCCESS: bytecount interval changed";
    }
    if (command == "hold off") {
        return "SUCCESS: hold flag set to OFF";
    }
    if (command == "hold release") {
        return "SUCCESS: hold release succeeded";
    }
    if (command.starts_with("username \"Auth\" ")) {
        return "SUCCESS: 'Auth' username entered, but not yet verified";
    }
    if (command.starts_with("password \"Auth\" ")) {
        return "SUCCESS: 'Auth' password entered, but not yet verified";
    }
    throw std::runtime_error("Unsupported management command");
}
} // namespace
ManagementCommands::~ManagementCommands() {
    for (auto& command : queue_) {
        Wipe(command.text);
    }
}
void ManagementCommands::Enqueue(std::vector<std::string> commands,
                                 std::optional<std::chrono::system_clock::time_point> expiry) {
    struct Guard {
        std::vector<std::string>& commands;
        ~Guard() {
            for (auto& command : commands) {
                Wipe(command);
            }
        }
    } guard{commands};
    if (queue_.size() + commands.size() > 8) {
        throw std::runtime_error("Management command queue exceeded limit");
    }
    for (auto& command : commands) {
        auto ack = ExpectedAck(command);
        queue_.push_back({command, std::move(ack), expiry});
    }
}
bool ManagementCommands::OnLine(std::string_view line) {
    if (ack_.empty() || line != ack_) {
        return false;
    }
    ack_.clear();
    return true;
}
std::optional<std::string> ManagementCommands::TakeNext(std::chrono::system_clock::time_point now) {
    if (waiting() || queue_.empty()) {
        return {};
    }
    auto& next = queue_.front();
    if (next.expiry && now >= *next.expiry) {
        throw std::runtime_error("Authentication code expired before command submission");
    }
    std::string result = next.text;
    Wipe(next.text);
    ack_ = std::move(next.ack);
    queue_.pop_front();
    return result;
}
} // namespace ownvpn
