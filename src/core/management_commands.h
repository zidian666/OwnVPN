#pragma once
#include "core.h"
#include <chrono>
#include <deque>

namespace ownvpn {
// One in-flight command at a time. Asynchronous notifications cannot advance
// the queue; credentials are never replayed after an ambiguous response.
class ManagementCommands {
  public:
    ~ManagementCommands();
    void Enqueue(std::vector<std::string> commands,
                 std::optional<std::chrono::system_clock::time_point> expiry = {});
    bool OnLine(std::string_view line);
    std::optional<std::string>
    TakeNext(std::chrono::system_clock::time_point now = std::chrono::system_clock::now());
    bool waiting() const {
        return !ack_.empty();
    }

  private:
    struct Command {
        std::string text, ack;
        std::optional<std::chrono::system_clock::time_point> expiry;
    };
    std::deque<Command> queue_;
    std::string ack_;
};
} // namespace ownvpn
