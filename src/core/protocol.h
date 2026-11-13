#pragma once
#include "otp_provider.h"
#include <memory>

namespace ownvpn {
std::string Base64(std::string_view value);
std::string Base64Decode(std::string_view value);
std::string ManagementQuote(std::string_view value);
// No sockets, processes, windows or persistence in this protocol state machine.
// The engine supplies transport and consumes generated commands/events.
class ManagementProtocol {
  public:
    ManagementProtocol(
        std::string username, std::string password, std::unique_ptr<IOtpProvider> otp, EventSink sink,
        OtpRequest context = {}, std::stop_token cancel = {},
        std::function<std::chrono::system_clock::time_point()> now = std::chrono::system_clock::now);
    ~ManagementProtocol();
    std::vector<std::string> OnLine(std::string_view line);
    bool terminal() const {
        return terminal_;
    }
    bool connected() const {
        return connected_;
    }
    auto authenticationExpiry() const {
        return authenticationExpiry_;
    }

  private:
    std::string username_, password_;
    std::unique_ptr<IOtpProvider> otp_;
    EventSink sink_;
    OtpRequest otpContext_;
    std::stop_token cancel_;
    std::function<std::chrono::system_clock::time_point()> now_;
    bool terminal_ = false, connected_ = false, authenticatedOnce_ = false;
    std::optional<std::chrono::system_clock::time_point> authenticationExpiry_;
    void Fail(std::wstring message);
};
} // namespace ownvpn
