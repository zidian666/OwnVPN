#pragma once
#include "profile.h"
#include <memory>
namespace ownvpn {
struct ConnectionRequest {
    ConnectionRequest() = default;
    ConnectionRequest(const ConnectionRequest&) = delete;
    ConnectionRequest& operator=(const ConnectionRequest&) = delete;
    ConnectionRequest(ConnectionRequest&&) noexcept = default;
    ConnectionRequest& operator=(ConnectionRequest&&) noexcept = default;
    Profile profile;
    std::string username;
    std::string password;
    std::string otp;
    bool automaticOtp = false;
    bool dnsFallback = false;
    ~ConnectionRequest() {
        Wipe(password);
        Wipe(otp);
    }
};

class IConnectionBackend {
  public:
    virtual ~IConnectionBackend() = default;
    virtual bool Start(ConnectionRequest request) = 0;
    virtual void Stop() = 0;
    virtual bool active() const = 0;
    virtual bool stopping() const = 0;
    virtual bool authorized() const = 0;
};
} // namespace ownvpn
