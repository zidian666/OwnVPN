#pragma once
#include "profile.h"
#include "protocol.h"
#include <atomic>
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
// Runs only inside the elevated helper process. No GUI dependencies.
// stopRequested must also return true if its controlling GUI goes away.
enum class EngineMode { Connect, HeldProbe, StartupProbe };
void RunOpenVpn(ConnectionRequest request, std::unique_ptr<IOtpProvider> otp, const EventSink& sink,
                const std::function<bool()>& stopRequested, EngineMode mode = EngineMode::Connect);
int RunElevatedWorker(std::wstring_view pipeName, DWORD expectedParent, std::wstring_view stopEventName);
// Read-only held management handshake against real OpenVPN: does not release
// HOLD, contact a remote server, create an adapter, or change any routes.
bool ProbeManagement(const EventSink& sink, bool releaseStartup = false);
} // namespace ownvpn
