#pragma once
#include "windows_platform.h"
#include "engine.h"
#include "ipc.h"
#include <thread>

namespace ownvpn {
// UI-side controller: owns one helper, authenticated IPC and an event pump.
// The UI remains unprivileged; only the tunnel helper requests elevation.
class ConnectionController final : public IConnectionBackend {
  public:
    using HelperLauncher = std::function<Handle(HWND, const std::wstring&, const std::wstring&)>;
    explicit ConnectionController(EventSink sink, HelperLauncher launcher = {},
                                  std::chrono::milliseconds startupTimeout = std::chrono::seconds(30),
                                  HWND owner = nullptr)
        : sink_(std::move(sink)), launcher_(std::move(launcher)), startupTimeout_(startupTimeout),
          owner_(owner) {}
    ~ConnectionController();
    bool Start(HWND owner, ConnectionRequest request);
    bool Start(ConnectionRequest request) override {
        return Start(owner_, std::move(request));
    }
    void Stop() override;
    bool active() const override {
        return active_;
    }
    bool stopping() const override {
        return stopping_;
    }
    bool authorized() const override {
        return sessionReady_ && helper_.valid() && WaitForSingleObject(helper_.value, 0) == WAIT_TIMEOUT;
    }

  private:
    EventSink sink_;
    HelperLauncher launcher_;
    std::chrono::milliseconds startupTimeout_;
    HWND owner_ = nullptr;
    Handle pipe_, helper_, stopEvent_;
    std::thread reader_;
    std::atomic<bool> active_ = false, stopping_ = false, sessionReady_ = false;
    void Pump(ConnectionRequest request, DWORD helperId, bool reuse);
    void CloseSession();
};
std::unique_ptr<IConnectionBackend> CreateWindowsConnectionBackend(HWND owner, EventSink sink);
} // namespace ownvpn
