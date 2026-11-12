#pragma once
#include <string>
#include <string_view>
#include <windows.h>

namespace ownvpn {
HICON LoadAppIcon(HINSTANCE instance, bool connected, bool small, UINT dpi);
enum class TrayAction { None, Show, ToggleConnection, Exit };
// UI-thread notification registration and menu; never owns a VPN connection.
class SystemTray {
  public:
    static constexpr UINT Message = WM_APP + 3;
    ~SystemTray();
    void Create(HWND owner, HINSTANCE instance);
    bool EnsurePresent();
    bool Recreate();
    void Update(bool connected, std::wstring_view status, bool active, bool stopping, bool retryPending,
                bool closing);
    TrayAction OnCallback(WPARAM wp, LPARAM lp);
    UINT TaskbarCreatedMessage() const {
        return taskbarCreated_;
    }
    void Remove();

  private:
    HWND owner_ = nullptr;
    HWND menuWindow_ = nullptr;
    HINSTANCE instance_ = nullptr;
    UINT taskbarCreated_ = 0;
    bool present_ = false, version4_ = false, connected_ = false;
    bool active_ = false, stopping_ = false, retryPending_ = false, closing_ = false;
    bool menuOpen_ = false;
    std::wstring tooltip_ = L"OwnVPN 准备连接";
};
} // namespace ownvpn
