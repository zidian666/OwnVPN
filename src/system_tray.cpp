#include "system_tray.h"
#include "../resources/resource.h"
#include "ui_text.h"
#include <algorithm>
#include <shellapi.h>
#include <windowsx.h>

namespace ownvpn {
HICON LoadAppIcon(HINSTANCE instance, bool connected, bool small, UINT dpi) {
    return static_cast<HICON>(
        LoadImageW(instance, MAKEINTRESOURCEW(connected ? IDI_OWNVPN_CONNECTED : IDI_OWNVPN), IMAGE_ICON,
                   GetSystemMetricsForDpi(small ? SM_CXSMICON : SM_CXICON, dpi),
                   GetSystemMetricsForDpi(small ? SM_CYSMICON : SM_CYICON, dpi), LR_SHARED));
}
namespace {
NOTIFYICONDATAW Data(HWND owner) {
    NOTIFYICONDATAW data{};
    data.cbSize = sizeof(data);
    data.hWnd = owner;
    data.uID = 1;
    return data;
}
void SetPresentation(NOTIFYICONDATAW& data, HINSTANCE instance, bool connected, const std::wstring& tooltip) {
    data.uFlags = NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    data.hIcon = LoadAppIcon(instance, connected, true, GetDpiForSystem());
    std::copy_n(tooltip.data(), std::min(tooltip.size(), std::size(data.szTip) - 1), data.szTip);
}
} // namespace
SystemTray::~SystemTray() {
    Remove();
}
void SystemTray::Create(HWND owner, HINSTANCE instance) {
    owner_ = owner;
    instance_ = instance;
    taskbarCreated_ = RegisterWindowMessageW(L"TaskbarCreated");
    EnsurePresent();
}
bool SystemTray::EnsurePresent() {
    if (present_) {
        return true;
    }
    if (!owner_) {
        return false;
    }
    auto data = Data(owner_);
    SetPresentation(data, instance_, connected_, tooltip_);
    data.uFlags |= NIF_MESSAGE;
    data.uCallbackMessage = Message;
    if (!data.hIcon || !Shell_NotifyIconW(NIM_ADD, &data)) {
        return false;
    }
    present_ = true;
    data.uVersion = NOTIFYICON_VERSION_4;
    version4_ = Shell_NotifyIconW(NIM_SETVERSION, &data) != FALSE;
    return true;
}
bool SystemTray::Recreate() {
    present_ = false;
    return EnsurePresent();
}
void SystemTray::Update(bool connected, std::wstring_view status, bool active, bool stopping,
                        bool retryPending, bool closing) {
    active_ = active;
    stopping_ = stopping;
    retryPending_ = retryPending;
    closing_ = closing;
    auto text = L"OwnVPN " + CleanUiText(status);
    if (connected_ == connected && tooltip_ == text) {
        return;
    }
    connected_ = connected;
    tooltip_ = std::move(text);
    if (!owner_) {
        return;
    }
    if (!present_) {
        EnsurePresent();
        return;
    }
    auto data = Data(owner_);
    SetPresentation(data, instance_, connected_, tooltip_);
    if (!Shell_NotifyIconW(NIM_MODIFY, &data)) {
        present_ = false;
        EnsurePresent();
    }
}
TrayAction SystemTray::OnCallback(WPARAM wp, LPARAM lp) {
    auto event = version4_ ? LOWORD(lp) : static_cast<UINT>(lp);
    if (event == NIN_SELECT || event == NIN_KEYSELECT || event == WM_LBUTTONDBLCLK) {
        return TrayAction::Show;
    }
    if ((event != WM_CONTEXTMENU && event != WM_RBUTTONUP) || menuOpen_) {
        return TrayAction::None;
    }
    NOTIFYICONIDENTIFIER identifier{};
    identifier.cbSize = sizeof(identifier);
    identifier.hWnd = owner_;
    identifier.uID = 1;
    RECT iconBounds{};
    bool haveIconBounds = SUCCEEDED(Shell_NotifyIconGetRect(&identifier, &iconBounds));
    POINT position{GET_X_LPARAM(wp), GET_Y_LPARAM(wp)};
    if (!version4_ || (position.x == -1 && position.y == -1)) {
        if (haveIconBounds) {
            position = {iconBounds.left, iconBounds.top};
        } else {
            GetCursorPos(&position);
        }
    }
    auto menu = CreatePopupMenu();
    if (!menu) {
        return TrayAction::None;
    }
    // The main window may be hidden or minimized. Give the menu its own
    // visible, zero-size topmost owner so it stays above the tray flyout.
    // Do not promote or restore the main window just to display a menu.
    if (!menuWindow_) {
        menuWindow_ = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_TOPMOST, L"STATIC", L"", WS_POPUP, position.x,
                                      position.y, 0, 0, nullptr, nullptr, instance_, nullptr);
    }
    if (!menuWindow_) {
        DestroyMenu(menu);
        return TrayAction::None;
    }
    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, tooltip_.c_str());
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, 1, L"显示主界面");
    AppendMenuW(menu, MF_STRING | ((stopping_ || closing_) ? MF_GRAYED : 0), 3,
                retryPending_ ? L"取消自动重连" : (active_ ? L"断开连接" : L"连接 VPN"));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, 2, L"退出");
    SetMenuDefaultItem(menu, 1, FALSE);
    SetWindowPos(menuWindow_, HWND_TOPMOST, position.x, position.y, 0, 0, SWP_NOACTIVATE | SWP_SHOWWINDOW);
    SetForegroundWindow(menuWindow_);
    TPMPARAMS parameters{sizeof(parameters), iconBounds};
    menuOpen_ = true;
    auto command =
        TrackPopupMenuEx(menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON | TPM_VERTICAL, position.x,
                         position.y, menuWindow_, haveIconBounds ? &parameters : nullptr);
    menuOpen_ = false;
    DestroyMenu(menu);
    PostMessageW(menuWindow_, WM_NULL, 0, 0);
    ShowWindow(menuWindow_, SW_HIDE);
    if (command == 1) {
        return TrayAction::Show;
    }
    if (command == 3 && !stopping_ && !closing_) {
        return TrayAction::ToggleConnection;
    }
    if (command == 2) {
        return TrayAction::Exit;
    }
    auto data = Data(owner_);
    Shell_NotifyIconW(NIM_SETFOCUS, &data);
    return TrayAction::None;
}
void SystemTray::Remove() {
    if (menuWindow_) {
        DestroyWindow(menuWindow_);
        menuWindow_ = nullptr;
    }
    if (present_) {
        auto data = Data(owner_);
        Shell_NotifyIconW(NIM_DELETE, &data);
    }
    present_ = false;
}
} // namespace ownvpn
