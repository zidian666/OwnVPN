#include "usage_panel.h"
#include "windows_platform.h"
#include <algorithm>
#include <commctrl.h>
#include <shellapi.h>

namespace ownvpn {
namespace {
constexpr wchar_t kPortalUrl[] = L"https://y2m.knownsec.com/auth/otp/login";
constexpr wchar_t kContent[] = L"1. 从邮件下载 users.pem，下载压缩包解压获得 **.ovpn\n\n"
                               L"2. 导入配置，选择 **.ovpn，随后选择 users.pem\n\n"
                               L"3. 从 <a href=\"https://y2m.knownsec.com/auth/otp/login\">"
                               L"https://y2m.knownsec.com/auth/otp/login</a> 获取二维码\n\n"
                               L"4. 导入二维码\n\n"
                               L"5. 选择自动重连，连接VPN\n\n"
                               L"6. 首次使用公司wifi连接vpn时，如果出现DNS解析失败，可使用其它网络连接vpn，"
                               L"成功连接后可以切换至公司wifi，以后可以使用公司wifi直接连接。"
                               L"（来自公司网络限制）\n"
                               L"如需在DNS解析失败时使用已保存的IP，请勾选“尝试绕过DNS”。";
} // namespace
void UsagePanel::Create(HWND parent, HFONT font) {
    if (window_) {
        return;
    }
    WNDCLASSEXW cls{};
    cls.cbSize = sizeof(cls);
    cls.hInstance = GetModuleHandleW(nullptr);
    cls.lpfnWndProc = WndProc;
    cls.lpszClassName = L"OwnVPN.UsagePanel";
    cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    cls.hbrBackground = static_cast<HBRUSH>(GetStockObject(WHITE_BRUSH));
    if (!RegisterClassExW(&cls) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        throw std::runtime_error("Cannot register usage panel");
    }
    window_ = CreateWindowExW(WS_EX_CONTROLPARENT | WS_EX_CLIENTEDGE, cls.lpszClassName, L"使用说明",
                              WS_CHILD | WS_VSCROLL | WS_CLIPCHILDREN, 0, 0, 0, 0, parent, nullptr,
                              cls.hInstance, this);
    if (!window_) {
        throw std::runtime_error("Cannot create usage panel");
    }
    content_ = CreateWindowExW(0, WC_LINK, kContent, WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, window_,
                               nullptr, cls.hInstance, nullptr);
    if (!content_) {
        throw std::runtime_error("Cannot create usage instructions");
    }
    SetFont(font);
}
void UsagePanel::SetFont(HFONT font) {
    if (!content_) {
        return;
    }
    SendMessageW(content_, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    Layout();
}
void UsagePanel::Layout() {
    if (!content_) {
        return;
    }
    RECT bounds{};
    GetClientRect(window_, &bounds);
    int padding = MulDiv(12, static_cast<int>(GetDpiForWindow(window_)), 96);
    int width = std::max(1, static_cast<int>(bounds.right) - 2 * padding);
    // LM_GETIDEALHEIGHT measures native wrapping at the available width.
    int ideal = static_cast<int>(SendMessageW(content_, LM_GETIDEALHEIGHT, width, 0));
    lineHeight_ = std::max(1, MulDiv(22, static_cast<int>(GetDpiForWindow(window_)), 96));
    contentHeight_ = std::max(ideal, lineHeight_) + 2 * padding;
    offset_ = std::clamp(offset_, 0, std::max(0, contentHeight_ - static_cast<int>(bounds.bottom)));
    SCROLLINFO scroll{sizeof(scroll),
                      SIF_RANGE | SIF_PAGE | SIF_POS,
                      0,
                      contentHeight_ - 1,
                      static_cast<UINT>(std::max<LONG>(0, bounds.bottom)),
                      offset_,
                      0};
    SetScrollInfo(window_, SB_VERT, &scroll, TRUE);
    MoveWindow(content_, padding, padding - offset_, width, std::max(ideal, lineHeight_), TRUE);
}
void UsagePanel::Scroll(int offset) {
    offset_ = offset;
    Layout();
}
LRESULT CALLBACK UsagePanel::WndProc(HWND window, UINT message, WPARAM wp, LPARAM lp) {
    auto self = reinterpret_cast<UsagePanel*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        self = static_cast<UsagePanel*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
        self->window_ = window;
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }
    if (!self) {
        return DefWindowProcW(window, message, wp, lp);
    }
    switch (message) {
    case WM_DPICHANGED_AFTERPARENT:
    case WM_SIZE:
        self->Layout();
        return 0;
    case WM_MOUSEWHEEL:
        self->Scroll(self->offset_ - GET_WHEEL_DELTA_WPARAM(wp) * self->lineHeight_ * 3 / WHEEL_DELTA);
        return 0;
    case WM_VSCROLL: {
        SCROLLINFO info{sizeof(info), SIF_ALL, 0, 0, 0, 0, 0};
        GetScrollInfo(window, SB_VERT, &info);
        int offset = self->offset_;
        switch (LOWORD(wp)) {
        case SB_LINEUP:
            offset -= self->lineHeight_;
            break;
        case SB_LINEDOWN:
            offset += self->lineHeight_;
            break;
        case SB_PAGEUP:
            offset -= static_cast<int>(info.nPage);
            break;
        case SB_PAGEDOWN:
            offset += static_cast<int>(info.nPage);
            break;
        case SB_THUMBTRACK:
            offset = info.nTrackPos;
            break;
        case SB_TOP:
            offset = 0;
            break;
        case SB_BOTTOM:
            offset = self->contentHeight_;
            break;
        }
        self->Scroll(offset);
        return 0;
    }
    case WM_NOTIFY: {
        auto header = reinterpret_cast<NMHDR*>(lp);
        if (header->hwndFrom == self->content_ && (header->code == NM_CLICK || header->code == NM_RETURN)) {
            // Open only our fixed enrollment portal, never a URL taken from
            // imported files, server output or notification-controlled text.
            if (reinterpret_cast<NMLINK*>(lp)->item.iLink == 0) {
                auto result = reinterpret_cast<INT_PTR>(
                    ShellExecuteW(window, L"open", kPortalUrl, nullptr, nullptr, SW_SHOWNORMAL));
                if (result <= 32) {
                    MessageBoxW(window, L"无法打开默认浏览器，请检查浏览器设置。", L"使用说明",
                                MB_OK | MB_ICONINFORMATION);
                }
            }
            return 0;
        }
        break;
    }
    case WM_CTLCOLORSTATIC: {
        auto dc = reinterpret_cast<HDC>(wp);
        SetBkColor(dc, RGB(255, 255, 255));
        SetTextColor(dc, RGB(26, 40, 59));
        return reinterpret_cast<LRESULT>(GetStockObject(WHITE_BRUSH));
    }
    }
    return DefWindowProcW(window, message, wp, lp);
}
} // namespace ownvpn
