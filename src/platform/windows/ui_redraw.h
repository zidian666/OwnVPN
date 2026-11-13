#pragma once
#include "windows_platform.h"
#include <windows.h>

namespace ownvpn {
// Keep a DPI/layout transition visually atomic, then repaint both the parent
// canvas and native child frames. Preserve hidden-window visibility.
class ScopedUiRedraw {
  public:
    explicit ScopedUiRedraw(HWND window) : window_(window), visible_(IsWindowVisible(window) != FALSE) {
        if (visible_) {
            SendMessageW(window_, WM_SETREDRAW, FALSE, 0);
        }
    }
    ~ScopedUiRedraw() {
        if (visible_) {
            SendMessageW(window_, WM_SETREDRAW, TRUE, 0);
            RedrawWindow(window_, nullptr, nullptr,
                         RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN | RDW_UPDATENOW);
        }
    }
    ScopedUiRedraw(const ScopedUiRedraw&) = delete;
    ScopedUiRedraw& operator=(const ScopedUiRedraw&) = delete;

  private:
    HWND window_;
    bool visible_;
};
} // namespace ownvpn
