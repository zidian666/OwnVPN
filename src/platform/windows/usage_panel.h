#pragma once
#include "windows_platform.h"
#include "core.h"

namespace ownvpn {
// Collapsible help content with native link keyboard navigation and scrolling.
class UsagePanel {
  public:
    void Create(HWND parent, HFONT font);
    HWND window() const {
        return window_;
    }
    void SetFont(HFONT font);
    bool HasFocus() const {
        return window_ && IsChild(window_, GetFocus());
    }

  private:
    HWND window_ = nullptr, content_ = nullptr;
    int offset_ = 0, contentHeight_ = 0, lineHeight_ = 20;
    void Layout();
    void Scroll(int offset);
    static LRESULT CALLBACK WndProc(HWND window, UINT message, WPARAM wp, LPARAM lp);
};
} // namespace ownvpn
