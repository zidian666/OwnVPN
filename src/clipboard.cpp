#include "clipboard.h"
#include <cstring>

namespace ownvpn {
bool CopyTextToClipboard(HWND owner, std::wstring_view text) {
    if (text.empty()) {
        return false;
    }
    const auto size = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL allocation = GlobalAlloc(GMEM_MOVEABLE, size);
    if (!allocation) {
        return false;
    }
    auto memory = static_cast<wchar_t*>(GlobalLock(allocation));
    if (!memory) {
        GlobalFree(allocation);
        return false;
    }
    memcpy(memory, text.data(), text.size() * sizeof(wchar_t));
    memory[text.size()] = L'\0';
    GlobalUnlock(allocation);
    bool copied = false;
    if (OpenClipboard(owner)) {
        copied = EmptyClipboard() && SetClipboardData(CF_UNICODETEXT, allocation);
        CloseClipboard();
    }
    if (!copied) {
        if (auto data = GlobalLock(allocation)) {
            SecureZeroMemory(data, size);
            GlobalUnlock(allocation);
        }
        GlobalFree(allocation);
    }
    return copied;
}
} // namespace ownvpn
