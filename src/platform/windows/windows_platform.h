#pragma once
#include "core.h"
#include <windows.h>
namespace ownvpn {
std::wstring WinError(DWORD error = GetLastError());
std::wstring QuoteArg(std::wstring_view value);
std::wstring CurrentSid();
fs::path Executable();
fs::path OpenVpnExecutable();
bool IsAdmin();
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    Handle() = default;
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() {
        reset();
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value(other.release()) {}
    Handle& operator=(Handle&& other) noexcept {
        reset(other.release());
        return *this;
    }
    bool valid() const {
        return value && value != INVALID_HANDLE_VALUE;
    }
    HANDLE release() {
        HANDLE h = value;
        value = INVALID_HANDLE_VALUE;
        return h;
    }
    void reset(HANDLE h = INVALID_HANDLE_VALUE) {
        if (valid()) {
            CloseHandle(value);
        }
        value = h;
    }
};

} // namespace ownvpn
