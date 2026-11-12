#pragma once
#include <filesystem>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <windows.h>

namespace ownvpn {
namespace fs = std::filesystem;
std::string Utf8(std::wstring_view s);
std::wstring Wide(std::string_view s);
inline fs::path PathFromUtf8(std::string_view s) {
    return fs::path(Wide(s));
}
std::string ReadFile(const fs::path& path);
void WriteFile(const fs::path& path, std::string_view data);
void Wipe(std::string& data);
void Wipe(std::wstring& data);
std::string RandomHex(size_t bytes = 16);
std::wstring WinError(DWORD error = GetLastError());
std::string Trim(std::string_view s);
std::wstring QuoteArg(std::wstring_view s);
std::wstring CurrentSid();
void PrivateDirectory(const fs::path& path);
fs::path AppData();
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

enum class EventType : uint32_t {
    Status = 1,
    Connected,
    Failed,
    Stopped,
    Traffic,
    Diagnostic,
    NeedOtp,
    RetryBlocked,
    ConnectionLost
};
struct Event {
    EventType type;
    std::wstring text;
};
using EventSink = std::function<void(Event)>;
} // namespace ownvpn
