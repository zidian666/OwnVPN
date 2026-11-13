#pragma once
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace ownvpn {
namespace fs = std::filesystem;
std::string Utf8(std::wstring_view s);
std::wstring Wide(std::string_view s);
inline fs::path PathFromUtf8(std::string_view s) {
    return fs::path(std::u8string(s.begin(), s.end()));
}
inline std::wstring PathText(const fs::path& path) {
    auto value = path.u8string();
    return Wide(std::string_view(reinterpret_cast<const char*>(value.data()), value.size()));
}
std::string ReadFile(const fs::path& path);
void WriteFile(const fs::path& path, std::string_view data);
void WipeBytes(std::span<unsigned char> data);
void Wipe(std::string& data);
void Wipe(std::wstring& data);
std::string RandomHex(size_t bytes = 16);
std::string Trim(std::string_view s);
void PrivateDirectory(const fs::path& path);
fs::path AppData();

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
