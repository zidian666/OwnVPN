#include "core.h"
#include <fstream>
namespace ownvpn {
std::string ReadFile(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Cannot read file: " + Utf8(PathText(path.filename())));
    }
    in.seekg(0, std::ios::end);
    auto size = in.tellg();
    if (size < 0 || size > 8 * 1024 * 1024) {
        throw std::runtime_error("File exceeds 8 MiB limit");
    }
    in.seekg(0);
    std::string s(static_cast<size_t>(size), '\0');
    if (!s.empty() && !in.read(s.data(), size)) {
        throw std::runtime_error("Cannot read complete file");
    }
    return s;
}
void WriteFile(const fs::path& path, std::string_view data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out || !out.write(data.data(), static_cast<std::streamsize>(data.size()))) {
        throw std::runtime_error("Cannot write file");
    }
}
std::string Trim(std::string_view s) {
    auto b = s.find_first_not_of(" \t\r\n");
    if (b == s.npos) {
        return {};
    }
    return std::string(s.substr(b, s.find_last_not_of(" \t\r\n") - b + 1));
}

void WipeBytes(std::span<unsigned char> data) {
    volatile unsigned char* memory = data.data();
    for (size_t i = 0; i < data.size(); ++i) {
        memory[i] = 0;
    }
}
void Wipe(std::string& value) {
    WipeBytes({reinterpret_cast<unsigned char*>(value.data()), value.size()});
    value.clear();
}
void Wipe(std::wstring& value) {
    WipeBytes({reinterpret_cast<unsigned char*>(value.data()), value.size() * sizeof(wchar_t)});
    value.clear();
}
} // namespace ownvpn
