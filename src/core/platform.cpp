#include "platform.h"
#include "credential_store.h"
#include "dns_fallback.h"

namespace ownvpn {
std::string RandomHex(size_t bytes) {
    std::vector<unsigned char> data(bytes);
    Platform().crypto.RandomBytes(data);
    constexpr char hex[] = "0123456789abcdef";
    std::string value;
    value.reserve(bytes * 2);
    for (auto byte : data) {
        value += hex[byte >> 4];
        value += hex[byte & 15];
    }
    WipeBytes(data);
    return value;
}
void PrivateDirectory(const fs::path& path) {
    Platform().paths.MakePrivateDirectory(path);
}
fs::path AppData() {
    return Platform().paths.DataDirectory();
}
std::wstring ReadProtectedValue(std::wstring_view profile, std::wstring_view field) {
    return Platform().secrets.Read(profile, field);
}
void StoreProtectedValue(std::wstring_view profile, std::wstring_view field, std::wstring_view value) {
    Platform().secrets.Write(profile, field, value);
}
std::vector<std::string> ResolveEndpoint(const std::string& host, int family,
                                         const std::function<bool()>& cancelled) {
    return Platform().network.Resolve(host, family, cancelled);
}
} // namespace ownvpn
