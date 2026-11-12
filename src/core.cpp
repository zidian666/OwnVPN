#include "core.h"
#include <bcrypt.h>
#include <fstream>
#include <sddl.h>
#include <shlobj.h>
#include <sstream>
#include <wincred.h>

namespace ownvpn {
std::string Utf8(std::wstring_view s) {
    if (s.empty()) {
        return {};
    }
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr,
                                0, nullptr, nullptr);
    if (!n) {
        throw std::runtime_error("Invalid Unicode text");
    }
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n,
                        nullptr, nullptr);
    return out;
}
std::wstring Wide(std::string_view s) {
    if (s.empty()) {
        return {};
    }
    int n =
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (!n) {
        return L"无法解码文本";
    }
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}
std::string ReadFile(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Cannot read file: " + Utf8(path.filename().wstring()));
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
void Wipe(std::string& s) {
    if (!s.empty()) {
        SecureZeroMemory(s.data(), s.size());
    }
    s.clear();
}
void Wipe(std::wstring& s) {
    if (!s.empty()) {
        SecureZeroMemory(s.data(), s.size() * sizeof(wchar_t));
    }
    s.clear();
}
std::string RandomHex(size_t bytes) {
    std::vector<unsigned char> data(bytes);
    if (BCryptGenRandom(nullptr, data.data(), static_cast<ULONG>(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) <
        0) {
        throw std::runtime_error("Random number generator failed");
    }
    const char* hex = "0123456789abcdef";
    std::string s;
    for (auto c : data) {
        s += hex[c >> 4];
        s += hex[c & 15];
    }
    return s;
}
std::wstring WinError(DWORD error) {
    wchar_t* message = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, error, 0, reinterpret_cast<LPWSTR>(&message), 0, nullptr);
    std::wstring s = message ? message : L"Windows 操作失败";
    if (message) {
        LocalFree(message);
    }
    return s;
}
std::string Trim(std::string_view s) {
    auto b = s.find_first_not_of(" \t\r\n");
    if (b == s.npos) {
        return {};
    }
    return std::string(s.substr(b, s.find_last_not_of(" \t\r\n") - b + 1));
}
std::wstring QuoteArg(std::wstring_view s) {
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (auto c : s) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        if (c == L'\"') {
            out.append(slashes * 2 + 1, L'\\');
        } else {
            out.append(slashes, L'\\');
        }
        slashes = 0;
        out += c;
    }
    out.append(slashes * 2, L'\\');
    out += L'\"';
    return out;
}
std::wstring CurrentSid() {
    Handle token;
    HANDLE t;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
        throw std::runtime_error("Cannot query user token");
    }
    token.reset(t);
    DWORD n = 0;
    GetTokenInformation(t, TokenUser, nullptr, 0, &n);
    std::vector<char> bytes(n);
    if (!GetTokenInformation(t, TokenUser, bytes.data(), n, &n)) {
        throw std::runtime_error("Cannot query user SID");
    }
    wchar_t* sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid, &sid)) {
        throw std::runtime_error("Cannot format user SID");
    }
    std::wstring s(sid);
    LocalFree(sid);
    return s;
}
void PrivateDirectory(const fs::path& path) {
    fs::create_directories(path);
    auto acl = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + CurrentSid() + L")";
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
        throw std::runtime_error("Cannot construct private directory ACL");
    }
    BOOL ok =
        SetFileSecurityW(path.c_str(), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd);
    LocalFree(sd);
    if (!ok) {
        throw std::runtime_error("Cannot protect private directory");
    }
}
fs::path AppData() {
    PWSTR p = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &p))) {
        throw std::runtime_error("Cannot locate LocalAppData");
    }
    fs::path path = fs::path(p) / L"OwnVPN";
    CoTaskMemFree(p);
    return path;
}
fs::path Executable() {
    std::wstring p(32768, L'\0');
    DWORD n = GetModuleFileNameW(nullptr, p.data(), static_cast<DWORD>(p.size()));
    if (!n || n >= p.size()) {
        throw std::runtime_error("Cannot locate executable");
    }
    p.resize(n);
    return p;
}
fs::path OpenVpnExecutable() {
    // Program Files is the trusted installation location; never search CWD/PATH.
    for (const auto id : {FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86}) {
        PWSTR p = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(id, 0, nullptr, &p))) {
            fs::path candidate = fs::path(p) / L"OpenVPN" / L"bin" / L"openvpn.exe";
            CoTaskMemFree(p);
            if (fs::is_regular_file(candidate)) {
                return candidate;
            }
        }
    }
    return {};
}
bool IsAdmin() {
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID group = nullptr;
    BOOL yes = FALSE;
    if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0,
                                 0, 0, 0, &group)) {
        CheckTokenMembership(nullptr, group, &yes);
        FreeSid(group);
    }
    return yes;
}
} // namespace ownvpn
