#include "platform.h"
#include "windows_platform.h"
#include <sddl.h>
#include <shlobj.h>
namespace ownvpn {
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
static void WindowsPrivateDirectory(const fs::path& path) {
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
static fs::path WindowsAppData() {
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

namespace {
class WindowsPaths final : public IPlatformPaths {
  public:
    fs::path DataDirectory() const override {
        return WindowsAppData();
    }
    void MakePrivateDirectory(const fs::path& path) const override {
        WindowsPrivateDirectory(path);
    }
};
} // namespace
IPlatformPaths& WindowsPathServices() {
    static WindowsPaths paths;
    return paths;
}
} // namespace ownvpn
