#include "platform.h"
#include "windows_platform.h"
#include <wincred.h>
namespace ownvpn {
static std::wstring Target(std::wstring_view id, std::wstring_view field) {
    return L"OwnVPN/" + std::wstring(id) + L"/" + std::wstring(field);
}
static std::wstring ReadWindowsValue(std::wstring_view id, std::wstring_view field) {
    PCREDENTIALW c = nullptr;
    auto target = Target(id, field);
    if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &c)) {
        return {};
    }
    std::wstring s(reinterpret_cast<wchar_t*>(c->CredentialBlob), c->CredentialBlobSize / sizeof(wchar_t));
    if (c->CredentialBlobSize) {
        SecureZeroMemory(c->CredentialBlob, c->CredentialBlobSize);
    }
    CredFree(c);
    return s;
}
static void WriteWindowsValue(std::wstring_view id, std::wstring_view field, std::wstring_view value) {
    auto target = Target(id, field);
    if (value.empty()) {
        CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0);
        return;
    }
    if (value.size() * sizeof(wchar_t) > CRED_MAX_CREDENTIAL_BLOB_SIZE) {
        throw std::runtime_error("Credential is too long");
    }
    CREDENTIALW c{};
    c.Type = CRED_TYPE_GENERIC;
    c.TargetName = target.data();
    c.Persist = CRED_PERSIST_LOCAL_MACHINE;
    c.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<wchar_t*>(value.data()));
    c.CredentialBlobSize = static_cast<DWORD>(value.size() * sizeof(wchar_t));
    if (!CredWriteW(&c, 0)) {
        throw std::runtime_error("Cannot save Windows credential");
    }
}

namespace {
class WindowsSecretStore final : public ISecretStore {
  public:
    std::wstring Read(std::wstring_view id, std::wstring_view field) const override {
        return ReadWindowsValue(id, field);
    }
    void Write(std::wstring_view id, std::wstring_view field, std::wstring_view value) override {
        WriteWindowsValue(id, field, value);
    }
};
} // namespace
ISecretStore& WindowsSecretServices() {
    static WindowsSecretStore store;
    return store;
}
} // namespace ownvpn
