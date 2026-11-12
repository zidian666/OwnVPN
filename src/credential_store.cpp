#include "credential_store.h"
#include <wincred.h>
namespace ownvpn {
static std::wstring Target(std::wstring_view id, std::wstring_view field) {
    return L"OwnVPN/" + std::wstring(id) + L"/" + std::wstring(field);
}
std::wstring ReadProtectedValue(std::wstring_view id, std::wstring_view field) {
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
void StoreProtectedValue(std::wstring_view id, std::wstring_view field, std::wstring_view value) {
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
Credentials LoadCredentials(std::wstring_view id) {
    Credentials c;
    c.username = ReadProtectedValue(id, L"username");
    c.password = ReadProtectedValue(id, L"password");
    DeleteLegacyOtp(id);
    c.rememberPassword = !c.password.empty();
    return c;
}
void SaveCredentials(std::wstring_view id, const Credentials& c) {
    StoreProtectedValue(id, L"username", c.username);
    StoreProtectedValue(id, L"password", c.rememberPassword ? c.password : L"");
    DeleteLegacyOtp(id);
}
void DeleteLegacyOtp(std::wstring_view id) {
    StoreProtectedValue(id, L"otp", L"");
}
void DeleteCredentials(std::wstring_view id) {
    for (auto field : {L"username", L"password", L"otp"}) {
        StoreProtectedValue(id, field, L"");
    }
}
} // namespace ownvpn
