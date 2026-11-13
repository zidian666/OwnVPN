#include "credential_store.h"
namespace ownvpn {
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
