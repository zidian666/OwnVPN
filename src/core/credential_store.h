#pragma once
#include "core.h"
namespace ownvpn {
struct Credentials {
    std::wstring username;
    std::wstring password;
    std::wstring otp;
    bool rememberPassword = false;
    void ClearSecrets() {
        Wipe(password);
        Wipe(otp);
    }
};
Credentials LoadCredentials(std::wstring_view profileId);
void SaveCredentials(std::wstring_view profileId, const Credentials& credentials);
void DeleteLegacyOtp(std::wstring_view profileId);
void DeleteCredentials(std::wstring_view profileId);
std::wstring ReadProtectedValue(std::wstring_view profileId, std::wstring_view field);
void StoreProtectedValue(std::wstring_view profileId, std::wstring_view field, std::wstring_view value);

} // namespace ownvpn
