#pragma once
#include "core.h"
namespace ownvpn {
// Only non-secret settings go into this file. Password/OTP are Windows credentials.
struct Settings {
    std::wstring profileId;
    static Settings Load();
    void Save() const;
};
} // namespace ownvpn
