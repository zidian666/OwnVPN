#pragma once
#include "totp_store.h"
namespace ownvpn {
// Returns true only after saving or explicitly deleting a binding.
bool ShowOtpSetupDialog(HWND owner, std::wstring profileId, std::wstring username);
} // namespace ownvpn
