#pragma once
#include "windows_platform.h"
#include <string_view>
#include <windows.h>

namespace ownvpn {
// On success Windows owns the Unicode clipboard allocation.
bool CopyTextToClipboard(HWND owner, std::wstring_view text);
} // namespace ownvpn
