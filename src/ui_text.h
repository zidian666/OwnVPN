#pragma once
#include <cstdint>
#include <string>
#include <string_view>

namespace ownvpn {
std::wstring FormatTrafficBytes(uint64_t bytes);
std::wstring CleanUiText(std::wstring_view text);
} // namespace ownvpn
