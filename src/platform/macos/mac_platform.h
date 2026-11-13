#pragma once
#include "platform.h"
#include <memory>

namespace ownvpn::mac {
// The app and the explicitly requested Keychain smoke test use separate services.
std::unique_ptr<ISecretStore> CreateSecretStore(std::string service);
std::string DecodeQr(const fs::path& image);
inline constexpr auto Version = "0.6.0-alpha.1";
} // namespace ownvpn::mac
