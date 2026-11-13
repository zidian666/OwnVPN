#pragma once
#include "mac_platform.h"

namespace ownvpn::mac {
class Crypto final : public ICryptoProvider {
  public:
    std::vector<unsigned char> Hmac(HashAlgorithm, std::span<const unsigned char>,
                                    std::span<const unsigned char>) const override;
    std::vector<unsigned char> Digest(HashAlgorithm, std::span<const unsigned char>) const override;
    void RandomBytes(std::span<unsigned char>) const override;
};
class Paths final : public IPlatformPaths {
  public:
    fs::path DataDirectory() const override;
    void MakePrivateDirectory(const fs::path&) const override;
};
class Network final : public INetworkServices {
  public:
    int IpFamily(const std::string&) const override;
    std::vector<std::string> Resolve(const std::string&, int, const std::function<bool()>&) const override;
};
} // namespace ownvpn::mac
