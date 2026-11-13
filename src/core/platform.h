#pragma once
#include "core.h"

namespace ownvpn {
enum class HashAlgorithm { Sha1, Sha256, Sha512 };
class ICryptoProvider {
  public:
    virtual ~ICryptoProvider() = default;
    virtual std::vector<unsigned char> Hmac(HashAlgorithm algorithm, std::span<const unsigned char> key,
                                            std::span<const unsigned char> message) const = 0;
    virtual std::vector<unsigned char> Digest(HashAlgorithm algorithm,
                                              std::span<const unsigned char> input) const = 0;
    virtual void RandomBytes(std::span<unsigned char> output) const = 0;
};
class ISecretStore {
  public:
    virtual ~ISecretStore() = default;
    virtual std::wstring Read(std::wstring_view profile, std::wstring_view field) const = 0;
    virtual void Write(std::wstring_view profile, std::wstring_view field, std::wstring_view value) = 0;
};
class IPlatformPaths {
  public:
    virtual ~IPlatformPaths() = default;
    virtual fs::path DataDirectory() const = 0;
    virtual void MakePrivateDirectory(const fs::path& path) const = 0;
};
class INetworkServices {
  public:
    virtual ~INetworkServices() = default;
    virtual int IpFamily(const std::string& address) const = 0;
    virtual std::vector<std::string> Resolve(const std::string& host, int family,
                                             const std::function<bool()>& cancelled) const = 0;
};
struct PlatformServices {
    ICryptoProvider& crypto;
    ISecretStore& secrets;
    IPlatformPaths& paths;
    INetworkServices& network;
};
// Each executable links exactly one platform adapter. Tests link an isolated
// in-memory adapter, never production credentials or real network services.
const PlatformServices& Platform();
} // namespace ownvpn
