#include "platform.h"
#include "windows_platform.h"
#include <bcrypt.h>
#include <limits>

namespace ownvpn {
namespace {
void Check(NTSTATUS result) {
    if (result < 0) {
        throw std::runtime_error("Windows cryptographic operation failed");
    }
}
ULONG Length(size_t size) {
    if (size > std::numeric_limits<ULONG>::max()) {
        throw std::runtime_error("Cryptographic input too large");
    }
    return static_cast<ULONG>(size);
}
struct Algorithm {
    BCRYPT_ALG_HANDLE value = nullptr;
    ~Algorithm() {
        if (value) {
            BCryptCloseAlgorithmProvider(value, 0);
        }
    }
};
struct Hash {
    BCRYPT_HASH_HANDLE value = nullptr;
    ~Hash() {
        if (value) {
            BCryptDestroyHash(value);
        }
    }
};
struct Buffer {
    std::vector<unsigned char> value;
    ~Buffer() {
        WipeBytes(value);
    }
};
class WindowsCrypto final : public ICryptoProvider {
    std::vector<unsigned char> Calculate(HashAlgorithm algorithm, bool hmac,
                                         std::span<const unsigned char> key,
                                         std::span<const unsigned char> input) const {
        const wchar_t* name = algorithm == HashAlgorithm::Sha1     ? BCRYPT_SHA1_ALGORITHM
                              : algorithm == HashAlgorithm::Sha256 ? BCRYPT_SHA256_ALGORITHM
                                                                   : BCRYPT_SHA512_ALGORITHM;
        Algorithm provider;
        Check(BCryptOpenAlgorithmProvider(&provider.value, name, nullptr,
                                          hmac ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0));
        DWORD objectSize = 0, hashSize = 0, resultSize = 0;
        Check(BCryptGetProperty(provider.value, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize),
                                sizeof(objectSize), &resultSize, 0));
        Check(BCryptGetProperty(provider.value, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashSize),
                                sizeof(hashSize), &resultSize, 0));
        Buffer object{std::vector<unsigned char>(objectSize)};
        Hash hash;
        Check(BCryptCreateHash(provider.value, &hash.value, object.value.data(), objectSize,
                               hmac ? const_cast<PUCHAR>(key.data()) : nullptr, hmac ? Length(key.size()) : 0,
                               0));
        Check(BCryptHashData(hash.value, const_cast<PUCHAR>(input.data()), Length(input.size()), 0));
        Buffer output{std::vector<unsigned char>(hashSize)};
        Check(BCryptFinishHash(hash.value, output.value.data(), hashSize, 0));
        return std::move(output.value);
    }

  public:
    std::vector<unsigned char> Hmac(HashAlgorithm algorithm, std::span<const unsigned char> key,
                                    std::span<const unsigned char> input) const override {
        return Calculate(algorithm, true, key, input);
    }
    std::vector<unsigned char> Digest(HashAlgorithm algorithm,
                                      std::span<const unsigned char> input) const override {
        return Calculate(algorithm, false, {}, input);
    }
    void RandomBytes(std::span<unsigned char> output) const override {
        Check(
            BCryptGenRandom(nullptr, output.data(), Length(output.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    }
};
} // namespace
ICryptoProvider& WindowsCryptoServices() {
    static WindowsCrypto crypto;
    return crypto;
}
} // namespace ownvpn
