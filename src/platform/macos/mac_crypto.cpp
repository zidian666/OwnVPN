#include "mac_services.h"
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <Security/SecRandom.h>
#include <limits>

namespace ownvpn::mac {
namespace {
size_t Size(HashAlgorithm algorithm) {
    switch (algorithm) {
    case HashAlgorithm::Sha1:
        return CC_SHA1_DIGEST_LENGTH;
    case HashAlgorithm::Sha256:
        return CC_SHA256_DIGEST_LENGTH;
    case HashAlgorithm::Sha512:
        return CC_SHA512_DIGEST_LENGTH;
    }
    throw std::runtime_error("Unsupported hash algorithm");
}
} // namespace
std::vector<unsigned char> Crypto::Hmac(HashAlgorithm algorithm, std::span<const unsigned char> key,
                                        std::span<const unsigned char> input) const {
    auto type = algorithm == HashAlgorithm::Sha1     ? kCCHmacAlgSHA1
                : algorithm == HashAlgorithm::Sha256 ? kCCHmacAlgSHA256
                                                     : kCCHmacAlgSHA512;
    std::vector<unsigned char> result(Size(algorithm));
    CCHmac(type, key.data(), key.size(), input.data(), input.size(), result.data());
    return result;
}
std::vector<unsigned char> Crypto::Digest(HashAlgorithm algorithm,
                                          std::span<const unsigned char> input) const {
    if (input.size() > std::numeric_limits<CC_LONG>::max()) {
        throw std::runtime_error("Hash input too large");
    }
    std::vector<unsigned char> result(Size(algorithm));
    auto count = static_cast<CC_LONG>(input.size());
    // SHA1 is required for existing TOTP enrollments, never for a new signature scheme.
    switch (algorithm) {
    case HashAlgorithm::Sha1:
        CC_SHA1(input.data(), count, result.data());
        break;
    case HashAlgorithm::Sha256:
        CC_SHA256(input.data(), count, result.data());
        break;
    case HashAlgorithm::Sha512:
        CC_SHA512(input.data(), count, result.data());
        break;
    }
    return result;
}
void Crypto::RandomBytes(std::span<unsigned char> output) const {
    if (SecRandomCopyBytes(kSecRandomDefault, output.size(), output.data()) != errSecSuccess) {
        WipeBytes(output);
        throw std::runtime_error("Secure random source failed");
    }
}
} // namespace ownvpn::mac
