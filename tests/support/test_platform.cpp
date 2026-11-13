#include "test_platform.h"
#include <algorithm>
#include <charconv>
#include <map>

using namespace ownvpn;
namespace {
// This adapter is linked ONLY by portable_core_tests. It cannot access OS
// credentials, perform DNS, or supply production cryptography.
class TestCrypto final : public ICryptoProvider {
    mutable uint64_t randomCall_ = 0;

  public:
    std::vector<unsigned char> Hmac(HashAlgorithm algorithm, std::span<const unsigned char> key,
                                    std::span<const unsigned char> message) const override {
        const std::string publicKey = "12345678901234567890";
        if (algorithm != HashAlgorithm::Sha1 || std::string(key.begin(), key.end()) != publicKey ||
            message.size() != 8 || message.back() != 1 ||
            !std::all_of(message.begin(), message.end() - 1, [](unsigned char byte) { return !byte; })) {
            throw std::runtime_error("Test adapter accepts only RFC6238 SHA1 counter=1 vector");
        }
        return {0x75, 0xa4, 0x8a, 0x19, 0xd4, 0xcb, 0xe1, 0x00, 0x64, 0x4e,
                0x8a, 0xc1, 0x39, 0x7e, 0xea, 0x74, 0x7a, 0x2d, 0x33, 0xab};
    }
    std::vector<unsigned char> Digest(HashAlgorithm, std::span<const unsigned char>) const override {
        throw std::runtime_error("Production hashing is deliberately unavailable in test adapter");
    }
    void RandomBytes(std::span<unsigned char> output) const override {
        auto value = ++randomCall_;
        for (size_t i = 0; i < output.size(); ++i) {
            output[i] = static_cast<unsigned char>(value >> ((i % 8) * 8));
        }
    }
};
class TestStore final : public ISecretStore {
    std::map<std::pair<std::wstring, std::wstring>, std::wstring> values_;

  public:
    std::wstring Read(std::wstring_view profile, std::wstring_view field) const override {
        auto found = values_.find({std::wstring(profile), std::wstring(field)});
        return found == values_.end() ? L"" : found->second;
    }
    void Write(std::wstring_view profile, std::wstring_view field, std::wstring_view value) override {
        auto key = std::make_pair(std::wstring(profile), std::wstring(field));
        auto found = values_.find(key);
        if (found != values_.end()) {
            Wipe(found->second);
            values_.erase(found);
        }
        if (!value.empty()) {
            values_[std::move(key)] = value;
        }
    }
    ~TestStore() override {
        for (auto& [key, value] : values_) {
            (void)key;
            Wipe(value);
        }
    }
};
class TestPaths final : public IPlatformPaths {
  public:
    fs::path root;
    fs::path DataDirectory() const override {
        if (root.empty()) {
            throw std::runtime_error("Test data root not initialized");
        }
        return root;
    }
    void MakePrivateDirectory(const fs::path& path) const override {
        auto relative = fs::absolute(path).lexically_normal().lexically_relative(
            fs::absolute(DataDirectory()).lexically_normal());
        if (relative.empty() || *relative.begin() == "..") {
            throw std::runtime_error("Test path outside temporary root");
        }
        fs::create_directories(path);
    }
};
class TestNetwork final : public INetworkServices {
  public:
    int IpFamily(const std::string& address) const override {
        if (address == "2001:db8::1" || address == "::1") {
            return 6;
        }
        size_t start = 0;
        for (int segment = 0; segment < 4; ++segment) {
            size_t end = address.find('.', start);
            if (segment == 3) {
                end = address.size();
            }
            if (end == std::string::npos || start == end) {
                return 0;
            }
            int value = -1;
            auto [last, error] = std::from_chars(address.data() + start, address.data() + end, value);
            if (error != std::errc{} || last != address.data() + end || value < 0 || value > 255) {
                return 0;
            }
            start = end + 1;
        }
        return 4;
    }
    std::vector<std::string> Resolve(const std::string&, int, const std::function<bool()>&) const override {
        throw std::runtime_error("Tests must inject DNS results; no real network allowed");
    }
};
TestPaths paths;
} // namespace
void SetTestDataDirectory(const fs::path& root) {
    paths.root = root;
}
namespace ownvpn {
const PlatformServices& Platform() {
    static TestCrypto crypto;
    static TestStore store;
    static TestNetwork network;
    static const PlatformServices services{crypto, store, paths, network};
    return services;
}
} // namespace ownvpn
