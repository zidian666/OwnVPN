#include "jni_support.h"
#include "platform.h"
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <mbedtls/md.h>
#include <sys/stat.h>
#include <unistd.h>
namespace ownvpn {
namespace {
const mbedtls_md_info_t* Algorithm(HashAlgorithm algorithm) {
    auto type = algorithm == HashAlgorithm::Sha1     ? MBEDTLS_MD_SHA1
                : algorithm == HashAlgorithm::Sha256 ? MBEDTLS_MD_SHA256
                                                     : MBEDTLS_MD_SHA512;
    auto result = mbedtls_md_info_from_type(type);
    if (!result) {
        throw std::runtime_error("Hash algorithm unavailable");
    }
    return result;
}
class Crypto final : public ICryptoProvider {
  public:
    std::vector<unsigned char> Hmac(HashAlgorithm algorithm, std::span<const unsigned char> key,
                                    std::span<const unsigned char> input) const override {
        auto info = Algorithm(algorithm);
        std::vector<unsigned char> result(mbedtls_md_get_size(info));
        if (mbedtls_md_hmac(info, key.data(), key.size(), input.data(), input.size(), result.data())) {
            throw std::runtime_error("HMAC failed");
        }
        return result;
    }
    std::vector<unsigned char> Digest(HashAlgorithm algorithm,
                                      std::span<const unsigned char> input) const override {
        auto info = Algorithm(algorithm);
        std::vector<unsigned char> result(mbedtls_md_get_size(info));
        if (mbedtls_md(info, input.data(), input.size(), result.data())) {
            throw std::runtime_error("Hash failed");
        }
        return result;
    }
    void RandomBytes(std::span<unsigned char> output) const override {
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            throw std::runtime_error("Secure random source unavailable");
        }
        size_t offset = 0;
        while (offset < output.size()) {
            auto count = read(fd, output.data() + offset, output.size() - offset);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                close(fd);
                WipeBytes(output);
                throw std::runtime_error("Secure random read failed");
            }
            offset += static_cast<size_t>(count);
        }
        close(fd);
    }
};
class Secrets final : public ISecretStore {
  public:
    std::wstring Read(std::wstring_view profile, std::wstring_view field) const override {
        android::Env env;
        auto method = env->GetStaticMethodID(android::Bridge(), "readSecret",
                                             "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
        auto p = android::String(env, Utf8(profile)), f = android::String(env, Utf8(field));
        auto value = static_cast<jstring>(env->CallStaticObjectMethod(android::Bridge(), method, p, f));
        android::CheckJava(env);
        auto text = android::Text(env, value);
        auto result = Wide(text);
        Wipe(text);
        env->DeleteLocalRef(value);
        env->DeleteLocalRef(p);
        env->DeleteLocalRef(f);
        return result;
    }
    void Write(std::wstring_view profile, std::wstring_view field, std::wstring_view value) override {
        android::Env env;
        auto method = env->GetStaticMethodID(android::Bridge(), "writeSecret",
                                             "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
        auto p = android::String(env, Utf8(profile)), f = android::String(env, Utf8(field));
        auto v = android::String(env, Utf8(value));
        env->CallStaticVoidMethod(android::Bridge(), method, p, f, v);
        android::CheckJava(env);
        env->DeleteLocalRef(p);
        env->DeleteLocalRef(f);
        env->DeleteLocalRef(v);
    }
};
class Paths final : public IPlatformPaths {
  public:
    fs::path DataDirectory() const override {
        auto root = android::DataRoot();
        if (root.empty()) {
            throw std::runtime_error("Android private directory not initialized");
        }
        return root;
    }
    void MakePrivateDirectory(const fs::path& path) const override {
        auto root = fs::weakly_canonical(DataDirectory());
        auto resolved = fs::weakly_canonical(path);
        auto relative = resolved.lexically_relative(root);
        if (relative.empty() || *relative.begin() == "..") {
            throw std::runtime_error("Path outside app storage");
        }
        fs::create_directories(path);
        if (chmod(path.c_str(), S_IRWXU)) {
            throw std::runtime_error("Cannot protect app directory");
        }
    }
};
class Network final : public INetworkServices {
  public:
    int IpFamily(const std::string& address) const override {
        in_addr v4{};
        in6_addr v6{};
        if (inet_pton(AF_INET, address.c_str(), &v4) == 1) {
            return 4;
        }
        return inet_pton(AF_INET6, address.c_str(), &v6) == 1 ? 6 : 0;
    }
    std::vector<std::string> Resolve(const std::string& host, int family,
                                     const std::function<bool()>& cancelled) const override {
        if (cancelled()) {
            throw std::runtime_error("Cancelled");
        }
        android::Env env;
        auto method =
            env->GetStaticMethodID(android::Bridge(), "resolve", "(Ljava/lang/String;I)[Ljava/lang/String;");
        auto name = android::String(env, host);
        auto array =
            static_cast<jobjectArray>(env->CallStaticObjectMethod(android::Bridge(), method, name, family));
        android::CheckJava(env);
        std::vector<std::string> result;
        if (array) {
            for (jsize i = 0; i < env->GetArrayLength(array); ++i) {
                auto value = static_cast<jstring>(env->GetObjectArrayElement(array, i));
                result.push_back(android::Text(env, value));
                env->DeleteLocalRef(value);
            }
        }
        env->DeleteLocalRef(array);
        env->DeleteLocalRef(name);
        if (cancelled()) {
            throw std::runtime_error("Cancelled");
        }
        return result;
    }
};
} // namespace
const PlatformServices& Platform() {
    static Crypto crypto;
    static Secrets secrets;
    static Paths paths;
    static Network network;
    static const PlatformServices services{crypto, secrets, paths, network};
    return services;
}
} // namespace ownvpn
