#include "jni_support.h"
#include "reconnect_policy.h"
#include "totp_store.h"
#include <BarcodeFormat.h>
#include <ReadBarcode.h>
#include <algorithm>
#include <chrono>
#include <client/ovpncli.hpp>
#include <openvpn/io/io.hpp>
#include <sstream>
using namespace ownvpn;
namespace a = ownvpn::android;
namespace ownvpn::android {
std::string ExpectedTopology(const Profile& profile) {
    std::string content = ReadFile(profile.config), line, block, result;
    std::istringstream input(content);
    while (std::getline(input, line)) {
        auto clean = Trim(line);
        if (!block.empty()) {
            if (clean == "</" + block + ">") {
                block.clear();
            }
            continue;
        }
        if (clean.starts_with('<')) {
            block = clean.substr(1, clean.size() - 2);
            continue;
        }
        auto tokens = ConfigTokens(clean);
        if (tokens.size() == 2 && tokens[0] == "topology") {
            result = tokens[1];
        }
    }
    Wipe(content);
    if (!result.empty() && result != "subnet" && result != "net30") {
        throw std::runtime_error("Android 配置暂不支持该拓扑");
    }
    return result;
}
std::string EngineConfig(const Profile& profile) {
    ProfileRepository().Validate(profile);
    std::istringstream input(ReadFile(profile.config));
    std::string line, block, result;
    while (std::getline(input, line)) {
        auto clean = Trim(line);
        if (!block.empty()) {
            result += line + '\n';
            if (clean == "</" + block + ">") {
                block.clear();
            }
            continue;
        }
        if (clean.empty() || clean[0] == '#') {
            continue;
        }
        if (clean.starts_with('<')) {
            block = clean.substr(1, clean.size() - 2);
            result += line + '\n';
            continue;
        }
        auto tokens = ConfigTokens(clean);
        if (tokens.empty()) {
            continue;
        }
        const auto& op = tokens[0];
        if (op == "ca" || op == "cert" || op == "key" || op == "tls-auth" || op == "tls-crypt" ||
            op == "extra-certs") {
            if (tokens.size() < 2) {
                throw std::runtime_error("Missing certificate file");
            }
            result += '<' + op + ">\n" + ReadFile(PathFromUtf8(tokens[1])) + "\n</" + op + ">\n";
            if (op == "tls-auth" && tokens.size() == 3) {
                result += "key-direction " + tokens[2] + '\n';
            }
        } else if (op == "topology" || op == "windows-driver" || op == "block-outside-dns" ||
                   op == "register-dns" || op == "disable-dco" || op == "auth-retry" || op == "mute") {
            // OpenVPN 3 receives topology from the server; the TUN callback
            // verifies it against ExpectedTopology. Other skipped options are
            // Windows process or logging settings.
        } else if (op == "dev" && tokens.size() > 1 && tokens[1] == "tap") {
            throw std::runtime_error("Android 仅支持 TUN 配置");
        } else if (op == "pkcs12" || op == "tls-crypt-v2" || op == "crl-verify") {
            throw std::runtime_error("此 Android 版本暂不支持该证书选项: " + op);
        } else {
            result += line + '\n';
        }
    }
    return result;
}
} // namespace ownvpn::android
extern "C" JNIEXPORT void JNICALL Java_com_ownvpn_android_NativeBridge_init(JNIEnv* env, jclass cls,
                                                                            jstring root) {
    try {
        a::Initialize(env, cls, a::Text(env, root));
        PrivateDirectory(AppData());
    } catch (const std::exception& error) {
        a::Throw(env, error);
    }
}
extern "C" JNIEXPORT jobjectArray JNICALL Java_com_ownvpn_android_NativeBridge_profiles(JNIEnv* env, jclass) {
    try {
        auto list = ProfileRepository().List();
        auto result = env->NewObjectArray(static_cast<jsize>(list.size() * 2),
                                          env->FindClass("java/lang/String"), nullptr);
        for (size_t i = 0; i < list.size(); ++i) {
            auto id = a::String(env, Utf8(list[i].id)), name = a::String(env, Utf8(list[i].name));
            env->SetObjectArrayElement(result, static_cast<jsize>(i * 2), id);
            env->SetObjectArrayElement(result, static_cast<jsize>(i * 2 + 1), name);
            env->DeleteLocalRef(id);
            env->DeleteLocalRef(name);
        }
        return result;
    } catch (const std::exception& error) {
        a::Throw(env, error);
        return nullptr;
    }
}
extern "C" JNIEXPORT jstring JNICALL Java_com_ownvpn_android_NativeBridge_importProfileFiles(
    JNIEnv* env, jclass, jstring ovpn, jstring pem, jobjectArray options, jobjectArray files,
    jstring referenceRoot) {
    try {
        if (!options || !files || env->GetArrayLength(options) != env->GetArrayLength(files) ||
            env->GetArrayLength(options) > 9) {
            throw std::runtime_error("Invalid dependency selection");
        }
        ProfileDependencyFiles selected;
        for (jsize i = 0; i < env->GetArrayLength(options); ++i) {
            auto op = static_cast<jstring>(env->GetObjectArrayElement(options, i));
            auto path = static_cast<jstring>(env->GetObjectArrayElement(files, i));
            if (!selected.emplace(a::Text(env, op), PathFromUtf8(a::Text(env, path))).second) {
                throw std::runtime_error("Duplicate dependency selection");
            }
            env->DeleteLocalRef(op);
            env->DeleteLocalRef(path);
        }
        auto profile =
            ProfileRepository().Import(PathFromUtf8(a::Text(env, ovpn)), PathFromUtf8(a::Text(env, pem)),
                                       selected, PathFromUtf8(a::Text(env, referenceRoot)));
        return a::String(env, Utf8(profile.id));
    } catch (const MissingProfileDependency& error) {
        auto type = env->FindClass("com/ownvpn/android/MissingDependencyException");
        auto constructor = env->GetMethodID(type, "<init>", "(Ljava/lang/String;Ljava/lang/String;)V");
        auto op = a::String(env, error.option()), reference = a::String(env, error.reference());
        auto exception = static_cast<jthrowable>(env->NewObject(type, constructor, op, reference));
        env->Throw(exception);
        env->DeleteLocalRef(exception);
        env->DeleteLocalRef(op);
        env->DeleteLocalRef(reference);
        env->DeleteLocalRef(type);
        return nullptr;
    } catch (const std::exception& error) {
        a::Throw(env, error);
        return nullptr;
    }
}
extern "C" JNIEXPORT void JNICALL Java_com_ownvpn_android_NativeBridge_bindTotp(JNIEnv* env, jclass,
                                                                                jstring id, jstring user,
                                                                                jstring input) {
    try {
        auto profile = a::FindProfile(a::Text(env, id));
        auto name = Wide(a::Text(env, user));
        if (name.empty()) {
            throw std::runtime_error("请先填写账号");
        }
        auto text = a::Text(env, input);
        auto config = ParseTotpInput(text, TotpAlgorithm::Sha1, 30);
        Wipe(text);
        ValidateTotp(config, true);
        TotpRepository().Bind(profile.id, name, config);
    } catch (const std::exception& error) {
        a::Throw(env, error);
    }
}
extern "C" JNIEXPORT jstring JNICALL Java_com_ownvpn_android_NativeBridge_totp(JNIEnv* env, jclass,
                                                                               jstring id, jstring user) {
    try {
        auto name = Wide(a::Text(env, user)), profile = Wide(a::Text(env, id));
        TotpRepository repository;
        if (!repository.Metadata(profile, name).bound) {
            return a::String(env, "");
        }
        auto config = repository.Load(profile, name);
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
        return a::String(env, GenerateTotp(config, now) + " " +
                                  std::to_string(config.periodSeconds - now % config.periodSeconds));
    } catch (const std::exception& error) {
        a::Throw(env, error);
        return nullptr;
    }
}
extern "C" JNIEXPORT jstring JNICALL Java_com_ownvpn_android_NativeBridge_decodeQr(JNIEnv* env, jclass,
                                                                                   jintArray pixels,
                                                                                   jint width, jint height) {
    try {
        if (width <= 0 || height <= 0 || width > 4096 || height > 4096 ||
            env->GetArrayLength(pixels) != width * height) {
            throw std::runtime_error("二维码图片尺寸无效");
        }
        std::vector<jint> argb(static_cast<size_t>(width) * height);
        env->GetIntArrayRegion(pixels, 0, width * height, argb.data());
        a::CheckJava(env);
        std::vector<unsigned char> gray(argb.size());
        for (size_t i = 0; i < argb.size(); ++i) {
            auto p = static_cast<uint32_t>(argb[i]);
            gray[i] = static_cast<unsigned char>(
                (((p >> 16) & 255) * 77 + ((p >> 8) & 255) * 150 + (p & 255) * 29) >> 8);
        }
        auto results = ZXing::ReadBarcodes({gray.data(), width, height, ZXing::ImageFormat::Lum},
                                           ZXing::ReaderOptions().setFormats(ZXing::BarcodeFormat::QRCode));
        if (results.size() != 1 || !results.front().isValid()) {
            throw std::runtime_error("请使用仅包含一个认证二维码的图片");
        }
        auto text = results.front().text();
        ValidateTotp(ParseTotpUri(text), true);
        auto value = a::String(env, text);
        Wipe(text);
        WipeBytes(gray);
        WipeBytes({reinterpret_cast<unsigned char*>(argb.data()), argb.size() * sizeof(jint)});
        return value;
    } catch (const std::exception& error) {
        a::Throw(env, error);
        return nullptr;
    }
}
extern "C" JNIEXPORT jint JNICALL Java_com_ownvpn_android_NativeBridge_retrySeconds(JNIEnv*, jclass,
                                                                                    jint attempt) {
    ReconnectPolicy policy;
    auto now = ReconnectPolicy::Clock::now();
    for (int i = 0; i <= std::min(std::max(attempt, 0), 6); ++i) {
        policy.AttemptStarted();
        policy.Schedule(now);
    }
    return policy.Remaining(now);
}
extern "C" JNIEXPORT jstring JNICALL Java_com_ownvpn_android_NativeBridge_selfTest(JNIEnv* env, jclass) {
    try {
        const int64_t times[] = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000LL};
        const char* expected[][6] = {
            {"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"},
            {"46119246", "68084774", "67062674", "91819424", "90698825", "77737706"},
            {"90693936", "25091201", "99943326", "93441116", "38618901", "47863826"}};
        for (int a = 0; a < 3; ++a) {
            std::string seed;
            for (int i = 0; i < (a == 0 ? 20 : a == 1 ? 32 : 64); ++i) {
                seed += static_cast<char>('0' + (i + 1) % 10);
            }
            TotpConfig c;
            c.secretBase32 = EncodeBase32({reinterpret_cast<const unsigned char*>(seed.data()), seed.size()});
            c.algorithm = static_cast<TotpAlgorithm>(a);
            c.digits = 8;
            for (int i = 0; i < 6; ++i) {
                if (GenerateTotp(c, times[i]) != expected[a][i]) {
                    throw std::runtime_error("RFC6238 mismatch");
                }
            }
        }
        return a::String(env, "PASS: 18 RFC6238 vectors (SHA1/SHA256/SHA512)");
    } catch (const std::exception& error) {
        a::Throw(env, error);
        return nullptr;
    }
}
extern "C" JNIEXPORT jstring JNICALL Java_com_ownvpn_android_NativeBridge_evaluateConfig(JNIEnv* env, jclass,
                                                                                         jstring input) {
    try {
        openvpn::ClientAPI::OpenVPNClientHelper helper;
        openvpn::ClientAPI::Config config;
        config.content = a::Text(env, input);
        auto result = helper.eval_config(config);
        Wipe(config.content);
        if (result.error) {
            throw std::runtime_error("OpenVPN 引擎无法解析该配置");
        }
        if (result.externalPki || result.privateKeyPasswordRequired) {
            throw std::runtime_error("当前版本需要未加密的内嵌客户端证书和私钥");
        }
        return a::String(env, "OK");
    } catch (const std::exception& error) {
        a::Throw(env, error);
        return nullptr;
    }
}
extern "C" JNIEXPORT jstring JNICALL Java_com_ownvpn_android_NativeBridge_validateProfile(JNIEnv* env, jclass,
                                                                                          jstring id) {
    try {
        openvpn::ClientAPI::OpenVPNClientHelper helper;
        openvpn::ClientAPI::Config config;
        config.content = a::EngineConfig(a::FindProfile(a::Text(env, id)));
        auto result = helper.eval_config(config);
        Wipe(config.content);
        if (result.error) {
            throw std::runtime_error("OpenVPN 引擎无法解析该配置");
        }
        if (result.externalPki || result.privateKeyPasswordRequired) {
            throw std::runtime_error("当前版本需要未加密的内嵌客户端证书和私钥");
        }
        return a::String(env, "OK");
    } catch (const std::exception& error) {
        a::Throw(env, error);
        return nullptr;
    }
}
