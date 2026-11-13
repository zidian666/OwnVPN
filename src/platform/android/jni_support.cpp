#include "jni_support.h"
#include "profile.h"
namespace ownvpn::android {
namespace {
JavaVM* vm = nullptr;
jclass bridgeClass = nullptr;
fs::path dataRoot;
} // namespace
Env::Env() {
    if (!vm) {
        throw std::runtime_error("Android platform is not initialized");
    }
    if (vm->GetEnv(reinterpret_cast<void**>(&value_), JNI_VERSION_1_6) == JNI_EDETACHED) {
        if (vm->AttachCurrentThread(&value_, nullptr) != JNI_OK) {
            throw std::runtime_error("JNI attach failed");
        }
        attached_ = true;
    }
}
Env::~Env() {
    if (attached_) {
        vm->DetachCurrentThread();
    }
}
void Initialize(JNIEnv* env, jclass bridge, std::string root) {
    env->GetJavaVM(&vm);
    if (!bridgeClass) {
        bridgeClass = static_cast<jclass>(env->NewGlobalRef(bridge));
    }
    dataRoot = PathFromUtf8(root);
}
jclass Bridge() {
    return bridgeClass;
}
fs::path DataRoot() {
    return dataRoot;
}
std::string Text(JNIEnv* env, jstring text) {
    if (!text) {
        return {};
    }
    const auto* chars = env->GetStringChars(text, nullptr);
    if (!chars) {
        throw std::runtime_error("Cannot read Java text");
    }
    std::wstring wide;
    auto count = env->GetStringLength(text);
    for (jsize i = 0; i < count; ++i) {
        uint32_t c = chars[i];
        if (c >= 0xd800 && c <= 0xdbff && i + 1 < count) {
            uint32_t next = chars[++i];
            if (next < 0xdc00 || next > 0xdfff) {
                env->ReleaseStringChars(text, chars);
                throw std::runtime_error("Invalid UTF16");
            }
            c = 0x10000 + ((c - 0xd800) << 10) + next - 0xdc00;
        }
        wide.push_back(static_cast<wchar_t>(c));
    }
    env->ReleaseStringChars(text, chars);
    auto result = Utf8(wide);
    Wipe(wide);
    return result;
}
jstring String(JNIEnv* env, std::string_view text) {
    auto wide = Wide(text);
    std::vector<jchar> chars;
    for (auto value : wide) {
        uint32_t c = static_cast<uint32_t>(value);
        if (c > 0xffff) {
            c -= 0x10000;
            chars.push_back(0xd800 + (c >> 10));
            chars.push_back(0xdc00 + (c & 1023));
        } else {
            chars.push_back(static_cast<jchar>(c));
        }
    }
    auto result = env->NewString(chars.data(), static_cast<jsize>(chars.size()));
    Wipe(wide);
    WipeBytes({reinterpret_cast<unsigned char*>(chars.data()), chars.size() * sizeof(jchar)});
    return result;
}
void CheckJava(JNIEnv* env) {
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        throw std::runtime_error("Android platform call failed");
    }
}
void Throw(JNIEnv* env, const std::exception& error) {
    env->ThrowNew(env->FindClass("java/lang/IllegalStateException"), error.what());
}
Profile FindProfile(std::string_view id) {
    for (const auto& profile : ProfileRepository().List()) {
        if (Utf8(profile.id) == id) {
            return profile;
        }
    }
    throw std::runtime_error("请选择有效配置");
}
} // namespace ownvpn::android
