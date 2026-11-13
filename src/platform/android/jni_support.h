#pragma once
#include "profile.h"
#include <jni.h>
namespace ownvpn::android {
class Env {
    bool attached_ = false;
    JNIEnv* value_ = nullptr;

  public:
    Env();
    ~Env();
    JNIEnv* operator->() const {
        return value_;
    }
    operator JNIEnv*() const {
        return value_;
    }
};
void Initialize(JNIEnv* env, jclass bridge, std::string root);
jclass Bridge();
fs::path DataRoot();
std::string Text(JNIEnv* env, jstring text);
jstring String(JNIEnv* env, std::string_view text);
void CheckJava(JNIEnv* env);
void Throw(JNIEnv* env, const std::exception& error);
Profile FindProfile(std::string_view id);
std::string EngineConfig(const Profile& profile);
std::string ExpectedTopology(const Profile& profile);
} // namespace ownvpn::android
