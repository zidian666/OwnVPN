#include "dns_fallback.h"
#include "jni_support.h"
#include "totp_store.h"
#include <android/log.h>
#include <atomic>
#include <cctype>
#include <client/ovpncli.hpp>
#include <map>
#include <memory>
#include <mutex>
#include <openvpn/io/io.hpp>
#include <sstream>
#include <thread>
using namespace ownvpn;
namespace a = ownvpn::android;
namespace api = openvpn::ClientAPI;
namespace {
std::string SafeSetupError(const std::string& text) {
    auto lower = text;
    for (auto& c : lower) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    for (auto word : {"password", "secret", "auth-token", "private key", "-----begin"}) {
        if (lower.find(word) != lower.npos) {
            return "VPN 引擎初始化失败";
        }
    }
    std::istringstream input(text);
    std::string token, result;
    while (input >> token && result.size() < 180) {
        if (token.size() > 24 || token.find("://") != token.npos) {
            token = "[已隐藏]";
        }
        if (!result.empty()) {
            result += ' ';
        }
        result += token;
    }
    return result.empty() ? "VPN 引擎初始化失败" : result;
}
class Client final : public api::OpenVPNClient {
    jobject service_;
    jclass type_;

  public:
    std::atomic<bool> cancelled{false};
    bool transportStarted = false;
    std::string expectedTopology;
    explicit Client(JNIEnv* env, jobject service) {
        service_ = env->NewGlobalRef(service);
        auto type = env->GetObjectClass(service);
        type_ = static_cast<jclass>(env->NewGlobalRef(type));
        env->DeleteLocalRef(type);
    }
    ~Client() override {
        a::Env env;
        env->DeleteGlobalRef(service_);
        env->DeleteGlobalRef(type_);
    }
    template <class... Args> bool Bool(const char* method, const char* signature, Args... args) {
        if (cancelled) {
            return false;
        }
        a::Env env;
        auto id = env->GetMethodID(type_, method, signature);
        auto result = env->CallBooleanMethod(service_, id, args...);
        a::CheckJava(env);
        return result;
    }
    bool Address(const char* method, const std::string& address, int prefix) {
        a::Env env;
        auto value = a::String(env, address);
        bool result = Bool(method, "(Ljava/lang/String;I)Z", value, prefix);
        env->DeleteLocalRef(value);
        return result;
    }
    void Notify(std::string_view name, std::string_view text) {
        a::Env env;
        auto id = env->GetMethodID(type_, "nativeEvent", "(Ljava/lang/String;Ljava/lang/String;)V");
        auto n = a::String(env, name), t = a::String(env, text);
        env->CallVoidMethod(service_, id, n, t);
        a::CheckJava(env);
        env->DeleteLocalRef(n);
        env->DeleteLocalRef(t);
    }
    bool socket_protect(openvpn_io::detail::socket_type socket, std::string, bool) override {
        return Bool("protectSocket", "(I)Z", static_cast<jint>(socket));
    }
    bool tun_builder_new() override {
        return Bool("newTunnel", "()Z");
    }
    bool tun_builder_set_remote_address(const std::string&, bool) override {
        return true;
    }
    bool tun_builder_add_address(const std::string& address, int prefix, const std::string&, bool ipv6,
                                 bool net30) override {
        if (!ipv6 && !expectedTopology.empty() && ((expectedTopology == "net30") != net30)) {
            Notify("SETUP_ERROR", "服务器下发的拓扑与原配置不一致，连接已停止");
            return false;
        }
        return Address("addAddress", address, prefix);
    }
    bool tun_builder_add_route(const std::string& address, int prefix, int, bool) override {
        return prefix <= 1 || Address("addRoute", address, prefix);
    }
    bool tun_builder_exclude_route(const std::string& address, int prefix, int, bool) override {
        return Address("excludeRoute", address, prefix);
    }
    bool tun_builder_reroute_gw(bool, bool, unsigned int) override {
        return true;
    }
    bool tun_builder_set_mtu(int mtu) override {
        return Bool("setMtu", "(I)Z", mtu);
    }
    bool tun_builder_set_session_name(const std::string&) override {
        return true;
    }
    bool tun_builder_set_dns_options(const openvpn::DnsOptions& dns) override {
        for (const auto& [priority, server] : dns.servers) {
            (void)priority;
            for (const auto& address : server.addresses) {
                if (address.port && address.port != 53) {
                    return false;
                }
                a::Env env;
                auto value = a::String(env, address.address);
                bool ok = Bool("addDns", "(Ljava/lang/String;)Z", value);
                env->DeleteLocalRef(value);
                if (!ok) {
                    return false;
                }
            }
        }
        return true;
    }
    bool tun_builder_set_allow_family(int family, bool allow) override {
        return !allow || Bool("allowFamily", "(I)Z", family);
    }
    int tun_builder_establish() override {
        if (cancelled) {
            return -1;
        }
        a::Env env;
        auto id = env->GetMethodID(type_, "establish", "()I");
        int result = env->CallIntMethod(service_, id);
        a::CheckJava(env);
        return result;
    }
    bool tun_builder_persist() override {
        return false;
    }
    bool pause_on_connection_timeout() override {
        return false;
    }
    void log(const api::LogInfo& entry) override {
        // Only selected handshake failures, passed through the secret redactor.
        if (entry.text.find("SSL Handshake") != entry.text.npos ||
            entry.text.find("TLS Error") != entry.text.npos ||
            entry.text.find("VERIFY ERROR") != entry.text.npos ||
            entry.text.find("mbed TLS") != entry.text.npos) {
            auto message = SafeSetupError(entry.text);
            __android_log_print(ANDROID_LOG_ERROR, "OwnVPNHandshake", "%s", message.c_str());
        }
    }
    void acc_event(const api::AppCustomControlMessageEvent&) override {}
    void external_pki_cert_request(api::ExternalPKICertRequest& request) override {
        request.error = true;
    }
    void external_pki_sign_request(api::ExternalPKISignRequest& request) override {
        request.error = true;
    }
    void event(const api::Event& event) override {
        __android_log_print(ANDROID_LOG_INFO, "OwnVPNEvent", "%s", event.name.c_str());
        if (event.error || event.fatal) {
            auto message = SafeSetupError(event.info);
            __android_log_print(ANDROID_LOG_ERROR, "OwnVPNError", "%s: %s", event.name.c_str(),
                                message.c_str());
        }
        if (event.name == "RESOLVE" || event.name == "CONNECTING" || event.name == "WAIT") {
            transportStarted = true;
        }
        if (cancelled) {
            stop();
            return;
        }
        if (event.name == "CONNECTED") {
            auto info = connection_info();
            Notify("CONNECTED", info.vpnIp4.empty() ? info.vpnIp6 : info.vpnIp4);
        } else {
            Notify(event.name, event.fatal ? "VPN 引擎报告连接错误" : "");
            // A fresh outer attempt obtains a fresh OTP instead of reusing an old concatenated password.
            if (event.name == "RECONNECTING") {
                stop();
            }
        }
    }
};
std::mutex sessionsMutex;
std::map<jlong, std::shared_ptr<Client>> sessions;
jlong nextSession = 1;
std::shared_ptr<Client> Get(jlong handle) {
    std::lock_guard lock(sessionsMutex);
    auto found = sessions.find(handle);
    return found == sessions.end() ? nullptr : found->second;
}
} // namespace
extern "C" JNIEXPORT jlong JNICALL Java_com_ownvpn_android_NativeBridge_newSession(JNIEnv* env, jclass,
                                                                                   jobject service) {
    try {
        auto client = std::make_shared<Client>(env, service);
        std::lock_guard lock(sessionsMutex);
        auto id = nextSession++;
        sessions.emplace(id, std::move(client));
        return id;
    } catch (const std::exception& error) {
        a::Throw(env, error);
        return 0;
    }
}
extern "C" JNIEXPORT void JNICALL Java_com_ownvpn_android_NativeBridge_stop(JNIEnv*, jclass, jlong handle) {
    if (auto client = Get(handle)) {
        client->cancelled = true;
        client->stop();
    }
}
extern "C" JNIEXPORT jstring JNICALL Java_com_ownvpn_android_NativeBridge_run(
    JNIEnv* env, jclass, jlong handle, jstring profileId, jstring username, jstring password, jstring otp,
    jboolean automatic, jboolean fallback) {
    auto client = Get(handle);
    if (!client) {
        return a::String(env, "CANCELLED");
    }
    struct Cleanup {
        jlong id;
        ~Cleanup() {
            std::lock_guard lock(sessionsMutex);
            sessions.erase(id);
        }
    } cleanup{handle};
    try {
        if (client->cancelled) {
            return a::String(env, "CANCELLED");
        }
        auto profile = a::FindProfile(a::Text(env, profileId));
        client->expectedTopology = a::ExpectedTopology(profile);
        client->Notify("PREPARING_CONFIG", "");
        auto configText = a::EngineConfig(profile);
        auto dns = PrepareDnsFallback(
            configText, profile.config.parent_path() / "dns-cache.txt", fallback,
            [&](const std::string& host, int family) {
                return ResolveEndpoint(host, family, [&] { return client->cancelled.load(); });
            },
            [&](Event event) { client->Notify("DIAGNOSTIC", Utf8(event.text)); },
            [&] { return client->cancelled.load(); });
        if (!dns.empty()) {
            Wipe(configText);
            configText = std::move(dns);
        }
        if (client->cancelled) {
            Wipe(configText);
            return a::String(env, "CANCELLED");
        }
        api::Config config;
        config.content = std::move(configText);
        config.guiVersion = "OwnVPN Android 0.5.0";
        config.connTimeout = 30;
        config.tunPersist = false;
        config.allowUnusedAddrFamilies = "yes";
        auto evaluation = client->eval_config(config);
        Wipe(config.content);
        if (evaluation.error) {
            client->Notify("CONFIG_ERROR", "配置或证书不兼容，请查看支持的配置选项");
            return a::String(env, "CONFIG_ERROR");
        }
        api::ProvideCreds credentials;
        credentials.username = a::Text(env, username);
        auto pass = a::Text(env, password), code = a::Text(env, otp);
        struct SecretGuard {
            std::string& pass;
            std::string& code;
            ~SecretGuard() {
                Wipe(pass);
                Wipe(code);
            }
        } secretGuard{pass, code};
        if (automatic) {
            client->Notify("PREPARING_OTP", "");
            TotpRepository repository;
            TotpOtpProvider provider(
                [&](const OtpRequest&) { return repository.Load(profile.id, Wide(credentials.username)); },
                SystemTotpClock(),
                [&](const OtpRequest&) {
                    return repository.LastIssuedCounter(profile.id, Wide(credentials.username));
                },
                [&](const OtpRequest&, int64_t counter) {
                    repository.MarkIssued(profile.id, Wide(credentials.username), counter);
                });
            std::stop_source cancel;
            std::jthread monitor([&](std::stop_token done) {
                while (!done.stop_requested()) {
                    if (client->cancelled) {
                        cancel.request_stop();
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
            });
            auto generated = provider.GetCode({}, cancel.get_token());
            code = generated.value;
        }
        if (client->cancelled) {
            Wipe(pass);
            Wipe(code);
            return a::String(env, "CANCELLED");
        }
        if (pass.empty() || code.size() != 6 || code.find_first_not_of("0123456789") != code.npos) {
            throw std::runtime_error("请填写密码和 6 位验证码");
        }
        credentials.password = pass + code;
        Wipe(pass);
        Wipe(code);
        auto credentialStatus = client->provide_creds(credentials);
        Wipe(credentials.password);
        if (credentialStatus.error) {
            return a::String(env, "AUTH_FAILED");
        }
        if (client->cancelled) {
            return a::String(env, "CANCELLED");
        }
        client->Notify("STARTING_ENGINE", "");
        auto result = client->connect();
        if (result.error && !client->transportStarted && !client->cancelled) {
            auto message = SafeSetupError(result.message);
            __android_log_print(ANDROID_LOG_ERROR, "OwnVPNSetup", "%s", message.c_str());
            client->Notify("SETUP_ERROR", message);
            return a::String(env, "CONFIG_ERROR");
        }
        return a::String(env, client->cancelled ? "CANCELLED"
                              : result.error    ? "CONNECTION_ERROR"
                                                : "DISCONNECTED");
    } catch (const std::exception&) {
        client->Notify("FAILED",
                       client->cancelled ? "连接已取消" : "连接准备失败，请核对配置、账号和验证码绑定");
        return a::String(env, client->cancelled ? "CANCELLED" : "FAILED");
    }
}
extern "C" JNIEXPORT jstring JNICALL Java_com_ownvpn_android_NativeBridge_probeProfile(JNIEnv* env, jclass,
                                                                                       jobject service,
                                                                                       jstring profileId) {
    try {
        auto client = std::make_shared<Client>(env, service);
        api::Config config;
        config.content = a::EngineConfig(a::FindProfile(a::Text(env, profileId)));
        config.connTimeout = 1;
        config.serverOverride = "127.0.0.1";
        config.portOverride = "9";
        config.protoOverride = "udp";
        auto evaluation = client->eval_config(config);
        Wipe(config.content);
        if (evaluation.error) {
            throw std::runtime_error("Profile evaluation failed");
        }
        api::ProvideCreds credentials;
        credentials.username = "public-test";
        credentials.password = "public-test";
        if (client->provide_creds(credentials).error) {
            throw std::runtime_error("Synthetic credentials rejected");
        }
        auto result = client->connect();
        if (!client->transportStarted) {
            throw std::runtime_error(SafeSetupError(result.message));
        }
        return a::String(env, "OK");
    } catch (const std::exception& error) {
        a::Throw(env, error);
        return nullptr;
    }
}
