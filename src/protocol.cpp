#include "protocol.h"
#include <sstream>
#include <wincrypt.h>

namespace ownvpn {
std::string Base64(std::string_view s) {
    DWORD n = 0;
    auto flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
    if (!CryptBinaryToStringA(reinterpret_cast<const BYTE*>(s.data()), static_cast<DWORD>(s.size()), flags,
                              nullptr, &n)) {
        throw std::runtime_error("Cannot encode base64");
    }
    std::string out(n, '\0');
    CryptBinaryToStringA(reinterpret_cast<const BYTE*>(s.data()), static_cast<DWORD>(s.size()), flags,
                         out.data(), &n);
    while (!out.empty() && out.back() == '\0') {
        out.pop_back();
    }
    return out;
}
std::string Base64Decode(std::string_view s) {
    DWORD n = 0;
    if (!CryptStringToBinaryA(s.data(), static_cast<DWORD>(s.size()),
                              CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, nullptr, &n, nullptr, nullptr)) {
        throw std::runtime_error("Invalid challenge username");
    }
    std::string out(n, '\0');
    if (!CryptStringToBinaryA(s.data(), static_cast<DWORD>(s.size()),
                              CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, reinterpret_cast<BYTE*>(out.data()),
                              &n, nullptr, nullptr)) {
        throw std::runtime_error("Invalid challenge username");
    }
    return out;
}
std::string ManagementQuote(std::string_view s) {
    if (s.find_first_of("\r\n") != s.npos || s.find('\0') != s.npos) {
        throw std::runtime_error("Control characters are not allowed in credentials");
    }
    std::string out = "\"";
    for (auto c : s) {
        if (c == '\\' || c == '\"') {
            out += '\\';
        }
        out += c;
    }
    return out + '\"';
}
ManagementProtocol::ManagementProtocol(std::string u, std::string p, std::unique_ptr<IOtpProvider> otp,
                                       EventSink sink, OtpRequest context, std::stop_token cancel,
                                       std::function<std::chrono::system_clock::time_point()> now)
    : username_(std::move(u)), password_(std::move(p)), otp_(std::move(otp)), sink_(std::move(sink)),
      otpContext_(std::move(context)), cancel_(cancel), now_(std::move(now)) {}
ManagementProtocol::~ManagementProtocol() {
    Wipe(username_);
    Wipe(password_);
}
void ManagementProtocol::Fail(std::wstring text) {
    terminal_ = true;
    connected_ = false;
    sink_({EventType::Failed, std::move(text)});
}
std::vector<std::string> ManagementProtocol::OnLine(std::string_view line) {
    if (terminal_) {
        return {};
    }
    if (line.starts_with(">HOLD:")) {
        return {"hold release"};
    }
    if (line.starts_with(">PASSWORD:Verification Failed:")) {
        sink_({EventType::RetryBlocked, L"认证被拒绝，自动重连已停止；请核对登录信息后手动连接。"});
        Fail(L"登录失败，请检查用户名、密码和新的 6 位验证码");
        return {};
    }
    if (line.starts_with(">PASSWORD:Need 'Auth'")) {
        if (authenticatedOnce_) {
            Fail(L"连接需要重新认证，请更新验证码后重新连接");
            return {};
        }
        try {
            otpContext_.username = Wide(username_);
            auto challenge = line.find(" SC:");
            if (challenge != line.npos) {
                auto comma = line.find(',', challenge);
                if (comma != line.npos) {
                    otpContext_.challenge = Wide(line.substr(comma + 1));
                }
            }
            sink_({EventType::Status, L"正在获取有效验证码…"});
            auto code = otp_->GetCode(otpContext_, cancel_);
            if (cancel_.stop_requested()) {
                Wipe(code.value);
                return {};
            }
            if (code.value.size() != 6 || code.value.find_first_not_of("0123456789") != code.value.npos) {
                Wipe(code.value);
                sink_({EventType::RetryBlocked, L"验证码不可用，自动重连已停止。"});
                Fail(L"验证码提供模块没有返回有效的 6 位数字");
                return {};
            }
            if (code.expiresAt && now_() >= *code.expiresAt) {
                Wipe(code.value);
                sink_({EventType::RetryBlocked, L"验证码已过期，自动重连已停止。"});
                Fail(L"验证码已过期，请更新验证码后连接");
                return {};
            }
            std::string secret;
            authenticationExpiry_ = code.expiresAt;
            if (line.find(" SC:") != line.npos) {
                if (line.find("SC:2,") != line.npos || line.find("SC:3,") != line.npos) {
                    secret = password_ + code.value;
                } else {
                    auto pass64 = Base64(password_);
                    secret = "SCRV1:" + pass64 + ":" + Base64(code.value);
                    Wipe(pass64);
                }
            } else {
                secret = password_ + code.value; // Confirmed company login contract.
            }
            auto user = "username \"Auth\" " + ManagementQuote(username_);
            auto pass = "password \"Auth\" " + ManagementQuote(secret);
            Wipe(secret);
            Wipe(code.value);
            Wipe(password_);
            authenticatedOnce_ = true;
            sink_({EventType::Status, L"正在验证账号…"});
            return {std::move(user), std::move(pass)};
        } catch (...) {
            if (cancel_.stop_requested()) {
                return {};
            }
            sink_({EventType::RetryBlocked, L"无法取得验证码，自动重连已停止；请检查绑定设置。"});
            Fail(L"无法取得有效验证码，请检查验证码、绑定设置和系统时间");
            return {};
        }
    }
    if (line.starts_with(">PASSWORD:Need ")) {
        sink_({EventType::RetryBlocked, L"需要额外认证信息，自动重连已停止。"});
        Fail(L"配置要求额外的私钥或代理密码；首版仅支持账号和验证码登录");
        return {};
    }
    if (line.starts_with(">FATAL:")) {
        if (line.find("AUTH_FAILED") != line.npos) {
            sink_({EventType::RetryBlocked, L"认证被拒绝，自动重连已停止。"});
        }
        Fail(L"OpenVPN 连接失败，请展开诊断查看原因");
        return {};
    }
    if (line.starts_with(">STATE:")) {
        std::istringstream stream(std::string{line.substr(7)});
        std::string stamp, state, description, ip;
        std::getline(stream, stamp, ',');
        std::getline(stream, state, ',');
        std::getline(stream, description, ',');
        std::getline(stream, ip, ',');
        if (state == "CONNECTED" && description == "SUCCESS") {
            connected_ = true;
            sink_({EventType::Connected, Wide(ip)});
        } else if (state == "AUTH") {
            sink_({EventType::Status, L"正在验证账号…"});
        } else if (state == "GET_CONFIG") {
            sink_({EventType::Status, L"正在获取公司网络配置…"});
        } else if (state == "ASSIGN_IP" || state == "ADD_ROUTES") {
            sink_({EventType::Status, L"正在配置内网连接…"});
        } else if (state == "RECONNECTING") {
            connected_ = false;
            sink_({EventType::ConnectionLost, L"VPN 连接意外中断。"});
            sink_({EventType::Status, L"连接中断，正在重新建立连接…"});
        } else if (state == "WAIT" || state == "CONNECTING" || state == "RESOLVE" || state == "TCP_CONNECT") {
            sink_({EventType::Status, L"正在联系公司 VPN…"});
        } else if (state == "EXITING") {
            connected_ = false;
            sink_({EventType::Status, L"正在断开连接…"});
        }
    }
    if (line.starts_with(">BYTECOUNT:")) {
        sink_({EventType::Traffic, Wide(line.substr(11))});
    }
    return {};
}
} // namespace ownvpn
