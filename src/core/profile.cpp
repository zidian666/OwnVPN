#include "profile.h"
#include <algorithm>
#include <map>
#include <set>
#include <sstream>

namespace ownvpn {
std::vector<std::string> ConfigTokens(std::string_view line) {
    std::vector<std::string> out;
    std::string token;
    char quote = 0;
    bool active = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '\\' && quote != '\'') {
            if (++i == line.size()) {
                throw std::runtime_error("Invalid trailing backslash in config");
            }
            token += line[i];
            active = true;
        } else if (quote) {
            if (c == quote) {
                quote = 0;
            } else {
                token += c;
            }
        } else if (c == '\'' || c == '\"') {
            quote = c;
            active = true;
        } else if ((c == '#' || c == ';') && !active) {
            break;
        } else if (c == ' ' || c == '\t' || c == '\r') {
            if (active) {
                out.push_back(token);
                token.clear();
                active = false;
            }
        } else {
            token += c;
            active = true;
        }
    }
    if (quote) {
        throw std::runtime_error("Unterminated quote in config");
    }
    if (active) {
        out.push_back(token);
    }
    return out;
}
std::string ConfigQuote(std::string_view s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '\r' || c == '\n' || c == '\0') {
            throw std::runtime_error("Invalid control character");
        }
        if (c == '\\' || c == '\"') {
            out += '\\';
        }
        out += c;
    }
    return out + '\"';
}
bool IsDefaultRoute(const std::vector<std::string>& t) {
    if (t.empty()) {
        return false;
    }
    if (t[0] == "redirect-gateway" || t[0] == "redirect-private") {
        return true;
    }
    if (t[0] == "route" && t.size() > 1) {
        if (t[1] == "0.0.0.0" || t[1] == "default" || t[1] == "0.0.0.0/0" || t[1] == "0.0.0.0/1" ||
            t[1] == "128.0.0.0/1") {
            return true;
        }
        if (t[1] == "128.0.0.0" && t.size() > 2 && t[2] == "128.0.0.0") {
            return true;
        }
    }
    return t[0] == "route-ipv6" && t.size() > 1 &&
           (t[1] == "::/0" || t[1] == "::/1" || t[1] == "8000::/1" || t[1] == "default");
}
std::string SplitTunnelPolicy() {
    return "\n# OwnVPN: keep local default routes; accept company-specific routes.\n"
           "pull-filter ignore \"redirect-gateway\"\n"
           "pull-filter ignore \"redirect-private\"\n"
           "pull-filter ignore \"route 0.0.0.0\"\n"
           "pull-filter ignore \"route default\"\n"
           "pull-filter ignore \"route 128.0.0.0 128.0.0.0\"\n"
           "pull-filter ignore \"route 128.0.0.0/1\"\n"
           "pull-filter ignore \"route-ipv6 ::/0\"\n"
           "pull-filter ignore \"route-ipv6 ::/1\"\n"
           "pull-filter ignore \"route-ipv6 8000::/1\"\n"
           "pull-filter ignore \"route-ipv6 default\"\n";
}
static const std::set<std::string> fileOptions = {
    "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "pkcs12", "extra-certs", "crl-verify"};
static const std::set<std::string> inlineOptions = {"ca",        "cert",         "key",    "tls-auth",
                                                    "tls-crypt", "tls-crypt-v2", "pkcs12", "extra-certs"};
static const std::set<std::string> safeOptions = {"client",
                                                  "dev",
                                                  "dev-type",
                                                  "dev-node",
                                                  "tls-client",
                                                  "remote",
                                                  "remote-random",
                                                  "remote-random-hostname",
                                                  "proto",
                                                  "port",
                                                  "rport",
                                                  "lport",
                                                  "nobind",
                                                  "bind",
                                                  "float",
                                                  "topology",
                                                  "reneg-sec",
                                                  "reneg-bytes",
                                                  "reneg-pkts",
                                                  "hand-window",
                                                  "tran-window",
                                                  "keepalive",
                                                  "ping",
                                                  "ping-restart",
                                                  "ping-exit",
                                                  "resolv-retry",
                                                  "connect-retry",
                                                  "connect-retry-max",
                                                  "connect-timeout",
                                                  "server-poll-timeout",
                                                  "explicit-exit-notify",
                                                  "persist-key",
                                                  "persist-tun",
                                                  "verb",
                                                  "mute",
                                                  "mute-replay-warnings",
                                                  "auth-user-pass",
                                                  "auth-retry",
                                                  "auth-nocache",
                                                  "auth",
                                                  "cipher",
                                                  "data-ciphers",
                                                  "data-ciphers-fallback",
                                                  "tls-cipher",
                                                  "tls-ciphersuites",
                                                  "tls-version-min",
                                                  "tls-version-max",
                                                  "remote-cert-tls",
                                                  "remote-cert-ku",
                                                  "remote-cert-eku",
                                                  "verify-x509-name",
                                                  "peer-fingerprint",
                                                  "key-direction",
                                                  "pull",
                                                  "route",
                                                  "route-ipv6",
                                                  "route-gateway",
                                                  "route-metric",
                                                  "route-delay",
                                                  "route-method",
                                                  "route-nopull",
                                                  "route-ipv6-gateway",
                                                  "ifconfig",
                                                  "ifconfig-ipv6",
                                                  "ifconfig-noexec",
                                                  "ifconfig-nowarn",
                                                  "dhcp-option",
                                                  "dns",
                                                  "tun-mtu",
                                                  "tun-mtu-extra",
                                                  "link-mtu",
                                                  "mssfix",
                                                  "fragment",
                                                  "sndbuf",
                                                  "rcvbuf",
                                                  "tcp-nodelay",
                                                  "socket-flags",
                                                  "fast-io",
                                                  "comp-lzo",
                                                  "compress",
                                                  "allow-compression",
                                                  "disable-dco",
                                                  "windows-driver",
                                                  "block-outside-dns",
                                                  "register-dns",
                                                  "push-peer-info",
                                                  "setenv-safe",
                                                  "static-challenge",
                                                  "tls-timeout",
                                                  "tls-exit",
                                                  "single-session"};
struct ParsedProfile {
    std::string config;
    std::map<std::string, fs::path> files;
};
static ParsedProfile ParseProfile(const fs::path& source, const fs::path& dest, const fs::path& fallbackPem,
                                  const ProfileDependencyFiles& selectedFiles,
                                  const fs::path& referenceRoot) {
    auto text = ReadFile(source);
    if (text.starts_with("\xef\xbb\xbf")) {
        text.erase(0, 3);
    }
    if (text.find('\0') != text.npos) {
        throw std::runtime_error("NUL character in profile");
    }
    ParsedProfile result;
    std::istringstream in(text);
    std::string line, block;
    bool remote = false;
    std::set<std::string> seenFiles;
    while (std::getline(in, line)) {
        auto clean = Trim(line);
        if (!block.empty()) {
            result.config += line + '\n';
            if (clean == "</" + block + ">") {
                block.clear();
            }
            continue;
        }
        if (clean.empty() || clean[0] == '#' || clean[0] == ';') {
            continue;
        }
        if (clean.starts_with("<")) {
            if (clean.size() < 3 || clean.back() != '>') {
                throw std::runtime_error("Invalid inline block");
            }
            auto tag = clean.substr(1, clean.size() - 2);
            if (!inlineOptions.contains(tag)) {
                throw std::runtime_error("Unsupported inline block: " + tag);
            }
            if (!seenFiles.insert(tag).second) {
                throw std::runtime_error("Duplicate certificate/key directive");
            }
            block = tag;
            result.config += clean + '\n';
            continue;
        }
        auto t = ConfigTokens(clean);
        if (t.empty()) {
            continue;
        }
        if (t[0].starts_with("--")) {
            t[0].erase(0, 2);
        }
        const auto& op = t[0];
        if (op == "remote") {
            remote = true;
        }
        if (op == "ns-cert-type") {
            if (t.size() != 2 || t[1] != "server") {
                throw std::runtime_error("Unsupported legacy certificate check");
            }
            result.config += "remote-cert-tls server\n";
            continue;
        }
        if (IsDefaultRoute(t)) {
            continue;
        }
        if (fileOptions.contains(op)) {
            if (t.size() < 2 || t.size() > 3 || t[1] == "[inline]") {
                throw std::runtime_error("Invalid certificate/key file directive: " + op);
            }
            if (!seenFiles.insert(op).second) {
                throw std::runtime_error("Duplicate certificate/key directive");
            }
            auto selected = selectedFiles.find(op);
            auto src = selected == selectedFiles.end() ? PathFromUtf8(t[1]) : selected->second;
            if (selected == selectedFiles.end() && src.is_relative()) {
                src = source.parent_path() / src;
            }
            bool accessible = fs::is_regular_file(src);
            if (selected == selectedFiles.end() && !referenceRoot.empty()) {
                auto relative =
                    fs::weakly_canonical(src).lexically_relative(fs::weakly_canonical(referenceRoot));
                accessible = accessible && !relative.empty() && *relative.begin() != "..";
            }
            if (selected == selectedFiles.end() && !accessible && (op == "cert" || op == "key") &&
                !fallbackPem.empty()) {
                src = fallbackPem;
                accessible = fs::is_regular_file(src);
            }
            if (!accessible) {
                throw MissingProfileDependency(op, t[1]);
            }
            // Generated dependency names cannot escape the private profile folder.
            auto dst = dest / PathFromUtf8(op + ".bin");
            result.files.emplace(op, src);
            result.config += op + ' ' + ConfigQuote(Utf8(dst.generic_wstring()));
            if (t.size() == 3) {
                result.config += ' ' + ConfigQuote(t[2]);
            }
            result.config += '\n';
            continue;
        }
        if (!safeOptions.contains(op)) {
            throw std::runtime_error("Unsupported profile option: " + op);
        }
        if (op == "auth-user-pass" || op == "auth-retry" || op == "auth-nocache" || op == "verb" ||
            op == "mute") {
            continue;
        }
        if (op == "dev" && (t.size() != 2 || (t[1] != "tun" && t[1] != "tap"))) {
            throw std::runtime_error("Only tun/tap devices are supported");
        }
        result.config += op;
        for (size_t i = 1; i < t.size(); ++i) {
            result.config += ' ' + ConfigQuote(t[i]);
        }
        result.config += '\n';
    }
    if (!block.empty()) {
        throw std::runtime_error("Unterminated inline certificate/key block");
    }
    if (!remote) {
        throw std::runtime_error("Profile has no remote endpoint");
    }
    result.config += "auth-user-pass\nauth-nocache\nauth-retry none\nverb 3\nmute 8\n";
    // Put our filters first. Imported user filters are not accepted.
    result.config = SplitTunnelPolicy() + result.config;
    Wipe(text);
    return result;
}
std::vector<Profile> ProfileRepository::List() const {
    std::vector<Profile> profiles;
    if (!fs::exists(root_)) {
        return profiles;
    }
    for (const auto& entry : fs::directory_iterator(root_)) {
        auto id = PathText(entry.path().filename());
        if (id.size() != 32 || id.find_first_not_of(L"0123456789abcdef") != id.npos) {
            continue;
        }
        auto config = entry.path() / L"profile.ovpn", meta = entry.path() / L"name.txt";
        if (entry.is_directory() && fs::is_regular_file(config) && fs::is_regular_file(meta)) {
            profiles.push_back({id, Wide(Trim(ReadFile(meta))), config});
        }
    }
    std::sort(profiles.begin(), profiles.end(), [](const auto& a, const auto& b) { return a.name < b.name; });
    return profiles;
}
Profile ProfileRepository::Import(const fs::path& source, const fs::path& pem,
                                  const ProfileDependencyFiles& selectedFiles,
                                  const fs::path& referenceRoot) {
    PrivateDirectory(root_.parent_path());
    PrivateDirectory(root_);
    auto id = Wide(RandomHex());
    auto dest = root_ / id;
    auto parsed = ParseProfile(source, dest, pem, selectedFiles, referenceRoot);
    PrivateDirectory(dest);
    try {
        for (const auto& [op, src] : parsed.files) {
            fs::copy_file(src, dest / PathFromUtf8(op + ".bin"), fs::copy_options::none);
        }
        WriteFile(dest / L"name.txt", Utf8(PathText(source.stem())));
        WriteFile(dest / L"profile.ovpn", parsed.config);
    } catch (...) {
        fs::remove_all(dest);
        Wipe(parsed.config);
        throw;
    }
    Wipe(parsed.config);
    return {id, PathText(source.stem()), dest / L"profile.ovpn"};
}
void ProfileRepository::Validate(const Profile& profile) const {
    // Re-parse before every privileged launch, including the managed copy.
    // Remove our generated policy for validation; no arbitrary pull-filters accepted.
    auto content = ReadFile(profile.config);
    auto policy = SplitTunnelPolicy();
    if (!content.starts_with(policy)) {
        throw std::runtime_error("Managed profile policy is missing or changed; re-import this profile");
    }
    // All remaining options have already been normalized. Validate with a scratch copy
    // in memory below rather than trusting a previously imported arbitrary config.
    content.erase(0, policy.size());
    std::istringstream lines(content);
    std::string line, block;
    while (std::getline(lines, line)) {
        auto clean = Trim(line);
        if (clean.empty() || clean[0] == '#' || clean[0] == ';') {
            continue;
        }
        if (!block.empty()) {
            if (clean == "</" + block + ">") {
                block.clear();
            }
            continue;
        }
        if (clean.starts_with("<")) {
            auto tag = clean.substr(1, clean.size() - 2);
            if (!inlineOptions.contains(tag)) {
                throw std::runtime_error("Unsupported inline block");
            }
            block = tag;
            continue;
        }
        auto t = ConfigTokens(clean);
        if (t.empty()) {
            continue;
        }
        if (IsDefaultRoute(t) || (!safeOptions.contains(t[0]) && !fileOptions.contains(t[0]))) {
            throw std::runtime_error("Managed profile contains an unsupported option");
        }
        if (fileOptions.contains(t[0])) {
            if (t.size() < 2) {
                throw std::runtime_error("Missing dependency path");
            }
            auto dep = PathFromUtf8(t[1]);
            if (!fs::is_regular_file(dep)) {
                throw std::runtime_error("Profile dependency no longer exists");
            }
            if (fs::weakly_canonical(dep.parent_path()) !=
                fs::weakly_canonical(profile.config.parent_path())) {
                throw std::runtime_error("Dependency outside managed profile");
            }
        }
        if (t[0] == "auth-user-pass" && t.size() != 1) {
            throw std::runtime_error("Credential files are not supported");
        }
    }
    Wipe(content);
    if (!block.empty()) {
        throw std::runtime_error("Unterminated inline block");
    }
}
} // namespace ownvpn
