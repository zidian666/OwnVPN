#include "dns_fallback.h"
#include "dns_defaults.h"
#include "platform.h"
#include <algorithm>
#include <chrono>
#include <map>
#include <set>
#include <sstream>

namespace ownvpn {
namespace {
int AddressFamily(const std::string& address) {
    return Platform().network.IpFamily(address);
}
bool HostValid(const std::string& host) {
    return !host.empty() && host.size() <= 253 && std::all_of(host.begin(), host.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-';
    });
}
std::string Lower(std::string text) {
    for (auto& c : text) {
        if (c >= 'A' && c <= 'Z') {
            c += 'a' - 'A';
        }
    }
    return text;
}
int Family(const std::string& proto) {
    if (proto.find('4') != proto.npos) {
        return 4;
    }
    if (proto.find('6') != proto.npos) {
        return 6;
    }
    return 0;
}
struct Entry {
    std::string ip;
    int64_t time;
};
} // namespace
std::string PrepareDnsFallback(std::string_view config, const fs::path& cache, bool enabled,
                               const EndpointResolver& resolver, const EventSink& sink,
                               const std::function<bool()>& cancelled) {
    std::map<std::string, Entry> entries;
    auto now =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    try {
        if (fs::exists(cache)) {
            std::istringstream input(ReadFile(cache));
            std::string host, ip;
            int family;
            int64_t time;
            while (input >> host >> family >> ip >> time) {
                if (HostValid(host) && family == AddressFamily(ip) && time > 0 && time <= now) {
                    entries[host + " " + std::to_string(family)] = {ip, time};
                }
            }
        }
    } catch (...) {
        sink({EventType::Diagnostic, L"DNS：历史地址缓存无法读取，将按域名解析。"});
    }
    std::string globalProto = "udp";
    std::istringstream scan{std::string(config)};
    std::string line, block;
    while (std::getline(scan, line)) {
        if (!block.empty()) {
            if (Trim(line) == "</" + block + ">") {
                block.clear();
            }
            continue;
        }
        auto clean = Trim(line);
        if (clean.starts_with('<')) {
            block = clean.substr(1, clean.size() - 2);
            continue;
        }
        auto tokens = ConfigTokens(line);
        if (tokens.size() == 2 && tokens[0] == "proto") {
            globalProto = tokens[1];
        }
    }
    scan.clear();
    scan.seekg(0);
    std::string output;
    bool changed = false, dirty = false;
    std::map<std::string, std::vector<std::string>> resolved;
    while (std::getline(scan, line)) {
        if (cancelled()) {
            throw std::runtime_error("DNS preparation cancelled");
        }
        auto clean = Trim(line);
        bool inlineContent = !block.empty();
        if (inlineContent) {
            if (clean == "</" + block + ">") {
                block.clear();
            }
        } else if (clean.starts_with('<')) {
            block = clean.substr(1, clean.size() - 2);
            inlineContent = true;
        }
        auto tokens = inlineContent ? std::vector<std::string>{} : ConfigTokens(line);
        if (tokens.size() >= 2 && tokens[0] == "remote" && !AddressFamily(tokens[1])) {
            auto host = Lower(tokens[1]);
            if (HostValid(host)) {
                int family = Family(tokens.size() >= 4 ? tokens[3] : globalProto);
                for (const auto& initial : InitialDnsAddresses) {
                    if (host == initial.host && family != 6 && !entries.contains(host + " 4")) {
                        entries[host + " 4"] = {initial.address, initial.updatedAt};
                        dirty = true;
                        sink({EventType::Diagnostic, L"DNS：" + Wide(host) + L" 尚无历史地址，已初始化为 " +
                                                         Wide(initial.address) +
                                                         L"；DNS 解析成功后自动更新。"});
                    }
                }
                auto key = host + " " + std::to_string(family);
                if (!resolved.contains(key)) {
                    sink({EventType::Status, L"正在解析 VPN 服务器域名…"});
                    resolved[key] = resolver(host, family);
                }
                if (cancelled()) {
                    throw std::runtime_error("DNS preparation cancelled");
                }
                auto& addresses = resolved[key];
                bool success = false;
                std::set<int> updatedFamilies;
                for (const auto& ip : addresses) {
                    int ipFamily = AddressFamily(ip);
                    if (ipFamily && (!family || family == ipFamily)) {
                        auto addressKey = host + " " + std::to_string(ipFamily);
                        if (!success) {
                            sink({EventType::Diagnostic,
                                  L"DNS：" + Wide(host) + L" 解析成功：" + Wide(ip) + L"；保持域名连接。"});
                        }
                        if (updatedFamilies.insert(ipFamily).second) {
                            entries[addressKey] = {ip, now};
                        }
                        dirty = true;
                        success = true;
                    }
                }
                if (!success) {
                    auto found = entries.find(host + " " + std::to_string(family == 6 ? 6 : 4));
                    if (found == entries.end() && !family) {
                        found = entries.find(host + " 6");
                    }
                    if (enabled && found != entries.end()) {
                        sink({EventType::Diagnostic, L"DNS：" + Wide(host) + L" 解析失败，尝试使用历史 IP " +
                                                         Wide(found->second.ip) + L"（缓存 " +
                                                         std::to_wstring((now - found->second.time) / 86400) +
                                                         L" 天）；证书校验保持开启。"});
                        tokens[1] = found->second.ip;
                        line = "remote";
                        for (size_t i = 1; i < tokens.size(); ++i) {
                            line += ' ' + ConfigQuote(tokens[i]);
                        }
                        changed = true;
                    } else {
                        sink({EventType::Diagnostic,
                              L"DNS：" + Wide(host) + L" 解析失败；" +
                                  (enabled ? std::wstring(L"没有可用的历史 IP，继续按原配置连接。")
                                           : std::wstring(L"未启用尝试绕过DNS，继续按原配置连接。"))});
                    }
                }
            }
        }
        output += line + '\n';
    }
    if (dirty) {
        std::string saved;
        for (const auto& [key, entry] : entries) {
            saved += key + " " + entry.ip + " " + std::to_string(entry.time) + '\n';
        }
        try {
            WriteFile(cache, saved);
        } catch (...) {
            sink({EventType::Diagnostic, L"DNS：历史地址缓存未能保存，下次连接可能无法使用。"});
        }
    }
    if (!changed) {
        Wipe(output);
    }
    return output;
}
} // namespace ownvpn
