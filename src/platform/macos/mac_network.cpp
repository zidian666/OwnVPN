#include "mac_services.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <dns_sd.h>
#include <poll.h>

namespace ownvpn::mac {
namespace {
struct Lookup {
    std::vector<std::string> addresses;
    bool done = false;
    DNSServiceErrorType error = kDNSServiceErr_NoError;
};
void Address(DNSServiceRef, DNSServiceFlags flags, uint32_t, DNSServiceErrorType error, const char*,
             const sockaddr* address, uint32_t, void* context) {
    auto& state = *static_cast<Lookup*>(context);
    if (error) {
        state.error = error;
        state.done = true;
        return;
    }
    if ((flags & kDNSServiceFlagsAdd) && address) {
        char text[INET6_ADDRSTRLEN]{};
        const void* source = nullptr;
        if (address->sa_family == AF_INET) {
            source = &reinterpret_cast<const sockaddr_in*>(address)->sin_addr;
        }
        if (address->sa_family == AF_INET6) {
            source = &reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr;
        }
        if (source && inet_ntop(address->sa_family, source, text, sizeof(text)) &&
            std::find(state.addresses.begin(), state.addresses.end(), text) == state.addresses.end()) {
            state.addresses.emplace_back(text);
        }
    }
    state.done = !(flags & kDNSServiceFlagsMoreComing);
}
struct Query {
    DNSServiceRef value = nullptr;
    ~Query() {
        if (value) {
            DNSServiceRefDeallocate(value);
        }
    }
};
} // namespace
int Network::IpFamily(const std::string& address) const {
    in_addr v4{};
    in6_addr v6{};
    if (inet_pton(AF_INET, address.c_str(), &v4) == 1) {
        return 4;
    }
    return inet_pton(AF_INET6, address.c_str(), &v6) == 1 ? 6 : 0;
}
std::vector<std::string> Network::Resolve(const std::string& host, int family,
                                          const std::function<bool()>& cancelled) const {
    if (cancelled()) {
        throw std::runtime_error("DNS lookup cancelled");
    }
    if (family != 0 && family != 4 && family != 6) {
        throw std::runtime_error("Invalid address family");
    }
    if (auto literal = IpFamily(host); literal) {
        return family == 0 || family == literal ? std::vector{host} : std::vector<std::string>{};
    }
    Lookup state;
    Query query;
    auto protocols = family == 4   ? kDNSServiceProtocol_IPv4
                     : family == 6 ? kDNSServiceProtocol_IPv6
                                   : kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6;
    auto error = DNSServiceGetAddrInfo(&query.value, 0, kDNSServiceInterfaceIndexAny, protocols, host.c_str(),
                                       Address, &state);
    if (error) {
        return {};
    }
    auto socket = DNSServiceRefSockFD(query.value);
    if (socket < 0) {
        return {};
    }
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (!state.done && std::chrono::steady_clock::now() < deadline) {
        if (cancelled()) {
            throw std::runtime_error("DNS lookup cancelled");
        }
        pollfd descriptor{socket, POLLIN, 0};
        auto count = poll(&descriptor, 1, 100);
        if (count < 0 && errno != EINTR) {
            return {};
        }
        if (count > 0 && (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            return {};
        }
        if (count > 0 && (descriptor.revents & POLLIN) && DNSServiceProcessResult(query.value)) {
            return {};
        }
    }
    if (cancelled()) {
        throw std::runtime_error("DNS lookup cancelled");
    }
    return state.error == kDNSServiceErr_NoError ? state.addresses : std::vector<std::string>{};
}
} // namespace ownvpn::mac
