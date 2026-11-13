#include "platform.h"
#include "windows_platform.h"
#include <algorithm>
#include <chrono>
#include <winsock2.h>
#include <ws2tcpip.h>
extern "C" WINSOCK_API_LINKAGE INT WSAAPI GetAddrInfoExCancel(LPHANDLE);
extern "C" WINSOCK_API_LINKAGE INT WSAAPI GetAddrInfoExOverlappedResult(LPOVERLAPPED);
namespace ownvpn {
namespace {
int AddressFamily(const std::string& address) {
    IN6_ADDR bytes{};
    if (InetPtonA(AF_INET, address.c_str(), &bytes) == 1) {
        return 4;
    }
    if (InetPtonA(AF_INET6, address.c_str(), &bytes) == 1) {
        return 6;
    }
    return 0;
}
} // namespace
static std::vector<std::string> WindowsResolveEndpoint(const std::string& host, int family,
                                                       const std::function<bool()>& cancelled) {
    WSADATA startup{};
    if (WSAStartup(MAKEWORD(2, 2), &startup)) {
        return {};
    }
    struct Cleanup {
        ~Cleanup() {
            WSACleanup();
        }
    } cleanup;
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event.valid()) {
        return {};
    }
    ADDRINFOEXW hints{};
    hints.ai_family = family == 4 ? AF_INET : family == 6 ? AF_INET6 : AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    OVERLAPPED operation{};
    operation.hEvent = event.value;
    PADDRINFOEXW result = nullptr;
    HANDLE query = nullptr;
    timeval timeout{3, 0};
    auto name = Wide(host);
    int error = GetAddrInfoExW(name.c_str(), nullptr, NS_DNS, nullptr, &hints, &result, &timeout, &operation,
                               nullptr, &query);
    if (error == WSA_IO_PENDING) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
        while (WaitForSingleObject(event.value, 50) == WAIT_TIMEOUT) {
            if (cancelled() || std::chrono::steady_clock::now() >= deadline) {
                GetAddrInfoExCancel(&query);
                WaitForSingleObject(event.value, INFINITE);
                break;
            }
        }
        error = GetAddrInfoExOverlappedResult(&operation);
    }
    std::vector<std::string> addresses;
    if (!error && !cancelled()) {
        for (auto item = result; item; item = item->ai_next) {
            char text[INET6_ADDRSTRLEN]{};
            const void* address =
                item->ai_family == AF_INET
                    ? static_cast<const void*>(&reinterpret_cast<sockaddr_in*>(item->ai_addr)->sin_addr)
                : item->ai_family == AF_INET6
                    ? static_cast<const void*>(&reinterpret_cast<sockaddr_in6*>(item->ai_addr)->sin6_addr)
                    : nullptr;
            if (address && InetNtopA(item->ai_family, address, text, sizeof(text)) &&
                std::find(addresses.begin(), addresses.end(), text) == addresses.end()) {
                addresses.emplace_back(text);
            }
        }
    }
    if (result) {
        FreeAddrInfoExW(result);
    }
    return addresses;
}

namespace {
class WindowsNetwork final : public INetworkServices {
  public:
    int IpFamily(const std::string& address) const override {
        return AddressFamily(address);
    }
    std::vector<std::string> Resolve(const std::string& host, int family,
                                     const std::function<bool()>& cancelled) const override {
        return WindowsResolveEndpoint(host, family, cancelled);
    }
};
} // namespace
INetworkServices& WindowsNetworkServices() {
    static WindowsNetwork network;
    return network;
}
} // namespace ownvpn
