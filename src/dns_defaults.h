#pragma once
#include <array>
#include <cstdint>

namespace ownvpn {
struct InitialDnsAddress {
    const char* host;
    const char* address;
    int64_t updatedAt;
};
// Verified against two public resolvers on 2026-11-11. Used only when this
// profile has no saved address; later successful system DNS replaces it.
inline constexpr std::array<InitialDnsAddress, 2> InitialDnsAddresses{{
    {"ksvpn.knownsec.com", "106.39.24.170", 1794367366},
    {"vpn.knownsec.com", "123.125.242.132", 1794367366},
}};
} // namespace ownvpn
