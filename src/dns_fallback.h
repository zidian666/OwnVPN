#pragma once
#include "profile.h"

namespace ownvpn {
using EndpointResolver = std::function<std::vector<std::string>(const std::string&, int)>;
// Family: 0 = either, 4 = IPv4, 6 = IPv6. Empty results mean lookup failed.
std::vector<std::string> ResolveEndpoint(const std::string& host, int family,
                                         const std::function<bool()>& cancelled);
// Returns an effective configuration only when DNS failed and a cached address
// was substituted. Certificate directives and original profile remain intact.
std::string PrepareDnsFallback(std::string_view config, const fs::path& cache, bool enabled,
                               const EndpointResolver& resolver, const EventSink& sink,
                               const std::function<bool()>& cancelled);
} // namespace ownvpn
