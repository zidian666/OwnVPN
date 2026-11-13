#pragma once
#include "totp.h"

namespace ownvpn {
struct TotpMetadata {
    bool bound = false;
    bool automatic = false;
    int periodSeconds = 30;
    TotpAlgorithm algorithm = TotpAlgorithm::Sha1;
};
// Bindings are isolated by both managed VPN profile ID and the exact VPN username.
// No seed, source QR image, or enrollment URI is written into settings/configs.
class TotpRepository {
  public:
    TotpMetadata Metadata(std::wstring_view profileId, std::wstring_view username) const;
    TotpConfig Load(std::wstring_view profileId, std::wstring_view username) const;
    void Bind(std::wstring_view profileId, std::wstring_view username, const TotpConfig& config) const;
    void SetAutomatic(std::wstring_view profileId, std::wstring_view username, bool enabled) const;
    void Remove(std::wstring_view profileId, std::wstring_view username) const;
    std::optional<int64_t> LastIssuedCounter(std::wstring_view profileId, std::wstring_view username) const;
    void MarkIssued(std::wstring_view profileId, std::wstring_view username, int64_t counter) const;
};
} // namespace ownvpn
