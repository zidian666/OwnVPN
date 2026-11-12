#pragma once
#include "core.h"

namespace ownvpn {
struct Profile {
    std::wstring id;
    std::wstring name;
    fs::path config;
};
// Builds a self-contained, private copy. Never modifies the source .ovpn or PEM.
// Unsupported executable directives fail closed instead of being silently run.
class ProfileRepository {
  public:
    explicit ProfileRepository(fs::path root = AppData() / L"profiles") : root_(std::move(root)) {}
    std::vector<Profile> List() const;
    Profile Import(const fs::path& ovpn, const fs::path& fallbackPem = {});
    void Validate(const Profile& profile) const;

  private:
    fs::path root_;
};
std::vector<std::string> ConfigTokens(std::string_view line);
std::string ConfigQuote(std::string_view s);
bool IsDefaultRoute(const std::vector<std::string>& tokens);
std::string SplitTunnelPolicy();
} // namespace ownvpn
