#pragma once
#include "core.h"
#include <map>

namespace ownvpn {
struct Profile {
    std::wstring id;
    std::wstring name;
    fs::path config;
};
class MissingProfileDependency final : public std::runtime_error {
  public:
    MissingProfileDependency(std::string option, std::string reference)
        : std::runtime_error("Missing dependency (" + option + "): " + reference), option_(std::move(option)),
          reference_(std::move(reference)) {}
    const std::string& option() const {
        return option_;
    }
    const std::string& reference() const {
        return reference_;
    }

  private:
    std::string option_, reference_;
};
// Files explicitly selected by the user for a particular directive. Mobile
// document providers do not grant access to the selected file's siblings.
using ProfileDependencyFiles = std::map<std::string, fs::path>;
// Builds a self-contained, private copy. Never modifies the source .ovpn or PEM.
// Unsupported executable directives fail closed instead of being silently run.
class ProfileRepository {
  public:
    explicit ProfileRepository(fs::path root = AppData() / L"profiles") : root_(std::move(root)) {}
    std::vector<Profile> List() const;
    Profile Import(const fs::path& ovpn, const fs::path& fallbackPem = {},
                   const ProfileDependencyFiles& selectedFiles = {}, const fs::path& referenceRoot = {});
    void Validate(const Profile& profile) const;

  private:
    fs::path root_;
};
std::vector<std::string> ConfigTokens(std::string_view line);
std::string ConfigQuote(std::string_view s);
bool IsDefaultRoute(const std::vector<std::string>& tokens);
std::string SplitTunnelPolicy();
} // namespace ownvpn
