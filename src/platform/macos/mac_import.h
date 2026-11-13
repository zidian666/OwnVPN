#pragma once
#include "profile.h"

namespace ownvpn::mac {
// A ZIP is extracted only into this object's private, bounded workspace.
// A selected .ovpn keeps its original sibling directory for dependency lookup.
class ImportSession {
  public:
    explicit ImportSession(const fs::path& source, const fs::path& temporaryRoot = {});
    ~ImportSession();
    ImportSession(const ImportSession&) = delete;
    ImportSession& operator=(const ImportSession&) = delete;
    const std::vector<fs::path>& configurations() const {
        return configurations_;
    }
    Profile Import(size_t index, const fs::path& pem, const ProfileDependencyFiles& files = {}) const;

  private:
    fs::path workspace_, referenceRoot_;
    std::vector<fs::path> configurations_;
    void Extract(const fs::path& zip);
    void Cleanup() noexcept;
};
} // namespace ownvpn::mac
