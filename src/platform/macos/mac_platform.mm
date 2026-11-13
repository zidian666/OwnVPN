#include "mac_services.h"
#import <Foundation/Foundation.h>
#include <cerrno>
#include <sys/stat.h>
#include <unistd.h>

namespace ownvpn::mac {
fs::path Paths::DataDirectory() const {
    @autoreleasepool {
        NSURL* root = [[NSFileManager defaultManager] URLForDirectory:NSApplicationSupportDirectory
                                                             inDomain:NSUserDomainMask
                                                    appropriateForURL:nil
                                                               create:NO
                                                                error:nil];
        if (!root) {
            throw std::runtime_error("Application Support directory unavailable");
        }
        return PathFromUtf8(root.path.UTF8String) / "OwnVPN";
    }
}
void Paths::MakePrivateDirectory(const fs::path& input) const {
    auto path = fs::absolute(input).lexically_normal();
    // Canonicalize system parents (such as /var -> /private/var); reject a
    // symlink at the private leaf instead of changing its destination's mode.
    auto parent = fs::canonical(path.parent_path());
    path = parent / path.filename();
    struct stat info{};
    if (lstat(path.c_str(), &info) != 0) {
        if (errno != ENOENT || mkdir(path.c_str(), 0700) != 0) {
            throw std::runtime_error("Cannot create private directory");
        }
        if (lstat(path.c_str(), &info) != 0) {
            throw std::runtime_error("Cannot inspect private directory");
        }
    }
    if (!S_ISDIR(info.st_mode) || info.st_uid != getuid() || S_ISLNK(info.st_mode)) {
        throw std::runtime_error("Private directory has unexpected ownership or type");
    }
    if (chmod(path.c_str(), 0700) != 0) {
        throw std::runtime_error("Cannot protect private directory");
    }
}
} // namespace ownvpn::mac
namespace ownvpn {
const PlatformServices& Platform() {
    static mac::Crypto crypto;
    static auto secrets = mac::CreateSecretStore("com.ownvpn.macos.credentials");
    static mac::Paths paths;
    static mac::Network network;
    static const PlatformServices services{crypto, *secrets, paths, network};
    return services;
}
} // namespace ownvpn
