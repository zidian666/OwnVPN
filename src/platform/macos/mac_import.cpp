#include "mac_import.h"
#include <algorithm>
#include <archive.h>
#include <archive_entry.h>
#include <array>
#include <cctype>
#include <fstream>
#include <memory>
#include <set>

namespace ownvpn::mac {
namespace {
std::string Extension(const fs::path& path) {
    auto text = path.extension().string();
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return std::tolower(c); });
    return text;
}
} // namespace
ImportSession::ImportSession(const fs::path& source, const fs::path& temporaryRoot) {
    if (!fs::is_regular_file(source)) {
        throw std::runtime_error("请选择配置文件");
    }
    if (Extension(source) == ".ovpn") {
        configurations_.push_back(fs::canonical(source));
        referenceRoot_ = configurations_[0].parent_path();
    } else if (Extension(source) == ".zip") {
        auto cache = temporaryRoot;
        if (cache.empty()) {
            PrivateDirectory(AppData());
            cache = AppData() / "imports";
        }
        PrivateDirectory(cache);
        workspace_ = cache / RandomHex();
        try {
            PrivateDirectory(workspace_);
            referenceRoot_ = workspace_;
            Extract(source);
        } catch (...) {
            Cleanup();
            throw;
        }
    } else {
        throw std::runtime_error("请选择 .ovpn 或 ZIP 配置包");
    }
}
void ImportSession::Extract(const fs::path& zip) {
    std::unique_ptr<archive, decltype(&archive_read_free)> reader(archive_read_new(), archive_read_free);
    if (!reader) {
        throw std::runtime_error("无法初始化 ZIP 读取器");
    }
    archive_read_support_format_zip(reader.get());
    if (archive_read_open_filename(reader.get(), zip.c_str(), 8192) != ARCHIVE_OK) {
        throw std::runtime_error("无法读取 ZIP 配置包");
    }
    size_t count = 0;
    uint64_t total = 0;
    std::set<fs::path> files;
    archive_entry* entry = nullptr;
    int status;
    while ((status = archive_read_next_header(reader.get(), &entry)) == ARCHIVE_OK) {
        if (++count > 128) {
            throw std::runtime_error("配置包文件数量过多");
        }
        auto raw = archive_entry_pathname_utf8(entry);
        if (!raw) {
            throw std::runtime_error("配置包文件名不是 UTF-8");
        }
        std::string name = raw;
        std::replace(name.begin(), name.end(), '\\', '/');
        auto relative = PathFromUtf8(name).lexically_normal();
        if (relative.empty() || relative == "." || relative.is_absolute() || *relative.begin() == ".." ||
            (name.size() > 1 && name[1] == ':')) {
            throw std::runtime_error("配置包路径无效");
        }
        if (archive_entry_symlink(entry) || archive_entry_hardlink(entry) ||
            (archive_entry_filetype(entry) != AE_IFREG && archive_entry_filetype(entry) != AE_IFDIR)) {
            throw std::runtime_error("配置包不允许链接或特殊文件");
        }
        auto target = workspace_ / relative;
        if (archive_entry_filetype(entry) == AE_IFDIR) {
            fs::create_directories(target);
            continue;
        }
        if (!files.insert(relative).second || fs::exists(target)) {
            throw std::runtime_error("配置包含重复文件");
        }
        fs::create_directories(target.parent_path());
        std::ofstream output(target, std::ios::binary);
        if (!output) {
            throw std::runtime_error("无法保存配置依赖");
        }
        std::array<char, 8192> buffer{};
        uint64_t size = 0;
        la_ssize_t length;
        while ((length = archive_read_data(reader.get(), buffer.data(), buffer.size())) > 0) {
            size += static_cast<uint64_t>(length);
            total += static_cast<uint64_t>(length);
            if (size > 16 * 1024 * 1024 || total > 32 * 1024 * 1024) {
                throw std::runtime_error("配置包解压后过大");
            }
            output.write(buffer.data(), length);
            if (!output) {
                throw std::runtime_error("无法保存配置依赖");
            }
        }
        WipeBytes({reinterpret_cast<unsigned char*>(buffer.data()), buffer.size()});
        if (length < 0) {
            throw std::runtime_error("配置包数据损坏");
        }
        output.close();
        fs::permissions(target, fs::perms::owner_read | fs::perms::owner_write);
        if (Extension(target) == ".ovpn") {
            configurations_.push_back(target);
        }
    }
    if (status != ARCHIVE_EOF) {
        throw std::runtime_error("配置包目录损坏");
    }
    if (configurations_.empty()) {
        throw std::runtime_error("配置包中没有 .ovpn");
    }
    std::sort(configurations_.begin(), configurations_.end());
}
Profile ImportSession::Import(size_t index, const fs::path& pem, const ProfileDependencyFiles& files) const {
    return ProfileRepository().Import(configurations_.at(index), pem, files, referenceRoot_);
}
void ImportSession::Cleanup() noexcept {
    if (!workspace_.empty()) {
        std::error_code ignored;
        fs::remove_all(workspace_, ignored);
    }
}
ImportSession::~ImportSession() {
    Cleanup();
}
} // namespace ownvpn::mac
