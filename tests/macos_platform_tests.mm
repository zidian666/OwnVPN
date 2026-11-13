#include "mac_import.h"
#include "mac_platform.h"
#include "profile.h"
#include "support/profile_import_cases.h"
#include "totp.h"
#import <Foundation/Foundation.h>
#include <archive.h>
#include <archive_entry.h>
#include <array>
#include <iostream>
#include <sys/stat.h>

using namespace ownvpn;
namespace {
int checks = 0;
void Check(bool value, const char* label) {
    ++checks;
    if (!value) {
        throw std::runtime_error(label);
    }
}
template <class F> void Throws(F action, const char* label) {
    bool failed = false;
    try {
        action();
    } catch (const std::exception&) {
        failed = true;
    }
    Check(failed, label);
}
void CryptoTests() {
    const int64_t times[] = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000LL};
    const char* expected[][6] = {{"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"},
                                 {"46119246", "68084774", "67062674", "91819424", "90698825", "77737706"},
                                 {"90693936", "25091201", "99943326", "93441116", "38618901", "47863826"}};
    for (int a = 0; a < 3; ++a) {
        std::string seed;
        for (int i = 0; i < (a == 0 ? 20 : a == 1 ? 32 : 64); ++i) {
            seed += static_cast<char>('0' + (i + 1) % 10);
        }
        TotpConfig config;
        config.secretBase32 =
            EncodeBase32({reinterpret_cast<const unsigned char*>(seed.data()), seed.size()});
        config.algorithm = static_cast<TotpAlgorithm>(a);
        config.digits = 8;
        for (int i = 0; i < 6; ++i) {
            Check(GenerateTotp(config, times[i]) == expected[a][i], "CommonCrypto RFC6238 vector");
        }
    }
    const std::array<unsigned char, 3> abc{'a', 'b', 'c'};
    auto digest = Platform().crypto.Digest(HashAlgorithm::Sha256, abc);
    const std::vector<unsigned char> expectedDigest{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    Check(digest == expectedDigest, "CommonCrypto SHA256 known answer");
    Check(RandomHex().size() == 32, "SecRandomCopyBytes supplies profile identifiers");
    Check(RandomHex() != RandomHex(), "secure random calls are not deterministic");
}
void Zip(const fs::path& path, std::string name, std::string content, bool link = false) {
    auto writer = archive_write_new();
    archive_write_set_format_zip(writer);
    if (archive_write_open_filename(writer, path.c_str()) != ARCHIVE_OK) {
        throw std::runtime_error("ZIP fixture creation failed");
    }
    auto entry = archive_entry_new();
    archive_entry_set_pathname(entry, name.c_str());
    archive_entry_set_perm(entry, 0600);
    archive_entry_set_filetype(entry, link ? AE_IFLNK : AE_IFREG);
    if (link) {
        archive_entry_set_symlink(entry, "outside");
    } else {
        archive_entry_set_size(entry, content.size());
    }
    if (archive_write_header(writer, entry) != ARCHIVE_OK) {
        throw std::runtime_error("ZIP fixture header failed");
    }
    if (!link && archive_write_data(writer, content.data(), content.size()) !=
                     static_cast<la_ssize_t>(content.size())) {
        throw std::runtime_error("ZIP fixture data failed");
    }
    archive_entry_free(entry);
    archive_write_close(writer);
    archive_write_free(writer);
}
void FileTests(const fs::path& root) {
    auto privateDir = root / "private";
    PrivateDirectory(privateDir);
    struct stat info{};
    Check(stat(privateDir.c_str(), &info) == 0 && (info.st_mode & 0777) == 0700,
          "private directories are owner-only");
    auto link = root / "link";
    fs::create_directory_symlink(privateDir, link);
    Throws([&] { PrivateDirectory(link); }, "private directory rejects symbolic leaf");
    fs::remove(link);
    ownvpn::testing::ProfileImportCases(root / "profiles", Check);
    auto archive = root / "package.zip", cache = root / "imports";
    Zip(archive, "nested/office.ovpn", "client\ndev tun\nremote vpn.example.invalid\n");
    {
        mac::ImportSession session(archive, cache);
        Check(session.configurations().size() == 1 && session.configurations()[0].filename() == "office.ovpn",
              "Mac ZIP import finds nested configurations");
    }
    Check(fs::is_empty(cache), "Mac import clears private temporary files");
    for (auto name : {"../escape.ovpn", "/escape.ovpn", "C:\\escape.ovpn"}) {
        Zip(archive, name, "public fixture");
        Throws([&] { mac::ImportSession session(archive, cache); }, "Mac ZIP traversal rejected");
    }
    Zip(archive, "link.ovpn", "", true);
    Throws([&] { mac::ImportSession session(archive, cache); }, "Mac ZIP links rejected");
    Zip(archive, "ca.txt", "no configuration");
    Throws([&] { mac::ImportSession session(archive, cache); }, "Mac ZIP requires configuration");
    Check(fs::is_empty(cache), "failed Mac imports remove workspaces");
}
void NetworkTests() {
    const auto& network = Platform().network;
    Check(network.IpFamily("192.0.2.1") == 4 && network.IpFamily("2001:db8::1") == 6,
          "Mac IP literal families");
    Check(network.IpFamily("not an address") == 0, "Mac rejects malformed IP literal");
    auto never = [] { return false; };
    Check(network.Resolve("192.0.2.1", 4, never) == std::vector<std::string>{"192.0.2.1"},
          "literal bypasses resolver");
    Check(network.Resolve("192.0.2.1", 6, never).empty(), "literal honors required family");
    Throws([&] { network.Resolve("example.invalid", 0, [] { return true; }); },
           "DNS cancellation before lookup");
}
void QrTests() {
    auto root = fs::path(OWNVPN_TEST_FIXTURES);
    auto config = ParseTotpUri(mac::DecodeQr(root / "totp-standard.png"));
    Check(config.digits == 6 && config.periodSeconds == 30, "Vision standard enrollment QR");
    Check(mac::DecodeQr(root / "totp-rotated.png") == mac::DecodeQr(root / "totp-standard.png"),
          "Vision handles rotated QR");
    for (auto name : {"blank.png", "multiple-qr.png", "not-totp.png"}) {
        Throws([&] { mac::DecodeQr(root / name); }, "Vision rejects missing, ambiguous or non-TOTP QR");
    }
}
void KeychainTest() {
    auto store = mac::CreateSecretStore("com.ownvpn.tests." + RandomHex());
    const auto profile = L"synthetic-profile", field = L"synthetic-field";
    try {
        Check(store->Read(profile, field).empty(), "isolated Keychain starts empty");
        store->Write(profile, field, L"公开合成样本");
        Check(store->Read(profile, field) == L"公开合成样本", "isolated Keychain Unicode roundtrip");
        store->Write(profile, field, L"updated");
        Check(store->Read(profile, field) == L"updated", "isolated Keychain update");
        store->Write(profile, field, L"");
        Check(store->Read(profile, field).empty(), "isolated Keychain deletion");
    } catch (...) {
        try {
            store->Write(profile, field, L"");
        } catch (...) {
        }
        throw;
    }
}
} // namespace
int main(int argc, char** argv) {
    umask(0077);
    @autoreleasepool {
        auto root = fs::canonical(fs::temp_directory_path()) / ("ownvpn-mac-tests-" + RandomHex());
        try {
            PrivateDirectory(root);
            CryptoTests();
            FileTests(root);
            NetworkTests();
            QrTests();
            if (argc == 2 && std::string_view(argv[1]) == "--keychain") {
                KeychainTest();
            } else if (argc != 1) {
                throw std::runtime_error("Usage: macos_platform_tests [--keychain]");
            }
            fs::remove_all(root);
            std::cout << "PASS: " << checks << " macOS platform checks\n";
            return 0;
        } catch (const std::exception& error) {
            std::error_code ignored;
            fs::remove_all(root, ignored);
            std::cerr << "FAIL: " << error.what() << '\n';
            return 1;
        }
    }
}
