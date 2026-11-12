#include "credential_store.h"
#include "profile.h"
#include "qr_import.h"
#include "settings.h"
#include "totp_store.h"
#include <iostream>
#include <objbase.h>
#include <wincred.h>

using namespace ownvpn;
// Local read-only diagnostics. Never prints a seed, enrollment URI, password,
// username, or current OTP; it only reports public parameters/comparison flags.
int wmain(int argc, wchar_t** argv) {
    auto com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool oracle = argc == 2 && std::wstring_view(argv[1]) == L"--oracle";
    bool referenceMatches = true;
    try {
        auto settings = Settings::Load();
        for (const auto& profile : ProfileRepository().List()) {
            auto savedUser = ReadProtectedValue(profile.id, L"username");
            auto savedPass = ReadProtectedValue(profile.id, L"password");
            std::cout << "profile=" << Utf8(profile.name) << ",id=" << Utf8(profile.id)
                      << ",selected=" << (profile.id == settings.profileId)
                      << ",has_user=" << !savedUser.empty() << ",has_password=" << !savedPass.empty()
                      << ",automatic="
                      << (!savedUser.empty() && TotpRepository().Metadata(profile.id, savedUser).automatic)
                      << '\n';
            Wipe(savedUser);
            Wipe(savedPass);
        }
        auto username = ReadProtectedValue(settings.profileId, L"username");
        auto password = ReadProtectedValue(settings.profileId, L"password");
        std::cout << "saved_username=" << !username.empty() << "\nsaved_password=" << !password.empty()
                  << '\n';
        Wipe(password);
        if (!username.empty()) {
            std::cout << "automatic_otp=" << TotpRepository().Metadata(settings.profileId, username).automatic
                      << '\n';
        }
        std::vector<TotpConfig> configs;
        if (!username.empty()) {
            configs.push_back(TotpRepository().Load(settings.profileId, username));
        } else {
            for (const auto& profile : ProfileRepository().List()) {
                auto prefix = L"OwnVPN/" + profile.id + L"/totp/";
                auto filter = prefix + L"*";
                DWORD count = 0;
                PCREDENTIALW* records = nullptr;
                if (!CredEnumerateW(filter.c_str(), 0, &count, &records)) {
                    continue;
                }
                struct RecordsGuard {
                    DWORD count;
                    PCREDENTIALW* records;
                    ~RecordsGuard() {
                        for (DWORD i = 0; i < count; ++i) {
                            SecureZeroMemory(records[i]->CredentialBlob, records[i]->CredentialBlobSize);
                        }
                        CredFree(records);
                    }
                } recordsGuard{count, records};
                for (DWORD i = 0; i < count; ++i) {
                    std::wstring name(records[i]->TargetName);
                    auto suffix = name.substr(prefix.size());
                    if (suffix.size() != 64 || suffix.find_first_not_of(L"0123456789abcdef") != suffix.npos) {
                        continue;
                    }
                    auto uri =
                        Utf8(std::wstring_view(reinterpret_cast<const wchar_t*>(records[i]->CredentialBlob),
                                               records[i]->CredentialBlobSize / sizeof(wchar_t)));
                    struct UriGuard {
                        std::string& uri;
                        ~UriGuard() {
                            Wipe(uri);
                        }
                    } uriGuard{uri};
                    configs.push_back(ParseTotpUri(uri));
                }
            }
        }
        std::cout << "binding_count=" << configs.size() << '\n';
        for (const auto& config : configs) {
            auto bytes = DecodeBase32(config.secretBase32);
            std::cout << "algorithm=" << AlgorithmName(config.algorithm)
                      << "\nperiod=" << config.periodSeconds << "\ndigits=" << config.digits
                      << "\nseed_bytes=" << bytes.size() << '\n';
            SecureZeroMemory(bytes.data(), bytes.size());
            std::cout << "public_test_seed=" << (config.secretBase32 == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
                      << '\n';
            std::cout << "common_documentation_seed=" << (config.secretBase32 == "JBSWY3DPEHPK3PXP") << '\n';
            if (oracle) {
                for (auto algorithm : {TotpAlgorithm::Sha1, TotpAlgorithm::Sha256, TotpAlgorithm::Sha512}) {
                    auto candidate = WithTotpParameters(config, algorithm, config.periodSeconds);
                    for (int64_t time :
                         {int64_t(0), int64_t(59), int64_t(1234567890), int64_t(20000000000)}) {
                        std::string expected;
                        if (!(std::cin >> expected)) {
                            referenceMatches = false;
                        }
                        auto actual = GenerateTotp(candidate, time);
                        referenceMatches = referenceMatches && actual == expected;
                        Wipe(expected);
                        Wipe(actual);
                    }
                }
            } else if (argc == 2) {
                auto source = ImportTotpQrImage(argv[1]);
                std::cout << "same_seed_as_qr=" << (source.secretBase32 == config.secretBase32)
                          << "\nqr_algorithm=" << AlgorithmName(source.algorithm)
                          << "\nqr_period=" << source.periodSeconds << '\n';
            }
            if (oracle) {
                std::cout << "independent_reference_match=" << referenceMatches << '\n';
            }
            Wipe(username);
        }
        if (SUCCEEDED(com)) {
            CoUninitialize();
        }
        return referenceMatches ? 0 : 2;
    } catch (const std::exception& error) {
        std::cerr << "diagnostic_error=" << error.what() << '\n';
        if (SUCCEEDED(com)) {
            CoUninitialize();
        }
        return 1;
    }
}
