#pragma once
#include "profile.h"
namespace ownvpn::testing {
template <class Check> void ProfileImportCases(const fs::path& root, Check check) {
    auto documents = root / "documents", selected = root / "selected";
    fs::create_directories(documents);
    fs::create_directories(selected);
    auto input = documents / "office.ovpn", pem = selected / "users.pem", ca = selected / "ca.crt",
         tls = selected / "tls.key";
    const std::string config = "client\ndev tun\nremote vpn.example.invalid 1194\ntls-auth company/key 1\nca "
                               "company/ca.crt\ncert company/users.pem\nkey company/users.pem\n";
    WriteFile(input, config);
    WriteFile(pem, "public client PEM fixture");
    WriteFile(ca, "public CA fixture");
    WriteFile(tls, "public TLS auth fixture");
    ProfileRepository repository(root / "managed");
    ProfileDependencyFiles chosen;
    auto missing = [&](std::string_view option, std::string_view reference) {
        bool caught = false;
        try {
            repository.Import(input, pem, chosen, documents);
        } catch (const MissingProfileDependency& error) {
            caught = error.option() == option && error.reference() == reference;
        }
        check(caught, "missing dependency preserves directive and original reference");
        check(repository.List().empty(), "incomplete import does not publish a profile");
    };
    missing("tls-auth", "company/key");
    chosen.emplace("tls-auth", tls);
    missing("ca", "company/ca.crt");
    chosen.emplace("ca", ca);
    auto profile = repository.Import(input, pem, chosen, documents);
    repository.Validate(profile);
    check(ReadFile(profile.config.parent_path() / "tls-auth.bin") == ReadFile(tls),
          "TLS authentication uses its selected key, never the PEM fallback");
    check(ReadFile(profile.config.parent_path() / "ca.bin") == ReadFile(ca),
          "CA uses its selected certificate");
    check(ReadFile(profile.config.parent_path() / "key.bin") == ReadFile(pem) &&
              ReadFile(profile.config.parent_path() / "cert.bin") == ReadFile(pem),
          "selected PEM supplies client certificate and private key");
    check(ReadFile(input) == config, "dependency completion leaves the selected configuration unchanged");
    fs::create_directories(documents / "company");
    WriteFile(documents / "company/key", ReadFile(tls));
    WriteFile(documents / "company/ca.crt", ReadFile(ca));
    auto packaged = repository.Import(input, pem, {}, documents);
    check(ReadFile(packaged.config.parent_path() / "tls-auth.bin") == ReadFile(tls),
          "archive layout resolves sibling TLS key");
    check(ReadFile(packaged.config.parent_path() / "ca.bin") == ReadFile(ca),
          "archive layout resolves sibling CA");
    auto before = repository.List().size();
    WriteFile(input,
              "client\ndev tun\nremote vpn.example.invalid\nca " + ConfigQuote(Utf8(PathText(ca))) + "\n");
    bool rejected = false;
    try {
        repository.Import(input, {}, {}, documents);
    } catch (const MissingProfileDependency& error) {
        rejected = error.option() == "ca";
    }
    check(rejected && repository.List().size() == before,
          "unselected files outside the mobile import workspace are not read");
    auto explicitFile = repository.Import(input, {}, {{"ca", ca}}, documents);
    check(ReadFile(explicitFile.config.parent_path() / "ca.bin") == ReadFile(ca),
          "explicit selection authorizes the particular external document");
}
} // namespace ownvpn::testing
