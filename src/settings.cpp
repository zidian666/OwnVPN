#include "settings.h"
namespace ownvpn {
Settings Settings::Load() {
    Settings s;
    auto path = AppData() / L"settings.ini";
    if (!fs::exists(path)) {
        return s;
    }
    auto id = Trim(ReadFile(path));
    if (id.size() == 32 && id.find_first_not_of("0123456789abcdef") == std::string::npos) {
        s.profileId = Wide(id);
    }
    return s;
}
void Settings::Save() const {
    PrivateDirectory(AppData());
    WriteFile(AppData() / L"settings.ini", Utf8(profileId));
}
} // namespace ownvpn
