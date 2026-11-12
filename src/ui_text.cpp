#include "ui_text.h"
#include <iomanip>
#include <locale>
#include <sstream>

namespace ownvpn {
std::wstring FormatTrafficBytes(uint64_t bytes) {
    if (!bytes) {
        return L"0 KB";
    }
    const bool megabytes = bytes >= 1024 * 1024;
    std::wostringstream text;
    text.imbue(std::locale::classic());
    text << std::fixed << std::setprecision(1)
         << static_cast<double>(bytes) / (megabytes ? 1048576.0 : 1024.0) << (megabytes ? L" MB" : L" KB");
    return text.str();
}
std::wstring CleanUiText(std::wstring_view text) {
    std::wstring output;
    for (wchar_t c : text) {
        if (c == L'\u2026') {
            continue;
        }
        output += c == L'\u00b7' ? L' ' : c;
    }
    return output;
}
} // namespace ownvpn
