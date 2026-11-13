#include "core.h"
#include <climits>

namespace ownvpn {
namespace {
bool Scalar(uint32_t value) {
    return value <= 0x10ffff && (value < 0xd800 || value > 0xdfff);
}
void AppendUtf8(std::string& out, uint32_t value) {
    if (value < 0x80) {
        out += static_cast<char>(value);
    } else if (value < 0x800) {
        out += static_cast<char>(0xc0 | (value >> 6));
        out += static_cast<char>(0x80 | (value & 63));
    } else if (value < 0x10000) {
        out += static_cast<char>(0xe0 | (value >> 12));
        out += static_cast<char>(0x80 | ((value >> 6) & 63));
        out += static_cast<char>(0x80 | (value & 63));
    } else {
        out += static_cast<char>(0xf0 | (value >> 18));
        out += static_cast<char>(0x80 | ((value >> 12) & 63));
        out += static_cast<char>(0x80 | ((value >> 6) & 63));
        out += static_cast<char>(0x80 | (value & 63));
    }
}
} // namespace
std::string Utf8(std::wstring_view input) {
    std::string output;
    for (size_t i = 0; i < input.size(); ++i) {
        uint32_t value = static_cast<uint32_t>(input[i]);
        if constexpr (sizeof(wchar_t) == 2) {
            if (value >= 0xd800 && value <= 0xdbff) {
                if (++i == input.size()) {
                    throw std::runtime_error("Invalid Unicode text");
                }
                uint32_t low = static_cast<uint32_t>(input[i]);
                if (low < 0xdc00 || low > 0xdfff) {
                    throw std::runtime_error("Invalid Unicode text");
                }
                value = 0x10000 + ((value - 0xd800) << 10) + low - 0xdc00;
            }
        }
        if (!Scalar(value)) {
            throw std::runtime_error("Invalid Unicode text");
        }
        AppendUtf8(output, value);
    }
    return output;
}
std::wstring Wide(std::string_view input) {
    std::wstring output;
    for (size_t i = 0; i < input.size();) {
        unsigned char first = static_cast<unsigned char>(input[i++]);
        uint32_t value = 0, minimum = 0;
        int remaining = 0;
        if (first < 0x80) {
            value = first;
        } else if (first >= 0xc2 && first <= 0xdf) {
            value = first & 31;
            minimum = 0x80;
            remaining = 1;
        } else if (first >= 0xe0 && first <= 0xef) {
            value = first & 15;
            minimum = 0x800;
            remaining = 2;
        } else if (first >= 0xf0 && first <= 0xf4) {
            value = first & 7;
            minimum = 0x10000;
            remaining = 3;
        } else {
            return L"无法解码文本";
        }
        if (input.size() - i < static_cast<size_t>(remaining)) {
            return L"无法解码文本";
        }
        for (int n = 0; n < remaining; ++n) {
            unsigned char next = static_cast<unsigned char>(input[i++]);
            if ((next & 0xc0) != 0x80) {
                return L"无法解码文本";
            }
            value = (value << 6) | (next & 63);
        }
        if (value < minimum || !Scalar(value)) {
            return L"无法解码文本";
        }
        if constexpr (sizeof(wchar_t) == 2) {
            if (value >= 0x10000) {
                value -= 0x10000;
                output += static_cast<wchar_t>(0xd800 | (value >> 10));
                output += static_cast<wchar_t>(0xdc00 | (value & 1023));
                continue;
            }
        }
        output += static_cast<wchar_t>(value);
    }
    return output;
}
} // namespace ownvpn
