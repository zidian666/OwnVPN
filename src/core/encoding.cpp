#include "protocol.h"

namespace ownvpn {
namespace {
constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int Value(char c) {
    auto index = alphabet.find(c);
    return index == alphabet.npos ? -1 : static_cast<int>(index);
}
} // namespace
std::string Base64(std::string_view input) {
    std::string output;
    for (size_t i = 0; i < input.size(); i += 3) {
        uint32_t value = static_cast<unsigned char>(input[i]) << 16;
        if (i + 1 < input.size()) {
            value |= static_cast<unsigned char>(input[i + 1]) << 8;
        }
        if (i + 2 < input.size()) {
            value |= static_cast<unsigned char>(input[i + 2]);
        }
        output += alphabet[(value >> 18) & 63];
        output += alphabet[(value >> 12) & 63];
        output += i + 1 < input.size() ? alphabet[(value >> 6) & 63] : '=';
        output += i + 2 < input.size() ? alphabet[value & 63] : '=';
    }
    return output;
}
std::string Base64Decode(std::string_view input) {
    std::string text;
    for (char c : input) {
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
            text += c;
        }
    }
    auto fail = [] { throw std::runtime_error("Invalid challenge username"); };
    if (text.size() % 4 == 1) {
        fail();
    }
    if (text.find('=') == text.npos) {
        while (text.size() % 4) {
            text += '=';
        }
    } else if (text.size() % 4) {
        fail();
    }
    std::string output;
    for (size_t i = 0; i < text.size(); i += 4) {
        int a = Value(text[i]), b = Value(text[i + 1]);
        int c = text[i + 2] == '=' ? 0 : Value(text[i + 2]);
        int d = text[i + 3] == '=' ? 0 : Value(text[i + 3]);
        bool pad2 = text[i + 2] == '=', pad1 = text[i + 3] == '=';
        if (a < 0 || b < 0 || c < 0 || d < 0 || (pad2 && !pad1) || ((pad2 || pad1) && i + 4 != text.size()) ||
            (pad2 && (b & 15)) || (!pad2 && pad1 && (c & 3))) {
            fail();
        }
        uint32_t value = (static_cast<uint32_t>(a) << 18) | (static_cast<uint32_t>(b) << 12) |
                         (static_cast<uint32_t>(c) << 6) | static_cast<uint32_t>(d);
        output += static_cast<char>(value >> 16);
        if (!pad2) {
            output += static_cast<char>((value >> 8) & 255);
        }
        if (!pad1) {
            output += static_cast<char>(value & 255);
        }
    }
    return output;
}
} // namespace ownvpn
