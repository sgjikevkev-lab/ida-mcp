#pragma once
#include <string>

namespace mcp {
    inline std::string SanitizeUnicode(const std::string& input) {
        std::string out;
        out.reserve(input.size());
        for (size_t i = 0; i < input.size();) {
            const auto c = static_cast<unsigned char>(input[i]);
            size_t length = c < 0x80 ? 1 : (c >= 0xC2 && c <= 0xDF) ? 2 :
                (c >= 0xE0 && c <= 0xEF) ? 3 : (c >= 0xF0 && c <= 0xF4) ? 4 : 0;
            bool valid = length && i + length <= input.size();
            for (size_t n = 1; valid && n < length; ++n)
                valid = (static_cast<unsigned char>(input[i + n]) & 0xC0) == 0x80;
            if (valid && length >= 3) {
                const auto second = static_cast<unsigned char>(input[i + 1]);
                if ((c == 0xE0 && second < 0xA0) || (c == 0xED && second >= 0xA0) ||
                    (c == 0xF0 && second < 0x90) || (c == 0xF4 && second >= 0x90)) valid = false;
            }
            if (valid) { out.append(input, i, length); i += length; }
            else { out += "\xEF\xBF\xBD"; ++i; }
        }
        return out;
    }
}
