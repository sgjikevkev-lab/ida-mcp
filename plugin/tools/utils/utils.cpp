#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <regex>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "utils.h"
#include <ida.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <funcs.hpp>

#include "sync/sync.h"

namespace tools::utils {
    ea_t ParseAddress(const std::string& str) {
        if (str.empty()) return BADADDR;

        std::string s = str;
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
        if (s.empty()) return BADADDR;

        // 1. If string explicitly starts with 0x / 0X, it is definitely a hexadecimal address
        if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
            try {
                return std::stoull(s.substr(2), nullptr, 16);
            } catch (...) {
                return BADADDR;
            }
        }

        // 2. Check if it matches an existing symbol or function name in IDB
        // (Ensures words like "add", "cafe", "dead", "bad", "face" resolve to symbols if they exist)
        ea_t named_ea = BADADDR;
        if (is_main_thread()) {
            named_ea = get_name_ea(BADADDR, s.c_str());
        } else {
            sync::SyncRead([&]() {
                named_ea = get_name_ea(BADADDR, s.c_str());
            });
        }
        if (named_ea != BADADDR) {
            return named_ea;
        }

        // 3. Try parsing as a hex number (e.g. "401000")
        bool is_hex = true;
        for (char c : s) {
            if (!isxdigit(static_cast<unsigned char>(c))) {
                is_hex = false;
                break;
            }
        }
        if (is_hex && !s.empty()) {
            try {
                return std::stoull(s, nullptr, 16);
            } catch (...) {
            }
        }

        return BADADDR;
    }

    std::string FormatAddress(ea_t ea) {
        char buf[32];
        qsnprintf(buf, sizeof(buf), "0x%" FMT_64 "x", static_cast<uint64>(ea));
        return buf;
    }

    std::string FormatSize(size_t size) {
        char buf[64];
        qsnprintf(buf, sizeof(buf), "%zu (0x%" FMT_64 "x)", size, static_cast<uint64>(size));
        return buf;
    }

    std::string Demangle(const std::string& name) {
        if (name.empty()) return "";
        qstring dem;
        if (demangle_name(&dem, name.c_str(), 0, DQT_FULL) > 0) {
            return SanitizeUtf8(dem.c_str());
        }
        return "";
    }

    ea_t GetAddressArg(const nlohmann::json& args, const std::string& key, ea_t default_ea) {
        auto it = args.find(key);
        if (it == args.end() || it->is_null()) {
            if (key == "address" || key == "addr" || key == "ea") {
                for (const char* alias : {"address", "addr", "ea", "target"}) {
                    auto a_it = args.find(alias);
                    if (a_it != args.end() && !a_it->is_null()) {
                        it = a_it;
                        break;
                    }
                }
            }
        }
        if (it == args.end() || it->is_null()) {
            return default_ea;
        }

        if (it->is_number_unsigned() || it->is_number_integer()) {
            return static_cast<ea_t>(it->get<uint64_t>());
        }
        if (it->is_string()) {
            return ParseAddress(it->get<std::string>());
        }
        return default_ea;
    }

    int64_t GetIntArg(const nlohmann::json& args, const std::string& key, int64_t default_val) {
        auto it = args.find(key);
        if (it == args.end() || it->is_null()) return default_val;

        if (it->is_number_integer() || it->is_number_unsigned()) {
            return it->get<int64_t>();
        }
        if (it->is_boolean()) {
            return it->get<bool>() ? 1 : 0;
        }
        if (it->is_string()) {
            const std::string& s = it->get<std::string>();
            try {
                if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
                    return std::stoll(s.substr(2), nullptr, 16);
                }
                return std::stoll(s);
            } catch (...) {
                return default_val;
            }
        }
        return default_val;
    }

    bool GetBoolArg(const nlohmann::json& args, const std::string& key, bool default_val) {
        auto it = args.find(key);
        if (it == args.end() || it->is_null()) return default_val;

        if (it->is_boolean()) {
            return it->get<bool>();
        }
        if (it->is_number()) {
            return it->get<int64_t>() != 0;
        }
        if (it->is_string()) {
            std::string s = it->get<std::string>();
            std::transform(s.begin(), s.end(), s.begin(), ::tolower);
            return (s == "true" || s == "1" || s == "yes");
        }
        return default_val;
    }

    std::string GetStringArg(const nlohmann::json& args, const std::string& key, const std::string& default_val) {
        auto it = args.find(key);
        if (it == args.end() || it->is_null()) return default_val;

        if (it->is_string()) {
            return it->get<std::string>();
        }
        if (it->is_number_integer() || it->is_number_unsigned()) {
            return std::to_string(it->get<int64_t>());
        }
        if (it->is_boolean()) {
            return it->get<bool>() ? "true" : "false";
        }
        return default_val;
    }

    bool PatternMatch(const std::string& text, const std::string& pattern, bool case_sensitive) {
        if (pattern.empty()) return true;

        bool has_special = false;
        bool is_glob = false;
        for (char c : pattern) {
            if (c == '*' || c == '?') {
                is_glob = true;
                has_special = true;
                break;
            }
            if (std::string(".^$|()[]{}+\\").find(c) != std::string::npos) {
                has_special = true;
            }
        }

        // Fast path: simple substring search (avoids heavy std::regex construction)
        if (!has_special) {
            if (case_sensitive) {
                return text.find(pattern) != std::string::npos;
            } else {
                auto it = std::search(
                    text.begin(), text.end(),
                    pattern.begin(), pattern.end(),
                    [](char ch1, char ch2) {
                        return ::tolower(static_cast<unsigned char>(ch1)) == ::tolower(static_cast<unsigned char>(ch2));
                    }
                );
                return it != text.end();
            }
        }

        std::string regex_str = "";
        if (is_glob) {
            for (char c : pattern) {
                if (c == '*') {
                    regex_str += ".*";
                } else if (c == '?') {
                    regex_str += ".";
                } else if (std::string(".^$|()[]{}+\\").find(c) != std::string::npos) {
                    regex_str += '\\';
                    regex_str += c;
                } else {
                    regex_str += c;
                }
            }
        } else {
            regex_str = pattern;
        }

        try {
            std::regex::flag_type flags = std::regex::ECMAScript;
            if (!case_sensitive) flags |= std::regex::icase;
            std::regex re(regex_str, flags);
            return std::regex_search(text, re);
        } catch (...) {
            if (case_sensitive) {
                return text.find(pattern) != std::string::npos;
            } else {
                std::string t = text;
                std::string p = pattern;
                std::transform(t.begin(), t.end(), t.begin(), ::tolower);
                std::transform(p.begin(), p.end(), p.begin(), ::tolower);
                return t.find(p) != std::string::npos;
            }
        }
    }

    std::string SanitizeUtf8(const std::string& input) {
        std::string out;
        out.reserve(input.size());
        for (size_t i = 0; i < input.size(); ) {
            unsigned char c = static_cast<unsigned char>(input[i]);
            if (c < 0x80) {
                out.push_back(c);
                i += 1;
            } else if ((c & 0xE0) == 0xC0 && i + 1 < input.size() && (static_cast<unsigned char>(input[i + 1]) & 0xC0) == 0x80) {
                out.push_back(input[i]);
                out.push_back(input[i + 1]);
                i += 2;
            } else if ((c & 0xF0) == 0xE0 && i + 2 < input.size() &&
                       (static_cast<unsigned char>(input[i + 1]) & 0xC0) == 0x80 &&
                       (static_cast<unsigned char>(input[i + 2]) & 0xC0) == 0x80) {
                out.push_back(input[i]);
                out.push_back(input[i + 1]);
                out.push_back(input[i + 2]);
                i += 3;
            } else if ((c & 0xF8) == 0xF0 && i + 3 < input.size() &&
                       (static_cast<unsigned char>(input[i + 1]) & 0xC0) == 0x80 &&
                       (static_cast<unsigned char>(input[i + 2]) & 0xC0) == 0x80 &&
                       (static_cast<unsigned char>(input[i + 3]) & 0xC0) == 0x80) {
                out.push_back(input[i]);
                out.push_back(input[i + 1]);
                out.push_back(input[i + 2]);
                out.push_back(input[i + 3]);
                i += 4;
            } else {
                // Replace invalid byte with UTF-8 replacement character U+FFFD
                out += "\xEF\xBF\xBD";
                i += 1;
            }
        }
        return out;
    }


    nlohmann::json SafeJsonString(const std::string& input) {

        return nlohmann::json(SanitizeUtf8(input));
    }

    nlohmann::json SafeJsonString(const char* input) {
        if (!input) return nlohmann::json("");
        return nlohmann::json(SanitizeUtf8(input));
    }

    nlohmann::json SafeJsonNullOrString(const std::string& input) {
        if (input.empty()) return nullptr;
        return nlohmann::json(SanitizeUtf8(input));
    }

    nlohmann::json SafeJsonNullOrString(const char* input) {
        if (!input || input[0] == '\0') return nullptr;
        return nlohmann::json(SanitizeUtf8(input));
    }
}

