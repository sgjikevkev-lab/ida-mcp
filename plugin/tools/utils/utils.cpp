#include "shared/utf8.h"
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <charconv>
#include <cctype>
#include <limits>
#include "shared/pattern_match.h"

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
            const char* begin = s.data() + 2;
            const char* end = s.data() + s.size();
            uint64_t value = 0;
            const auto parsed = std::from_chars(begin, end, value, 16);
            if (begin == end || parsed.ec != std::errc{} || parsed.ptr != end || value == BADADDR)
                return BADADDR;
            return static_cast<ea_t>(value);
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
            sync::Checkpoint();
            if (!isxdigit(static_cast<unsigned char>(c))) {
                is_hex = false;
                break;
            }
        }
        if (is_hex && !s.empty()) {
            uint64_t value = 0;
            const auto parsed = std::from_chars(s.data(), s.data() + s.size(), value, 16);
            if (parsed.ec == std::errc{} && parsed.ptr == s.data() + s.size() && value != BADADDR)
                return static_cast<ea_t>(value);
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
                    sync::Checkpoint();
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

        if (it->is_number_unsigned()) {
            const auto value = it->get<uint64_t>();
            if (value == BADADDR || value > std::numeric_limits<ea_t>::max()) return default_ea;
            return static_cast<ea_t>(value);
        }
        if (it->is_number_integer()) {
            const auto value = it->get<int64_t>();
            if (value < 0) return default_ea;
            return static_cast<ea_t>(value);
        }
        if (it->is_string()) {
            return ParseAddress(it->get<std::string>());
        }
        return default_ea;
    }

    int64_t GetIntArg(const nlohmann::json& args, const std::string& key, int64_t default_val) {
        auto it = args.find(key);
        if (it == args.end() || it->is_null()) return default_val;

        if (it->is_number_unsigned()) {
            const auto value = it->get<uint64_t>();
            return value > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ? default_val : static_cast<int64_t>(value);
        }
        if (it->is_number_integer()) {
            return it->get<int64_t>();
        }
        if (it->is_boolean()) {
            return it->get<bool>() ? 1 : 0;
        }
        if (it->is_string()) {
            const std::string& s = it->get<std::string>();
            const bool is_hex = s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X');
            const char* begin = s.data() + (is_hex ? 2 : 0);
            const char* end = s.data() + s.size();
            int64_t value = 0;
            const auto parsed = std::from_chars(begin, end, value, is_hex ? 16 : 10);
            if (begin == end || parsed.ec != std::errc{} || parsed.ptr != end) return default_val;
            return value;
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
            std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
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
        if (it->is_number_unsigned()) {
            return std::to_string(it->get<uint64_t>());
        }
        if (it->is_number_integer()) {
            return std::to_string(it->get<int64_t>());
        }
        if (it->is_boolean()) {
            return it->get<bool>() ? "true" : "false";
        }
        return default_val;
    }

    bool PatternMatch(const std::string& text, const std::string& pattern, bool case_sensitive) {
        sync::Checkpoint();
        return mcp::MatchName(text, pattern, case_sensitive, [] { sync::Checkpoint(); });
    }

    std::string SanitizeUtf8(const std::string& input) {
        return mcp::SanitizeUnicode(input);
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

