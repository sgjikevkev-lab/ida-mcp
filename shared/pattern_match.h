#pragma once
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string>

namespace mcp {
    // Substring/glob matching without recursive regular-expression backtracking.
    // A pattern without wildcards is always a literal, including C++ punctuation.
    template<class Checkpoint>
    bool MatchName(const std::string& text, const std::string& pattern, bool sensitive, Checkpoint checkpoint) {
        if (pattern.size() > 1024) throw std::invalid_argument("Name pattern exceeds 1024 bytes");
        auto equal = [sensitive](char a, char b) {
            return sensitive ? a == b : std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
        };
        if (pattern.find_first_of("*?") == std::string::npos)
            return std::search(text.begin(), text.end(), pattern.begin(), pattern.end(), equal) != text.end();
        // Implicit leading/trailing stars retain the previous substring-search semantics.
        const std::string glob = "*" + pattern + "*";
        size_t ti = 0, pi = 0, star = std::string::npos, retry = 0, steps = 0;
        while (ti < text.size()) {
            if ((++steps & 1023) == 0) checkpoint();
            if (pi < glob.size() && glob[pi] != '*' && (glob[pi] == '?' || equal(text[ti], glob[pi]))) { ++ti; ++pi; }
            else if (pi < glob.size() && glob[pi] == '*') { star = pi++; retry = ti; }
            else if (star != std::string::npos) { pi = star + 1; ti = ++retry; }
            else return false;
        }
        while (pi < glob.size() && glob[pi] == '*') ++pi;
        return pi == glob.size();
    }
}
