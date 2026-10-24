#pragma once
#include <stdexcept>
#include "json.h"

namespace mcp {
    inline nlohmann::json ParseBoundedJson(const std::string& text) {
        return nlohmann::json::parse(text, [](int depth, nlohmann::json::parse_event_t, nlohmann::json&) {
            if (depth > 64) throw std::invalid_argument("JSON nesting exceeds 64 levels");
            return true;
        });
    }
    inline nlohmann::json TryParseBoundedJson(const std::string& text) {
        try { return ParseBoundedJson(text); }
        catch (...) { return nlohmann::json(nlohmann::json::value_t::discarded); }
    }
}
