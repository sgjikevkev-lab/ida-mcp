#pragma once
#include <string>
#include "json.h"

namespace mcp {
    inline const char* SearchParameter(const std::string& tool) {
        if (tool == "get_segments") return "name";
        if (tool == "list_funcs" || tool == "list_globals" || tool == "get_exports" ||
            tool == "imports_query" || tool == "strings" || tool == "types" || tool == "rtti")
            return "pattern";
        return nullptr;
    }

    inline bool HasSearchNameAlias(const std::string& tool) {
        // In these two tools, name selects one specific type/class rather than a filter.
        return tool != "types" && tool != "rtti";
    }

    inline std::string NormalizeToolArguments(const std::string& tool, nlohmann::json& args) {
        if (!args.is_object()) return "arguments: expected object";
        const char* canonical = SearchParameter(tool);
        if (canonical == nullptr) return {};
        std::string supplied;
        for (const char* key : {"pattern", "query", "name"}) {
            if (std::string(key) == "name" && !HasSearchNameAlias(tool)) continue;
            if (!args.contains(key)) continue;
            if (!supplied.empty())
                return "arguments: use only one search parameter (" + supplied + " or " + key + ")";
            supplied = key;
        }
        if (!supplied.empty() && supplied != canonical) {
            args[canonical] = std::move(args[supplied]);
            args.erase(supplied);
        }
        return {};
    }

    inline void AddSearchAliases(nlohmann::json& tools) {
        for (auto& tool : tools) {
            const std::string name = tool["name"];
            const char* canonical = SearchParameter(name);
            if (canonical == nullptr) continue;
            auto& properties = tool["inputSchema"]["properties"];
            const auto original = properties[canonical];
            for (const char* alias : {"pattern", "query", "name"}) {
                if (properties.contains(alias) || (std::string(alias) == "name" && !HasSearchNameAlias(name))) continue;
                properties[alias] = original;
                properties[alias]["description"] = std::string("Alias for '") + canonical + "'. Use only one search parameter.";
            }
        }
    }
}
