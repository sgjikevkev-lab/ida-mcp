#pragma once
#include <string>
#include "json.h"
#include "utf8.h"

namespace mcp {
    inline std::string ValidateArguments(const nlohmann::json& schema, const nlohmann::json& value,
                                         const std::string& path = "arguments", size_t depth = 0) {
        if (depth > 64) return path + ": nesting exceeds 64 levels";
        const std::string type = schema.value("type", "");
        if ((!type.empty()) && !((type == "object" && value.is_object()) ||
            (type == "array" && value.is_array()) || (type == "string" && value.is_string()) ||
            (type == "integer" && value.is_number_integer()) || (type == "number" && value.is_number()) ||
            (type == "boolean" && value.is_boolean()) || (type == "null" && value.is_null())))
            return path + ": expected " + type;
        if (schema.contains("enum")) {
            bool matched = false;
            for (const auto& candidate : schema["enum"]) if (candidate == value) matched = true;
            if (!matched) return path + ": unsupported value";
        }
        if (value.is_number()) {
            if (schema.contains("minimum") && value.get<double>() < schema["minimum"].get<double>())
                return path + ": below minimum " + schema["minimum"].dump();
            if (schema.contains("maximum") && value.get<double>() > schema["maximum"].get<double>())
                return path + ": above maximum " + schema["maximum"].dump();
        }
        if (value.is_string() && schema.contains("maxLength") && UnicodeLength(value.get_ref<const std::string&>()) > schema["maxLength"].get<size_t>())
            return path + ": string too long";
        if (value.is_object()) {
            if (schema.contains("required")) for (const auto& key : schema["required"])
                if (!value.contains(key.get<std::string>())) return path + ": missing " + key.get<std::string>();
            const auto properties = schema.value("properties", nlohmann::json::object());
            for (auto it = value.begin(); it != value.end(); ++it) {
                if (properties.contains(it.key())) {
                    auto error = ValidateArguments(properties[it.key()], it.value(), path + "." + it.key(), depth + 1);
                    if (!error.empty()) return error;
                } else if (schema.value("additionalProperties", true) == false)
                    return path + ": unknown parameter " + it.key();
            }
        }
        if (value.is_array()) {
            if (schema.contains("minItems") && value.size() < schema["minItems"].get<size_t>()) return path + ": empty array";
            if (schema.contains("maxItems") && value.size() > schema["maxItems"].get<size_t>()) return path + ": too many items";
            if (schema.contains("items")) for (size_t i = 0; i < value.size(); ++i) {
                auto error = ValidateArguments(schema["items"], value[i], path + "[" + std::to_string(i) + "]", depth + 1);
                if (!error.empty()) return error;
            }
        }
        if (schema.contains("anyOf")) {
            bool matched = false;
            for (const auto& option : schema["anyOf"])
                if (ValidateArguments(option, value, path, depth + 1).empty()) matched = true;
            if (!matched) return path + ": required parameter combination missing";
        }
        if (schema.contains("oneOf")) {
            size_t matched = 0;
            for (const auto& option : schema["oneOf"])
                if (ValidateArguments(option, value, path, depth + 1).empty()) ++matched;
            if (matched != 1) return path + ": provide exactly one supported parameter combination";
        }
        return {};
    }
}
