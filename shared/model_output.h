#pragma once
#include <string>
#include <vector>
#include "json.h"
#include "runtime_limits.h"

namespace mcp::output {
    using json = nlohmann::json;
    inline std::string Scalar(const json& value) {
        return value.dump(-1, ' ', false, json::error_handler_t::replace);
    }

    inline bool IsTable(const json& rows) {
        if (!rows.is_array() || rows.size() < 2 || !rows[0].is_object() || rows[0].empty()) return false;
        for (const auto& row : rows) {
            if (!row.is_object() || row.size() != rows[0].size()) return false;
            for (auto it = rows[0].begin(); it != rows[0].end(); ++it)
                if (!row.contains(it.key()) || !row[it.key()].is_primitive()) return false;
        }
        return true;
    }

    inline bool HasMultilineString(const json& value, size_t depth = 0) {
        // Render() deliberately stops expanding at the same depth. Keep this
        // preflight bounded too: Python tool results can be more deeply nested
        // than requests parsed by the router.
        if (depth >= 32) return false;
        if (value.is_string()) return value.get_ref<const std::string&>().find('\n') != std::string::npos;
        if (value.is_array()) {
            for (const auto& item : value)
                if (HasMultilineString(item, depth + 1)) return true;
        } else if (value.is_object()) {
            for (auto it = value.begin(); it != value.end(); ++it)
                if (HasMultilineString(it.value(), depth + 1)) return true;
        }
        return false;
    }

    inline void Render(std::string& out, const json& value, size_t depth = 0) {
        const std::string indent(depth * 2, ' ');
        if (depth < 32 && value.is_array() && !value.empty() && value[0].is_object()) {
            bool first = true;
            for (const auto& item : value) {
                if (!first) out += '\n';
                first = false;
                out += indent + "-\n";
                if (item.is_object() || item.is_array()) Render(out, item, depth + 1);
                else out += indent + "  " + Scalar(item);
            }
            return;
        }
        if (depth >= 32 || !value.is_object() || value.empty()) {
            out += Scalar(value);
            return;
        }
        bool first = true;
        for (auto it = value.begin(); it != value.end(); ++it) {
            if (!first) out += '\n';
            first = false;
            out += indent + Scalar(it.key());
            if (IsTable(it.value())) {
                out += "[" + std::to_string(it.value().size()) + "]:\n" + indent + "  ";
                bool column = false;
                for (auto cell = it.value()[0].begin(); cell != it.value()[0].end(); ++cell) {
                    if (column) out += '\t';
                    column = true;
                    out += Scalar(cell.key());
                }
                for (const auto& row : it.value()) {
                    out += '\n' + indent + "  ";
                    column = false;
                    for (auto cell = row.begin(); cell != row.end(); ++cell) {
                        if (column) out += '\t';
                        column = true;
                        out += Scalar(cell.value());
                    }
                }
            } else if (it.value().is_string() && it.value().get_ref<const std::string&>().find('\n') != std::string::npos) {
                out += ": |\n";
                const auto& text = it.value().get_ref<const std::string&>();
                size_t start = 0;
                while (start < text.size()) {
                    size_t end = text.find('\n', start);
                    if (end == std::string::npos) end = text.size();
                    out += indent + "  " + text.substr(start, end - start);
                    if (end < text.size()) out += '\n';
                    start = end + 1;
                }
            } else if ((it.value().is_object() && !it.value().empty()) ||
                       (it.value().is_array() && !it.value().empty() && it.value()[0].is_object())) {
                out += ":\n";
                Render(out, it.value(), depth + 1);
            } else {
                out += ": " + Scalar(it.value());
            }
        }
    }

    inline std::string Format(json payload) {
        if (payload.is_object()) {
            const auto status = payload.value("status", json(nullptr));
            if (status == "success" || status == "error") payload.erase("status");
            payload.erase("elapsed_sec");
            for (const char* key : {"count", "returned", "returned_count"}) {
                if (!payload.contains(key) || !payload[key].is_number_unsigned()) continue;
                for (const auto& member : payload) {
                    if (member.is_array() && member.size() == payload[key].get<size_t>()) {
                        payload.erase(key);
                        break;
                    }
                }
            }
        }
        std::string rendered;
        Render(rendered, payload);
        // Small objects are often shorter as compact JSON. Large tables and
        // multiline code benefit from the model-facing text representation.
        auto compact = Scalar(payload);
        if (compact.size() <= 256) return compact;
        if (HasMultilineString(payload)) return rendered;
        return rendered.size() < compact.size() ? rendered : compact;
    }
}
