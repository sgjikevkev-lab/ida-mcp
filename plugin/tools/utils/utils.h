#pragma once
#include <string>
#include <vector>
#include <cstdint>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include <ida.hpp>

namespace tools::utils {
    ea_t ParseAddress(const std::string& str);
    std::string FormatAddress(ea_t ea);
    std::string FormatSize(size_t size);
    bool PatternMatch(const std::string& text, const std::string& pattern, bool case_sensitive = false);
    std::string SanitizeUtf8(const std::string& input);

    ea_t GetAddressArg(const nlohmann::json& args, const std::string& key, ea_t default_ea = BADADDR);
    int64_t GetIntArg(const nlohmann::json& args, const std::string& key, int64_t default_val = 0);
    bool GetBoolArg(const nlohmann::json& args, const std::string& key, bool default_val = false);
    std::string GetStringArg(const nlohmann::json& args, const std::string& key, const std::string& default_val = "");

    nlohmann::json SafeJsonString(const std::string& input);
    nlohmann::json SafeJsonString(const char* input);
    nlohmann::json SafeJsonNullOrString(const std::string& input);
    nlohmann::json SafeJsonNullOrString(const char* input);

    inline nlohmann::json MakeToolTextResult(const nlohmann::json& id, const std::string& text, bool is_error = false) {
        constexpr size_t MAX_TEXT_LEN = 2 * 1024 * 1024; // 2 MB safety limit
        std::string final_text;
        if (text.size() > MAX_TEXT_LEN) {
            final_text = text.substr(0, MAX_TEXT_LEN);
            final_text += "\n[Warning: output truncated at 2MB safety limit. Use pagination parameters like offset/count to retrieve remaining items]";
        } else {
            final_text = text;
        }
        final_text = SanitizeUtf8(final_text);

        nlohmann::json res = {
            {"content", nlohmann::json::array({{{"type", "text"}, {"text", std::move(final_text)}}})},
            {"isError", is_error}
        };
        return nlohmann::json({
            {"jsonrpc", "2.0"},
            {"id", id},
            {"result", res}
        });
    }

    inline nlohmann::json MakeToolResult(const nlohmann::json& id, const std::string& text, bool is_error = false) {
        return MakeToolTextResult(id, text, is_error);
    }

    inline nlohmann::json MakeToolResultJson(const nlohmann::json& id, const nlohmann::json& json_data, bool is_error = false) {
        std::string dumped = json_data.dump(2);
        return MakeToolTextResult(id, dumped, is_error);
    }

    inline nlohmann::json MakeToolSuccessJson(const nlohmann::json& id, nlohmann::json payload = nlohmann::json::object()) {
        if (!payload.is_object()) {
            nlohmann::json wrapper = {
                {"status", "success"},
                {"data", std::move(payload)}
            };
            return MakeToolResultJson(id, wrapper, false);
        }
        if (!payload.contains("status")) {
            payload["status"] = "success";
        }
        return MakeToolResultJson(id, payload, false);
    }

    inline nlohmann::json MakeToolErrorJson(const nlohmann::json& id, const std::string& message, const std::string& error_code = "", int code_num = 0) {
        nlohmann::json err = {
            {"status", "error"},
            {"message", message}
        };
        if (!error_code.empty()) {
            err["error_code"] = error_code;
        }
        if (code_num != 0) {
            err["code"] = code_num;
        }
        return MakeToolResultJson(id, err, true);
    }

    inline nlohmann::json MakeToolError(const nlohmann::json& id, const std::string& error_code, const std::string& message = "", int code_num = 0) {
        std::string msg = message.empty() ? error_code : message;
        return MakeToolErrorJson(id, msg, error_code, code_num);
    }
}
