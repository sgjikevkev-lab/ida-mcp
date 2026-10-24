#include "shared/utf8.h"
#pragma once
#include <string>
#include <vector>
#include "shared/model_output.h"
#pragma warning(push, 0)
#pragma warning(disable: 26819 26495 26812 26451 6001 6011)
#include "shared/json.h"
#pragma warning(pop)


namespace mcp {
    using json = nlohmann::json;
    using ordered_json = nlohmann::ordered_json;

    namespace constants {
        constexpr const char* JSONRPC_VERSION = "2.0";
        constexpr const char* DEFAULT_PROTOCOL_VERSION = "2024-11-05";
        constexpr const char* SERVER_NAME = "ida-multi-mcp-router-cpp";
        constexpr const char* SERVER_VERSION = "2.0.0";
    }

    inline json MakeSuccessResponse(const json& id, const json& result) {
        return {
            {"jsonrpc", constants::JSONRPC_VERSION},
            {"id", id},
            {"result", result}
        };
    }

    inline json MakeErrorResponse(const json& id, int code, const std::string& message) {
        return {
            {"jsonrpc", constants::JSONRPC_VERSION},
            {"id", id},
            {"error", {
                {"code", code},
                {"message", message}
            }}
        };
    }

    inline std::string SanitizeUtf8(const std::string& input) {
        return mcp::SanitizeUnicode(input);
    }

    inline json MakeTextContent(const std::string& text) {
        return json::array({
            {
                {"type", "text"},
                {"text", SanitizeUtf8(text)}
            }
        });
    }

    inline json MakeToolCallResult(const std::string& text, bool is_error = false) {
        std::string formatted = text;
        auto payload = json::parse(text, nullptr, false);
        if (!payload.is_discarded()) formatted = output::Format(std::move(payload));
        json res = {
            {"content", MakeTextContent(formatted)}
        };
        if (is_error) {
            res["isError"] = true;
        }
        return res;
    }
}
