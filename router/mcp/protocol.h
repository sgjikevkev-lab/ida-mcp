#pragma once
#include <string>
#include <vector>
#pragma warning(push, 0)
#pragma warning(disable: 26819 26495 26812 26451 6001 6011)
#include "!ibs/json.h"
#pragma warning(pop)


namespace mcp {
    using json = nlohmann::json;
    using ordered_json = nlohmann::ordered_json;

    namespace constants {
        constexpr const char* JSONRPC_VERSION = "2.0";
        constexpr const char* DEFAULT_PROTOCOL_VERSION = "2024-11-05";
        constexpr const char* SERVER_NAME = "ida-multi-mcp-router-cpp";
        constexpr const char* SERVER_VERSION = "1.2.1";
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
                out += "\xEF\xBF\xBD";
                i += 1;
            }
        }
        return out;
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
        json res = {
            {"content", MakeTextContent(text)}
        };
        if (is_error) {
            res["isError"] = true;
        }
        return res;
    }
}
