#include <iostream>
#include <stdexcept>
#include "shared/ida_tools_schema.h"
#include "shared/argument_validation.h"
#include "shared/model_output.h"
#include "shared/utf8.h"
#include "shared/pattern_match.h"
#include "shared/json_parse.h"

using nlohmann::json;
static void Check(bool success, const char* description) {
    if (!success) throw std::runtime_error(description);
}
static const json& Schema(const char* name) {
    for (const auto& tool : mcp::GetDefaultIdaToolsSchema())
        if (tool["name"] == name) return tool["inputSchema"];
    throw std::runtime_error("missing tool");
}
int main() {
    try {
        Check(mcp::ValidateArguments(Schema("get_bytes"), {{"addr", "main"}, {"size", 8}}).empty(), "valid bytes");
        Check(!mcp::ValidateArguments(Schema("get_bytes"), {{"addr", "main"}, {"size", -1}}).empty(), "negative size");
        Check(!mcp::ValidateArguments(Schema("get_bytes"), {{"addr", "main"}, {"size", "8"}}).empty(), "wrong type");
        Check(!mcp::ValidateArguments(Schema("get_bytes"), {{"addr", "main"}, {"garbage", true}}).empty(), "unknown field");
        Check(!mcp::ValidateArguments(Schema("decompile"), json::object()).empty(), "required target");
        Check(!mcp::ValidateArguments(Schema("decompile"), {{"addr", "main"}, {"addrs", {"main"}}}).empty(), "ambiguous target");
        Check(!mcp::ValidateArguments(Schema("decompile"), {{"addrs", json::array()}}).empty(), "empty batch");
        Check(!mcp::ValidateArguments(Schema("py"), {{"code", "1"}, {"timeout", 1}}).empty(), "fixed deadline");
        Check(!mcp::ValidateArguments(Schema("get_ast"), {{"addr", "main"}, {"max_depth", 100000}}).empty(), "bounded recursion");
        Check(mcp::ValidateArguments(Schema("get_ast"), {{"addr", "main"}, {"pattern", {{"op", "cot_call"}, {"callee", "memcpy"}}}}).empty(), "free AST pattern");
        json rows = json::array();
        for (int i = 0; i < 100; ++i) rows.push_back({{"address", "0x140001000"}, {"name", "example_function"}, {"size", i}});
        json payload = {{"status", "success"}, {"elapsed_sec", 1}, {"functions", rows}};
        auto text = mcp::output::Format(payload);
        Check(text.find("functions\"[100]") != std::string::npos, "table representation");
        Check(text.size() < payload.dump().size() * 8 / 10, "table saves repeated keys");
        Check(text.find("elapsed_sec") == std::string::npos, "no routine telemetry");
        Check(mcp::output::Format({{"flag", false}, {"zero", 0}, {"empty", ""}, {"none", nullptr}}).find("false") != std::string::npos, "preserve false values");
        auto nested = mcp::output::Format({{"result", {{"status", "success"}, {"elapsed_sec", 5}}}});
        Check(nested.find("elapsed_sec") != std::string::npos, "preserve user result");
        auto code = mcp::output::Format({{"functions", json::array({
            {{"address", "0x1000"}, {"code", "return \"" + std::string(300, 'x') + "\\\\path\";\nreturn 2;\n"}},
            {{"address", "0x2000"}, {"code", "return 3;\n"}, {"partial", true}}
        })}});
        Check(code.find("return 2;\n") != std::string::npos && code.find("\\nreturn") == std::string::npos,
              "batched code uses literal lines when shorter");
        Check(mcp::SanitizeUnicode("valid") == "valid", "valid Unicode");
        Check(mcp::TryParseBoundedJson(std::string(100, '[') + "0" + std::string(100, ']')).is_discarded(), "bounded JSON depth");
        Check(mcp::MatchName("std::vector<int>::size()", "size()", false, [] {}), "literal C++ punctuation");
        Check(mcp::MatchName("prefix_CreateFileW_suffix", "create*file?", false, [] {}), "glob match");
        Check(!mcp::MatchName("CreateFileW", "Delete*", false, [] {}), "glob miss");
        Check(!mcp::MatchName("CreateFileW", "create", true, [] {}), "case-sensitive match");
        for (auto invalid : {"\xC0\xAF", "\xED\xA0\x80", "\xF4\x90\x80\x80", "\xE2\x82"})
            Check(json::parse(json(mcp::SanitizeUnicode(invalid)).dump()).is_string(), "invalid Unicode repaired");
        std::cout << "Contract and output checks passed\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
