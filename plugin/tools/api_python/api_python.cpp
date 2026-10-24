#include "api_python.h"
#include "python_runner.h"
#include "tools/utils/utils.h"
#include "sync/sync.h"
#include "sync/cache_manager.h"
#include <filesystem>
#include <fstream>
#include <expr.hpp>

namespace tools::python {
    namespace {
        std::string Base64Encode(const std::string& input) {
            constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            uint32_t value = 0;
            int bits = -6;
            for (unsigned char c : input) {
                value = (value << 8) | c;
                bits += 8;
                while (bits >= 0) {
                    out += alphabet[(value >> bits) & 63];
                    bits -= 6;
                }
            }
            if (bits > -6) out += alphabet[((value << 8) >> (bits + 8)) & 63];
            while (out.size() % 4) out += '=';
            return out;
        }
        error_t idaapi ShouldStop(idc_value_t*, idc_value_t* result) {
            if (!result) return eOk;
            auto* operation = sync::current_operation;
            int stopped = 0;
            if (operation) {
                if (std::chrono::steady_clock::now() >= operation->deadline) stopped = 2;
                else if (operation->cancelled.load(std::memory_order_acquire)) stopped = 1;
            }
            result->set_long(stopped);
            return eOk;
        }
        struct ExecutionCleanup {
            ~ExecutionCleanup() {
                del_idc_func("__ida_mcp_stop");
                // A failing script can still have changed the database.
                cache::InvalidateIDBDependentCaches();
            }
        };
    }

    nlohmann::json ApiPython::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "py") return ExecutePy(id, args);
        return tools::utils::MakeToolErrorJson(id, "Unknown Python tool", "tool_not_found");
    }

    nlohmann::json ApiPython::ExecutePy(const nlohmann::json& id, const nlohmann::json& args) {
        sync::Checkpoint();
        if (args.contains("code") && !args["code"].is_string())
            return tools::utils::MakeToolErrorJson(id, "Parameter 'code' must be a string", "invalid_code");
        if (args.contains("file") && !args["file"].is_string())
            return tools::utils::MakeToolErrorJson(id, "Parameter 'file' must be a string", "invalid_script_path");
        std::string code = tools::utils::GetStringArg(args, "code");
        const std::string file = tools::utils::GetStringArg(args, "file");
        if (args.contains("code") && args.contains("file"))
            return tools::utils::MakeToolErrorJson(id, "Specify either 'code' or 'file', not both", "conflicting_python_input");
        if (!args.contains("code") && !args.contains("file"))
            return tools::utils::MakeToolErrorJson(id, "Either 'code' or 'file' is required", "python_input_required");
        if (args.contains("file") && file.empty())
            return tools::utils::MakeToolErrorJson(id, "Script path must not be empty", "invalid_script_path");
        if (code.size() > mcp::limits::result_bytes)
            return tools::utils::MakeToolErrorJson(id, "Python code exceeds 2 MiB", "script_too_large");

        nlohmann::json argv = nlohmann::json::array();
        if (args.contains("argv")) {
            if (!args["argv"].is_array() || args["argv"].size() > 64)
                return tools::utils::MakeToolErrorJson(id, "argv must be an array of at most 64 strings", "invalid_argv");
            size_t argv_bytes = 0;
            for (const auto& value : args["argv"]) {
                if (!value.is_string())
                    return tools::utils::MakeToolErrorJson(id, "Every argv item must be a string", "invalid_argv");
                const size_t length = value.get_ref<const std::string&>().size();
                if (length > 65536 - argv_bytes)
                    return tools::utils::MakeToolErrorJson(id, "Combined argv must not exceed 64 KiB", "invalid_argv");
                argv_bytes += length;
                argv.push_back(value);
            }
        }

        std::string filename = "<mcp>";
        if (!file.empty()) {
            if (file.size() > 32768)
                return tools::utils::MakeToolErrorJson(id, "Script path exceeds 32 KiB", "invalid_script_path");
            std::filesystem::path path;
            try {
                path = std::filesystem::absolute(std::filesystem::u8path(file));
            } catch (const std::exception&) {
                return tools::utils::MakeToolErrorJson(id, "Script path is invalid", "invalid_script_path");
            }
            std::error_code ec;
            const auto size = std::filesystem::file_size(path, ec);
            if (ec) return tools::utils::MakeToolErrorJson(id, "Script file cannot be read", "file_not_found");
            if (size > mcp::limits::result_bytes)
                return tools::utils::MakeToolErrorJson(id, "Script exceeds 2 MiB", "script_too_large");
            std::ifstream stream(path, std::ios::binary);
            if (!stream) return tools::utils::MakeToolErrorJson(id, "Script file cannot be opened", "file_open_failed");
            code.resize(static_cast<size_t>(size));
            if (size > 0) {
                stream.read(code.data(), static_cast<std::streamsize>(size));
                if (stream.gcount() != static_cast<std::streamsize>(size))
                    return tools::utils::MakeToolErrorJson(id, "Script file changed while it was being read", "file_read_failed");
            }
            char extra_byte = 0;
            stream.read(&extra_byte, 1);
            if (stream.gcount() > 0)
                return tools::utils::MakeToolErrorJson(id, "Script exceeds 2 MiB", "script_too_large");
            try {
                auto utf8 = path.u8string();
                filename.assign(reinterpret_cast<const char*>(utf8.data()), utf8.size());
            } catch (const std::exception&) {
                return tools::utils::MakeToolErrorJson(id, "Script path cannot be converted to UTF-8", "invalid_script_path");
            }
        }
        extlang_object_t language = find_extlang_by_name("Python");
        if (!language) language = find_extlang_by_ext("py");
        if (!language || !language->eval_snippet || !language->eval_expr)
            return tools::utils::MakeToolErrorJson(id, "IDAPython is unavailable", "python_unavailable");
        const ext_idcfunc_t stop_function = {"__ida_mcp_stop", ShouldStop, "", nullptr, 0, EXTFUN_BASE};
        if (!add_idc_func(stop_function))
            return tools::utils::MakeToolErrorJson(id, "Cannot register Python cancellation callback", "python_unavailable");
        ExecutionCleanup cleanup;
        std::string wrapper = kPythonRunner;
        wrapper += "\n__ida_mcp_execute('" + Base64Encode(code) + "','" + Base64Encode(filename) + "','" +
            Base64Encode(argv.dump()) + "')\ndel __ida_mcp_execute\n";
        qstring error;
        if (!language->eval_snippet(wrapper.c_str(), &error))
            return tools::utils::MakeToolErrorJson(id, tools::utils::SanitizeUtf8(error.c_str()), "extlang_error");
        idc_value_t result;
        if (!language->eval_expr(&result, BADADDR, "__import__('sys').modules['_ida_mcp_runtime'].response", &error) || result.vtype != VT_STR)
            return tools::utils::MakeToolErrorJson(id, "Cannot read Python result", "extlang_error");
        const char* response_data = result.c_str();
        const size_t response_size = response_data ? std::char_traits<char>::length(response_data) : 0;
        if (response_size > mcp::limits::result_bytes)
            return tools::utils::MakeToolErrorJson(id, "Python response exceeds 2 MiB", "output_too_large");
        auto response = nlohmann::json::parse(response_data ? response_data : "", nullptr, false);
        if (response.is_discarded() || !response.is_object())
            return tools::utils::MakeToolErrorJson(id, "Invalid Python result", "extlang_error");
        const bool failed = response.contains("error_code");
        return tools::utils::MakeToolResultJson(id, response, failed);
    }
}
