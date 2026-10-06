#include <string>
#include <vector>
#include <filesystem>
#include <fstream>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "api_python.h"
#include "tools/utils/utils.h"
#include "sync/sync.h"
#include "sync/cache_manager.h"

#include <ida.hpp>
#include <expr.hpp>

namespace tools::python {
    namespace {
        std::string Base64Encode(const std::string& in) {
            static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            out.reserve(((in.size() + 2) / 3) * 4);
            int val = 0, valb = -6;
            for (uint8_t c : in) {
                val = (val << 8) + c;
                valb += 8;
                while (valb >= 0) {
                    out.push_back(tbl[(val >> valb) & 0x3F]);
                    valb -= 6;
                }
            }
            if (valb > -6) out.push_back(tbl[((val << 8) >> (valb + 8)) & 0x3F]);
            while (out.size() % 4) out.push_back('=');
            return out;
        }

        bool EvalStringExpr(const extlang_t* el, const char* expr, std::string& out_str) {
            if (!el || !el->eval_expr) return false;
            idc_value_t rv;
            qstring errbuf;
            if (el->eval_expr(&rv, BADADDR, expr, &errbuf) && rv.vtype == VT_STR) {
                out_str = rv.c_str();
                return true;
            }
            return false;
        }

        bool EvalBoolExpr(const extlang_t* el, const char* expr, bool& out_bool) {
            if (!el || !el->eval_expr) return false;
            idc_value_t rv;
            qstring errbuf;
            if (el->eval_expr(&rv, BADADDR, expr, &errbuf)) {
                if (rv.vtype == VT_LONG) {
                    out_bool = (rv.num != 0);
                    return true;
                } else if (rv.vtype == VT_INT64) {
                    out_bool = (rv.i64 != 0);
                    return true;
                }
            }
            return false;
        }
    }

    bool ApiPython::CanHandle(const std::string& name) const {
        return name == "py";
    }

    nlohmann::json ApiPython::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "py") return ExecutePy(id, args);
        return tools::utils::MakeToolErrorJson(id, "Method not found: " + name, "method_not_found");
    }

    nlohmann::json ApiPython::ExecutePy(const nlohmann::json& id, const nlohmann::json& args) {
        std::string file_path = tools::utils::GetStringArg(args, "file", tools::utils::GetStringArg(args, "path"));
        std::string code = tools::utils::GetStringArg(args, "code", tools::utils::GetStringArg(args, "expr"));
        int64_t timeout_sec = tools::utils::GetIntArg(args, "timeout", 480);
        if (timeout_sec <= 0) timeout_sec = 480;
        if (timeout_sec > 3600) timeout_sec = 3600;
        uint32_t timeout_ms = static_cast<uint32_t>(timeout_sec * 1000);

        if (file_path.empty() && code.empty()) {
            return tools::utils::MakeToolErrorJson(
                id,
                "Either 'code' (Python expression/script) or 'file' (path to .py file) must be provided",
                "code_or_file_required"
            );
        }

        std::string script_filename = "<mcp>";
        if (!file_path.empty()) {
            std::error_code ec;
            std::filesystem::path p(file_path);
            if (!std::filesystem::exists(p, ec) || !std::filesystem::is_regular_file(p, ec)) {
                return tools::utils::MakeToolErrorJson(
                    id,
                    "Python script file not found or is not a regular file: " + file_path,
                    "file_not_found"
                );
            }

            std::ifstream ifs(p, std::ios::binary);
            if (!ifs.is_open()) {
                return tools::utils::MakeToolErrorJson(
                    id,
                    "Failed to open Python script file: " + file_path,
                    "file_open_failed"
                );
            }
            code.assign((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
            script_filename = std::filesystem::absolute(p).string();
        }

        // Prepare Base64 encoded payload
        std::string b64_code = Base64Encode(code);
        std::string b64_filename = Base64Encode(script_filename);

        std::string b64_argv_items;
        if (args.contains("argv") && args["argv"].is_array()) {
            bool first = true;
            for (const auto& item : args["argv"]) {
                std::string s;
                if (item.is_string()) s = item.get<std::string>();
                else if (item.is_number()) s = item.dump();
                else continue;
                if (!first) b64_argv_items += ", ";
                first = false;
                b64_argv_items += "__b64.b64decode('" + Base64Encode(s) + "').decode('utf-8', errors='replace')";
            }
        }

        // Build wrapper script
        std::string wrapper =
            "import sys as __s, io as __io, base64 as __b64, traceback as __tb, json as __j, os as __os\n"
            "__s.__mcp_old_out = __s.stdout\n"
            "__s.__mcp_old_err = __s.stderr\n"
            "__s.__mcp_old_argv = getattr(__s, 'argv', [])\n"
            "__s.__mcp_old_path = list(__s.path)\n"
            "__mcp_buf_out = __io.StringIO()\n"
            "__mcp_buf_err = __io.StringIO()\n"
            "__s.stdout = __mcp_buf_out\n"
            "__s.stderr = __mcp_buf_err\n"
            "__mcp_res_val = None\n"
            "__mcp_res_json = 'null'\n"
            "__mcp_exc_str = ''\n"
            "__mcp_has_exc = False\n"
            "try:\n"
            "    __filename = __b64.b64decode('" + b64_filename + "').decode('utf-8', errors='replace')\n"
            "    __code_bytes = __b64.b64decode('" + b64_code + "')\n"
            "    __code_str = __code_bytes.decode('utf-8', errors='replace')\n"
            "    if __filename != '<mcp>':\n"
            "        globals()['__file__'] = __filename\n"
            "        __dir = __os.path.dirname(__os.path.abspath(__filename))\n"
            "        if __dir and __dir not in __s.path:\n"
            "            __s.path.insert(0, __dir)\n"
            "    __s.argv = [__filename] + [" + b64_argv_items + "]\n"
            "    import ast as __ast\n"
            "    __tree = __ast.parse(__code_str, __filename)\n"
            "    if __tree.body and isinstance(__tree.body[-1], __ast.Expr):\n"
            "        __last_expr = __tree.body.pop()\n"
            "        if __tree.body:\n"
            "            exec(compile(__tree, __filename, 'exec'), globals())\n"
            "        __expr_mod = __ast.Expression(__last_expr.value)\n"
            "        __mcp_res_val = eval(compile(__expr_mod, __filename, 'eval'), globals())\n"
            "    else:\n"
            "        exec(compile(__tree, __filename, 'exec'), globals())\n"
            "except BaseException:\n"
            "    __mcp_has_exc = True\n"
            "    __mcp_exc_str = __tb.format_exc()\n"
            "finally:\n"
            "    __s.stdout = __s.__mcp_old_out\n"
            "    __s.stderr = __s.__mcp_old_err\n"
            "    __s.argv = __s.__mcp_old_argv\n"
            "    __s.path = __s.__mcp_old_path\n"
            "if not __mcp_has_exc and __mcp_res_val is not None:\n"
            "    try:\n"
            "        __mcp_res_json = __j.dumps(__mcp_res_val)\n"
            "    except:\n"
            "        try:\n"
            "            __mcp_res_json = __j.dumps(str(__mcp_res_val))\n"
            "        except:\n"
            "            __mcp_res_json = __j.dumps(repr(__mcp_res_val))\n";

        bool has_exc = false;
        std::string exc_str;
        std::string captured_stdout;
        std::string captured_stderr;
        std::string res_json;
        std::string internal_err;
        bool snippet_ok = false;

        bool sync_ok = sync::SyncWrite([&]() {
            extlang_object_t el = find_extlang_by_name("Python");
            if (!el) {
                el = find_extlang_by_ext("py");
            }
            if (!el) {
                internal_err = "Python extlang provider is not initialized or available in IDA Pro";
                return;
            }

            qstring errbuf;
            snippet_ok = el->eval_snippet ? el->eval_snippet(wrapper.c_str(), &errbuf) : false;
            if (!snippet_ok) {
                internal_err = errbuf.c_str();
            }

            // Extract outputs
            EvalBoolExpr(el, "bool(__mcp_has_exc)", has_exc);
            EvalStringExpr(el, "__mcp_exc_str", exc_str);
            EvalStringExpr(el, "__mcp_buf_out.getvalue()", captured_stdout);
            EvalStringExpr(el, "__mcp_buf_err.getvalue()", captured_stderr);
            EvalStringExpr(el, "__mcp_res_json", res_json);

            // Cleanup wrapper globals
            qstring cleanup_err;
            if (el->eval_snippet) {
                el->eval_snippet(
                    "try:\n"
                    "    del __mcp_buf_out, __mcp_buf_err, __mcp_res_val, __mcp_res_json, __mcp_exc_str, __mcp_has_exc\n"
                    "except: pass\n",
                    &cleanup_err
                );
            }
        }, timeout_ms);

        if (!sync_ok) {
            return tools::utils::MakeToolErrorJson(
                id,
                "Python script execution timed out or was cancelled after " + std::to_string(timeout_sec) + " seconds",
                "execution_timeout"
            );
        }

        if (!internal_err.empty() && !snippet_ok && exc_str.empty()) {
            return tools::utils::MakeToolErrorJson(
                id,
                internal_err,
                "extlang_error"
            );
        }

        if (has_exc) {
            nlohmann::ordered_json err_res;
            err_res["status"] = "error";
            err_res["error_code"] = "py_exec_error";
            err_res["message"] = tools::utils::SanitizeUtf8(exc_str);
            err_res["stdout"] = tools::utils::SanitizeUtf8(captured_stdout);
            err_res["stderr"] = tools::utils::SanitizeUtf8(captured_stderr);
            return tools::utils::MakeToolResultJson(id, err_res, true);
        }

        // Cache invalidation after successful Python execution
        cache::InvalidateIDBDependentCaches();

        nlohmann::ordered_json res;
        res["status"] = "success";
        if (script_filename != "<mcp>") {
            res["file"] = script_filename;
        }

        if (!res_json.empty() && res_json != "null") {
            try {
                res["result"] = nlohmann::json::parse(res_json);
            } catch (...) {
                res["result"] = res_json;
            }
        } else {
            res["result"] = nullptr;
        }

        res["stdout"] = tools::utils::SanitizeUtf8(captured_stdout);
        res["stderr"] = tools::utils::SanitizeUtf8(captured_stderr);

        return tools::utils::MakeToolSuccessJson(id, res);
    }
}
