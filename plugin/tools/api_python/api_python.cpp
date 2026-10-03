#include <string>
#include <vector>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "api_python.h"
#include "tools/utils/utils.h"
#include "sync/sync.h"

#include <ida.hpp>
#include <expr.hpp>

namespace tools::python {
    namespace {
        // Escape user code for safe embedding inside triple-quoted Python string.
        // We escape backslashes and triple-quotes to prevent injection.
        std::string EscapePyTripleQuote(const std::string& code) {
            std::string out;
            out.reserve(code.size() + 32);
            for (size_t i = 0; i < code.size(); ++i) {
                if (code[i] == '\\') {
                    out += "\\\\";
                } else if (i + 2 < code.size() && code[i] == '\'' && code[i+1] == '\'' && code[i+2] == '\'') {
                    out += "\\'\\'\\'";
                    i += 2;
                } else {
                    out += code[i];
                }
            }
            return out;
        }

        // Extract buffered stdout/stderr via a second eval_expr call
        void ExtractCapturedOutput(const extlang_t* el, std::string& out_stdout, std::string& out_stderr) {
            if (!el || !el->eval_expr) return;

            idc_value_t rv;
            qstring errbuf;

            // Get stdout
            if (el->eval_expr(&rv, BADADDR, "__mcp_buf_out.getvalue()", &errbuf) && rv.vtype == VT_STR) {
                out_stdout = rv.c_str();
            }

            // Get stderr
            if (el->eval_expr(&rv, BADADDR, "__mcp_buf_err.getvalue()", &errbuf) && rv.vtype == VT_STR) {
                out_stderr = rv.c_str();
            }

            // Cleanup: restore original streams and delete buffers
            el->eval_snippet(
                "import sys as __s\n"
                "if hasattr(__s, '__mcp_old_stdout'):\n"
                "    __s.stdout = __s.__mcp_old_stdout\n"
                "    __s.stderr = __s.__mcp_old_stderr\n"
                "    del __s.__mcp_old_stdout, __s.__mcp_old_stderr\n"
                "try:\n"
                "    del __mcp_buf_out, __mcp_buf_err\n"
                "except: pass\n",
                &errbuf
            );
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

        if (file_path.empty() && code.empty()) {
            return tools::utils::MakeToolErrorJson(
                id,
                "Either 'code' (Python expression/script) or 'file' (path to .py file) must be provided",
                "code_or_file_required"
            );
        }

        // File execution mode
        if (!file_path.empty()) {
            bool ok = false;
            std::string err;
            std::string captured_stdout;
            std::string captured_stderr;

            sync::SyncWrite([&]() {
                qstring errbuf;
                const extlang_t* el = find_extlang_by_ext("py");
                if (!el) {
                    errbuf = "Python extlang provider is not initialized in IDA Pro";
                    err = errbuf.c_str();
                    return;
                }

                // Setup stdout/stderr redirect before file execution
                if (el->eval_snippet) {
                    el->eval_snippet(
                        "import sys as __s, io as __io\n"
                        "__s.__mcp_old_stdout, __s.__mcp_old_stderr = __s.stdout, __s.stderr\n"
                        "__mcp_buf_out = __io.StringIO()\n"
                        "__mcp_buf_err = __io.StringIO()\n"
                        "__s.stdout = __mcp_buf_out\n"
                        "__s.stderr = __mcp_buf_err\n",
                        &errbuf
                    );
                }

                if (el->compile_file) {
                    ok = el->compile_file(file_path.c_str(), nullptr, &errbuf);
                }

                if (!ok) {
                    err = errbuf.c_str();
                }

                // Capture output regardless of success/failure
                ExtractCapturedOutput(el, captured_stdout, captured_stderr);
            });

            if (!ok) {
                nlohmann::json err_detail = {
                    {"stdout", captured_stdout},
                    {"stderr", captured_stderr}
                };
                return tools::utils::MakeToolErrorJson(
                    id,
                    err.empty() ? ("Failed to execute Python script: " + file_path) : err,
                    "exec_file_failed"
                );
            }

            nlohmann::json res = {
                {"status", "success"},
                {"file", file_path},
                {"stdout", captured_stdout},
                {"stderr", captured_stderr}
            };
            return tools::utils::MakeToolSuccessJson(id, res);
        }

        // Code evaluation/execution mode
        std::string out;
        bool ok = false;
        std::string err_desc;
        std::string captured_stdout;
        std::string captured_stderr;

        sync::SyncWrite([&]() {
            qstring errbuf;

            const extlang_t* el = find_extlang_by_name("Python");
            if (!el) {
                el = find_extlang_by_ext("py");
            }

            if (!el) {
                err_desc = "Python extlang provider is not available";
                return;
            }

            // Build wrapped code with stdout/stderr redirect
            std::string escaped = EscapePyTripleQuote(code);
            std::string wrapper =
                "import sys as __s, io as __io\n"
                "__s.__mcp_old_stdout, __s.__mcp_old_stderr = __s.stdout, __s.stderr\n"
                "__mcp_buf_out = __io.StringIO()\n"
                "__mcp_buf_err = __io.StringIO()\n"
                "__s.stdout = __mcp_buf_out\n"
                "__s.stderr = __mcp_buf_err\n"
                "__mcp_result = None\n"
                "try:\n"
                "    __mcp_result = eval(compile('''" + escaped + "''', '<mcp>', 'eval'))\n"
                "except SyntaxError:\n"
                "    exec(compile('''" + escaped + "''', '<mcp>', 'exec'))\n"
                "finally:\n"
                "    __s.stdout, __s.stderr = __s.__mcp_old_stdout, __s.__mcp_old_stderr\n";

            if (el->eval_snippet) {
                ok = el->eval_snippet(wrapper.c_str(), &errbuf);
            }

            if (ok) {
                // Extract return value
                idc_value_t rv;
                if (el->eval_expr && el->eval_expr(&rv, BADADDR, "__mcp_result", &errbuf)) {
                    if (rv.vtype == VT_STR) {
                        out = rv.c_str();
                    } else if (rv.vtype == VT_LONG) {
                        out = std::to_string(rv.num);
                    } else if (rv.vtype == VT_INT64) {
                        out = std::to_string(rv.i64);
                    } else {
                        qstring str_val;
                        if (print_idcv(&str_val, rv)) {
                            out = str_val.c_str();
                        } else {
                            out = "None";
                        }
                    }
                }

                // Capture stdout/stderr
                ExtractCapturedOutput(el, captured_stdout, captured_stderr);

                // Cleanup __mcp_result
                if (el->eval_snippet) {
                    el->eval_snippet(
                        "try:\n    del __mcp_result\nexcept: pass\n",
                        &errbuf
                    );
                }
            } else {
                err_desc = tools::utils::SanitizeUtf8(errbuf.c_str());

                // Still try to capture any partial output and restore streams
                ExtractCapturedOutput(el, captured_stdout, captured_stderr);
            }
        });

        if (!ok) {
            nlohmann::json res = {
                {"status", "error"},
                {"error_code", "py_eval_failed"},
                {"message", err_desc.empty() ? "Python evaluation error" : err_desc},
                {"stdout", captured_stdout},
                {"stderr", captured_stderr}
            };
            return tools::utils::MakeToolErrorJson(
                id,
                err_desc.empty() ? "Python evaluation error" : err_desc,
                "py_eval_failed"
            );
        }

        nlohmann::json res = {
            {"status", "success"},
            {"result", out},
            {"stdout", captured_stdout},
            {"stderr", captured_stderr}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }
}

