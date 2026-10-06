#include <chrono>
#include <cmath>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "tool_registry.h"
#include "shared/ida_tools_schema.h"
#include "server/status_tracker.h"
#include "utils/utils.h"

namespace tools {
    ToolRegistry::ToolRegistry() {
        api_core_ = std::make_unique<tools::core::ApiCore>();
        api_memory_ = std::make_unique<tools::memory::ApiMemory>();
        api_analysis_ = std::make_unique<tools::analysis::ApiAnalysis>();
        api_modify_ = std::make_unique<tools::modify::ApiModify>();
        api_types_ = std::make_unique<tools::types::ApiTypes>();
        api_composite_ = std::make_unique<tools::composite::ApiComposite>();
        api_sigmaker_ = std::make_unique<tools::sigmaker::ApiSigmaker>();
        api_python_ = std::make_unique<tools::python::ApiPython>();
        api_rtti_ = std::make_unique<tools::rtti::ApiRtti>();
        api_hexrays_ = std::make_unique<tools::hexrays_ast::ApiHexrays>();

        RegisterHandlers();
    }

    nlohmann::json ToolRegistry::GetToolsSchema() const {
        return mcp::GetDefaultIdaToolsSchema();
    }

    void ToolRegistry::RegisterHandlers() {
        // get_status
        handlers_["get_status"] = [](const auto& id, const auto& /*args*/) {
            return server::PluginStatusTracker::Instance().GetStatusJson(id);
        };

        // api_core
        auto reg_core = [this](const char* name) {
            handlers_[name] = [this, name](const auto& id, const auto& args) {
                return api_core_->Dispatch(id, name, args);
            };
        };
        reg_core("idb_save");
        reg_core("get_segments");
        reg_core("get_exports");
        reg_core("imports_query");
        reg_core("strings");
        reg_core("list_funcs");
        reg_core("list_globals");

        // api_memory
        auto reg_mem = [this](const char* name) {
            handlers_[name] = [this, name](const auto& id, const auto& args) {
                return api_memory_->Dispatch(id, name, args);
            };
        };
        reg_mem("get_bytes");

        // api_analysis
        auto reg_ana = [this](const char* name) {
            handlers_[name] = [this, name](const auto& id, const auto& args) {
                return api_analysis_->Dispatch(id, name, args);
            };
        };
        reg_ana("decompile");
        reg_ana("disasm");
        reg_ana("basic_blocks");
        reg_ana("xref_query");
        reg_ana("callgraph");
        reg_ana("find_bytes");
        reg_ana("insn_query");
        reg_ana("find_path");

        // api_modify
        auto reg_mod = [this](const char* name) {
            handlers_[name] = [this, name](const auto& id, const auto& args) {
                return api_modify_->Dispatch(id, name, args);
            };
        };
        reg_mod("refactor");

        // api_types
        auto reg_typ = [this](const char* name) {
            handlers_[name] = [this, name](const auto& id, const auto& args) {
                return api_types_->Dispatch(id, name, args);
            };
        };
        reg_typ("types");
        reg_typ("stack_frame");
        reg_typ("reconstruct_struct");

        // api_composite
        auto reg_comp = [this](const char* name) {
            handlers_[name] = [this, name](const auto& id, const auto& args) {
                return api_composite_->Dispatch(id, name, args);
            };
        };
        reg_comp("survey_binary");
        reg_comp("analyze_function");
        reg_comp("trace_data_flow");

        // api_sigmaker
        handlers_["make_signature"] = [this](const auto& id, const auto& args) {
            return api_sigmaker_->Dispatch(id, "make_signature", args);
        };

        // api_python
        handlers_["py"] = [this](const auto& id, const auto& args) {
            return api_python_->Dispatch(id, "py", args);
        };

        // api_rtti
        auto reg_rtti = [this](const char* name) {
            handlers_[name] = [this, name](const auto& id, const auto& args) {
                return api_rtti_->Dispatch(id, name, args);
            };
        };
        reg_rtti("rtti");
        reg_rtti("resolve_vcall");

        // api_hexrays
        auto reg_hex = [this](const char* name) {
            handlers_[name] = [this, name](const auto& id, const auto& args) {
                return api_hexrays_->Dispatch(id, name, args);
            };
        };
        reg_hex("get_ast");
        reg_hex("mba_simplify");
        reg_hex("simplify_predicate");
    }

    namespace {
        void InjectElapsedSec(nlohmann::json& rpc_resp, double elapsed_sec) {
            try {
                if (rpc_resp.contains("result") &&
                    rpc_resp["result"].contains("content") &&
                    rpc_resp["result"]["content"].is_array() &&
                    !rpc_resp["result"]["content"].empty() &&
                    rpc_resp["result"]["content"][0].contains("text") &&
                    rpc_resp["result"]["content"][0]["text"].is_string()) {

                    std::string& text = rpc_resp["result"]["content"][0]["text"].get_ref<std::string&>();
                    size_t first_brace = text.find('{');
                    if (first_brace == std::string::npos) return;

                    nlohmann::ordered_json parsed = nlohmann::ordered_json::parse(text.substr(first_brace));
                    if (parsed.is_object()) {
                        nlohmann::ordered_json canonical;
                        if (parsed.contains("status")) {
                            canonical["status"] = parsed["status"];
                        } else {
                            canonical["status"] = "success";
                        }

                        for (auto it = parsed.begin(); it != parsed.end(); ++it) {
                            if (it.key() != "status" && it.key() != "elapsed_sec") {
                                canonical[it.key()] = std::move(it.value());
                            }
                        }

                        double rounded = std::round(elapsed_sec * 1000.0) / 1000.0;
                        canonical["elapsed_sec"] = rounded;

                        text = canonical.dump(2);
                    }
                }
            } catch (...) {
            }
        }

        std::string SafeDumpJson(const nlohmann::json& j) {
            try {
                return j.dump();
            } catch (const std::exception& e) {
                return tools::utils::MakeToolErrorJson(nullptr, std::string("JSON serialization error: ") + e.what(), "serialization_error").dump();
            } catch (...) {
                return tools::utils::MakeToolErrorJson(nullptr, "JSON serialization error", "serialization_error").dump();
            }
        }
    }

    std::string ToolRegistry::HandleRequest(const std::string& raw_body) {
        nlohmann::json req;
        try {
            req = nlohmann::json::parse(raw_body);
        } catch (...) {
            return nlohmann::json({
                {"jsonrpc", "2.0"},
                {"id", nullptr},
                {"error", {{"code", -32700}, {"message", "Parse error: Invalid JSON"}}}
            }).dump();
        }

        auto id = req.contains("id") ? req["id"] : nullptr;
        std::string method = req.value("method", "");

        if (method == "initialize") {
            return SafeDumpJson(nlohmann::json({
                {"jsonrpc", "2.0"},
                {"id", id},
                {"result", {
                    {"protocolVersion", "2024-11-05"},
                    {"serverInfo", {
                        {"name", "ida-pro-mcp"},
                        {"version", "1.2.0"}
                    }},
                    {"capabilities", {
                        {"tools", nlohmann::json::object()}
                    }}
                }}
            }));
        }

        if (method == "ping") {
            return SafeDumpJson(nlohmann::json({
                {"jsonrpc", "2.0"},
                {"id", id},
                {"result", nlohmann::json::object()}
            }));
        }

        if (method == "tools/list") {
            return SafeDumpJson(nlohmann::json({
                {"jsonrpc", "2.0"},
                {"id", id},
                {"result", {
                    {"tools", GetToolsSchema()}
                }}
            }));
        }

        if (method == "tools/call") {
            nlohmann::json params = req.value("params", nlohmann::json::object());
            std::string name = params.value("name", "");
            nlohmann::json args = params.value("arguments", nlohmann::json::object());
            auto start_time = std::chrono::steady_clock::now();
            try {
                nlohmann::json res = DispatchToolCall(id, name, args);
                auto end_time = std::chrono::steady_clock::now();
                double elapsed_sec = std::chrono::duration<double>(end_time - start_time).count();
                InjectElapsedSec(res, elapsed_sec);
                return SafeDumpJson(res);
            } catch (const std::exception& e) {
                auto end_time = std::chrono::steady_clock::now();
                double elapsed_sec = std::chrono::duration<double>(end_time - start_time).count();
                nlohmann::json err = tools::utils::MakeToolErrorJson(id, std::string("Internal error: ") + e.what(), "internal_error");
                InjectElapsedSec(err, elapsed_sec);
                return SafeDumpJson(err);
            } catch (...) {
                auto end_time = std::chrono::steady_clock::now();
                double elapsed_sec = std::chrono::duration<double>(end_time - start_time).count();
                nlohmann::json err = tools::utils::MakeToolErrorJson(id, "Unknown internal error", "internal_error");
                InjectElapsedSec(err, elapsed_sec);
                return SafeDumpJson(err);
            }
        }

        return SafeDumpJson(nlohmann::json({
            {"jsonrpc", "2.0"},
            {"id", id},
            {"error", {{"code", -32601}, {"message", "Method not found: " + method}}}
        }));
    }

    nlohmann::json ToolRegistry::DispatchToolCall(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        auto it = handlers_.find(name);
        if (it != handlers_.end()) {
            return it->second(id, args);
        }

        return tools::utils::MakeToolErrorJson(id, "Tool not found: " + name, "tool_not_found");
    }
}
