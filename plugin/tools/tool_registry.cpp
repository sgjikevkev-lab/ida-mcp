#include "sync/operation.h"
#include <chrono>
#include "shared/argument_validation.h"
#include "shared/json_parse.h"

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "tool_registry.h"
#include "shared/ida_tools_schema.h"
#include "server/status_tracker.h"
#include "utils/utils.h"

namespace tools {
    namespace {
        nlohmann::json MakeRpcError(const nlohmann::json& id, int code, const std::string& message) {
            return nlohmann::json({
                {"jsonrpc", "2.0"},
                {"id", id},
                {"error", {{"code", code}, {"message", message}}}
            });
        }
    }

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
        reg_ana("emulate_function");

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
        std::string SafeDumpJson(const nlohmann::json& j) {
            try {
                return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
            } catch (const sync::OperationStopped&) { throw; } catch (const std::exception& e) {
                return tools::utils::MakeToolErrorJson(nullptr, std::string("JSON serialization error: ") + e.what(), "serialization_error").dump();
            } catch (...) {
                return tools::utils::MakeToolErrorJson(nullptr, "JSON serialization error", "serialization_error").dump();
            }
        }
    }

    std::string ToolRegistry::HandleRequest(const std::string& raw_body) {
        nlohmann::json req;
        try {
            req = mcp::ParseBoundedJson(raw_body);
        } catch (const sync::OperationStopped&) { throw; } catch (...) {
            return nlohmann::json({
                {"jsonrpc", "2.0"},
                {"id", nullptr},
                {"error", {{"code", -32700}, {"message", "Parse error: Invalid JSON"}}}
            }).dump();
        }

        if (!req.is_object() || req.value("jsonrpc", nlohmann::json(nullptr)) != "2.0" ||
            !req.contains("method") || !req["method"].is_string())
            return nlohmann::json({{"jsonrpc", "2.0"}, {"id", nullptr},
                {"error", {{"code", -32600}, {"message", "Invalid JSON-RPC request"}}}}).dump();
        auto id = req.contains("id") ? req["id"] : nullptr;
        std::string method = req.value("method", "");

        if (method == "initialize") {
            nlohmann::json params = nlohmann::json::object();
            if (req.contains("params")) {
                params = req["params"];
                if (!params.is_object())
                    return SafeDumpJson(MakeRpcError(id, -32602, "params must be an object"));
            }
            if (params.contains("protocolVersion") && !params["protocolVersion"].is_string())
                return SafeDumpJson(MakeRpcError(id, -32602, "protocolVersion must be a string"));
            return SafeDumpJson(nlohmann::json({
                {"jsonrpc", "2.0"},
                {"id", id},
                {"result", {
                    {"protocolVersion", "2024-11-05"},
                    {"serverInfo", {
                        {"name", "ida-pro-mcp"},
                        {"version", "2.2.0"}
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
            if (!req.contains("params") || !req["params"].is_object())
                return SafeDumpJson(MakeRpcError(id, -32602, "params must be an object"));
            const auto& params = req["params"];
            if (!params.contains("name") || !params["name"].is_string() || params["name"].get_ref<const std::string&>().empty())
                return SafeDumpJson(MakeRpcError(id, -32602, "name must be a non-empty string"));
            std::string name = params["name"].get<std::string>();
            nlohmann::json args = nlohmann::json::object();
            if (params.contains("arguments")) {
                args = params["arguments"];
                if (!args.is_object())
                    return SafeDumpJson(MakeRpcError(id, -32602, "arguments must be an object"));
            }
            try {
                nlohmann::json res = DispatchToolCall(id, name, args);

                return SafeDumpJson(res);
            } catch (const sync::OperationStopped&) { throw; } catch (const std::exception& e) {
                nlohmann::json err = tools::utils::MakeToolErrorJson(id, std::string("Internal error: ") + e.what(), "internal_error");

                return SafeDumpJson(err);
            } catch (...) {
                nlohmann::json err = tools::utils::MakeToolErrorJson(id, "Unknown internal error", "internal_error");

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
        sync::Checkpoint();
        bool schema_found = false;
        for (const auto& tool : GetToolsSchema()) {
            sync::Checkpoint();
            if (tool["name"] != name) continue;
            schema_found = true;
            auto error = mcp::ValidateArguments(tool["inputSchema"], args);
            if (!error.empty()) return tools::utils::MakeToolErrorJson(id, error, "invalid_params");
            break;
        }
        if (!schema_found)
            return tools::utils::MakeToolErrorJson(id, "Tool not found: " + name, "tool_not_found");
        auto it = handlers_.find(name);
        if (it != handlers_.end()) {
            return it->second(id, args);
        }

        return tools::utils::MakeToolErrorJson(id, "Tool not found: " + name, "tool_not_found");
    }
}
