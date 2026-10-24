#include "ida_router.h"
#include "ida/discovery.h"
#include "mcp/transport.h"
#include "shared/ida_tools_schema.h"
#include <chrono>
#include <cmath>
#include <filesystem>
#include <random>
#include "shared/json_parse.h"
#include "shared/argument_validation.h"
#include "shared/runtime_limits.h"

namespace router {
    void IdaRouter::RefreshInstances(bool force) {
        auto now = std::chrono::steady_clock::now();
        if (!force && !instances_.empty() && !active_file_.empty()) {
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_discovery_time_).count();
            if (elapsed_ms < 1500) {
                return;
            }
        }
        last_discovery_time_ = now;

        std::string cur = active_file_;
        std::wstring active_pipe = active_client_.IsConnected() ? active_client_.GetCurrentPipe() : L"";

        instances_ = ida::InstanceDiscovery::Discover(active_pipe, &active_client_);

        if (!cur.empty() && instances_.find(cur) != instances_.end()) {
            active_file_ = cur;
        } else if (cur.empty() && !selection_required_ && instances_.size() == 1) {
            active_file_ = instances_.begin()->first;
        } else {
            if (!cur.empty()) selection_required_ = true;
            active_file_.clear();
            active_client_.Disconnect();
        }

        if (!active_file_.empty()) {
            const auto& target_pipe = instances_[active_file_].pipe_name;
            if (!active_client_.IsConnected() || active_client_.GetCurrentPipe() != target_pipe) {
                active_client_.Disconnect();
                active_client_.Connect(target_pipe, 3000);
            }
        }
    }

    mcp::json IdaRouter::GetCustomTools() const {
        return mcp::json::array({
            {
                {"name", "get_available_files"},
                {"description", "List all currently open binaries across active IDA Pro instances and show active selection."},
                {"inputSchema", {
                    {"type", "object"},
                    {"properties", mcp::json::object()},
                    {"additionalProperties", false}
                }}
            },
            {
                {"name", "switch_file"},
                {"description", "Switch active IDA Pro context to another open binary by filename."},
                {"inputSchema", {
                    {"type", "object"},
                    {"properties", {
                        {"filename", {
                            {"type", "string"},
                            {"description", "Target binary filename to activate (e.g. 'target.exe')"}
                        }}
                    }},
                    {"required", {"filename"}},
                    {"additionalProperties", false}
                }}
            }
        });
    }

    void IdaRouter::HandleInitialize(const mcp::json& req, const mcp::json& id) {
        std::string proto = req.value("params", mcp::json::object()).value("protocolVersion", mcp::constants::DEFAULT_PROTOCOL_VERSION);
        if (proto != "2024-11-05" && proto != "2025-03-26" && proto != "2025-06-18")
            proto = mcp::constants::DEFAULT_PROTOCOL_VERSION;
        mcp::json resp = mcp::MakeSuccessResponse(id, {
            {"protocolVersion", proto},
            {"serverInfo", {
                {"name", mcp::constants::SERVER_NAME},
                {"version", mcp::constants::SERVER_VERSION}
            }},
            {"capabilities", {
                {"tools", mcp::json::object()}
            }}
        });
        mcp::StdioTransport::Send(resp);
    }

    IdaRouter::~IdaRouter() {
        active_client_.Cancel();
        if (worker_thread_.joinable()) worker_thread_.join();
        active_client_.Disconnect();
    }

    void IdaRouter::HandleToolsList(const mcp::json& req, const mcp::json& id) {
        mcp::json all_tools = GetCustomTools();
        for (const auto& tool : mcp::GetDefaultIdaToolsSchema()) all_tools.push_back(tool);
        mcp::StdioTransport::Send(mcp::MakeSuccessResponse(id, {{"tools", all_tools}}));
    }

    void IdaRouter::HandleGetAvailableFiles(const mcp::json& id) {
        auto t0 = std::chrono::steady_clock::now();
        bool busy_now = false;
        {
            std::lock_guard<std::mutex> lock(status_mtx_);
            busy_now = is_busy_;
        }
        if (!busy_now) {
            RefreshInstances();
        }

        mcp::json files_arr = mcp::json::array();
        for (const auto& kv : instances_) {
            files_arr.push_back(kv.first);
        }
        auto t1 = std::chrono::steady_clock::now();
        double elapsed_sec = std::round(std::chrono::duration<double>(t1 - t0).count() * 1000.0) / 1000.0;

        mcp::ordered_json res = {
            {"status", "success"},
            {"active_file", active_file_.empty() ? nullptr : mcp::json(active_file_)},
            {"files", files_arr},
            {"elapsed_sec", elapsed_sec}
        };
        mcp::StdioTransport::Send(mcp::MakeSuccessResponse(id, mcp::MakeToolCallResult(res.dump(2))));
    }

    void IdaRouter::HandleSwitchFile(const mcp::json& id, const mcp::json& args) {
        auto t0 = std::chrono::steady_clock::now();

        if (!args.is_object() || !args.contains("filename") || !args["filename"].is_string()) {
            mcp::json files_arr = mcp::json::array();
            for (const auto& kv : instances_) {
                files_arr.push_back(kv.first);
            }
            mcp::ordered_json res = {
                {"status", "error"},
                {"message", "Argument 'filename' is required and must be a string"},
                {"available_files", files_arr},
                {"elapsed_sec", 0.0}
            };
            mcp::StdioTransport::Send(mcp::MakeSuccessResponse(
                id,
                mcp::MakeToolCallResult(res.dump(2), true)
            ));
            return;
        }

        std::string target = args["filename"].get<std::string>();
        auto sep = target.find_last_of("\\/");
        if (sep != std::string::npos) {
            target = target.substr(sep + 1);
        }

        {
            std::lock_guard<std::mutex> lock(status_mtx_);
            if (is_busy_) {
                mcp::ordered_json res = {
                    {"status", "error"},
                    {"error_code", "busy"},
                    {"message", "Cannot switch file while tool '" + active_tool_ + "' is executing in IDA Pro."}
                };
                mcp::StdioTransport::Send(mcp::MakeSuccessResponse(
                    id,
                    mcp::MakeToolCallResult(res.dump(2), true)
                ));
                return;
            }
        }

        RefreshInstances(true);

        std::string matched_key;
        std::vector<std::string> matches;
        if (instances_.contains(target)) matches.push_back(target);
        else {
            for (const auto& [key, instance] : instances_)
                if (_stricmp(key.c_str(), target.c_str()) == 0) matches.push_back(key);
            if (matches.empty()) for (const auto& [key, instance] : instances_) {
                const auto stem = std::filesystem::path(key).stem().string();
                const auto idb = std::filesystem::path(instance.idb_path).filename().string();
                if (_stricmp(stem.c_str(), target.c_str()) == 0 || _stricmp(idb.c_str(), target.c_str()) == 0)
                    matches.push_back(key);
            }
        }
        if (matches.size() > 1) {
            mcp::StdioTransport::Send(mcp::MakeSuccessResponse(id, mcp::MakeToolCallResult(
                mcp::json({{"error_code", "ambiguous_file"}, {"matches", matches}}).dump(), true)));
            return;
        }
        if (!matches.empty()) matched_key = matches.front();

        auto t1 = std::chrono::steady_clock::now();
        double elapsed_sec = std::round(std::chrono::duration<double>(t1 - t0).count() * 1000.0) / 1000.0;

        if (!matched_key.empty()) {
            if (active_file_ != matched_key || !active_client_.IsConnected()) {
                active_client_.Disconnect();
                if (!active_client_.Connect(instances_[matched_key].pipe_name, 3000)) {
                    mcp::StdioTransport::Send(mcp::MakeSuccessResponse(id, mcp::MakeToolCallResult(
                        mcp::json({{"error_code", "connection_failed"}, {"message", "Cannot connect to selected IDA database"}}).dump(), true)));
                    return;
                }
                active_file_ = matched_key;
                selection_required_ = false;
            }

            mcp::ordered_json res = {
                {"status", "success"},
                {"active_file", matched_key},
                {"elapsed_sec", elapsed_sec}
            };
            mcp::StdioTransport::Send(mcp::MakeSuccessResponse(
                id,
                mcp::MakeToolCallResult(res.dump(2))
            ));
        } else {
            mcp::json files_arr = mcp::json::array();
            for (const auto& kv : instances_) {
                files_arr.push_back(kv.first);
            }
            mcp::ordered_json res = {
                {"status", "error"},
                {"message", "Target binary '" + target + "' is not loaded in any active IDA Pro instance"},
                {"available_files", files_arr},
                {"elapsed_sec", elapsed_sec}
            };
            mcp::StdioTransport::Send(mcp::MakeSuccessResponse(
                id,
                mcp::MakeToolCallResult(res.dump(2), true)
            ));
        }
    }

    void IdaRouter::ForwardToolCall(const mcp::json& req, const mcp::json& id, const std::string& raw_tool_call) {
        std::string previous_active = active_file_;

        if (active_file_.empty() || instances_.find(active_file_) == instances_.end()) {
            mcp::json files_arr = mcp::json::array();
            for (const auto& kv : instances_) {
                files_arr.push_back(kv.first);
            }

            std::string msg = previous_active.empty()
                ? "No active IDA Pro file selected. Please call switch_file to select an open file."
                : "Active IDA Pro file '" + previous_active + "' was closed or went offline. Please call switch_file to select an open file.";

            mcp::json err_res = {
                {"status", "error"},
                {"error_code", "no_active_file"},
                {"message", msg},
                {"available_files", files_arr}
            };

            mcp::StdioTransport::Send(mcp::MakeSuccessResponse(
                id,
                mcp::MakeToolCallResult(err_res.dump(2), true)
            ));
            return;
        }

        const auto& inst = instances_[active_file_];

        // Guard against dead IDA process: if process died, disconnect immediately to release pipe
        if (!ida::InstanceDiscovery::IsPidAlive(inst.pid)) {
            active_client_.Disconnect();
            mcp::json files_arr = mcp::json::array();
            for (const auto& kv : instances_) {
                files_arr.push_back(kv.first);
            }
            mcp::json err_res = {
                {"status", "error"},
                {"error_code", "instance_offline_or_crashed"},
                {"file", active_file_},
                {"message", "IDA Pro process has terminated"},
                {"available_files", files_arr}
            };
            mcp::StdioTransport::Send(mcp::MakeSuccessResponse(
                id,
                mcp::MakeToolCallResult(err_res.dump(2), true)
            ));
            return;
        }

        // Connect persistent pipe if not already connected
        if (!active_client_.IsConnected()) {
            if (!active_client_.Connect(inst.pipe_name, 3000)) {
                    mcp::json err_res = {
                    {"status", "error"},
                    {"error_code", "connection_failed"},
                    {"file", active_file_},
                    {"message", "Could not connect to IDA Pro Named Pipe"}
                };
                mcp::StdioTransport::Send(mcp::MakeSuccessResponse(
                    id,
                    mcp::MakeToolCallResult(err_res.dump(2), true)
                ));
                return;
            }
        }

        std::string pipe_resp;
        mcp::json forwarded = req;
        { std::lock_guard<std::mutex> lock(status_mtx_); forwarded["_cancel_token"] = active_cancel_token_; }
        const std::string payload_to_send = forwarded.dump();

        // Perform persistent transaction (30-minute limit)
        if (!active_client_.Transact(payload_to_send, pipe_resp, mcp::limits::operation_ms)) {
            const DWORD transport_error = active_client_.LastError();
            active_client_.Disconnect();

            mcp::json files_arr = mcp::json::array();
            for (const auto& kv : instances_) {
                files_arr.push_back(kv.first);
            }

            mcp::json err_res = {
                {"status", "error"},
                {"error_code", transport_error == ERROR_TIMEOUT ? "execution_timeout" : "connection_lost"},
                {"message", transport_error == ERROR_TIMEOUT ? "30-minute limit exceeded; cancellation requested on disconnect. Check get_status before retrying." : "IDA connection lost; execution outcome is unknown. Do not blindly retry mutations."},
                {"available_files", files_arr}
            };

            mcp::StdioTransport::Send(mcp::MakeSuccessResponse(
                id,
                mcp::MakeToolCallResult(err_res.dump(2), true)
            ));
            return;
        }

        // Forward response directly
        try {
            mcp::json parsed = mcp::json::parse(pipe_resp);
            if (!parsed.is_object() || parsed.value("jsonrpc", mcp::json(nullptr)) != "2.0" ||
                parsed.value("id", mcp::json(nullptr)) != id || (!parsed.contains("result") && !parsed.contains("error")))
                throw std::runtime_error("Mismatched backend response");
            mcp::StdioTransport::Send(parsed);
        } catch (...) {
            mcp::StdioTransport::Send(mcp::MakeSuccessResponse(
                id,
                mcp::MakeToolCallResult(mcp::json({{"error_code", "invalid_backend_response"},
                    {"message", "Invalid or mismatched response from IDA; execution outcome is unknown"}}).dump(), true)
            ));
        }
    }

    void IdaRouter::HandleGetStatus(const mcp::json& id) {
        mcp::json result;
        {
            std::lock_guard<std::mutex> lock(status_mtx_);
            result = {{"busy", is_busy_}, {"active_file", active_file_.empty() ? mcp::json(nullptr) : mcp::json(active_file_)}};
            if (is_busy_) {
                result["tool"] = active_tool_;
                result["elapsed_seconds"] = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - active_tool_start_).count();
            }
        }
        if (!result["busy"].get<bool>() && !active_file_.empty() && instances_.contains(active_file_)) {
            std::string response;
            const mcp::json request = {{"jsonrpc", "2.0"}, {"id", id}, {"method", "tools/call"},
                                      {"params", {{"name", "get_status"}, {"arguments", mcp::json::object()}}}};
            if (ipc::PipeClient::CallOnce(instances_.at(active_file_).pipe_name, request.dump(), response, 500)) {
                auto parsed = mcp::json::parse(response, nullptr, false);
                if (!parsed.is_discarded() && parsed.is_object() && parsed.contains("result")) {
                    parsed["id"] = id;
                    mcp::StdioTransport::Send(parsed);
                    return;
                }
            } else result["reachable"] = false;
        }
        mcp::StdioTransport::Send(mcp::MakeSuccessResponse(id, mcp::MakeToolCallResult(result.dump())));
    }

    void IdaRouter::DispatchToolCallAsync(
        const mcp::json& req,
        const mcp::json& id,
        const std::string& raw_tool_call,
        const std::string& name,
        const mcp::json& args
    ) {
        bool busy_snapshot;
        { std::lock_guard<std::mutex> lock(status_mtx_); busy_snapshot = is_busy_; }
        if (!busy_snapshot) {
            if (worker_thread_.joinable()) worker_thread_.join();
            RefreshInstances();
        }
        // Generate the cancellation token before publishing busy state. A
        // throwing random_device must not strand the router in a busy state.
        std::random_device entropy;
        const std::string cancel_token = std::to_string(entropy()) + "-" +
            std::to_string(entropy()) + "-" + std::to_string(entropy());
        {
            std::lock_guard<std::mutex> lock(status_mtx_);
            if (is_busy_) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - active_tool_start_).count();
                double elapsed_sec = std::round(elapsed_ms / 10.0) / 100.0;

                char sec_buf[32];
                snprintf(sec_buf, sizeof(sec_buf), "%.2f", elapsed_sec);

                mcp::json err_res = {
                    {"status", "error"},
                    {"error_code", "busy"},
                    {"message", "IDA Pro is busy executing tool '" + active_tool_ + "' (" + std::string(sec_buf) + "s elapsed). Use 'get_status' to monitor progress."},
                    {"current_tool", active_tool_},
                    {"elapsed_sec", elapsed_sec}
                };
                mcp::StdioTransport::Send(mcp::MakeSuccessResponse(
                    id,
                    mcp::MakeToolCallResult(err_res.dump(2), true)
                ));
                return;
            }

            is_busy_ = true;
            active_tool_ = name;
            active_request_id_ = id;
            active_cancel_token_ = cancel_token;
            active_tool_args_ = (args.is_null() || args.empty()) ? "" : args.dump();
            if (active_tool_args_.size() > 200) {
                active_tool_args_ = active_tool_args_.substr(0, 197) + "...";
            }
            active_tool_start_ = std::chrono::steady_clock::now();
        }

        try {
            worker_thread_ = std::thread([this, req, id, raw_tool_call]() {
            try {
                ForwardToolCall(req, id, raw_tool_call);
            } catch (const std::exception& e) {
                mcp::json err_res = {
                    {"status", "error"},
                    {"error_code", "internal_error"},
                    {"message", std::string("Internal exception during tool execution: ") + e.what()}
                };
                mcp::StdioTransport::Send(mcp::MakeSuccessResponse(
                    id,
                    mcp::MakeToolCallResult(err_res.dump(2), true)
                ));
            } catch (...) {
                mcp::json err_res = {
                    {"status", "error"},
                    {"error_code", "internal_error"},
                    {"message", "Unknown internal exception during tool execution"}
                };
                mcp::StdioTransport::Send(mcp::MakeSuccessResponse(
                    id,
                    mcp::MakeToolCallResult(err_res.dump(2), true)
                ));
            }

            {
                std::lock_guard<std::mutex> lock(status_mtx_);
                is_busy_ = false;
                active_tool_.clear();
                active_tool_args_.clear();
            }
            });
        } catch (...) {
            {
                std::lock_guard<std::mutex> lock(status_mtx_);
                if (is_busy_ && active_request_id_ == id) {
                    is_busy_ = false;
                    active_tool_.clear();
                    active_tool_args_.clear();
                    active_cancel_token_.clear();
                }
            }
            mcp::StdioTransport::Send(mcp::MakeSuccessResponse(id,
                mcp::MakeToolCallResult(mcp::json({
                    {"error_code", "worker_start_failed"},
                    {"message", "Could not start the tool worker thread"}
                }).dump(), true)));
        }
    }

    void IdaRouter::HandleToolsCall(const mcp::json& req, const mcp::json& id, const std::string& raw_tool_call) {
        mcp::json params = req.value("params", mcp::json::object());
        std::string name = params.value("name", "");
        mcp::json args = params.value("arguments", mcp::json::object());

        auto schemas = GetCustomTools();
        for (const auto& tool : mcp::GetDefaultIdaToolsSchema()) schemas.push_back(tool);
        bool found = false;
        for (const auto& tool : schemas) {
            if (tool["name"] != name) continue;
            found = true;
            auto error = mcp::ValidateArguments(tool["inputSchema"], args);
            if (!error.empty()) {
                mcp::StdioTransport::Send(mcp::MakeSuccessResponse(id,
                    mcp::MakeToolCallResult(mcp::json({{"error_code", "invalid_params"}, {"message", error}}).dump(), true)));
                return;
            }
            break;
        }
        if (!found) {
            mcp::StdioTransport::Send(mcp::MakeSuccessResponse(id,
                mcp::MakeToolCallResult(mcp::json({{"error_code", "tool_not_found"}, {"message", name}}).dump(), true)));
            return;
        }
        if (name == "get_status") {
            HandleGetStatus(id);
        } else if (name == "get_available_files") {
            HandleGetAvailableFiles(id);
        } else if (name == "switch_file") {
            HandleSwitchFile(id, args);
        } else {
            DispatchToolCallAsync(req, id, raw_tool_call, name, args);
        }
    }

    void IdaRouter::ProcessMessage(const std::string& raw_message) {
        if (raw_message.empty()) return;

        mcp::json id = nullptr;
        try {
            mcp::json req = mcp::ParseBoundedJson(raw_message);
            if (!req.is_object() || req.value("jsonrpc", mcp::json(nullptr)) != "2.0" ||
                !req.contains("method") || !req["method"].is_string()) {
                mcp::StdioTransport::Send(mcp::MakeErrorResponse(nullptr, -32600, "Invalid JSON-RPC request"));
                return;
            }
            if (req.contains("id")) {
                id = req["id"];
            }
            std::string method = req.value("method", "");
            if (method == "notifications/cancelled") {
                const auto params = req.value("params", mcp::json::object());
                if (!params.is_object()) return;
                mcp::json cancellation;
                std::wstring pipe;
                {
                    std::lock_guard<std::mutex> lock(status_mtx_);
                    if (!is_busy_ || params.value("requestId", mcp::json(nullptr)) != active_request_id_ ||
                        !instances_.contains(active_file_)) return;
                    pipe = instances_.at(active_file_).pipe_name;
                    cancellation = {{"jsonrpc", "2.0"}, {"method", "ida/cancel"},
                        {"params", {{"requestId", active_request_id_}, {"token", active_cancel_token_}}}};
                }
                ipc::PipeClient::NotifyOnce(pipe, cancellation.dump());
                return;
            }
            if (!req.contains("id") && method != "notifications/initialized") return;

            if (method == "initialize") {
                HandleInitialize(req, id);
            } else if (method == "notifications/initialized") {
            } else if (method == "ping") {
                if (!id.is_null()) {
                    mcp::StdioTransport::Send(mcp::MakeSuccessResponse(id, mcp::json::object()));
                }
            } else if (method == "tools/list") {
                HandleToolsList(req, id);
            } else if (method == "tools/call") {
                HandleToolsCall(req, id, raw_message);
            } else if (!id.is_null()) {
                mcp::StdioTransport::Send(mcp::MakeErrorResponse(id, -32601, "Method not found: " + method));
            }
        } catch (const mcp::json::parse_error& e) {
            mcp::StdioTransport::Send(mcp::MakeErrorResponse(nullptr, -32700, std::string("Parse error: Invalid JSON: ") + e.what()));
        } catch (const std::exception& e) {
            mcp::StdioTransport::Send(mcp::MakeErrorResponse(id, -32602, std::string("Invalid params or request: ") + e.what()));
        } catch (...) {
            mcp::StdioTransport::Send(mcp::MakeErrorResponse(id, -32603, "Internal server error"));
        }
    }

    void IdaRouter::Run() {
        mcp::StdioTransport::RunLoop([this](const std::string& line) {
            ProcessMessage(line);
        });
    }
}
