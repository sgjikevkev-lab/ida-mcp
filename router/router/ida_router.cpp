#include "ida_router.h"
#include "ida/discovery.h"
#include "mcp/transport.h"
#include "shared/ida_tools_schema.h"
#include <chrono>
#include <cmath>

namespace router {
    void IdaRouter::RefreshInstances() {
        std::string cur = active_file_;
        active_client_.Disconnect();
        instances_ = ida::InstanceDiscovery::Discover();
        if (instances_.empty() || (!cur.empty() && instances_.find(cur) == instances_.end())) {
            active_file_.clear();
        } else if (!cur.empty() && instances_.find(cur) != instances_.end()) {
            active_file_ = cur;
        }
        if (active_file_.empty() && instances_.size() == 1) {
            active_file_ = instances_.begin()->first;
        }
    }

    mcp::json IdaRouter::GetCustomTools() const {
        return mcp::json::array({
            {
                {"name", "get_available_files"},
                {"description", "List all currently open binaries/IDBs across active IDA Pro instances and show active selection."},
                {"inputSchema", {
                    {"type", "object"},
                    {"properties", mcp::json::object()}
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
                            {"description", "Target binary filename (e.g. 'target.exe')"}
                        }}
                    }},
                    {"required", {"filename"}}
                }}
            }
        });
    }

    void IdaRouter::HandleInitialize(const mcp::json& req, const mcp::json& id) {
        std::string proto = req.value("params", mcp::json::object()).value("protocolVersion", mcp::constants::DEFAULT_PROTOCOL_VERSION);
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
        active_client_.Disconnect();
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
    }

    void IdaRouter::HandleToolsList(const mcp::json& req, const mcp::json& id) {
        mcp::json all_tools = GetCustomTools();

        // If an instance is active and not currently busy, try querying tools directly from plugin
        bool queried_from_instance = false;
        bool busy_now = false;
        {
            std::lock_guard<std::mutex> lock(status_mtx_);
            busy_now = is_busy_;
        }

        if (!busy_now && !active_file_.empty() && instances_.find(active_file_) != instances_.end()) {
            const auto& inst = instances_[active_file_];
            if (active_client_.Connect(inst.pipe_name, 2000)) {
                std::string resp;
                if (active_client_.Transact(req.dump(), resp, 5000)) {
                    try {
                        mcp::json parsed = mcp::json::parse(resp);
                        if (parsed.contains("result") && parsed["result"].contains("tools") && parsed["result"]["tools"].is_array()) {
                            for (const auto& t : parsed["result"]["tools"]) {
                                all_tools.push_back(t);
                            }
                            queried_from_instance = true;
                        }
                    } catch (...) {
                    }
                }
            }
        }

        // Fallback to default schema if not queried from instance
        if (!queried_from_instance) {
            const auto& default_tools = mcp::GetDefaultIdaToolsSchema();
            for (const auto& t : default_tools) {
                all_tools.push_back(t);
            }
        }

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

        mcp::json res = {
            {"status", "success"},
            {"active_file", active_file_.empty() ? nullptr : mcp::json(active_file_)},
            {"count", instances_.size()},
            {"files", files_arr},
            {"elapsed_sec", elapsed_sec}
        };
        mcp::StdioTransport::Send(mcp::MakeSuccessResponse(id, mcp::MakeToolCallResult(res.dump(2))));
    }

    void IdaRouter::HandleSwitchFile(const mcp::json& id, const mcp::json& args) {
        auto t0 = std::chrono::steady_clock::now();
        std::string target = args.value("filename", "");

        {
            std::lock_guard<std::mutex> lock(status_mtx_);
            if (is_busy_) {
                mcp::json res = {
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

        RefreshInstances();

        auto t1 = std::chrono::steady_clock::now();
        double elapsed_sec = std::round(std::chrono::duration<double>(t1 - t0).count() * 1000.0) / 1000.0;

        if (instances_.find(target) != instances_.end()) {
            active_client_.Disconnect();
            active_file_ = target;
            active_client_.Connect(instances_[target].pipe_name, 3000);

            mcp::json res = {
                {"status", "success"},
                {"active_file", target},
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
            mcp::json res = {
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
            RefreshInstances();
        }

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
            RefreshInstances();
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
                RefreshInstances();
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
        const std::string& payload_to_send = raw_tool_call.empty() ? req.dump() : raw_tool_call;

        // Perform persistent transaction (8-minute timeout)
        if (!active_client_.Transact(payload_to_send, pipe_resp, 480000)) {
            // Disconnect and refresh
            active_client_.Disconnect();
            RefreshInstances();

            mcp::json files_arr = mcp::json::array();
            for (const auto& kv : instances_) {
                files_arr.push_back(kv.first);
            }

            mcp::json err_res = {
                {"status", "error"},
                {"error_code", "instance_offline_or_crashed"},
                {"file", active_file_},
                {"message", "IDA Pro instance disconnected, crashed or exceeded 8-minute timeout"},
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
            parsed["id"] = id;
            mcp::StdioTransport::Send(parsed);
        } catch (...) {
            mcp::StdioTransport::Send(mcp::MakeSuccessResponse(
                id,
                mcp::MakeToolCallResult(pipe_resp)
            ));
        }
    }

    void IdaRouter::HandleGetStatus(const mcp::json& id) {
        std::lock_guard<std::mutex> lock(status_mtx_);
        mcp::json res = {
            {"status", "success"},
            {"busy", is_busy_}
        };

        if (is_busy_) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - active_tool_start_).count();
            res["active_file"] = active_file_.empty() ? nullptr : mcp::json(active_file_);
            if (!active_file_.empty() && instances_.find(active_file_) != instances_.end()) {
                res["pid"] = instances_[active_file_].pid;
            }
            res["current_tool"] = active_tool_;
            if (!active_tool_args_.empty()) {
                res["tool_args"] = active_tool_args_;
            }
            res["elapsed_ms"] = elapsed_ms;
            res["elapsed_sec"] = std::round(elapsed_ms / 10.0) / 100.0;
            res["message"] = "executing " + active_tool_;
        } else {
            if (active_file_.empty() || instances_.find(active_file_) == instances_.end()) {
                RefreshInstances();
            }
            if (!active_file_.empty() && instances_.find(active_file_) != instances_.end()) {
                const auto& inst = instances_[active_file_];
                if (ida::InstanceDiscovery::IsPidAlive(inst.pid)) {
                    res["active_file"] = active_file_;
                    res["pid"] = inst.pid;
                    res["message"] = "idle";
                } else {
                    active_client_.Disconnect();
                    RefreshInstances();
                    res["active_file"] = active_file_.empty() ? nullptr : mcp::json(active_file_);
                    res["message"] = active_file_.empty() ? "idle (no active IDA instance)" : "idle";
                }
            } else {
                res["active_file"] = nullptr;
                res["message"] = "idle (no active IDA instance, use get_available_files / switch_file)";
            }
        }

        mcp::StdioTransport::Send(mcp::MakeSuccessResponse(
            id,
            mcp::MakeToolCallResult(res.dump(2))
        ));
    }

    void IdaRouter::DispatchToolCallAsync(
        const mcp::json& req,
        const mcp::json& id,
        const std::string& raw_tool_call,
        const std::string& name,
        const mcp::json& args
    ) {
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

            if (worker_thread_.joinable()) {
                worker_thread_.join();
            }

            is_busy_ = true;
            active_tool_ = name;
            active_tool_args_ = (args.is_null() || args.empty()) ? "" : args.dump();
            if (active_tool_args_.size() > 200) {
                active_tool_args_ = active_tool_args_.substr(0, 197) + "...";
            }
            active_tool_start_ = std::chrono::steady_clock::now();
        }

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
    }

    void IdaRouter::HandleToolsCall(const mcp::json& req, const mcp::json& id, const std::string& raw_tool_call) {
        mcp::json params = req.value("params", mcp::json::object());
        std::string name = params.value("name", "");
        mcp::json args = params.value("arguments", mcp::json::object());

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

        try {
            mcp::json req = mcp::json::parse(raw_message);
            std::string method = req.value("method", "");
            auto id = req.contains("id") ? req["id"] : nlohmann::json(nullptr);

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
        } catch (...) {
            mcp::StdioTransport::Send(mcp::MakeErrorResponse(nullptr, -32700, "Parse error: Invalid JSON"));
        }
    }

    void IdaRouter::Run() {
        mcp::StdioTransport::RunLoop([this](const std::string& line) {
            ProcessMessage(line);
        });
    }
}
