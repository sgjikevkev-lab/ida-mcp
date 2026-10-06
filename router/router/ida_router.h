#pragma once
#include <map>
#include <string>
#include <mutex>
#include <thread>
#include <chrono>
#include "ida/instance.h"
#include "ipc/pipe_client.h"
#include "mcp/protocol.h"

namespace router {
    class IdaRouter {
    public:
        IdaRouter() = default;
        ~IdaRouter();

        void RefreshInstances(bool force = false);
        void ProcessMessage(const std::string& raw_message);
        void Run();

    private:
        mcp::json GetCustomTools() const;
        void HandleInitialize(const mcp::json& req, const mcp::json& id);
        void HandleToolsList(const mcp::json& req, const mcp::json& id);
        void HandleToolsCall(const mcp::json& req, const mcp::json& id, const std::string& raw_tool_call);
        void HandleGetStatus(const mcp::json& id);
        void HandleGetAvailableFiles(const mcp::json& id);
        void HandleSwitchFile(const mcp::json& id, const mcp::json& args);
        void DispatchToolCallAsync(
            const mcp::json& req,
            const mcp::json& id,
            const std::string& raw_tool_call,
            const std::string& name,
            const mcp::json& args
        );
        void ForwardToolCall(const mcp::json& req, const mcp::json& id, const std::string& raw_tool_call);

        std::map<std::string, ida::IdaInstance> instances_;
        std::string active_file_;
        ipc::PipeClient active_client_;

        std::mutex status_mtx_;
        bool is_busy_{false};
        std::string active_tool_;
        std::string active_tool_args_;
        std::chrono::steady_clock::time_point active_tool_start_;
        std::chrono::steady_clock::time_point last_discovery_time_{};
        std::thread worker_thread_;
    };
}
