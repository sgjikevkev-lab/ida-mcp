#include "pipe_server.h"
#include "shared/pipe_io.h"
#include "shared/json_parse.h"
#include <nalt.hpp>
#include <loader.hpp>

namespace server {
    PipeServer::PipeServer() : tool_registry_(std::make_shared<tools::ToolRegistry>()) {}
    PipeServer::~PipeServer() { Stop(); }

    bool PipeServer::Start() {
        if (running_.load()) return true;
        char binary[QMAXPATH] = {};
        get_root_filename(binary, sizeof(binary));
        const char* path = get_path(PATH_TYPE_IDB);
        instance_info_ = {{"pid", GetCurrentProcessId()}, {"binary", binary},
                          {"idb_path", path ? path : ""}, {"backend", "gui"}};
        pipe_name_ = L"\\\\.\\pipe\\ida_mcp_" + std::to_wstring(GetCurrentProcessId());
        shutdown_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!shutdown_event_) return false;
        try {
            clients_.reserve(16);
            running_.store(true);
            server_thread_ = std::thread([this] {
                try { ServerLoop(); }
                catch (...) {
                    SetEvent(shutdown_event_);
                    for (auto& client : clients_) if (client.thread.joinable()) client.thread.join();
                    clients_.clear();
                }
            });
        } catch (...) {
            running_.store(false);
            CloseHandle(shutdown_event_);
            shutdown_event_ = nullptr;
            return false;
        }
        msg("[IDA MCP] Named pipe server started\n");
        return true;
    }

    void PipeServer::Stop() {
        if (!running_.exchange(false)) return;
        SetEvent(shutdown_event_);
        if (server_thread_.joinable()) server_thread_.join();
        dispatcher_.Stop();
        CloseHandle(shutdown_event_);
        shutdown_event_ = nullptr;
    }

    void PipeServer::ServerLoop() {
        while (running_.load()) {
            for (auto it = clients_.begin(); it != clients_.end();) {
                if (it->done->load(std::memory_order_acquire)) {
                    it->thread.join();
                    it = clients_.erase(it);
                } else ++it;
            }
            if (clients_.size() >= 16) {
                WaitForSingleObject(shutdown_event_, 50);
                continue;
            }
            HANDLE pipe = CreateNamedPipeW(pipe_name_.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                16, 65536, 65536, 0, nullptr);
            if (pipe == INVALID_HANDLE_VALUE) {
                WaitForSingleObject(shutdown_event_, 50);
                continue;
            }
            OVERLAPPED ov{};
            ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!ov.hEvent) { CloseHandle(pipe); break; }
            bool connected = ConnectNamedPipe(pipe, &ov) != FALSE;
            const DWORD error = connected ? ERROR_SUCCESS : GetLastError();
            if (error == ERROR_PIPE_CONNECTED) connected = true;
            else if (error == ERROR_IO_PENDING) {
                HANDLE events[] = {ov.hEvent, shutdown_event_};
                const DWORD wr = WaitForMultipleObjects(2, events, FALSE, INFINITE);
                DWORD transferred = 0;
                if (wr == WAIT_OBJECT_0)
                    connected = GetOverlappedResult(pipe, &ov, &transferred, FALSE) != FALSE;
                else {
                    CancelIoEx(pipe, &ov);
                    GetOverlappedResult(pipe, &ov, &transferred, TRUE);
                }
            }
            CloseHandle(ov.hEvent);
            if (!connected || !running_.load()) { CloseHandle(pipe); continue; }
            auto done = std::make_shared<std::atomic<bool>>(false);
            clients_.push_back({std::thread([this, pipe, done] {
                try { HandleClient(pipe); } catch (...) { /* close the client, never unwind a thread */ }
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
                done->store(true, std::memory_order_release);
            }), done});
        }
        for (auto& client : clients_) client.thread.join();
        clients_.clear();
    }

    void PipeServer::HandleClient(HANDLE pipe) {
        std::string input;
        std::shared_ptr<ToolJob> pending;
        auto send = [&](const std::string& response) {
            return ipc::WriteFrame(pipe, response + "\n", GetTickCount64() + 5000, shutdown_event_);
        };
        auto error = [&](const nlohmann::json& id, const std::string& message, const std::string& code) {
            return send(tools::utils::MakeToolErrorJson(id, message, code).dump());
        };
        while (running_.load()) {
            if (pending) {
                if (pending->done.load(std::memory_order_acquire)) {
                    if (!send(pending->response)) break;
                    pending.reset();
                } else if (std::chrono::steady_clock::now() >= pending->operation.deadline) {
                    dispatcher_.Abandon(pending);
                    if (!error(pending->id,
                        "30-minute limit exceeded; cancellation requested. Backend stays busy until execution stops.",
                        "execution_timeout")) break;
                    pending.reset();
                }
            }
            char buffer[8192];
            DWORD bytes = 0;
            if (!ipc::Transfer(pipe, false, buffer, sizeof(buffer), bytes, GetTickCount64() + 100, shutdown_event_)) {
                if (GetLastError() == ERROR_TIMEOUT) continue;
                break;
            }
            if (bytes == 0) break;
            input.append(buffer, bytes);
            if (input.size() > mcp::limits::frame_bytes) {
                error(nullptr, "Request exceeds 32 MiB", "payload_too_large");
                break;
            }
            size_t newline;
            while ((newline = input.find('\n')) != std::string::npos) {
                std::string line = input.substr(0, newline);
                input.erase(0, newline + 1);
                if (line.empty()) continue;
                auto request = mcp::TryParseBoundedJson(line);
                if (request.is_discarded()) {
                    if (!send(nlohmann::json({{"jsonrpc", "2.0"}, {"id", nullptr},
                        {"error", {{"code", -32700}, {"message", "Invalid JSON"}}}}).dump())) return;
                    continue;
                }
                if (!request.is_object()) {
                    if (!error(nullptr, "Request must be an object", "invalid_request")) return;
                    continue;
                }
                const auto id = request.value("id", nlohmann::json(nullptr));
                const std::string method = tools::utils::GetStringArg(request, "method");
                if (method == "notifications/cancelled") {
                    auto params = request.value("params", nlohmann::json::object());
                    if (pending && params.is_object() && params.value("requestId", nlohmann::json(nullptr)) == pending->id)
                        pending->operation.cancelled.store(true, std::memory_order_release);
                    continue;
                }
                if (method == "ida/cancel") {
                    const auto params = request.value("params", nlohmann::json::object());
                    if (params.is_object()) dispatcher_.Cancel(params.value("requestId", nlohmann::json(nullptr)),
                        tools::utils::GetStringArg(params, "token"));
                    continue;
                }
                if (!request.contains("id")) continue;
                if (method == "get_instance_info" || method == "ida/info") {
                    if (!send(nlohmann::json({{"jsonrpc", "2.0"}, {"id", id}, {"result", instance_info_}}).dump())) return;
                    continue;
                }
                if (method != "tools/call") {
                    if (!send(tool_registry_->HandleRequest(line))) return;
                    continue;
                }
                const auto params = request.value("params", nlohmann::json::object());
                if (!params.is_object()) {
                    if (!error(id, "params must be an object", "invalid_params")) return;
                    continue;
                }
                const std::string name = tools::utils::GetStringArg(params, "name");
                if (name == "get_status") {
                    if (!send(PluginStatusTracker::Instance().GetStatusJson(id).dump())) return;
                    continue;
                }
                if (pending) {
                    if (!error(id, "A tool is already running; use get_status", "busy")) return;
                    continue;
                }
                if (dispatcher_.Quarantined()) {
                    if (!error(id, "Backend quarantined after a native fault; restart IDA", "backend_quarantined")) return;
                    continue;
                }
                auto registry = tool_registry_;
                pending = dispatcher_.Submit(id, name, [registry, line] { return registry->HandleRequest(line); },
                    tools::utils::GetStringArg(request, "_cancel_token"));
                if (!pending && !error(id, "IDA is busy; use get_status", "busy")) return;
            }
        }
        if (pending) dispatcher_.Abandon(pending);
    }
}
