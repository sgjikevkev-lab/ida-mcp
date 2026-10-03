#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <vector>
#include <algorithm>

#include "pipe_server.h"
#include "status_tracker.h"
#include "discovery/registration.h"
#include "sync/sync.h"
#include "tools/utils/utils.h"

#include <ida.hpp>
#include <nalt.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

namespace server {

    namespace {
        constexpr size_t MAX_ACCUMULATED = 32 * 1024 * 1024; // 32 MB buffer cap

        bool IsWriteTool(const std::string& name) {
            return name == "idb_save" ||
                   name == "rename" ||
                   name == "set_type" ||
                   name == "set_comment" ||
                   name == "rename_lvar" ||
                   name == "set_lvar_type" ||
                   name == "recompile" ||
                   name == "declare_type" ||
                   name == "rtti_create_struct" ||
                   name == "py";
        }

        bool WriteToPipe(HANDLE hPipe, const std::string& data) {
            const char* ptr = data.data();
            size_t remaining = data.size();
            while (remaining > 0) {
                DWORD to_write = static_cast<DWORD>(std::min<size_t>(remaining, 65536));
                DWORD written = 0;
                if (!WriteFile(hPipe, ptr, to_write, &written, nullptr) || written == 0) {
                    return false;
                }
                ptr += written;
                remaining -= written;
            }
            return true;
        }

        nlohmann::json QueryInstanceInfo(const nlohmann::json& id) {
            char root_fn[QMAXPATH] = {0};
            char idb_path[QMAXPATH] = {0};

            sync::SyncRead([&]() {
                get_root_filename(root_fn, sizeof(root_fn));
                qstrncpy(idb_path, get_path(PATH_TYPE_IDB), sizeof(idb_path));
            });

            return nlohmann::json({
                {"jsonrpc", "2.0"},
                {"id", id},
                {"result", {
                    {"pid", GetCurrentProcessId()},
                    {"binary", std::string(root_fn)},
                    {"idb_path", std::string(idb_path)},
                    {"backend", "gui"}
                }}
            });
        }

        struct tool_exec_request_t : public exec_request_t {
            std::function<void()> work;
            HANDLE hEvent = NULL;
            DWORD exception_code = 0;
            std::atomic<bool> done{false};
            std::atomic<bool> abandoned{false};

            tool_exec_request_t(std::function<void()> w) : work(std::move(w)) {
                hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
            }

            virtual ~tool_exec_request_t() {
                if (hEvent) {
                    CloseHandle(hEvent);
                    hEvent = NULL;
                }
            }

            virtual ssize_t idaapi execute() override {
                if (!abandoned.load()) {
                    try {
                        work();
                    } catch (...) {
                        exception_code = 0xE06D7363;
                    }
                }
                done.store(true);
                if (hEvent) {
                    SetEvent(hEvent);
                }
                if (abandoned.load()) {
                    delete this;
                }
                return 0;
            }
        };
    } // anonymous namespace

    PipeServer::PipeServer() {
        tool_registry_ = std::make_unique<tools::ToolRegistry>();
    }

    PipeServer::~PipeServer() {
        Stop();
    }

    bool PipeServer::Start() {
        DWORD pid = GetCurrentProcessId();
        pipe_name_ = L"\\\\.\\pipe\\ida_mcp_" + std::to_wstring(pid);

        shutdown_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!shutdown_event_) return false;

        running_ = true;
        server_thread_ = std::thread([this]() {
            ServerLoop();
        });

        msg("[IDA MCP] Native Named Pipe server listening on \\\\.\\pipe\\ida_mcp_%lu\n", pid);
        return true;
    }

    void PipeServer::Stop() {
        if (!running_) return;
        running_ = false;

        if (shutdown_event_) {
            SetEvent(shutdown_event_);
        }

        // Connect dummy client to wake up any blocked ConnectNamedPipe
        HANDLE hDummy = CreateFileW(
            pipe_name_.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );
        if (hDummy != INVALID_HANDLE_VALUE) {
            CloseHandle(hDummy);
        }

        if (server_thread_.joinable()) {
            server_thread_.join();
        }

        if (shutdown_event_) {
            CloseHandle(shutdown_event_);
            shutdown_event_ = NULL;
        }
    }

    void PipeServer::ServerLoop() {
        while (running_) {
            OVERLAPPED ov{};
            ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!ov.hEvent) break;

            SECURITY_DESCRIPTOR sd;
            InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
            SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);
            SECURITY_ATTRIBUTES sa{};
            sa.nLength = sizeof(sa);
            sa.lpSecurityDescriptor = &sd;
            sa.bInheritHandle = FALSE;

            HANDLE hPipe = CreateNamedPipeW(
                pipe_name_.c_str(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                0,
                &sa
            );

            if (hPipe == INVALID_HANDLE_VALUE) {
                CloseHandle(ov.hEvent);
                if (!running_) break;
                Sleep(50);
                continue;
            }

            BOOL connect_res = ConnectNamedPipe(hPipe, &ov);
            DWORD err = GetLastError();

            if (!connect_res) {
                if (err == ERROR_IO_PENDING) {
                    HANDLE events[2] = { ov.hEvent, shutdown_event_ };
                    DWORD wait_res = WaitForMultipleObjects(2, events, FALSE, INFINITE);
                    if (wait_res != WAIT_OBJECT_0) {
                        CancelIo(hPipe);
                        CloseHandle(ov.hEvent);
                        CloseHandle(hPipe);
                        break;
                    }
                } else if (err != ERROR_PIPE_CONNECTED) {
                    CloseHandle(ov.hEvent);
                    CloseHandle(hPipe);
                    if (!running_) break;
                    continue;
                }
            }

            CloseHandle(ov.hEvent);

            if (!running_) {
                CloseHandle(hPipe);
                break;
            }

            // Handle client connection directly on this server thread
            HandleClient(hPipe);
        }
    }

    void PipeServer::HandleClient(HANDLE hPipe) {
        std::string accumulated;
        char buffer[8192];

        while (running_) {
            OVERLAPPED ov_read{};
            ov_read.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!ov_read.hEvent) break;

            DWORD bytes_read = 0;
            BOOL read_ok = ReadFile(hPipe, buffer, sizeof(buffer), &bytes_read, &ov_read);
            DWORD r_err = GetLastError();

            if (!read_ok) {
                if (r_err == ERROR_IO_PENDING) {
                    HANDLE wait_evts[2] = { ov_read.hEvent, shutdown_event_ };
                    DWORD wr = WaitForMultipleObjects(2, wait_evts, FALSE, INFINITE);
                    if (wr != WAIT_OBJECT_0) {
                        CancelIo(hPipe);
                        CloseHandle(ov_read.hEvent);
                        break;
                    }
                    if (!GetOverlappedResult(hPipe, &ov_read, &bytes_read, FALSE)) {
                        CloseHandle(ov_read.hEvent);
                        break;
                    }
                } else {
                    CloseHandle(ov_read.hEvent);
                    break;
                }
            }
            CloseHandle(ov_read.hEvent);

            if (bytes_read == 0) {
                break; // Client disconnected
            }

            if (accumulated.size() + bytes_read > MAX_ACCUMULATED) {
                accumulated.clear();
                std::string err_resp = tools::utils::MakeToolErrorJson(
                    nullptr,
                    "Payload exceeded 32 MB safety limit",
                    "payload_too_large"
                ).dump() + "\n";
                WriteToPipe(hPipe, err_resp);
                continue;
            }

            accumulated.append(buffer, bytes_read);

            size_t newline_pos;
            while ((newline_pos = accumulated.find('\n')) != std::string::npos) {
                std::string line = accumulated.substr(0, newline_pos);
                accumulated.erase(0, newline_pos + 1);

                while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) {
                    line.pop_back();
                }
                if (line.empty()) continue;

                nlohmann::json req;
                try {
                    req = nlohmann::json::parse(line);
                } catch (...) {
                    std::string err_resp = nlohmann::json({
                        {"jsonrpc", "2.0"},
                        {"id", nullptr},
                        {"error", {{"code", -32700}, {"message", "Parse error: Invalid JSON"}}}
                    }).dump() + "\n";
                    WriteToPipe(hPipe, err_resp);
                    continue;
                }

                std::string method = req.value("method", "");
                auto id = req.value("id", nlohmann::json(nullptr));

                if (method == "get_instance_info" || method == "ida/info") {
                    std::string resp = QueryInstanceInfo(id).dump() + "\n";
                    WriteToPipe(hPipe, resp);
                    continue;
                }

                if (method == "initialize" || method == "tools/list" || method == "ping") {
                    std::string resp = tool_registry_->HandleRequest(line) + "\n";
                    WriteToPipe(hPipe, resp);
                    continue;
                }

                if (method == "tools/call") {
                    nlohmann::json params = req.value("params", nlohmann::json::object());
                    std::string name = params.value("name", "");
                    nlohmann::json args = params.value("arguments", nlohmann::json::object());

                    if (name == "get_status") {
                        std::string resp = PluginStatusTracker::Instance().GetStatusJson(id).dump() + "\n";
                        WriteToPipe(hPipe, resp);
                        continue;
                    }

                    // Dispatch tool execution to IDA's main thread
                    std::string summary = args.empty() ? "" : args.dump();
                    if (summary.size() > 200) {
                        summary = summary.substr(0, 197) + "...";
                    }
                    PluginStatusTracker::Instance().BeginTool(name, summary);

                    std::string response_json;
                    auto* exec_req = new tool_exec_request_t([&]() {
                        try {
                            response_json = tool_registry_->HandleRequest(line);
                        } catch (const std::exception& e) {
                            response_json = tools::utils::MakeToolErrorJson(id, std::string("Internal error: ") + e.what(), "internal_error").dump();
                        } catch (...) {
                            response_json = tools::utils::MakeToolErrorJson(id, "Unknown internal exception", "internal_error").dump();
                        }
                    });

                    int reqf = IsWriteTool(name) ? MFF_WRITE : MFF_READ;
                    ssize_t req_id = execute_sync(*exec_req, reqf | MFF_NOWAIT);

                    // Wait for completion while servicing any concurrent get_status requests
                    while (!exec_req->done.load() && running_) {
                        OVERLAPPED ov_status{};
                        ov_status.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
                        char s_buf[4096];
                        DWORD s_bytes = 0;
                        BOOL s_read_ok = ReadFile(hPipe, s_buf, sizeof(s_buf), &s_bytes, &ov_status);
                        DWORD s_err = GetLastError();

                        if (!s_read_ok && s_err != ERROR_IO_PENDING) {
                            CloseHandle(ov_status.hEvent);
                            WaitForSingleObject(exec_req->hEvent, INFINITE);
                            delete exec_req;
                            PluginStatusTracker::Instance().EndTool();
                            goto client_disconnected;
                        }

                        HANDLE wait_arr[3] = { shutdown_event_, exec_req->hEvent, ov_status.hEvent };
                        DWORD wr = WaitForMultipleObjects(3, wait_arr, FALSE, INFINITE);

                        if (wr == WAIT_OBJECT_0) {
                            // Server shutdown requested
                            CancelIo(hPipe);
                            CloseHandle(ov_status.hEvent);
                            cancel_exec_request(static_cast<int>(req_id));
                            exec_req->abandoned.store(true);
                            PluginStatusTracker::Instance().EndTool();
                            goto client_disconnected;
                        } else if (wr == WAIT_OBJECT_0 + 1) {
                            // Tool finished!
                            CancelIo(hPipe);
                            CloseHandle(ov_status.hEvent);
                            break;
                        } else if (wr == WAIT_OBJECT_0 + 2) {
                            // Pipe input arrived while IDA is busy
                            if (s_err == ERROR_IO_PENDING) {
                                GetOverlappedResult(hPipe, &ov_status, &s_bytes, FALSE);
                            }
                            CloseHandle(ov_status.hEvent);

                            if (s_bytes > 0) {
                                accumulated.append(s_buf, s_bytes);
                                size_t nl_p;
                                while ((nl_p = accumulated.find('\n')) != std::string::npos) {
                                    std::string s_line = accumulated.substr(0, nl_p);
                                    accumulated.erase(0, nl_p + 1);
                                    while (!s_line.empty() && (s_line.back() == '\r' || s_line.back() == ' ')) s_line.pop_back();
                                    if (s_line.empty()) continue;

                                    try {
                                        nlohmann::json s_req = nlohmann::json::parse(s_line);
                                        auto s_id = s_req.value("id", nlohmann::json(nullptr));
                                        std::string s_method = s_req.value("method", "");
                                        std::string s_tool = "";
                                        if (s_req.contains("params") && s_req["params"].contains("name")) {
                                            s_tool = s_req["params"]["name"].get<std::string>();
                                        }

                                        if (s_tool == "get_status") {
                                            std::string st_resp = PluginStatusTracker::Instance().GetStatusJson(s_id).dump() + "\n";
                                            WriteToPipe(hPipe, st_resp);
                                        } else {
                                            std::string busy_resp = tools::utils::MakeToolErrorJson(
                                                s_id,
                                                "IDA is busy executing tool '" + name + "'. Current progress can be checked with 'get_status'.",
                                                "busy"
                                            ).dump() + "\n";
                                            WriteToPipe(hPipe, busy_resp);
                                        }
                                    } catch (...) {
                                    }
                                }
                            }
                        }
                    }

                    delete exec_req;
                    PluginStatusTracker::Instance().EndTool();

                    response_json += "\n";
                    WriteToPipe(hPipe, response_json);
                    continue;
                }

                // Any other method
                std::string resp = tool_registry_->HandleRequest(line) + "\n";
                WriteToPipe(hPipe, resp);
            }
        }

    client_disconnected:
        FlushFileBuffers(hPipe);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}
