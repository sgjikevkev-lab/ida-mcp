#include "pipe_client.h"
#include <vector>
#include <algorithm>
#include "shared/pipe_io.h"

namespace ipc {
    PipeClient::~PipeClient() {
        Disconnect();
        if (stop_event_) CloseHandle(stop_event_);
    }

    void PipeClient::Disconnect() {
        if (hPipe_ != INVALID_HANDLE_VALUE) {
            CloseHandle(hPipe_);
            hPipe_ = INVALID_HANDLE_VALUE;
        }
        current_pipe_.clear();
        leftover_.clear();
    }

    bool PipeClient::Connect(const std::wstring& pipe_name, DWORD timeout_ms) {
        if (IsConnected() && current_pipe_ == pipe_name) {
            return true;
        }
        Disconnect();
        if (!stop_event_ || WaitForSingleObject(stop_event_, 0) == WAIT_OBJECT_0) return false;

        DWORD start_time = GetTickCount();
        while (true) {
            HANDLE h = CreateFileW(
                pipe_name.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                nullptr
            );

            if (h != INVALID_HANDLE_VALUE) {
                hPipe_ = h;
                current_pipe_ = pipe_name;
                return true;
            }

            DWORD err = GetLastError();
            bool is_transient = (err == ERROR_PIPE_BUSY ||
                                 err == ERROR_FILE_NOT_FOUND ||
                                 err == ERROR_ACCESS_DENIED ||
                                 err == ERROR_BROKEN_PIPE ||
                                 err == ERROR_BAD_NETPATH ||
                                 err == ERROR_PIPE_NOT_CONNECTED);
            if (!is_transient) {
                return false;
            }

            DWORD elapsed = GetTickCount() - start_time;
            if (elapsed >= timeout_ms) {
                return false;
            }

            if (err != ERROR_PIPE_BUSY) {
                Sleep(20);
                continue;
            }

            DWORD wait_chunk = std::min<DWORD>(timeout_ms - elapsed, 200);
            if (!WaitNamedPipeW(pipe_name.c_str(), wait_chunk)) {
                Sleep(20);
            }
        }
    }

    bool PipeClient::Transact(const std::string& request_json, std::string& out_response, DWORD timeout_ms) {
        last_error_ = ERROR_SUCCESS;
        if (!IsConnected()) { last_error_ = ERROR_PIPE_NOT_CONNECTED; return false; }
        const ULONGLONG deadline = GetTickCount64() + timeout_ms;
        std::string payload = request_json;
        if (payload.empty() || payload.back() != '\n') payload += '\n';
        auto fail = [&] {
            last_error_ = GetLastError();
            Disconnect();
            return false;
        };
        if (payload.size() > mcp::limits::frame_bytes) { SetLastError(ERROR_BUFFER_OVERFLOW); return fail(); }
        if (!WriteFrame(hPipe_, payload, deadline, stop_event_)) return fail();
        while (true) {
            size_t newline = leftover_.find('\n');
            if (newline != std::string::npos) {
                out_response = leftover_.substr(0, newline);
                leftover_.erase(0, newline + 1);
                return true;
            }
            char buffer[8192];
            DWORD count = 0;
            if (!Transfer(hPipe_, false, buffer, sizeof(buffer), count, deadline, stop_event_)) return fail();
            if (!count) { SetLastError(ERROR_BROKEN_PIPE); return fail(); }
            leftover_.append(buffer, count);
            if (leftover_.size() > mcp::limits::frame_bytes) { SetLastError(ERROR_BUFFER_OVERFLOW); return fail(); }
        }
    }

    bool PipeClient::NotifyOnce(const std::wstring& pipe_name, const std::string& request_json) {
        PipeClient client;
        if (!client.Connect(pipe_name, 500)) return false;
        return WriteFrame(client.hPipe_, request_json + "\n", GetTickCount64() + 500);
    }

    bool PipeClient::CallOnce(
        const std::wstring& pipe_name,
        const std::string& request_json,
        std::string& out_response,
        DWORD timeout_ms
    ) {
        PipeClient client;
        if (!client.Connect(pipe_name, timeout_ms)) {
            return false;
        }
        return client.Transact(request_json, out_response, timeout_ms);
    }
}

