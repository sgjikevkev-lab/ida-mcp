#include "pipe_client.h"
#include <vector>
#include <algorithm>

namespace ipc {
    PipeClient::~PipeClient() {
        Disconnect();
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
        if (!IsConnected()) return false;

        std::string payload = request_json;
        if (payload.empty() || payload.back() != '\n') {
            payload.push_back('\n');
        }

        // Overlapped Write
        OVERLAPPED ov_write{};
        ov_write.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov_write.hEvent) return false;

        DWORD written = 0;
        BOOL write_ok = WriteFile(hPipe_, payload.data(), static_cast<DWORD>(payload.size()), &written, &ov_write);
        if (!write_ok) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                DWORD wait_res = WaitForSingleObject(ov_write.hEvent, timeout_ms);
                if (wait_res != WAIT_OBJECT_0) {
                    CancelIo(hPipe_);
                    CloseHandle(ov_write.hEvent);
                    Disconnect();
                    return false;
                }
                GetOverlappedResult(hPipe_, &ov_write, &written, FALSE);
            } else {
                CloseHandle(ov_write.hEvent);
                Disconnect();
                return false;
            }
        }
        CloseHandle(ov_write.hEvent);

        // Check if leftover_ already has a complete line
        size_t existing_nl = leftover_.find('\n');
        if (existing_nl != std::string::npos) {
            out_response = leftover_.substr(0, existing_nl);
            leftover_.erase(0, existing_nl + 1);
            while (!out_response.empty() && (out_response.back() == '\r' || out_response.back() == ' ')) {
                out_response.pop_back();
            }
            return true;
        }

        // Overlapped Read until newline in leftover_
        out_response.clear();
        char buf[8192];

        OVERLAPPED ov_read{};
        ov_read.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov_read.hEvent) return false;

        DWORD start_time = GetTickCount();

        while (true) {
            DWORD elapsed = GetTickCount() - start_time;
            if (elapsed >= timeout_ms) {
                CancelIo(hPipe_);
                CloseHandle(ov_read.hEvent);
                Disconnect();
                return false;
            }
            DWORD remaining_time = timeout_ms - elapsed;

            ResetEvent(ov_read.hEvent);
            DWORD bytes_read = 0;
            BOOL read_ok = ReadFile(hPipe_, buf, sizeof(buf), &bytes_read, &ov_read);

            if (!read_ok) {
                DWORD err = GetLastError();
                if (err == ERROR_IO_PENDING) {
                    DWORD wait_res = WaitForSingleObject(ov_read.hEvent, remaining_time);
                    if (wait_res != WAIT_OBJECT_0) {
                        CancelIo(hPipe_);
                        CloseHandle(ov_read.hEvent);
                        Disconnect();
                        return false;
                    }
                    if (!GetOverlappedResult(hPipe_, &ov_read, &bytes_read, FALSE)) {
                        CloseHandle(ov_read.hEvent);
                        Disconnect();
                        return false;
                    }
                } else {
                    // Pipe broken (IDA crashed or disconnected)
                    CloseHandle(ov_read.hEvent);
                    Disconnect();
                    return false;
                }
            }

            if (bytes_read == 0) {
                // EOF / pipe closed
                CloseHandle(ov_read.hEvent);
                Disconnect();
                return false;
            }

            leftover_.append(buf, bytes_read);

            size_t nl = leftover_.find('\n');
            if (nl != std::string::npos) {
                out_response = leftover_.substr(0, nl);
                leftover_.erase(0, nl + 1);
                while (!out_response.empty() && (out_response.back() == '\r' || out_response.back() == ' ')) {
                    out_response.pop_back();
                }
                break;
            }
        }

        CloseHandle(ov_read.hEvent);
        return true;
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

