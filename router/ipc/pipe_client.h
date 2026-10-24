#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include "shared/runtime_limits.h"

namespace ipc {
    class PipeClient {
    public:
        PipeClient() : stop_event_(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {}
        void Cancel() { if (stop_event_) SetEvent(stop_event_); }
        DWORD LastError() const { return last_error_; }
        ~PipeClient();

        bool Connect(const std::wstring& pipe_name, DWORD timeout_ms = 5000);
        void Disconnect();
        bool IsConnected() const { return hPipe_ != INVALID_HANDLE_VALUE; }
        const std::wstring& GetCurrentPipe() const { return current_pipe_; }

        bool Transact(const std::string& request_json, std::string& out_response, DWORD timeout_ms = mcp::limits::operation_ms);
        static bool NotifyOnce(const std::wstring& pipe_name, const std::string& request_json);

        static bool CallOnce(
            const std::wstring& pipe_name,
            const std::string& request_json,
            std::string& out_response,
            DWORD timeout_ms = 5000
        );

    private:
        HANDLE stop_event_ = nullptr;
        DWORD last_error_ = ERROR_SUCCESS;
        HANDLE hPipe_ = INVALID_HANDLE_VALUE;
        std::wstring current_pipe_;
        std::string leftover_;
    };
}

