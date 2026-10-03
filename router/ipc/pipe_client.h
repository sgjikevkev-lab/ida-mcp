#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>

namespace ipc {
    class PipeClient {
    public:
        PipeClient() = default;
        ~PipeClient();

        bool Connect(const std::wstring& pipe_name, DWORD timeout_ms = 5000);
        void Disconnect();
        bool IsConnected() const { return hPipe_ != INVALID_HANDLE_VALUE; }

        bool Transact(const std::string& request_json, std::string& out_response, DWORD timeout_ms = 480000);

        static bool CallOnce(
            const std::wstring& pipe_name,
            const std::string& request_json,
            std::string& out_response,
            DWORD timeout_ms = 5000
        );

    private:
        HANDLE hPipe_ = INVALID_HANDLE_VALUE;
        std::wstring current_pipe_;
        std::string leftover_;
    };
}

