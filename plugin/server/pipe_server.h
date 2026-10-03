#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include "tools/tool_registry.h"

namespace server {
    class PipeServer {
    public:
        PipeServer();
        ~PipeServer();

        bool Start();
        void Stop();
        std::wstring GetPipeName() const { return pipe_name_; }

    private:
        std::wstring pipe_name_;
        std::atomic<bool> running_{false};
        std::thread server_thread_;
        std::unique_ptr<tools::ToolRegistry> tool_registry_;
        HANDLE shutdown_event_ = NULL;

        void ServerLoop();
        void HandleClient(HANDLE hPipe);
    };
}

