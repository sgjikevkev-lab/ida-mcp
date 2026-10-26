#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <cstdint>
#include <memory>
#include <vector>
#include "tools/tool_registry.h"
#include "dispatcher.h"

namespace server {
    class PipeServer {
    public:
        PipeServer();
        ~PipeServer();
        bool Start();
        void Stop();
        void SetEnabled(bool enabled);
        bool IsEnabled() const { return enabled_.load(std::memory_order_acquire); }
        std::wstring GetPipeName() const { return pipe_name_; }
    private:
        struct Client {
            std::thread thread;
            std::shared_ptr<std::atomic<bool>> done;
        };
        std::wstring pipe_name_;
        std::atomic<bool> running_{false};
        std::atomic<bool> enabled_{true};
        uint32_t pipe_slot_ = 0;
        std::thread server_thread_;
        std::vector<Client> clients_;
        std::shared_ptr<tools::ToolRegistry> tool_registry_;
        MainThreadDispatcher dispatcher_;
        nlohmann::json instance_info_;
        HANDLE shutdown_event_ = nullptr;
        void ServerLoop();
        void HandleClient(HANDLE pipe);
    };
}
