#pragma once
#include <iostream>
#include <string>
#include <functional>
#include <mutex>
#include "shared/runtime_limits.h"
#pragma warning(push, 0)
#pragma warning(disable: 26819 26495 26812 26451 6001 6011)
#include "shared/json.h"
#pragma warning(pop)


namespace mcp {
    class StdioTransport {
    private:
        static std::mutex& CoutMutex() {
            static std::mutex mtx;
            return mtx;
        }

    public:
        using MessageHandler = std::function<void(const std::string&)>;

        static void Send(const nlohmann::json& j) {
            std::string s = j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
            std::lock_guard<std::mutex> lock(CoutMutex());
            std::cout << s << "\n" << std::flush;
        }

        static void RunLoop(const MessageHandler& on_message) {
            std::string line;
            bool oversized = false;
            auto* buffer = std::cin.rdbuf();
            for (int ch; (ch = buffer->sbumpc()) != std::char_traits<char>::eof();) {
                if (ch == '\n') {
                    if (oversized) Send({{"jsonrpc", "2.0"}, {"id", nullptr},
                        {"error", {{"code", -32600}, {"message", "Request exceeds 32 MiB"}}}});
                    else if (!line.empty()) on_message(line);
                    line.clear();
                    oversized = false;
                } else if (!oversized) {
                    if (line.size() >= limits::frame_bytes) { line.clear(); oversized = true; }
                    else line += static_cast<char>(ch);
                }
            }
            if (!oversized && !line.empty()) on_message(line);
        }
    };
}
