#pragma once
#include <iostream>
#include <string>
#include <functional>
#include <mutex>
#pragma warning(push, 0)
#pragma warning(disable: 26819 26495 26812 26451 6001 6011)
#include "!ibs/json.h"
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
            std::string s = j.dump();
            std::lock_guard<std::mutex> lock(CoutMutex());
            std::cout << s << "\n" << std::flush;
        }

        static void SendRaw(const std::string& raw) {
            std::lock_guard<std::mutex> lock(CoutMutex());
            std::cout << raw << "\n" << std::flush;
        }

        static void RunLoop(const MessageHandler& on_message) {
            std::string line;
            while (std::getline(std::cin, line)) {
                if (!line.empty()) {
                    on_message(line);
                }
            }
        }
    };
}
