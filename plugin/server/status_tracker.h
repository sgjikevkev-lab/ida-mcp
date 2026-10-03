#pragma once
#include <string>
#include <mutex>
#include <chrono>
#include <atomic>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "tools/utils/utils.h"

namespace server {

class PluginStatusTracker {
public:
    static PluginStatusTracker& Instance() {
        static PluginStatusTracker tracker;
        return tracker;
    }

    void BeginTool(const std::string& tool, const std::string& args_summary = "") {
        std::lock_guard<std::mutex> lock(mtx_);
        current_tool_ = tool;
        args_summary_ = args_summary;
        start_time_ = std::chrono::steady_clock::now();
        current_step_ = 0;
        total_steps_ = 0;
        progress_message_.clear();
        is_busy_.store(true, std::memory_order_release);
    }

    void UpdateProgress(uint64_t current, uint64_t total, const std::string& msg = "") {
        std::lock_guard<std::mutex> lock(mtx_);
        current_step_ = current;
        total_steps_ = total;
        if (!msg.empty()) {
            progress_message_ = msg;
        }
    }

    void EndTool() {
        std::lock_guard<std::mutex> lock(mtx_);
        is_busy_.store(false, std::memory_order_release);
        current_tool_.clear();
        args_summary_.clear();
        current_step_ = 0;
        total_steps_ = 0;
        progress_message_.clear();
    }

    bool IsBusy() const {
        return is_busy_.load(std::memory_order_acquire);
    }

    std::string GetCurrentTool() const {
        std::lock_guard<std::mutex> lock(mtx_);
        return current_tool_;
    }

    nlohmann::json GetStatusJson(const nlohmann::json& id) {
        std::lock_guard<std::mutex> lock(mtx_);
        bool busy = is_busy_.load(std::memory_order_acquire);
        nlohmann::json res = {
            {"status", "success"},
            {"busy", busy}
        };

        if (busy) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_).count();
            res["current_tool"] = current_tool_;
            if (!args_summary_.empty()) {
                res["tool_args"] = args_summary_;
            }
            res["elapsed_ms"] = elapsed_ms;
            res["elapsed_sec"] = elapsed_ms / 1000.0;
            if (total_steps_ > 0) {
                res["progress"] = {
                    {"current", current_step_},
                    {"total", total_steps_},
                    {"percentage", (current_step_ * 100) / total_steps_}
                };
            }
            if (!progress_message_.empty()) {
                res["message"] = progress_message_;
            } else {
                res["message"] = "executing " + current_tool_;
            }
        } else {
            res["message"] = "idle";
        }

        return tools::utils::MakeToolSuccessJson(id, res);
    }

private:
    PluginStatusTracker() = default;
    ~PluginStatusTracker() = default;
    PluginStatusTracker(const PluginStatusTracker&) = delete;
    PluginStatusTracker& operator=(const PluginStatusTracker&) = delete;

    mutable std::mutex mtx_;
    std::atomic<bool> is_busy_{false};
    std::string current_tool_;
    std::string args_summary_;
    std::chrono::steady_clock::time_point start_time_;
    uint64_t current_step_{0};
    uint64_t total_steps_{0};
    std::string progress_message_;
};

} // namespace server
