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
    inline static thread_local PluginStatusTracker* current_tracker_ = nullptr;

public:
    PluginStatusTracker() = default;
    ~PluginStatusTracker() = default;

    static PluginStatusTracker& Instance() {
        if (current_tracker_) return *current_tracker_;
        static PluginStatusTracker tracker;
        return tracker;
    }

    class Scope {
    public:
        explicit Scope(PluginStatusTracker& tracker) : previous_(current_tracker_) {
            current_tracker_ = &tracker;
        }
        ~Scope() { current_tracker_ = previous_; }
        Scope(const Scope&) = delete;
        Scope& operator=(const Scope&) = delete;
    private:
        PluginStatusTracker* previous_;
    };

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

    void SetIdaVersion(const std::string& version) {
        std::lock_guard<std::mutex> lock(mtx_);
        ida_version_ = version;
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

    void Quarantine(nlohmann::json fault) {
        std::lock_guard<std::mutex> lock(mtx_);
        last_fault_ = std::move(fault);
        quarantined_.store(true, std::memory_order_release);
    }

    void ResetQuarantine() {
        std::lock_guard<std::mutex> lock(mtx_);
        quarantined_.store(false, std::memory_order_release);
        ++quarantine_resets_;
    }

    std::string GetCurrentTool() const {
        std::lock_guard<std::mutex> lock(mtx_);
        return current_tool_;
    }

    nlohmann::json GetStatusJson(const nlohmann::json& id, bool enabled = true) {
        std::lock_guard<std::mutex> lock(mtx_);
        bool busy = is_busy_.load(std::memory_order_acquire);
        nlohmann::json res = {
            {"busy", busy},
            {"enabled", enabled},
            {"ida_version", ida_version_}
        };
        if (quarantined_.load(std::memory_order_acquire)) res["quarantined"] = true;
        if (!last_fault_.is_null()) res["last_fault"] = last_fault_;
        if (quarantine_resets_ != 0) res["quarantine_resets"] = quarantine_resets_;

        if (busy) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_).count();
            res["current_tool"] = current_tool_;
            if (!args_summary_.empty()) {
                res["tool_args"] = args_summary_;
            }
            res["elapsed_seconds"] = elapsed_ms / 1000;
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
        }

        return tools::utils::MakeToolSuccessJson(id, res);
    }

private:
    PluginStatusTracker(const PluginStatusTracker&) = delete;
    PluginStatusTracker& operator=(const PluginStatusTracker&) = delete;

    mutable std::mutex mtx_;
    std::atomic<bool> is_busy_{false};
    std::atomic<bool> quarantined_{false};
    nlohmann::json last_fault_;
    uint64_t quarantine_resets_ = 0;
    std::string current_tool_;
    std::string ida_version_;
    std::string args_summary_;
    std::chrono::steady_clock::time_point start_time_;
    uint64_t current_step_{0};
    uint64_t total_steps_{0};
    std::string progress_message_;
};

} // namespace server
