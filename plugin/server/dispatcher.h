#pragma once
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>
#include <map>
#include <sstream>
#include <excpt.h>
#include <ida.hpp>
#include <kernwin.hpp>
#include "sync/sync.h"
#include "status_tracker.h"
#include "sync/cache_manager.h"

namespace server {
    // batch mode handles IDA's standard unattended behavior, but ui_ask_file
    // can still reach the UI dispatcher. Return an empty, IDA-allocated path
    // for that request while a non-Python MCP operation is active.
    class UnattendedUiScope {
        std::atomic<bool> active_{false};
        bool enabled_ = false;
        bool hooked_ = false;
        bool previous_batch_ = false;

        static ssize_t idaapi BlockModalUi(void* user_data, int notification_code, va_list) {
            auto* scope = static_cast<UnattendedUiScope*>(user_data);
            if (!scope || !scope->active_.load(std::memory_order_acquire)) return 0;
            if (notification_code != ui_ask_file) return 0;
            // A nonzero HT_UI return value becomes the callui() result. For
            // ui_ask_file that result is a char*, so return a valid empty
            // string rather than an integer sentinel (which can crash callers).
            return reinterpret_cast<ssize_t>(qstrdup(""));
        }

    public:
        explicit UnattendedUiScope(bool enabled) {
            if (!enabled) return;
            enabled_ = true;
            previous_batch_ = batch;
            batch = true;
            active_.store(true, std::memory_order_release);
            hooked_ = hook_to_notification_point(HT_UI, BlockModalUi, this);
            if (!hooked_) {
                active_.store(false, std::memory_order_release);
                batch = previous_batch_;
            }
        }

        ~UnattendedUiScope() {
            if (!enabled_) return;
            active_.store(false, std::memory_order_release);
            if (hooked_) unhook_from_notification_point(HT_UI, BlockModalUi, this);
            batch = previous_batch_;
        }

        bool IsActive() const { return hooked_; }
    };

    struct ToolJob {
        sync::Operation operation;
        std::atomic<bool> done{false};
        std::atomic<bool> started{false};
        nlohmann::json id;
        std::string name;
        std::string cancel_token;
        nlohmann::json diagnostic_arguments = nlohmann::json::object();
        std::function<std::string()> work;
        std::string response;
    };

    class MainThreadDispatcher {
        struct Request : exec_request_t {
            MainThreadDispatcher& owner;
            std::shared_ptr<ToolJob> job;
            ssize_t request_id = -1;
            Request(MainThreadDispatcher& o, std::shared_ptr<ToolJob> j) : owner(o), job(std::move(j)) {}
            ssize_t idaapi execute() override {
                owner.Execute(*this);
                return 0;
            }
        };
        std::mutex mutex_;
        PluginStatusTracker status_tracker_;
        std::vector<std::unique_ptr<Request>> requests_;
        std::shared_ptr<ToolJob> active_;
        std::atomic<bool> quarantined_{false};
        std::atomic<bool> reset_available_{false};
        std::atomic<bool> enabled_{true};
        bool stopping_ = false;
        std::map<std::string, nlohmann::json> early_cancellations_;
        bool CancelQueuedLocked(const std::shared_ptr<ToolJob>& job) {
            if (job->started.load(std::memory_order_acquire) || job->done.load(std::memory_order_acquire)) return false;
            for (auto& request : requests_) {
                if (request->job != job || request->request_id < 0) continue;
                if (!cancel_exec_request(static_cast<int>(request->request_id))) return false;
                const bool timeout = std::chrono::steady_clock::now() >= job->operation.deadline;
                job->response = tools::utils::MakeToolErrorJson(job->id,
                    timeout ? "30-minute limit exceeded before execution" : "Cancelled before execution",
                    timeout ? "execution_timeout" : "cancelled").dump();
                job->work = {};
                job->done.store(true, std::memory_order_release);
                status_tracker_.EndTool();
                return true;
            }
            return false;
        }

        struct FaultInfo {
            void* address = nullptr;
            DWORD flags = 0;
            DWORD parameter_count = 0;
            ULONG_PTR access_type = 0;
            ULONG_PTR access_address = 0;
            void* stack[32] = {};
            USHORT count = 0;
        };
        static int FaultFilter(EXCEPTION_POINTERS* exception, FaultInfo* info) {
            // Let ordinary C++ exceptions unwind normally.
            if (exception->ExceptionRecord->ExceptionCode == 0xE06D7363) return EXCEPTION_CONTINUE_SEARCH;
            info->address = exception->ExceptionRecord->ExceptionAddress;
            info->flags = exception->ExceptionRecord->ExceptionFlags;
            info->parameter_count = exception->ExceptionRecord->NumberParameters;
            if (info->parameter_count >= 2) {
                info->access_type = exception->ExceptionRecord->ExceptionInformation[0];
                info->access_address = exception->ExceptionRecord->ExceptionInformation[1];
            }
            info->count = CaptureStackBackTrace(0, 32, info->stack, nullptr);
            return EXCEPTION_EXECUTE_HANDLER;
        }
        template<class F> static DWORD InvokeNative(F& func, FaultInfo* info) {
            DWORD code = 0;
            __try { func(); }
            __except (FaultFilter(GetExceptionInformation(), info)) { code = GetExceptionCode(); }
            return code;
        }
        void Execute(Request& request) {
            auto job = request.job;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                // This callback runs on the same main thread as earlier callbacks.
                // Their execute() and IDA's dispatcher have both returned now.
                std::erase_if(requests_, [&](const auto& r) {
                    return r.get() != &request && r->job->done.load(std::memory_order_acquire);
                });
            }
            if (!enabled_.load(std::memory_order_acquire) && job->name != "reset_quarantine") {
                job->response = tools::utils::MakeToolErrorJson(job->id,
                    "MCP is disabled for this IDA database", "file_inactive").dump();
                job->work = {};
                status_tracker_.EndTool();
                job->done.store(true, std::memory_order_release);
                return;
            }
            PluginStatusTracker::Scope status_scope(status_tracker_);
            job->started.store(true, std::memory_order_release);
            sync::OperationScope operation(&job->operation);
            // Python intentionally retains IDAPython's interactive cancellation.
            // Other tools get both IDA batch mode and an SDK notification guard.
            UnattendedUiScope unattended_ui(job->name != "py");
            if (job->name != "py" && !unattended_ui.IsActive()) {
                job->response = tools::utils::MakeToolErrorJson(job->id,
                    "Could not enforce unattended IDA UI mode", "ui_guard_unavailable").dump();
                job->work = {};
                status_tracker_.EndTool();
                job->done.store(true, std::memory_order_release);
                return;
            }
            auto invoke = [&]() {
                try {
                    sync::Checkpoint();
                    cache::ApplyPendingChanges();
                    job->response = job->work();
                    sync::Checkpoint();
                } catch (const sync::OperationStopped& e) {
                    job->response = tools::utils::MakeToolErrorJson(job->id, e.what(),
                        e.timed_out ? "execution_timeout" : "cancelled").dump();
                } catch (const std::exception& e) {
                    job->response = tools::utils::MakeToolErrorJson(job->id, e.what(), "internal_error").dump();
                } catch (...) {
                    job->response = tools::utils::MakeToolErrorJson(job->id, "Unknown execution error", "internal_error").dump();
                }
            };
            FaultInfo fault_info;
            const DWORD fault = InvokeNative(invoke, &fault_info);
            if (fault) {
                // Keep native diagnostics in IDA's log, out of ordinary model responses.
                msg("[IDA MCP] Native fault %08lX at %p\n", fault, fault_info.address);
                for (USHORT i = 0; i < fault_info.count; ++i) {
                    HMODULE module = nullptr;
                    char path[MAX_PATH] = {};
                    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                        reinterpret_cast<const char*>(fault_info.stack[i]), &module);
                    if (module) GetModuleFileNameA(module, path, sizeof(path));
                    msg("[IDA MCP]   %s + 0x%llX\n", path,
                        static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(fault_info.stack[i]) - reinterpret_cast<uintptr_t>(module)));
                }
                quarantined_.store(true, std::memory_order_release);
                const bool can_reset = fault == EXCEPTION_ACCESS_VIOLATION &&
                    (fault_info.flags & EXCEPTION_NONCONTINUABLE) == 0 &&
                    (fault_info.parameter_count < 2 || fault_info.access_type == 0);
                reset_available_.store(can_reset, std::memory_order_release);
                auto hex = [](uint64_t value) {
                    std::ostringstream output;
                    output << "0x" << std::uppercase << std::hex << value;
                    return output.str();
                };
                nlohmann::json diagnostic = {{"tool", job->name}, {"exception_code", hex(fault)},
                    {"exception_address", hex(reinterpret_cast<uintptr_t>(fault_info.address))}, {"reset_available", can_reset}};
                if (!job->diagnostic_arguments.empty()) diagnostic["arguments"] = job->diagnostic_arguments;
                if (fault == EXCEPTION_ACCESS_VIOLATION && fault_info.parameter_count >= 2) {
                    diagnostic["access"] = fault_info.access_type == 0 ? "read" : fault_info.access_type == 1 ? "write" : "execute";
                    diagnostic["access_address"] = hex(fault_info.access_address);
                }
                status_tracker_.Quarantine(std::move(diagnostic));
                job->response = tools::utils::MakeToolErrorJson(job->id,
                    can_reset ? "Native fault; backend quarantined. Inspect get_status, then explicitly reset_quarantine or restart IDA."
                              : "Native fault; backend quarantined. Restart IDA before further tools.",
                    "native_fault", static_cast<int>(fault)).dump();
            }
            job->work = {};
            status_tracker_.EndTool();
            job->done.store(true, std::memory_order_release);
        }
    public:
        void SetIdaVersion(const std::string& version) { status_tracker_.SetIdaVersion(version); }
        nlohmann::json GetStatusJson(const nlohmann::json& id, bool enabled) {
            return status_tracker_.GetStatusJson(id, enabled);
        }
        void SetEnabled(bool enabled) { enabled_.store(enabled, std::memory_order_release); }
        bool Quarantined() const { return quarantined_.load(std::memory_order_acquire); }
        nlohmann::json ResetQuarantine(const nlohmann::json& id) {
            if (!is_main_thread())
                return tools::utils::MakeToolErrorJson(id, "Recovery requires the IDA main thread", "internal_error");
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (stopping_ || !active_ || active_->name != "reset_quarantine" ||
                    !active_->started.load(std::memory_order_acquire) || active_->done.load(std::memory_order_acquire))
                    return tools::utils::MakeToolErrorJson(id, "Recovery must be submitted through the dispatcher", "busy");
            }
            if (!Quarantined())
                return tools::utils::MakeToolSuccessJson(id, {{"quarantined", false}, {"reset", false}});
            if (!reset_available_.load(std::memory_order_acquire))
                return tools::utils::MakeToolErrorJson(id,
                    "This native fault cannot be reset; restart IDA", "restart_required");
            // Only an explicitly submitted recovery job reaches here, after the
            // failed callback has returned. Never repeat the failed operation.
            cache::InvalidateIDBDependentCaches();
            sync::callback_exception = {};
            sync::recursion_depth = 0;
            status_tracker_.ResetQuarantine();
            quarantined_.store(false, std::memory_order_release);
            reset_available_.store(false, std::memory_order_release);
            return tools::utils::MakeToolSuccessJson(id, {{"quarantined", false}, {"reset", true},
                {"warning", "Reset does not repair process memory; restart IDA if further faults occur."}});
        }
        bool Cancel(const nlohmann::json& id, const std::string& token) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (token.empty()) return false;
            if (!active_ || active_->id != id || active_->cancel_token != token ||
                active_->done.load(std::memory_order_acquire)) {
                if (early_cancellations_.size() >= 64) early_cancellations_.clear();
                early_cancellations_[token] = id;
                return false;
            }
            active_->operation.cancelled.store(true, std::memory_order_release);
            CancelQueuedLocked(active_);
            return true;
        }
        void Abandon(const std::shared_ptr<ToolJob>& job) {
            std::lock_guard<std::mutex> lock(mutex_);
            job->operation.cancelled.store(true, std::memory_order_release);
            CancelQueuedLocked(job);
        }
        std::shared_ptr<ToolJob> Submit(const nlohmann::json& id, const std::string& name,
                                       std::function<std::string()> work, const std::string& token = {},
                                       const nlohmann::json& arguments = nlohmann::json::object()) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_ || (Quarantined() && name != "reset_quarantine") || (active_ && !active_->done.load(std::memory_order_acquire)))
                return {};
            std::erase_if(requests_, [](const auto& request) {
                return request->job->done.load(std::memory_order_acquire) &&
                       !request->job->started.load(std::memory_order_acquire);
            });
            auto job = std::make_shared<ToolJob>();
            job->id = id;
            job->name = name;
            if (arguments.is_object()) for (const char* key : {"addr", "var", "scan_depth"})
                if (arguments.contains(key)) job->diagnostic_arguments[key] = arguments[key];
            job->cancel_token = token;
            auto early = early_cancellations_.find(token);
            if (early != early_cancellations_.end()) {
                if (early->second == id) job->operation.cancelled.store(true, std::memory_order_release);
                early_cancellations_.erase(early);
            }
            job->work = std::move(work);
            auto req = std::make_unique<Request>(*this, job);
            Request* ptr = req.get();
            requests_.push_back(std::move(req));
            active_ = job;
            status_tracker_.BeginTool(name);
            // All tools, including decompilation, can update IDA metadata.
            ptr->request_id = execute_sync(*ptr, MFF_WRITE | MFF_NOWAIT);
            if (ptr->request_id < 0) {
                job->response = tools::utils::MakeToolErrorJson(id, "IDA rejected execution request", "dispatch_failed").dump();
                job->work = {};
                job->done.store(true, std::memory_order_release);
                status_tracker_.EndTool();
            }
            return job;
        }
        // Stop is called from the main thread after client threads are joined.
        // No callback can be running concurrently on that same thread.
        void Stop() {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
            for (auto& request : requests_) {
                request->job->operation.cancelled.store(true, std::memory_order_release);
                if (!request->job->done.load(std::memory_order_acquire) && request->request_id >= 0)
                    cancel_exec_request(static_cast<int>(request->request_id));
            }
            requests_.clear();
            active_.reset();
        }
    };
}
