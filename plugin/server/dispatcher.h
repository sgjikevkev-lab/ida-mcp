#pragma once
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>
#include <map>
#include <excpt.h>
#include "sync/sync.h"
#include "status_tracker.h"
#include "sync/cache_manager.h"

namespace server {
    struct ToolJob {
        sync::Operation operation;
        std::atomic<bool> done{false};
        std::atomic<bool> started{false};
        nlohmann::json id;
        std::string name;
        std::string cancel_token;
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
        std::vector<std::unique_ptr<Request>> requests_;
        std::shared_ptr<ToolJob> active_;
        std::atomic<bool> quarantined_{false};
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
                PluginStatusTracker::Instance().EndTool();
                return true;
            }
            return false;
        }

        struct FaultInfo {
            void* address = nullptr;
            void* stack[32] = {};
            USHORT count = 0;
        };
        static int FaultFilter(EXCEPTION_POINTERS* exception, FaultInfo* info) {
            // Let ordinary C++ exceptions unwind normally.
            if (exception->ExceptionRecord->ExceptionCode == 0xE06D7363) return EXCEPTION_CONTINUE_SEARCH;
            info->address = exception->ExceptionRecord->ExceptionAddress;
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
            job->started.store(true, std::memory_order_release);
            sync::OperationScope operation(&job->operation);
            const bool previous_batch = batch;
            // Python intentionally retains IDAPython's interactive cancellation.
            if (job->name != "py") batch = true;
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
            batch = previous_batch;
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
                PluginStatusTracker::Instance().Quarantine();
                job->response = tools::utils::MakeToolErrorJson(job->id,
                    "Native IDA fault; backend quarantined. Restart IDA before further tools.",
                    "native_fault", static_cast<int>(fault)).dump();
            }
            job->work = {};
            PluginStatusTracker::Instance().EndTool();
            job->done.store(true, std::memory_order_release);
        }
    public:
        bool Quarantined() const { return quarantined_.load(std::memory_order_acquire); }
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
                                       std::function<std::string()> work, const std::string& token = {}) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_ || Quarantined() || (active_ && !active_->done.load(std::memory_order_acquire)))
                return {};
            std::erase_if(requests_, [](const auto& request) {
                return request->job->done.load(std::memory_order_acquire) &&
                       !request->job->started.load(std::memory_order_acquire);
            });
            auto job = std::make_shared<ToolJob>();
            job->id = id;
            job->name = name;
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
            PluginStatusTracker::Instance().BeginTool(name);
            // All tools, including decompilation, can update IDA metadata.
            ptr->request_id = execute_sync(*ptr, MFF_WRITE | MFF_NOWAIT);
            if (ptr->request_id < 0) {
                job->response = tools::utils::MakeToolErrorJson(id, "IDA rejected execution request", "dispatch_failed").dump();
                job->work = {};
                job->done.store(true, std::memory_order_release);
                PluginStatusTracker::Instance().EndTool();
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
