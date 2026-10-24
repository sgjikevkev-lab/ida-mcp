#pragma once
#include <atomic>
#include <chrono>
#include <stdexcept>
#include <exception>
#include <utility>
#include "shared/runtime_limits.h"

namespace sync {
    struct OperationStopped : std::runtime_error {
        bool timed_out;
        explicit OperationStopped(bool timeout)
            : std::runtime_error(timeout ? "Operation exceeded the 30-minute limit" : "Operation cancelled"),
              timed_out(timeout) {}
    };

    struct Operation {
        std::atomic<bool> cancelled{false};
        const std::chrono::steady_clock::time_point deadline;
        explicit Operation(std::chrono::steady_clock::time_point end =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(mcp::limits::operation_ms)) : deadline(end) {}
    };

    inline thread_local Operation* current_operation = nullptr;
    inline thread_local std::exception_ptr callback_exception;
    inline void SaveCallbackException() {
        if (!callback_exception) callback_exception = std::current_exception();
    }
    inline thread_local size_t recursion_depth = 0;
    class RecursionGuard {
    public:
        RecursionGuard() {
            if (recursion_depth >= 256) throw std::runtime_error("Analysis recursion limit exceeded");
            ++recursion_depth;
        }
        ~RecursionGuard() { --recursion_depth; }
    };
    class OperationScope {
        Operation* previous_;
        std::exception_ptr previous_exception_;
    public:
        explicit OperationScope(Operation* op) : previous_(current_operation),
            previous_exception_(std::exchange(callback_exception, {})) { current_operation = op; }
        ~OperationScope() { current_operation = previous_; callback_exception = previous_exception_; }
    };

    inline void Checkpoint() {
        if (callback_exception) std::rethrow_exception(std::exchange(callback_exception, {}));
        if (!current_operation) return;
        if (std::chrono::steady_clock::now() >= current_operation->deadline)
            throw OperationStopped(true);
        if (current_operation->cancelled.load(std::memory_order_acquire))
            throw OperationStopped(false);
    }
}
