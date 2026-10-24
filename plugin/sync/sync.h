#pragma once
#include <utility>
#include <stdexcept>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <ida.hpp>
#include <kernwin.hpp>
#include "operation.h"

#ifdef wait
#undef wait
#endif
#ifdef waitid
#undef waitid
#endif
#ifdef waitpid
#undef waitpid
#endif

namespace sync {
    // Only PipeServer schedules work. Tool lambdas capture stack references
    // and must never outlive the calling frame.
    template <typename F>
    inline bool SyncRead(F&& func, uint32_t = mcp::limits::operation_ms, DWORD* code = nullptr) {
        if (!is_main_thread()) throw std::logic_error("IDA API called outside the main-thread dispatcher");
        Checkpoint();
        if (code) *code = 0;
        std::forward<F>(func)();
        Checkpoint();
        return true;
    }
    template <typename F>
    inline bool SyncWrite(F&& func, uint32_t timeout = mcp::limits::operation_ms, DWORD* code = nullptr) {
        return SyncRead(std::forward<F>(func), timeout, code);
    }
    template <typename F>
    inline bool SyncToMainThread(F&& func, DWORD* code = nullptr) {
        return SyncRead(std::forward<F>(func), mcp::limits::operation_ms, code);
    }
}
