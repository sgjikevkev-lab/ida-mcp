#pragma once
#include <utility>
#include <functional>
#include <atomic>
#include <excpt.h>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <ida.hpp>
#include <kernwin.hpp>

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
    namespace detail {
        template <typename F>
        inline DWORD InvokeWithSeh(F& func) {
            DWORD code = 0;
            __try {
                func();
            }
            __except (code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
                // Intercept hardware exceptions (Access Violation 0xC0000005, divide-by-zero, etc.)
            }
            return code;
        }

        struct JobState {
            std::function<void()> func;
            HANDLE hEvent = NULL;
            std::atomic<bool> cancelled{false};
            std::atomic<bool> done{false};
            DWORD exception_code = 0;

            JobState(std::function<void()> f) : func(std::move(f)) {
                hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
            }

            ~JobState() {
                if (hEvent) {
                    CloseHandle(hEvent);
                    hEvent = NULL;
                }
            }
        };

        struct async_exec_request_t : public exec_request_t {
            std::shared_ptr<JobState> state;
            std::atomic<bool> abandoned{false};

            async_exec_request_t(std::shared_ptr<JobState> s) : state(std::move(s)) {}

            virtual ~async_exec_request_t() = default;

            virtual ssize_t idaapi execute() override {
                if (state && !state->cancelled.load(std::memory_order_acquire)) {
                    try {
                        state->exception_code = InvokeWithSeh(state->func);
                    } catch (...) {
                        state->exception_code = 0xE06D7363; // C++ exception code
                    }
                }

                if (state) {
                    state->done.store(true, std::memory_order_release);
                    if (state->hEvent) {
                        SetEvent(state->hEvent);
                    }
                }

                if (abandoned.load(std::memory_order_acquire)) {
                    delete this;
                }
                return 0;
            }
        };

        inline bool ExecuteSyncWithTimeout(
            std::function<void()> func,
            int reqf,
            uint32_t timeout_ms,
            DWORD* out_exception_code = nullptr
        ) {
            if (is_main_thread()) {
                DWORD code = 0;
                try {
                    code = InvokeWithSeh(func);
                } catch (...) {
                    code = 0xE06D7363;
                }
                if (out_exception_code) *out_exception_code = code;
                return code == 0;
            }

            auto state = std::make_shared<JobState>(std::move(func));
            HANDLE hEvt = state->hEvent;
            auto* req = new async_exec_request_t(state);
            ssize_t req_id = execute_sync(*req, reqf | MFF_NOWAIT);

            DWORD wait_res = WaitForSingleObject(hEvt, timeout_ms);
            if (wait_res == WAIT_TIMEOUT) {
                state->cancelled.store(true, std::memory_order_release);
                bool cancelled = cancel_exec_request(static_cast<int>(req_id));
                if (cancelled) {
                    delete req;
                } else {
                    req->abandoned.store(true, std::memory_order_release);
                }
                if (out_exception_code) *out_exception_code = WAIT_TIMEOUT;
                return false;
            }

            DWORD exc = state->exception_code;
            if (out_exception_code) *out_exception_code = exc;
            delete req;
            return exc == 0;
        }
    }

    // Fast synchronization: ok for UI-related queries that do not modify database
    template <typename F>
    inline bool SyncFast(F&& func, uint32_t timeout_ms = 30000, DWORD* out_exception_code = nullptr) {
        return detail::ExecuteSyncWithTimeout(std::forward<F>(func), MFF_FAST, timeout_ms, out_exception_code);
    }

    // Read synchronization: safe to query database, does NOT suspend if a modal dialog is open (8-minute timeout)
    template <typename F>
    inline bool SyncRead(F&& func, uint32_t timeout_ms = 480000, DWORD* out_exception_code = nullptr) {
        return detail::ExecuteSyncWithTimeout(std::forward<F>(func), MFF_READ, timeout_ms, out_exception_code);
    }

    // Write synchronization: for code that modifies database (8-minute timeout)
    template <typename F>
    inline bool SyncWrite(F&& func, uint32_t timeout_ms = 480000, DWORD* out_exception_code = nullptr) {
        return detail::ExecuteSyncWithTimeout(std::forward<F>(func), MFF_WRITE, timeout_ms, out_exception_code);
    }

    // Compatibility wrapper: defaults to SyncRead (8-minute timeout)
    template <typename F>
    inline bool SyncToMainThread(F&& func, DWORD* out_exception_code = nullptr) {
        return SyncRead(std::forward<F>(func), 480000, out_exception_code);
    }
}
