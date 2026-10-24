#include <iostream>
#include "plugin/server/dispatcher.h"

namespace tools::utils {
    std::string SanitizeUtf8(const std::string& value) { return value; }
}
static void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
static void ExecuteQueued() {
    auto* request = test_requests.back();
    Check(request != nullptr, "missing request");
    request->execute();
    // IDA can still use the request after execute() returns.
    Check(std::string(typeid(*request).name()).size() > 0, "request released early");
    test_requests.back() = nullptr;
}
int main() {
    try {
        static_assert(mcp::limits::operation_ms == 1800000);
        {
            sync::Operation expired(std::chrono::steady_clock::now() - std::chrono::seconds(1));
            sync::OperationScope operation(&expired);
            bool timed_out = false;
            try { sync::Checkpoint(); } catch (const sync::OperationStopped& e) { timed_out = e.timed_out; }
            Check(timed_out, "expired deadline stops execution");
        }
        server::MainThreadDispatcher dispatcher;
        auto first = dispatcher.Submit(1, "get_bytes", [] {
            Check(batch, "ordinary tools must suppress dialogs");
            Check(test_ui_hook != nullptr, "ordinary tools must install the file-dialog guard");
            return std::string("first-result");
        });
        Check(!dispatcher.Submit(2, "get_bytes", [] { return std::string(); }), "must reject overlapping jobs");
        ExecuteQueued();
        Check(first->done.load() && first->response == "first-result", "job result");
        Check(!batch && destroyed_requests == 0, "restore batch; retain request through IDA dispatch return");
        auto python = dispatcher.Submit(2, "py", [] {
            Check(!batch, "Python manual cancellation must stay interactive");
            Check(test_ui_hook == nullptr, "Python must not install the file-dialog guard");
            throw std::runtime_error("test-failure");
            return std::string();
        });
        ExecuteQueued();
        Check(python->done.load() && python->response.find("test-failure") != std::string::npos, "contain C++ error");
        Check(!batch && destroyed_requests == 1, "retire previous request on next main-thread callback");
        auto cancelled = dispatcher.Submit(3, "get_bytes", [] { throw std::runtime_error("must not run"); return std::string(); }, "token");
        Check(!dispatcher.Cancel(3, "wrong-token"), "cancel must match token");
        Check(dispatcher.Cancel(3, "token"), "cancel matching job");
        Check(test_requests.back() == nullptr, "remove cancelled request from IDA queue");
        Check(cancelled->response.find("cancelled") != std::string::npos, "cancel queued operation");
        dispatcher.Cancel(4, "early-token");
        auto early = dispatcher.Submit(4, "get_bytes", [] { throw std::runtime_error("must not run"); return std::string(); }, "early-token");
        ExecuteQueued();
        Check(early->response.find("cancelled") != std::string::npos, "handle cancellation arriving before submission");
        auto fault = dispatcher.Submit(5, "get_bytes", [] {
            RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, nullptr);
            return std::string();
        });
        ExecuteQueued();
        Check(dispatcher.Quarantined() && fault->response.find("native_fault") != std::string::npos, "native fault quarantine");
        Check(!batch, "batch restored after hardware fault");
        Check(!dispatcher.Submit(6, "get_bytes", [] { return std::string(); }), "quarantined backend must refuse calls");
        dispatcher.Stop();
        Check(destroyed_requests == 5, "request objects must be released");
        server::MainThreadDispatcher stopped;
        stopped.Submit(7, "get_bytes", [] { return std::string(); });
        stopped.Stop();
        Check(destroyed_requests == 6, "shutdown cancels and releases queued request");
        std::cout << "Dispatcher checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
