#pragma once
#include <windows.h>
#include <vector>
#include "ida.hpp"
using ssize_t = intptr_t;
inline constexpr int MFF_WRITE = 2;
inline constexpr int MFF_NOWAIT = 4;
inline bool batch = false;
inline bool is_main_thread() { return true; }
inline int msg(const char*, ...) { return 0; }
inline int destroyed_requests = 0;
struct exec_request_t {
    virtual ssize_t execute() = 0;
    virtual ~exec_request_t() { ++destroyed_requests; }
};
inline std::vector<exec_request_t*> test_requests;
inline ssize_t execute_sync(exec_request_t& request, int flags) {
    if (flags != (MFF_WRITE | MFF_NOWAIT)) throw std::runtime_error("unsafe scheduling flags");
    test_requests.push_back(&request);
    return static_cast<ssize_t>(test_requests.size());
}
inline bool cancel_exec_request(int id) {
    auto& request = test_requests.at(id - 1);
    if (!request) return false;
    request = nullptr;
    return true;
}
