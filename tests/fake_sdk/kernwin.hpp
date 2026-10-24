#pragma once
#include <windows.h>
#include <cstdarg>
#include <cstring>
#include <vector>
#include "ida.hpp"
using ssize_t = intptr_t;
inline constexpr int MFF_WRITE = 2;
inline constexpr int MFF_NOWAIT = 4;
inline bool batch = false;
inline constexpr int HT_UI = 1;
inline constexpr int ui_ask_file = 1;
using test_ui_hook_t = ssize_t (*)(void*, int, va_list);
inline test_ui_hook_t test_ui_hook = nullptr;
inline void* test_ui_hook_data = nullptr;
inline bool hook_to_notification_point(int hook_type, test_ui_hook_t callback, void* user_data) {
    if (hook_type != HT_UI || callback == nullptr || test_ui_hook != nullptr) return false;
    test_ui_hook = callback;
    test_ui_hook_data = user_data;
    return true;
}
inline int unhook_from_notification_point(int hook_type, test_ui_hook_t callback, void* user_data) {
    if (hook_type != HT_UI || callback != test_ui_hook || user_data != test_ui_hook_data) return 0;
    test_ui_hook = nullptr;
    test_ui_hook_data = nullptr;
    return 1;
}
inline char* qstrdup(const char* value) {
    if (value == nullptr) return nullptr;
    const size_t length = std::strlen(value);
    auto* result = new char[length + 1];
    std::memcpy(result, value, length + 1);
    return result;
}
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
