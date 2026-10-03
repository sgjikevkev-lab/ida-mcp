#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>

namespace ida {
    struct IdaInstance {
        std::wstring pipe_name;
        DWORD pid = 0;
        std::string binary;
        std::string idb_path;
        std::string backend;
    };
}
