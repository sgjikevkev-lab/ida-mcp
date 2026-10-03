#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>

namespace discovery {
    class InstanceRegistration {
    public:
        static std::wstring GetPipeName(DWORD pid = 0);
        static bool IsPidAlive(DWORD pid);
        static void CleanupLegacyInstances();
    };
}
