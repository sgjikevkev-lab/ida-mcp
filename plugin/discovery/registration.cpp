#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <string>
#include <filesystem>
#include "registration.h"

#pragma comment(lib, "shell32.lib")

namespace discovery {
    std::wstring InstanceRegistration::GetPipeName(DWORD pid) {
        if (pid == 0) pid = GetCurrentProcessId();
        return L"\\\\.\\pipe\\ida_mcp_" + std::to_wstring(pid);
    }

    bool InstanceRegistration::IsPidAlive(DWORD pid) {
        if (pid == 0) return false;
        HANDLE hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) {
            DWORD err = GetLastError();
            return (err == ERROR_ACCESS_DENIED);
        }
        DWORD wait_res = WaitForSingleObject(hProcess, 0);
        CloseHandle(hProcess);
        return wait_res == WAIT_TIMEOUT;
    }

    void InstanceRegistration::CleanupLegacyInstances() {
        PWSTR appDataPath = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &appDataPath))) {
            std::filesystem::path path = appDataPath;
            CoTaskMemFree(appDataPath);
            path /= "Hex-Rays";
            path /= "IDA Pro";
            path /= "mcp";
            path /= "instances";

            std::error_code ec;
            if (std::filesystem::exists(path, ec)) {
                std::filesystem::remove_all(path, ec);
            }
        }
    }
}
