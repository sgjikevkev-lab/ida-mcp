#include "discovery.h"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <filesystem>
#include <iostream>

#pragma warning(push, 0)
#pragma warning(disable: 26819 26495 26812 26451 6001 6011)
#include "!ibs/json.h"
#pragma warning(pop)

#include "ipc/pipe_client.h"

namespace ida {
    namespace fs = std::filesystem;
    using json = nlohmann::json;

    bool InstanceDiscovery::IsPidAlive(DWORD pid) {
        if (pid == 0) return false;
        HANDLE hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) {
            DWORD err = GetLastError();
            return (err == ERROR_ACCESS_DENIED);
        }
        DWORD wait_res = WaitForSingleObject(hProcess, 0);
        CloseHandle(hProcess);
        return (wait_res == WAIT_TIMEOUT);
    }

    std::map<std::string, IdaInstance> InstanceDiscovery::Discover() {
        std::map<std::string, IdaInstance> found;

        WIN32_FIND_DATAW find_data{};
        HANDLE hFind = FindFirstFileW(L"\\\\.\\pipe\\ida_mcp_*", &find_data);
        if (hFind == INVALID_HANDLE_VALUE) {
            return found;
        }

        const std::wstring prefix = L"ida_mcp_";

        do {
            std::wstring pipe_file = find_data.cFileName;
            if (pipe_file.rfind(prefix, 0) != 0) continue;

            DWORD pid = 0;
            try {
                pid = std::stoul(pipe_file.substr(prefix.size()));
            } catch (...) {
                continue;
            }

            if (pid == 0 || !IsPidAlive(pid)) {
                continue;
            }

            std::wstring full_pipe_name = L"\\\\.\\pipe\\" + pipe_file;

            std::string resp;
            std::string req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_instance_info\"}\n";
            if (!ipc::PipeClient::CallOnce(full_pipe_name, req, resp, 2000)) {
                continue;
            }

            try {
                json j = json::parse(resp);
                json result = j.value("result", json::object());

                IdaInstance inst;
                inst.pipe_name = full_pipe_name;
                inst.pid = static_cast<DWORD>(result.value("pid", pid));
                inst.binary = result.value("binary", "");
                inst.idb_path = result.value("idb_path", "");
                inst.backend = result.value("backend", "gui");

                if (inst.binary.empty() && !inst.idb_path.empty()) {
                    inst.binary = fs::path(inst.idb_path).filename().string();
                }
                if (inst.binary.empty()) {
                    inst.binary = "ida_" + std::to_string(inst.pid);
                }

                inst.binary = fs::path(inst.binary).filename().string();

                std::string unique_name = inst.binary;
                int counter = 1;
                while (found.find(unique_name) != found.end()) {
                    unique_name = inst.binary + "_" + std::to_string(counter++);
                }

                inst.binary = unique_name;
                found[unique_name] = inst;
            } catch (...) {
                continue;
            }
        } while (FindNextFileW(hFind, &find_data));

        FindClose(hFind);
        return found;
    }
}
