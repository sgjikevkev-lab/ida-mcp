#include "discovery.h"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <filesystem>
#include <iostream>
#include <vector>
#include <set>
#include <algorithm>

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

    std::map<std::string, IdaInstance> InstanceDiscovery::Discover(
        const std::wstring& active_pipe,
        ipc::PipeClient* active_client
    ) {
        std::map<std::string, IdaInstance> found;

        // Phase 1: Snapshot all candidate pipes matching ida_mcp_* and verify PID is alive.
        // The find handle MUST be closed BEFORE connecting to any pipe so that NPFS directory mutations
        // cannot corrupt enumeration or cause duplicate / missed instances.
        std::vector<std::pair<DWORD, std::wstring>> candidates;
        std::set<DWORD> seen_pids;

        WIN32_FIND_DATAW find_data{};
        HANDLE hFind = FindFirstFileW(L"\\\\.\\pipe\\ida_mcp_*", &find_data);
        if (hFind != INVALID_HANDLE_VALUE) {
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

                if (seen_pids.insert(pid).second) {
                    candidates.push_back({pid, L"\\\\.\\pipe\\" + pipe_file});
                }
            } while (FindNextFileW(hFind, &find_data));

            FindClose(hFind);
        }

        if (candidates.empty()) {
            return found;
        }

        // Sort by PID for stable, deterministic ordering
        std::sort(candidates.begin(), candidates.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });

        // Phase 2: Query metadata from each candidate pipe
        const std::string req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_instance_info\"}\n";

        for (const auto& [pid, full_pipe_name] : candidates) {
            std::string resp;
            bool ok = false;

            // If this candidate matches our currently connected active client, query over the existing pipe
            if (!active_pipe.empty() && active_client && active_client->IsConnected() &&
                full_pipe_name == active_pipe) {
                ok = active_client->Transact(req, resp, 2000);
            }

            if (!ok) {
                ok = ipc::PipeClient::CallOnce(full_pipe_name, req, resp, 2000);
            }

            if (!ok) {
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

                // If two distinct PIDs really have the same binary name (e.g. server.dll from two different paths),
                // disambiguate unique keys with _1, _2, etc.
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
        }

        return found;
    }
}
