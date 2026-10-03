#pragma once
#include "instance.h"
#include <map>
#include <string>

namespace ipc {
    class PipeClient;
}

namespace ida {
    class InstanceDiscovery {
    public:
        static bool IsPidAlive(DWORD pid);
        static std::map<std::string, IdaInstance> Discover(
            const std::wstring& active_pipe = L"",
            ipc::PipeClient* active_client = nullptr
        );
    };
}
