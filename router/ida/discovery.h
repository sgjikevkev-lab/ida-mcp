#pragma once
#include "instance.h"
#include <map>
#include <string>

namespace ida {
    class InstanceDiscovery {
    public:
        static bool IsPidAlive(DWORD pid);
        static std::map<std::string, IdaInstance> Discover();
    };
}
