#pragma once
#include <string>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

namespace tools::memory {
    class ApiMemory {
    public:
        ApiMemory() = default;

        nlohmann::json GetSchema() const;
        bool CanHandle(const std::string& name) const;
        nlohmann::json Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args);

    private:
        nlohmann::json GetBytes(const nlohmann::json& id, const nlohmann::json& args);
    };
}
