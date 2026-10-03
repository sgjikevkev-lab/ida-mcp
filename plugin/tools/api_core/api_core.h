#pragma once
#include <string>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

namespace tools::core {
    class ApiCore {
    public:
        ApiCore() = default;

        bool CanHandle(const std::string& name) const;
        nlohmann::json Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args);

    private:
        nlohmann::json IdbSave(const nlohmann::json& id);
        nlohmann::json ListFuncs(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json ListGlobals(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json ImportsQuery(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json GetExports(const nlohmann::json& id);
        nlohmann::json GetSegments(const nlohmann::json& id);
        nlohmann::json SearchStrings(const nlohmann::json& id, const nlohmann::json& args);
    };
}
