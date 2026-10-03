#pragma once
#include <string>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

namespace tools::types {
    class ApiTypes {
    public:
        ApiTypes() = default;

        bool CanHandle(const std::string& name) const;
        nlohmann::json Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args);

    private:
        nlohmann::json DeclareType(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json TypeQuery(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json TypeInspect(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json ReadStruct(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json StackFrame(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json ReconstructStruct(const nlohmann::json& id, const nlohmann::json& args);
    };
}
