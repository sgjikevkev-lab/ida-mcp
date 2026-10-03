#pragma once
#include <string>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

namespace tools::modify {
    class ApiModify {
    public:
        ApiModify() = default;

        bool CanHandle(const std::string& name) const;
        nlohmann::json Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args);

    private:
        nlohmann::json Rename(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json SetType(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json SetComment(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json RenameLvar(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json SetLvarType(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json Recompile(const nlohmann::json& id, const nlohmann::json& args);
    };
}
