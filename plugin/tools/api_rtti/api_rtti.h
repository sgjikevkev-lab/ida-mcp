#pragma once
#include <string>
#include <vector>
#include <chrono>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

namespace tools::rtti {
    class ApiRtti {
    public:
        ApiRtti();

        nlohmann::json GetSchema() const;
        bool CanHandle(const std::string& name) const;
        nlohmann::json Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args);

    private:
        nlohmann::json RttiListClasses(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json RttiGetClass(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json RttiRefresh(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json RttiCreateStruct(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json ResolveVcall(const nlohmann::json& id, const nlohmann::json& args);
    };
}
