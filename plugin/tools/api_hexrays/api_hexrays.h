#pragma once
#include <string>
#include <vector>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

namespace tools::hexrays_ast {
    class ApiHexrays {
    public:
        ApiHexrays() = default;

        nlohmann::json GetSchema() const;
        bool CanHandle(const std::string& name) const;
        nlohmann::json Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args);

    private:
        nlohmann::json GetAst(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json AstMatch(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json MbaSimplify(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json SimplifyPredicate(const nlohmann::json& id, const nlohmann::json& args);
    };
}
