#pragma once
#include <string>
#include <vector>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

namespace tools::composite {
    class ApiComposite {
    public:
        ApiComposite() = default;

        nlohmann::json GetSchema() const;
        bool CanHandle(const std::string& name) const;
        nlohmann::json Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args);

    private:
        nlohmann::json SurveyBinary(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json AnalyzeFunction(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json TraceDataFlow(const nlohmann::json& id, const nlohmann::json& args);
    };
}
