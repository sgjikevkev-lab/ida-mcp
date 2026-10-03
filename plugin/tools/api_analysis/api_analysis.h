#pragma once
#include <string>
#include <vector>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

namespace tools::analysis {
    class ApiAnalysis {
    public:
        ApiAnalysis() = default;

        nlohmann::json GetSchema() const;
        bool CanHandle(const std::string& name) const;
        nlohmann::json Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args);

    private:
        nlohmann::json Decompile(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json Disasm(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json BasicBlocks(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json XrefQuery(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json Callgraph(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json FindBytes(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json InsnQuery(const nlohmann::json& id, const nlohmann::json& args);
        nlohmann::json FindPath(const nlohmann::json& id, const nlohmann::json& args);
    };
}
