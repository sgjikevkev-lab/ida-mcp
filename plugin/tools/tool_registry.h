#pragma once
#include <string>
#include <memory>
#include <chrono>
#include <functional>
#include <unordered_map>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "api_core/api_core.h"
#include "api_memory/api_memory.h"
#include "api_analysis/api_analysis.h"
#include "api_modify/api_modify.h"
#include "api_types/api_types.h"
#include "api_composite/api_composite.h"
#include "api_sigmaker/api_sigmaker.h"
#include "api_python/api_python.h"
#include "api_rtti/api_rtti.h"
#include "api_hexrays/api_hexrays.h"

namespace tools {
    using ToolHandler = std::function<nlohmann::json(const nlohmann::json& id, const nlohmann::json& args)>;

    class ToolRegistry {
    public:
        ToolRegistry();

        std::string HandleRequest(const std::string& raw_body);
        nlohmann::json GetToolsSchema() const;

    private:
        std::unordered_map<std::string, ToolHandler> handlers_;

        std::unique_ptr<tools::core::ApiCore> api_core_;
        std::unique_ptr<tools::memory::ApiMemory> api_memory_;
        std::unique_ptr<tools::analysis::ApiAnalysis> api_analysis_;
        std::unique_ptr<tools::modify::ApiModify> api_modify_;
        std::unique_ptr<tools::types::ApiTypes> api_types_;
        std::unique_ptr<tools::composite::ApiComposite> api_composite_;
        std::unique_ptr<tools::sigmaker::ApiSigmaker> api_sigmaker_;
        std::unique_ptr<tools::python::ApiPython> api_python_;
        std::unique_ptr<tools::rtti::ApiRtti> api_rtti_;
        std::unique_ptr<tools::hexrays_ast::ApiHexrays> api_hexrays_;

        void RegisterHandlers();
        nlohmann::json DispatchToolCall(const nlohmann::json& id, const std::string& name, const nlohmann::json& args);
    };
}
