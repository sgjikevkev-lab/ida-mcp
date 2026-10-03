#pragma once
#include <string>
#include <vector>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

namespace tools::sigmaker {
    void InvalidateSegmentCache();

    class ApiSigmaker {
    public:
        ApiSigmaker() = default;

        nlohmann::json GetSchema() const;
        bool CanHandle(const std::string& name) const;
        nlohmann::json Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args);

    private:
        nlohmann::json MakeSignature(const nlohmann::json& id, const nlohmann::json& args);
    };
}
