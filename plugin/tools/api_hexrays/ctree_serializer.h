#pragma once
#include <string>
#include <map>
#include <vector>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include <ida.hpp>
#include <hexrays.hpp>

namespace tools::hexrays_ast {
    const char* CTypeToString(ctype_t op);
    ctype_t StringToCType(const std::string& str);

    nlohmann::json SerializeCItem(const citem_t* item, const cfunc_t* cf, int max_depth = 128, int current_depth = 0);
    nlohmann::json SerializeLvars(const cfunc_t* cf);

    std::string CleanItemText(const citem_t* item, const cfunc_t* cf);

    bool MatchPattern(
        const citem_t* node,
        const cfunc_t* cf,
        const nlohmann::json& pattern,
        std::map<std::string, nlohmann::json>& bindings
    );
}
