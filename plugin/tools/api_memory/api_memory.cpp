#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "api_memory.h"
#include "tools/utils/utils.h"
#include "sync/sync.h"

#include <ida.hpp>
#include <bytes.hpp>
#include <nalt.hpp>
#include <name.hpp>

namespace tools::memory {
    bool ApiMemory::CanHandle(const std::string& name) const {
        return name == "get_bytes" ||
               name == "get_string";
    }

    nlohmann::json ApiMemory::GetSchema() const {
        return nlohmann::json::array();
    }

    nlohmann::json ApiMemory::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "get_bytes") return GetBytes(id, args);
        if (name == "get_string") return GetString(id, args);

        return tools::utils::MakeToolErrorJson(id, "Method not found: " + name, "method_not_found");
    }

    nlohmann::json ApiMemory::GetBytes(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        int64_t size_val = tools::utils::GetIntArg(args, "size", tools::utils::GetIntArg(args, "count", 0));

        if (ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }
        if (size_val <= 0) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'size' must be positive", "invalid_size");
        }

        size_t sz = static_cast<size_t>(size_val);
        if (sz > 1024 * 1024) sz = 1024 * 1024; // 1 MB clamp

        std::vector<uint8_t> buf(sz);
        ssize_t read_bytes = 0;

        sync::SyncRead([&]() {
            read_bytes = get_bytes(buf.data(), sz, ea);
        });

        if (read_bytes <= 0) {
            return tools::utils::MakeToolErrorJson(id, "Failed to read bytes at address " + tools::utils::FormatAddress(ea), "read_failed");
        }

        std::ostringstream ss;
        for (ssize_t i = 0; i < read_bytes; ++i) {
            if (i > 0) ss << " ";
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buf[i]);
        }

        nlohmann::json res = {
            {"status", "success"},
            {"address", tools::utils::FormatAddress(ea)},
            {"size", read_bytes},
            {"hex", ss.str()}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiMemory::GetString(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        if (ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }

        std::string str_val;
        bool ok = false;

        sync::SyncRead([&]() {
            qstring qstr;
            size_t len = get_max_strlit_length(ea, STRTYPE_C);
            if (len > 0 && get_strlit_contents(&qstr, ea, len, STRTYPE_C) > 0) {
                ok = true;
                str_val = tools::utils::SanitizeUtf8(qstr.c_str());
            }
        });

        if (!ok) {
            return tools::utils::MakeToolErrorJson(id, "No string literal found at address " + tools::utils::FormatAddress(ea), "no_string_at_addr");
        }

        nlohmann::json res = {
            {"status", "success"},
            {"address", tools::utils::FormatAddress(ea)},
            {"length", str_val.size()},
            {"string", str_val}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }
}
