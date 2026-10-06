#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "api_memory.h"
#include "tools/utils/utils.h"
#include "sync/sync.h"

#include <ida.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <nalt.hpp>
#include <name.hpp>

namespace tools::memory {
    bool ApiMemory::CanHandle(const std::string& name) const {
        return name == "get_bytes";
    }

    nlohmann::json ApiMemory::GetSchema() const {
        return nlohmann::json::array();
    }

    nlohmann::json ApiMemory::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "get_bytes") return GetBytes(id, args);

        return tools::utils::MakeToolErrorJson(id, "Method not found: " + name, "method_not_found");
    }

    nlohmann::json ApiMemory::GetBytes(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        if (ea == BADADDR) {
            std::string raw_addr = tools::utils::GetStringArg(args, "addr");
            std::string msg = "Parameter 'addr' could not be resolved";
            if (!raw_addr.empty()) msg += ": " + raw_addr;
            return tools::utils::MakeToolErrorJson(id, msg, "invalid_addr");
        }

        // Default to 32 bytes if omitted; if explicitly passed <= 0, return error
        int64_t size_val = 32;
        if (args.contains("size") || args.contains("count")) {
            size_val = tools::utils::GetIntArg(args, "size", tools::utils::GetIntArg(args, "count", 32));
            if (size_val <= 0) {
                return tools::utils::MakeToolErrorJson(id, "Parameter 'size' must be positive", "invalid_size");
            }
        }

        constexpr size_t MAX_READ_SIZE = 4096;
        size_t sz = static_cast<size_t>(size_val);
        if (sz > MAX_READ_SIZE) sz = MAX_READ_SIZE;

        segment_t* seg = nullptr;
        bool loaded = false;
        sync::SyncRead([&]() {
            seg = getseg(ea);
            loaded = is_loaded(ea);
        });

        if (!seg && !loaded) {
            return tools::utils::MakeToolErrorJson(id, "Address " + tools::utils::FormatAddress(ea) + " is outside mapped binary segments", "unmapped_addr");
        }

        // If reading past segment bounds, clamp size to available segment data to prevent read failure
        if (seg && ea < seg->end_ea) {
            size_t seg_avail = static_cast<size_t>(seg->end_ea - ea);
            if (sz > seg_avail) sz = seg_avail;
        }

        std::vector<uint8_t> buf(sz);
        ssize_t read_bytes = 0;

        sync::SyncRead([&]() {
            read_bytes = get_bytes(buf.data(), sz, ea, 0);
            if (read_bytes <= 0) {
                // Retry with GMB_READALL in case range has uninitialized/BSS tail
                read_bytes = get_bytes(buf.data(), sz, ea, GMB_READALL);
            }
        });

        if (read_bytes <= 0) {
            if (!loaded) {
                return tools::utils::MakeToolErrorJson(id, "Address " + tools::utils::FormatAddress(ea) + " is uninitialized or not loaded in database", "not_loaded");
            }
            return tools::utils::MakeToolErrorJson(id, "Failed to read bytes at address " + tools::utils::FormatAddress(ea), "read_failed");
        }

        std::ostringstream ss;
        std::string ascii_str;
        ascii_str.reserve(read_bytes);

        for (ssize_t i = 0; i < read_bytes; ++i) {
            if (i > 0) ss << " ";
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buf[i]);
            uint8_t b = buf[i];
            ascii_str += (b >= 32 && b <= 126) ? static_cast<char>(b) : '.';
        }

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["address"] = tools::utils::FormatAddress(ea);
        res["size"] = read_bytes;
        res["hex"] = ss.str();
        res["ascii"] = ascii_str;

        return tools::utils::MakeToolSuccessJson(id, res);
    }
}

