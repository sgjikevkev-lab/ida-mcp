#include <string>
#include <vector>
#include <functional>
#include <sstream>
#include <iomanip>
#include <unordered_set>
#include <map>
#include <set>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "api_types.h"
#include "tools/utils/utils.h"
#include "sync/sync.h"
#include "sync/cache_manager.h"

#include <ida.hpp>
#include <typeinf.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <frame.hpp>
#include <hexrays.hpp>
#include <lines.hpp>

#include <regex>

namespace tools::types {
    namespace {
        static thread_local std::string g_parse_errors;

        static int ida_export DeclPrinter(const char *format, ...) {
            char buf[1024];
            va_list va;
            va_start(va, format);
            qvsnprintf(buf, sizeof(buf), format, va);
            va_end(va);
            g_parse_errors += buf;
            return 0;
        }

        tinfo_t GetTypeByName(const std::string& name) {
            std::string clean = name;
            if (clean.rfind("struct ", 0) == 0) clean = clean.substr(7);
            else if (clean.rfind("union ", 0) == 0) clean = clean.substr(6);
            else if (clean.rfind("enum ", 0) == 0) clean = clean.substr(5);

            tinfo_t tif;
            til_t* local_ti = get_idati();
            // 1. Try resolving in idati (Local Types) with default decl_type=BTF_TYPEDEF
            if (local_ti && tif.get_named_type(local_ti, clean.c_str())) {
                return tif;
            }
            // 2. Try resolving across all loaded base tils
            if (tif.get_named_type(nullptr, clean.c_str())) {
                return tif;
            }
            // 3. Try each loaded base TIL explicitly
            if (local_ti) {
                for (int b = 0; b < local_ti->nbases; ++b) {
                    if (local_ti->base[b] && tif.get_named_type(local_ti->base[b], clean.c_str())) {
                        return tif;
                    }
                }
            }
            // 4. Try IDB structures/enums by TID
            tid_t tid = get_named_type_tid(clean.c_str());
            if (tid != BADADDR) {
                uint32 ord = get_tid_ordinal(tid);
                if (ord != 0 && local_ti && tif.get_numbered_type(local_ti, ord)) {
                    return tif;
                }
            }
            return tinfo_t();
        }
    }

    bool ApiTypes::CanHandle(const std::string& name) const {
        return name == "types" ||
               name == "stack_frame" ||
               name == "reconstruct_struct";
    }

    nlohmann::json ApiTypes::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "types") return UnifiedTypes(id, args);
        if (name == "stack_frame") return StackFrame(id, args);
        if (name == "reconstruct_struct") return ReconstructStruct(id, args);

        return tools::utils::MakeToolErrorJson(id, "Method not found: " + name, "method_not_found");
    }

    nlohmann::json ApiTypes::UnifiedTypes(const nlohmann::json& id, const nlohmann::json& args) {
        // 1. Declare mode (c_code present)
        if (args.contains("c_code")) {
            return DeclareType(id, args);
        }

        // 2. Read memory struct instance (addr AND (name OR type OR struct) present)
        if (args.contains("addr") && (args.contains("name") || args.contains("type") || args.contains("struct"))) {
            nlohmann::json struct_args = args;
            if (!struct_args.contains("name") && struct_args.contains("type")) {
                struct_args["name"] = struct_args["type"];
            } else if (!struct_args.contains("name") && struct_args.contains("struct")) {
                struct_args["name"] = struct_args["struct"];
            }
            return ReadStruct(id, struct_args);
        }

        // 3. Batch type inspection (names array)
        if (args.contains("names") && args["names"].is_array()) {
            nlohmann::json results = nlohmann::json::array();
            for (const auto& n : args["names"]) {
                if (!n.is_string()) continue;
                nlohmann::json inspect_args = args;
                inspect_args["name"] = n.get<std::string>();
                nlohmann::json res = TypeInspect(id, inspect_args);
                if (res.contains("result")) {
                    results.push_back(res["result"]);
                } else {
                    results.push_back({{"name", n.get<std::string>()}, {"status", "not_found"}});
                }
            }
            nlohmann::ordered_json resp;
            resp["status"] = "success";
            resp["count"] = results.size();
            resp["types"] = results;
            return tools::utils::MakeToolSuccessJson(id, resp);
        }

        // 4. Single type inspection (name or type present)
        if (args.contains("name") || args.contains("type")) {
            nlohmann::json inspect_args = args;
            if (!inspect_args.contains("name") && inspect_args.contains("type")) {
                inspect_args["name"] = inspect_args["type"];
            }
            return TypeInspect(id, inspect_args);
        }

        // 5. Query / search mode (pattern, query, or fallback)
        return TypeQuery(id, args);
    }

    nlohmann::json ApiTypes::DeclareType(const nlohmann::json& id, const nlohmann::json& args) {
        std::string decls = tools::utils::GetStringArg(args, "c_code", tools::utils::GetStringArg(args, "declarations", tools::utils::GetStringArg(args, "code")));
        if (decls.empty()) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'c_code' is required", "c_code_required");
        }

        int pack = static_cast<int>(tools::utils::GetIntArg(args, "pack", 0));
        bool detailed = tools::utils::GetBoolArg(args, "detailed", true);
        std::string explicit_name = tools::utils::GetStringArg(args, "name");

        int hti_flags = HTI_DCL | HTI_SEMICOLON | HTI_RELAXED;
        if (pack == 1) hti_flags |= HTI_PAK1;
        else if (pack == 2) hti_flags |= HTI_PAK2;
        else if (pack == 4) hti_flags |= HTI_PAK4;
        else if (pack == 8) hti_flags |= HTI_PAK8;
        else if (pack == 16) hti_flags |= HTI_PAK16;
        else hti_flags |= HTI_PAKDEF;

        g_parse_errors.clear();
        int errs = 0;
        sync::SyncWrite([&]() {
            errs = parse_decls(get_idati(), decls.c_str(), DeclPrinter, hti_flags);
        });

        if (errs != 0) {
            std::string clean_err = tools::utils::SanitizeUtf8(g_parse_errors.c_str());
            while (!clean_err.empty() && (clean_err.back() == '\n' || clean_err.back() == '\r' || clean_err.back() == ' ')) {
                clean_err.pop_back();
            }
            std::string msg = "C parser encountered " + std::to_string(errs) + " error(s)";
            if (!clean_err.empty()) {
                msg += ": " + clean_err;
            }
            return tools::utils::MakeToolErrorJson(id, msg, "declare_type_failed", errs);
        }

        cache::InvalidateIDBAnalysis();

        // Collect candidate names of declared types to inspect
        std::vector<std::string> candidate_names;
        if (!explicit_name.empty()) {
            candidate_names.push_back(explicit_name);
        }

        try {
            // Find struct / union / enum names:
            std::regex re_tag(R"((?:struct|union|enum)\s+([A-Za-z_][A-Za-z0-9_]*))");
            auto words_begin = std::sregex_iterator(decls.begin(), decls.end(), re_tag);
            auto words_end = std::sregex_iterator();
            for (auto it = words_begin; it != words_end; ++it) {
                std::smatch m = *it;
                if (m.size() > 1) {
                    std::string tag_name = m[1].str();
                    if (std::find(candidate_names.begin(), candidate_names.end(), tag_name) == candidate_names.end()) {
                        candidate_names.push_back(tag_name);
                    }
                }
            }

            // Find typedef names (last identifier before semicolon):
            std::regex re_td(R"(typedef\s+[^;]+?\s+([A-Za-z_][A-Za-z0-9_]*)\s*;)");
            auto td_begin = std::sregex_iterator(decls.begin(), decls.end(), re_td);
            for (auto it = td_begin; it != words_end; ++it) {
                std::smatch m = *it;
                if (m.size() > 1) {
                    std::string td_name = m[1].str();
                    if (std::find(candidate_names.begin(), candidate_names.end(), td_name) == candidate_names.end()) {
                        candidate_names.push_back(td_name);
                    }
                }
            }
        } catch (...) {}

        nlohmann::json types_arr = nlohmann::json::array();
        sync::SyncRead([&]() {
            for (const auto& c_name : candidate_names) {
                tinfo_t tif = GetTypeByName(c_name);
                if (tif.empty() || !tif.present()) continue;

                nlohmann::ordered_json item;
                item["name"] = c_name;
                std::string kind = "type";
                if (tif.is_struct()) kind = "struct";
                else if (tif.is_union()) kind = "union";
                else if (tif.is_enum()) kind = "enum";
                else if (tif.is_typedef()) kind = "typedef";
                else if (tif.is_func()) kind = "function";
                item["kind"] = kind;

                size_t sz = tif.get_size();
                if (sz != BADSIZE) {
                    item["size"] = sz;
                }

                if (tif.is_udt()) {
                    int nmembers = tif.get_udt_nmembers();
                    item["fields_count"] = nmembers;
                    if (detailed) {
                        nlohmann::json f_arr = nlohmann::json::array();
                        for (int i = 0; i < nmembers; ++i) {
                            udm_t udm;
                            if (tif.get_udm(&udm, static_cast<size_t>(i)) >= 0) {
                                nlohmann::ordered_json f;
                                f["name"] = tools::utils::SanitizeUtf8(udm.name.c_str());
                                f["offset"] = udm.offset / 8;
                                f["size"] = udm.size / 8;
                                qstring m_decl;
                                udm.type.print(&m_decl, udm.name.c_str(), PRTYPE_1LINE | PRTYPE_SEMI);
                                f["type"] = tools::utils::SanitizeUtf8(m_decl.c_str());
                                f_arr.push_back(std::move(f));
                            }
                        }
                        item["fields"] = std::move(f_arr);
                    }
                } else if (tif.is_enum()) {
                    enum_type_data_t ei;
                    if (tif.get_enum_details(&ei)) {
                        item["members_count"] = ei.size();
                        if (detailed) {
                            nlohmann::json m_arr = nlohmann::json::array();
                            for (size_t i = 0; i < ei.size(); ++i) {
                                m_arr.push_back({
                                    {"name", tools::utils::SanitizeUtf8(ei[i].name.c_str())},
                                    {"value", ei[i].value}
                                });
                            }
                            item["members"] = std::move(m_arr);
                        }
                    }
                }

                types_arr.push_back(std::move(item));
            }
        });

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["declared_count"] = types_arr.size();

        if (!types_arr.empty()) {
            res["types"] = types_arr;
            if (types_arr.size() == 1) {
                const auto& single = types_arr[0];
                res["name"] = single["name"];
                res["kind"] = single["kind"];
                if (single.contains("size")) res["size"] = single["size"];
                if (single.contains("fields_count")) res["fields_count"] = single["fields_count"];
                if (single.contains("fields")) res["fields"] = single["fields"];
                if (single.contains("members_count")) res["members_count"] = single["members_count"];
                if (single.contains("members")) res["members"] = single["members"];
            }
        } else {
            res["message"] = "Declarations compiled and registered into type library";
        }

        if (!g_parse_errors.empty()) {
            std::string clean_w = tools::utils::SanitizeUtf8(g_parse_errors.c_str());
            while (!clean_w.empty() && (clean_w.back() == '\n' || clean_w.back() == '\r' || clean_w.back() == ' ')) {
                clean_w.pop_back();
            }
            if (!clean_w.empty()) {
                res["compiler_messages"] = clean_w;
            }
        }

        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiTypes::TypeQuery(const nlohmann::json& id, const nlohmann::json& args) {
        std::string pattern = tools::utils::GetStringArg(args, "pattern", tools::utils::GetStringArg(args, "filter"));
        std::string kind_filter = tools::utils::GetStringArg(args, "kind", "all");
        std::transform(kind_filter.begin(), kind_filter.end(), kind_filter.begin(), ::tolower);

        bool local_only = tools::utils::GetBoolArg(args, "local_only", false);
        bool detailed = tools::utils::GetBoolArg(args, "detailed", true);
        std::string til_filter = tools::utils::GetStringArg(args, "til");

        size_t offset = static_cast<size_t>(tools::utils::GetIntArg(args, "offset", 0));
        if (offset == 0) {
            std::string cursor_str = tools::utils::GetStringArg(args, "cursor");
            if (!cursor_str.empty()) {
                try {
                    offset = static_cast<size_t>(std::stoull(cursor_str, nullptr, 0));
                } catch (...) {}
            }
        }

        size_t count = static_cast<size_t>(tools::utils::GetIntArg(args, "count", 50));
        if (count <= 0) count = 50;
        if (count > 2000) count = 2000;

        nlohmann::json types_arr = nlohmann::json::array();
        size_t total = 0;
        int next_offset = -1;
        std::unordered_set<std::string> seen;

        sync::SyncRead([&]() {
            std::vector<til_t*> tils_to_search;
            til_t* local_ti = get_idati();
            if (local_ti) {
                if (til_filter.empty() || til_filter == "all" || til_filter == "local" || (local_ti->name && til_filter == local_ti->name)) {
                    tils_to_search.push_back(local_ti);
                }
                if (!local_only && til_filter != "local") {
                    for (int b = 0; b < local_ti->nbases; ++b) {
                        til_t* base_ti = local_ti->base[b];
                        if (!base_ti) continue;
                        if (!til_filter.empty() && til_filter != "all" && (!base_ti->name || til_filter != base_ti->name)) {
                            continue;
                        }
                        tils_to_search.push_back(base_ti);
                    }
                }
            }

            for (til_t* cur_til : tils_to_search) {
                const char* named = first_named_type(cur_til, NTF_TYPE);
                while (named != nullptr) {
                    std::string t_name = named;
                    named = next_named_type(cur_til, named, NTF_TYPE);

                    if (!seen.insert(t_name).second) continue;
                    if (!pattern.empty() && !tools::utils::PatternMatch(t_name, pattern)) continue;

                    tinfo_t tif;
                    bool tif_resolved = false;
                    auto resolve_tif = [&]() {
                        if (!tif_resolved) {
                            if (!tif.get_named_type(cur_til, t_name.c_str())) {
                                if (cur_til != local_ti) tif.get_named_type(local_ti, t_name.c_str());
                            }
                            if (tif.empty() || !tif.present()) {
                                tif.get_named_type(nullptr, t_name.c_str());
                            }
                            tif_resolved = true;
                        }
                    };

                    if (kind_filter != "all") {
                        resolve_tif();
                        if (kind_filter == "struct" && !tif.is_struct()) continue;
                        if (kind_filter == "union" && !tif.is_union()) continue;
                        if (kind_filter == "enum" && !tif.is_enum()) continue;
                        if (kind_filter == "typedef" && !tif.is_typedef()) continue;
                        if (kind_filter == "function" && !tif.is_func()) continue;
                    }

                    if (total >= offset && types_arr.size() < count) {
                        if (detailed) {
                            resolve_tif();
                            nlohmann::ordered_json item;
                            item["name"] = t_name;
                            std::string kind = "type";
                            if (!tif.empty() && tif.present()) {
                                if (tif.is_struct()) kind = "struct";
                                else if (tif.is_union()) kind = "union";
                                else if (tif.is_enum()) kind = "enum";
                                else if (tif.is_typedef()) kind = "typedef";
                                else if (tif.is_func()) kind = "function";
                            }
                            item["kind"] = kind;

                            if (!tif.empty() && tif.present()) {
                                size_t sz = tif.get_size();
                                if (sz != BADSIZE && sz != 0) {
                                    item["size"] = sz;
                                }
                                if (tif.is_udt()) {
                                    item["fields_count"] = tif.get_udt_nmembers();
                                } else if (tif.is_enum()) {
                                    item["members_count"] = tif.get_enum_nmembers();
                                }
                            }

                            if (cur_til == local_ti) {
                                item["til"] = "local";
                            } else if (cur_til && cur_til->name) {
                                item["til"] = cur_til->name;
                            }
                            types_arr.push_back(std::move(item));
                        } else {
                            types_arr.push_back(t_name);
                        }
                        next_offset = static_cast<int>(total + 1);
                    }
                    total++;
                }
            }

            if (next_offset >= static_cast<int>(total)) {
                next_offset = -1;
            }
        });

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["total"] = total;
        res["count"] = types_arr.size();
        res["types"] = types_arr;
        if (next_offset != -1) {
            res["next_offset"] = next_offset;
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiTypes::TypeInspect(const nlohmann::json& id, const nlohmann::json& args) {
        std::string name = tools::utils::GetStringArg(args, "name", tools::utils::GetStringArg(args, "type"));
        if (name.empty()) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'name' is required", "name_required");
        }

        bool show_padding = tools::utils::GetBoolArg(args, "show_padding", true);

        std::string decl_str;
        std::string kind = "type";
        std::string target_type;
        size_t type_size = 0;
        size_t total_padding = 0;
        nlohmann::json fields = nlohmann::json::array();
        nlohmann::json members = nlohmann::json::array();
        bool found = false;

        sync::SyncRead([&]() {
            tinfo_t tif = GetTypeByName(name);
            if (!tif.empty() && tif.present()) {
                found = true;
                type_size = tif.get_size();

                if (tif.is_struct()) kind = "struct";
                else if (tif.is_union()) kind = "union";
                else if (tif.is_enum()) kind = "enum";
                else if (tif.is_typedef()) kind = "typedef";
                else if (tif.is_func()) kind = "function";

                // Format definition
                qstring decl;
                bool ok = tif.print(&decl, name.c_str(), PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_DEF | PRTYPE_SEMI);
                if (!ok || decl.empty()) {
                    tif.print(&decl, nullptr, PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_DEF | PRTYPE_SEMI);
                }
                decl_str = tools::utils::SanitizeUtf8(decl.c_str());

                // If typedef, get underlying type
                if (tif.is_typedef()) {
                    qstring target_decl;
                    tif.print(&target_decl, nullptr, PRTYPE_1LINE);
                    std::string td_s = tools::utils::SanitizeUtf8(target_decl.c_str());
                    if (!td_s.empty() && td_s.back() == ';') td_s.pop_back();
                    while (!td_s.empty() && td_s.back() == ' ') td_s.pop_back();
                    target_type = td_s;
                }

                // If struct or union, enumerate fields
                if (tif.is_udt()) {
                    int nmembers = tif.get_udt_nmembers();
                    uint64 cur_bit = 0;
                    for (int i = 0; i < nmembers; ++i) {
                        udm_t udm;
                        if (tif.get_udm(&udm, static_cast<size_t>(i)) >= 0) {
                            if (udm.offset > cur_bit && cur_bit != 0) {
                                uint64 pad_bits = udm.offset - cur_bit;
                                if (pad_bits % 8 == 0) {
                                    total_padding += static_cast<size_t>(pad_bits / 8);
                                }
                            }

                            nlohmann::ordered_json f;
                            f["name"] = tools::utils::SanitizeUtf8(udm.name.c_str());
                            uint64 byte_offset = udm.offset / 8;
                            uint64 byte_size = udm.size / 8;
                            f["offset"] = byte_offset;
                            char hex_off[32];
                            qsnprintf(hex_off, sizeof(hex_off), "0x%llX", (unsigned long long)byte_offset);
                            f["offset_hex"] = hex_off;
                            f["size"] = byte_size;

                            qstring type_only;
                            udm.type.print(&type_only, nullptr, PRTYPE_1LINE);
                            std::string clean_t = tools::utils::SanitizeUtf8(type_only.c_str());
                            if (!clean_t.empty() && clean_t.back() == ';') clean_t.pop_back();
                            while (!clean_t.empty() && clean_t.back() == ' ') clean_t.pop_back();
                            f["type"] = clean_t;

                            qstring m_decl;
                            udm.type.print(&m_decl, udm.name.c_str(), PRTYPE_1LINE | PRTYPE_SEMI);
                            f["decl"] = tools::utils::SanitizeUtf8(m_decl.c_str());

                            if (udm.type.is_bitfield()) {
                                bitfield_type_data_t bfd;
                                if (udm.type.get_bitfield_details(&bfd)) {
                                    f["is_bitfield"] = true;
                                    f["bit_offset"] = udm.offset % 8;
                                    f["bit_width"] = bfd.width;
                                }
                            }

                            if (!udm.cmt.empty()) {
                                f["comment"] = tools::utils::SanitizeUtf8(udm.cmt.c_str());
                            }

                            fields.push_back(std::move(f));
                            cur_bit = udm.offset + udm.size;
                        }
                    }

                    if (type_size != BADSIZE && type_size * 8 > cur_bit && cur_bit != 0) {
                        total_padding += (type_size * 8 - cur_bit) / 8;
                    }
                } else if (tif.is_enum()) {
                    enum_type_data_t ei;
                    if (tif.get_enum_details(&ei)) {
                        for (size_t i = 0; i < ei.size(); ++i) {
                            nlohmann::ordered_json m;
                            m["name"] = tools::utils::SanitizeUtf8(ei[i].name.c_str());
                            m["value"] = ei[i].value;
                            char hex_val[32];
                            qsnprintf(hex_val, sizeof(hex_val), "0x%llX", (unsigned long long)ei[i].value);
                            m["value_hex"] = hex_val;
                            if (!ei[i].cmt.empty()) {
                                m["comment"] = tools::utils::SanitizeUtf8(ei[i].cmt.c_str());
                            }
                            members.push_back(std::move(m));
                        }
                    }
                }
            }
        });

        if (!found || decl_str.empty()) {
            return tools::utils::MakeToolErrorJson(
                id,
                "Type '" + name + "' does not exist in local type library or loaded base TILs",
                "type_not_found"
            );
        }

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["name"] = name;
        res["kind"] = kind;
        if (type_size != BADSIZE && type_size != 0) {
            res["size"] = type_size;
            char hex_sz[32];
            qsnprintf(hex_sz, sizeof(hex_sz), "0x%llX", (unsigned long long)type_size);
            res["size_hex"] = hex_sz;
        }

        if (!target_type.empty()) {
            res["target_type"] = target_type;
        }

        if (kind == "struct" || kind == "union") {
            res["fields_count"] = fields.size();
            if (show_padding && total_padding > 0) {
                res["padding_bytes"] = total_padding;
            }
        } else if (kind == "enum") {
            res["members_count"] = members.size();
        }

        res["declaration"] = decl_str;

        if (!fields.empty()) {
            res["fields"] = std::move(fields);
        }
        if (!members.empty()) {
            res["members"] = std::move(members);
        }

        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiTypes::ReadStruct(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        if (ea == BADADDR) ea = tools::utils::GetAddressArg(args, "address");

        std::string struct_name = tools::utils::GetStringArg(args, "name", tools::utils::GetStringArg(args, "struct"));
        int max_depth = static_cast<int>(tools::utils::GetIntArg(args, "max_depth", 2));
        if (max_depth <= 0) max_depth = 2;
        if (max_depth > 5) max_depth = 5;
        int array_limit = static_cast<int>(tools::utils::GetIntArg(args, "array_limit", 16));
        if (array_limit <= 0) array_limit = 16;
        if (array_limit > 128) array_limit = 128;

        if (struct_name.empty()) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'name' or 'struct' is required", "struct_name_required");
        }

        if (ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' is required", "addr_required");
        }

        bool unmapped = false;
        sync::SyncRead([&]() {
            if (!is_mapped(ea)) {
                unmapped = true;
            }
        });
        if (unmapped) {
            return tools::utils::MakeToolErrorJson(
                id,
                "Memory address " + tools::utils::FormatAddress(ea) + " is not mapped in IDB database",
                "unmapped_address"
            );
        }

        nlohmann::json fields_arr = nlohmann::json::array();
        size_t struct_size = 0;
        bool found = false;
        std::vector<uint8_t> bulk_buf;
        bool has_bulk = false;

        sync::SyncRead([&]() {
            tinfo_t tif = GetTypeByName(struct_name);
            if (tif.empty()) return;

            found = true;
            struct_size = tif.get_size();

            if (struct_size > 0 && struct_size <= 0x100000) {
                bulk_buf.resize(struct_size, 0);
                ssize_t rb = get_bytes(bulk_buf.data(), struct_size, ea, GMB_READALL);
                if (rb > 0) {
                    has_bulk = true;
                    if (static_cast<size_t>(rb) < struct_size) {
                        bulk_buf.resize(rb);
                    }
                }
            }

            std::function<nlohmann::ordered_json(ea_t, const tinfo_t&, const qstring&, size_t, size_t, int, int, int)> ReadFieldRecursive;

            ReadFieldRecursive = [&](
                ea_t base_ea,           // base address in memory
                const tinfo_t& ftype,   // field type
                const qstring& fname,   // field name
                size_t f_offset_bits,   // offset from parent (in bits)
                size_t f_size,          // field size in bytes
                int depth,
                int max_d,
                int arr_lim
            ) -> nlohmann::ordered_json {
                size_t offset_bytes = f_offset_bits / 8;
                ea_t field_ea = (base_ea != BADADDR) ? (base_ea + offset_bytes) : BADADDR;

                qstring type_str;
                ftype.print(&type_str, nullptr, PRTYPE_1LINE);
                std::string clean_type = tools::utils::SanitizeUtf8(type_str.c_str());
                if (!clean_type.empty() && clean_type.back() == ';') clean_type.pop_back();
                while (!clean_type.empty() && clean_type.back() == ' ') clean_type.pop_back();

                char hex_off[32];
                qsnprintf(hex_off, sizeof(hex_off), "0x%llX", (unsigned long long)offset_bytes);

                nlohmann::ordered_json field_obj;
                field_obj["name"] = tools::utils::SanitizeUtf8(fname.c_str());
                field_obj["offset"] = offset_bytes;
                field_obj["offset_hex"] = hex_off;
                field_obj["size"] = f_size;
                field_obj["type"] = clean_type;

                auto read_val = [&](size_t sz, uint64_t& out_val) -> bool {
                    if (sz == 0 || sz > 8) return false;
                    size_t root_off = (field_ea != BADADDR && ea != BADADDR && field_ea >= ea) ? static_cast<size_t>(field_ea - ea) : 0;
                    if (has_bulk && root_off + sz <= bulk_buf.size()) {
                        out_val = 0;
                        memcpy(&out_val, bulk_buf.data() + root_off, sz);
                        return true;
                    }
                    if (field_ea != BADADDR && is_mapped(field_ea)) {
                        out_val = 0;
                        if (sz == 1) { out_val = get_byte(field_ea); return true; }
                        if (sz == 2) { out_val = get_word(field_ea); return true; }
                        if (sz == 4) { out_val = get_dword(field_ea); return true; }
                        if (sz == 8) { out_val = get_qword(field_ea); return true; }
                        if (get_bytes(&out_val, sz, field_ea) == static_cast<ssize_t>(sz)) {
                            return true;
                        }
                    }
                    return false;
                };

                // 1. Bitfield handling
                if (ftype.is_bitfield()) {
                    bitfield_type_data_t bfd;
                    if (ftype.get_bitfield_details(&bfd)) {
                        size_t enc_sz = bfd.nbytes > 0 ? bfd.nbytes : f_size;
                        if (enc_sz > 8) enc_sz = 8;
                        uint64_t enc_val = 0;
                        if (read_val(enc_sz, enc_val)) {
                            uint8_t bit_off = static_cast<uint8_t>(f_offset_bits % (enc_sz * 8));
                            uint64_t mask = (bfd.width >= 64) ? ~0ULL : ((1ULL << bfd.width) - 1);
                            uint64_t bit_val = (enc_val >> bit_off) & mask;
                            field_obj["is_bitfield"] = true;
                            field_obj["bit_offset"] = bit_off;
                            field_obj["bit_width"] = bfd.width;
                            char bhex[32];
                            qsnprintf(bhex, sizeof(bhex), "0x%llX", (unsigned long long)bit_val);
                            field_obj["value"] = bhex;
                            field_obj["dec_value"] = static_cast<int64_t>(bit_val);
                            return field_obj;
                        }
                    }
                }

                // 2. Nested struct/union: recurse
                if (ftype.is_udt() && depth < max_d) {
                    udt_type_data_t nested;
                    if (ftype.get_udt_details(&nested)) {
                        nlohmann::json nested_fields = nlohmann::json::array();
                        for (const auto& nm : nested) {
                            size_t nm_size = nm.type.get_size();
                            size_t nested_off = f_offset_bits + nm.offset;
                            nested_fields.push_back(
                                ReadFieldRecursive(base_ea, nm.type, nm.name, nested_off, nm_size, depth + 1, max_d, arr_lim)
                            );
                        }
                        field_obj["fields"] = nested_fields;
                    }
                }
                // 3. Array: read elements and detect strings
                else if (ftype.is_array() && depth < max_d) {
                    tinfo_t elem_type;
                    int nelems_total = -1;
                    array_type_data_t ai;
                    if (ftype.get_array_details(&ai)) {
                        elem_type = ai.elem_type;
                        nelems_total = static_cast<int>(ai.nelems);
                    }

                    if (!elem_type.empty() && nelems_total > 0) {
                        size_t elem_size = elem_type.get_size();
                        field_obj["array_total"] = nelems_total;

                        // Check if char array / string
                        if (elem_type.is_char() || (elem_size == 1 && elem_type.is_integral())) {
                            std::string str_val;
                            size_t max_read = std::min<size_t>(nelems_total, 256);
                            for (size_t c = 0; c < max_read; ++c) {
                                uint8_t b = 0;
                                size_t root_off = (field_ea != BADADDR && ea != BADADDR && field_ea >= ea) ? static_cast<size_t>(field_ea - ea + c) : 0;
                                if (has_bulk && root_off < bulk_buf.size()) {
                                    b = bulk_buf[root_off];
                                } else if (field_ea != BADADDR && is_mapped(field_ea + c)) {
                                    b = get_byte(field_ea + c);
                                } else {
                                    break;
                                }
                                if (b == 0) break;
                                if (b >= 32 && b <= 126) str_val += static_cast<char>(b);
                                else {
                                    char hex_c[8];
                                    qsnprintf(hex_c, sizeof(hex_c), "\\x%02X", (unsigned int)b);
                                    str_val += hex_c;
                                }
                            }
                            field_obj["string_value"] = str_val;
                        }

                        int show_count = std::min(nelems_total, arr_lim);
                        field_obj["array_shown"] = show_count;

                        nlohmann::json elems = nlohmann::json::array();
                        for (int i = 0; i < show_count; ++i) {
                            qstring idx_name;
                            idx_name.sprnt("[%d]", i);
                            size_t elem_offset_bits = f_offset_bits + static_cast<size_t>(i) * elem_size * 8;
                            elems.push_back(
                                ReadFieldRecursive(base_ea, elem_type, idx_name, elem_offset_bits, elem_size, depth + 1, max_d, arr_lim)
                            );
                        }
                        field_obj["elements"] = elems;
                    }
                }
                // 4. Pointer: dereference with proper field size and RVA detection
                else if (ftype.is_ptr() && field_ea != BADADDR) {
                    size_t ptr_sz = f_size > 0 ? f_size : (inf_is_64bit() ? 8 : 4);
                    if (ptr_sz > 8) ptr_sz = 8;
                    uint64_t raw_ptr = 0;
                    if (read_val(ptr_sz, raw_ptr)) {
                        ea_t pointed = static_cast<ea_t>(raw_ptr);
                        field_obj["value"] = tools::utils::FormatAddress(pointed);
                        if (pointed != 0 && pointed != BADADDR) {
                            if (is_mapped(pointed)) {
                                qstring pointed_name;
                                get_ea_name(&pointed_name, pointed);
                                if (!pointed_name.empty()) {
                                    field_obj["pointed_name"] = tools::utils::SanitizeUtf8(pointed_name.c_str());
                                }

                                qstring str_buf;
                                if (get_strlit_contents(&str_buf, pointed, 128, STRTYPE_C) > 0) {
                                    field_obj["string_preview"] = tools::utils::SanitizeUtf8(str_buf.c_str());
                                }
                            } else if (ptr_sz == 4 && inf_is_64bit()) {
                                // 32-bit RVA in 64-bit binary
                                ea_t rva_target = get_imagebase() + pointed;
                                if (is_mapped(rva_target)) {
                                    field_obj["rva_target"] = tools::utils::FormatAddress(rva_target);
                                    qstring rva_name;
                                    get_ea_name(&rva_name, rva_target);
                                    if (!rva_name.empty()) {
                                        field_obj["pointed_name"] = tools::utils::SanitizeUtf8(rva_name.c_str());
                                    }
                                }
                            }
                        }
                    }
                }
                // 5. Enum: resolve constant name
                else if (ftype.is_enum() && field_ea != BADADDR) {
                    uint64_t raw_val = 0;
                    if (read_val(f_size, raw_val)) {
                        char hex_buf[32];
                        qsnprintf(hex_buf, sizeof(hex_buf), "0x%llX", (unsigned long long)raw_val);
                        field_obj["value"] = hex_buf;
                        field_obj["dec_value"] = static_cast<int64_t>(raw_val);
                        enum_type_data_t ei;
                        if (ftype.get_enum_details(&ei)) {
                            for (const auto& em : ei) {
                                if (static_cast<uint64_t>(em.value) == raw_val) {
                                    field_obj["enum_name"] = tools::utils::SanitizeUtf8(em.name.c_str());
                                    break;
                                }
                            }
                        }
                    }
                }
                // 6. Scalar: integers, floats, doubles
                else if (field_ea != BADADDR) {
                    uint64_t raw_val = 0;
                    if (read_val(f_size, raw_val)) {
                        char hex_buf[32];
                        if (f_size == 1) qsnprintf(hex_buf, sizeof(hex_buf), "0x%02X", (uint8_t)raw_val);
                        else if (f_size == 2) qsnprintf(hex_buf, sizeof(hex_buf), "0x%04X", (uint16_t)raw_val);
                        else if (f_size == 4) qsnprintf(hex_buf, sizeof(hex_buf), "0x%08X", (uint32_t)raw_val);
                        else qsnprintf(hex_buf, sizeof(hex_buf), "0x%llX", (unsigned long long)raw_val);
                        field_obj["value"] = hex_buf;

                        if (ftype.is_float() && f_size == 4) {
                            float f = 0.0f;
                            memcpy(&f, &raw_val, sizeof(float));
                            field_obj["float_value"] = f;
                        } else if (ftype.is_double() && f_size == 8) {
                            double d = 0.0;
                            memcpy(&d, &raw_val, sizeof(double));
                            field_obj["float_value"] = d;
                        } else if (ftype.is_integral()) {
                            if (f_size == 1) field_obj["dec_value"] = static_cast<int64_t>(static_cast<int8_t>(raw_val));
                            else if (f_size == 2) field_obj["dec_value"] = static_cast<int64_t>(static_cast<int16_t>(raw_val));
                            else if (f_size == 4) field_obj["dec_value"] = static_cast<int64_t>(static_cast<int32_t>(raw_val));
                            else if (f_size == 8) field_obj["dec_value"] = static_cast<int64_t>(raw_val);
                        }
                    }
                }

                return field_obj;
            };

            udt_type_data_t udt;
            if (tif.get_udt_details(&udt)) {
                for (const auto& m : udt) {
                    size_t m_size = m.type.get_size();
                    fields_arr.push_back(
                        ReadFieldRecursive(ea, m.type, m.name, m.offset, m_size, 0, max_depth, array_limit)
                    );
                }
            }
        });

        if (!found || fields_arr.empty()) {
            return tools::utils::MakeToolErrorJson(
                id,
                "Struct '" + struct_name + "' was not found or contains no fields",
                "struct_not_found"
            );
        }

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["address"] = tools::utils::FormatAddress(ea);
        res["struct"] = struct_name;
        res["size"] = struct_size;
        char hex_sz[32];
        qsnprintf(hex_sz, sizeof(hex_sz), "0x%llX", (unsigned long long)struct_size);
        res["size_hex"] = hex_sz;
        res["max_depth"] = max_depth;

        if (has_bulk && !bulk_buf.empty()) {
            std::string hex_str;
            size_t preview_len = std::min<size_t>(bulk_buf.size(), 64);
            for (size_t b = 0; b < preview_len; ++b) {
                char hb[4];
                qsnprintf(hb, sizeof(hb), "%02X ", bulk_buf[b]);
                hex_str += hb;
            }
            if (bulk_buf.size() > 64) hex_str += "...";
            else if (!hex_str.empty()) hex_str.pop_back();
            res["raw_bytes"] = hex_str;
        }

        res["fields"] = std::move(fields_arr);
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiTypes::StackFrame(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        if (ea == BADADDR) ea = tools::utils::GetAddressArg(args, "func");
        if (ea == BADADDR) ea = tools::utils::GetAddressArg(args, "function");

        if (ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }

        bool include_lvars = tools::utils::GetBoolArg(args, "include_lvars", true);

        nlohmann::json members_arr = nlohmann::json::array();
        nlohmann::json lvars_arr = nlohmann::json::array();
        ea_t fn_start = BADADDR;
        ea_t fn_end = BADADDR;
        std::string fn_name;
        std::string fn_demangled;
        bool found_fn = false;
        size_t frame_total_size = 0;
        asize_t frsize = 0;
        ushort frregs = 0;
        asize_t argsize = 0;
        asize_t fpd = 0;

        sync::SyncRead([&]() {
            func_t* fn = get_func(ea);
            if (!fn && is_code(get_flags(ea))) {
                add_func(ea);
                fn = get_func(ea);
            }
            if (!fn) return;

            found_fn = true;
            fn_start = fn->start_ea;
            fn_end = fn->end_ea;
            frsize = fn->frsize;
            frregs = fn->frregs;
            argsize = fn->argsize;
            fpd = fn->fpd;

            qstring name_buf;
            get_func_name(&name_buf, fn_start);
            fn_name = tools::utils::SanitizeUtf8(name_buf.c_str());
            fn_demangled = tools::utils::Demangle(fn_name);

            tinfo_t frame_tif;
            if (get_func_frame(&frame_tif, fn)) {
                frame_total_size = frame_tif.get_size();
                udt_type_data_t udt;
                if (frame_tif.get_udt_details(&udt)) {
                    // Find return address offset for category classification
                    uint64 ret_addr_bit_offset = static_cast<uint64>(-1);
                    for (const auto& m : udt) {
                        if (m.name == FRAME_UDM_NAME_R) {
                            ret_addr_bit_offset = m.offset;
                            break;
                        }
                    }

                    for (const auto& m : udt) {
                        qstring type_name;
                        m.type.print(&type_name, nullptr, PRTYPE_1LINE);
                        std::string clean_type = tools::utils::SanitizeUtf8(type_name.c_str());
                        if (!clean_type.empty() && clean_type.back() == ';') clean_type.pop_back();
                        while (!clean_type.empty() && clean_type.back() == ' ') clean_type.pop_back();

                        size_t offset_bytes = m.offset / 8;
                        size_t m_size = m.type.get_size();

                        std::string category = "local";
                        if (m.name == FRAME_UDM_NAME_R) {
                            category = "return_address";
                        } else if (m.name == FRAME_UDM_NAME_S) {
                            category = "saved_registers";
                        } else if (ret_addr_bit_offset != static_cast<uint64>(-1)) {
                            if (m.offset > ret_addr_bit_offset) {
                                category = "argument";
                            } else {
                                category = "local";
                            }
                        }

                        // Calculate BP displacement relative to real frame pointer:
                        int64_t bp_base = static_cast<int64_t>(frsize - fpd);
                        int64_t bp_disp = static_cast<int64_t>(offset_bytes) - bp_base;

                        char hex_off[32];
                        qsnprintf(hex_off, sizeof(hex_off), "0x%llX", (unsigned long long)offset_bytes);

                        char bp_hex[32];
                        if (bp_disp < 0) {
                            qsnprintf(bp_hex, sizeof(bp_hex), "-0x%llX", (unsigned long long)(-bp_disp));
                        } else {
                            qsnprintf(bp_hex, sizeof(bp_hex), "+0x%llX", (unsigned long long)bp_disp);
                        }

                        nlohmann::ordered_json item;
                        item["name"] = tools::utils::SanitizeUtf8(m.name.c_str());
                        item["category"] = category;
                        item["offset"] = offset_bytes;
                        item["offset_hex"] = hex_off;
                        item["sp_offset"] = offset_bytes;
                        item["sp_offset_hex"] = hex_off;
                        item["bp_offset"] = bp_disp;
                        item["bp_offset_hex"] = bp_hex;
                        item["size"] = m_size;
                        item["type"] = clean_type;

                        if (!m.cmt.empty()) {
                            item["comment"] = tools::utils::SanitizeUtf8(m.cmt.c_str());
                        }

                        members_arr.push_back(std::move(item));
                    }
                }
            }

            if (include_lvars && init_hexrays_plugin()) {
                cfuncptr_t cfunc = decompile(fn, nullptr, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                if (cfunc) {
                    const lvars_t* lvars = cfunc->get_lvars();
                    if (lvars) {
                        for (size_t i = 0; i < lvars->size(); ++i) {
                            const lvar_t& v = (*lvars)[i];
                            nlohmann::ordered_json v_obj;
                            v_obj["name"] = tools::utils::SanitizeUtf8(v.name.c_str());
                            qstring v_type;
                            v.tif.print(&v_type, nullptr, PRTYPE_1LINE);
                            std::string clean_vt = tools::utils::SanitizeUtf8(v_type.c_str());
                            if (!clean_vt.empty() && clean_vt.back() == ';') clean_vt.pop_back();
                            while (!clean_vt.empty() && clean_vt.back() == ' ') clean_vt.pop_back();

                            v_obj["type"] = clean_vt;
                            v_obj["size"] = v.width;
                            v_obj["is_arg"] = v.is_arg_var();

                            if (v.is_reg_var()) {
                                v_obj["location"] = "register";
                                qstring rname;
                                get_mreg_name(&rname, v.get_reg1(), v.width, nullptr);
                                std::string reg_str = tools::utils::SanitizeUtf8(rname.c_str());
                                if (!reg_str.empty()) {
                                    v_obj["register"] = reg_str;
                                    v_obj["location_detail"] = reg_str;
                                }
                            } else if (v.is_stk_var()) {
                                v_obj["location"] = "stack";
                                sval_t stkoff = v.get_stkoff();
                                v_obj["stack_offset"] = stkoff;
                                char stk_hex[32];
                                qsnprintf(stk_hex, sizeof(stk_hex), "0x%llX", (unsigned long long)stkoff);
                                v_obj["stack_offset_hex"] = stk_hex;
                                sval_t delta = cfunc->get_stkoff_delta();
                                sval_t ida_stk = stkoff - delta;
                                v_obj["ida_stack_offset"] = ida_stk;
                                char ida_hex[32];
                                qsnprintf(ida_hex, sizeof(ida_hex), "0x%llX", (unsigned long long)ida_stk);
                                v_obj["ida_stack_offset_hex"] = ida_hex;
                                v_obj["location_detail"] = "stkoff: " + std::string(stk_hex);
                            } else {
                                v_obj["location"] = "other";
                            }

                            if (!v.cmt.empty()) {
                                v_obj["comment"] = tools::utils::SanitizeUtf8(v.cmt.c_str());
                            }
                            lvars_arr.push_back(std::move(v_obj));
                        }
                    }
                }
            }
        });

        if (!found_fn) {
            return tools::utils::MakeToolErrorJson(
                id,
                "No function found containing address " + tools::utils::FormatAddress(ea),
                "function_not_found"
            );
        }

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["address"] = tools::utils::FormatAddress(fn_start);
        res["name"] = fn_name;
        if (!fn_demangled.empty()) {
            res["demangled"] = fn_demangled;
        }
        res["frame_size"] = frame_total_size;
        char hex_fr[32];
        qsnprintf(hex_fr, sizeof(hex_fr), "0x%llX", (unsigned long long)frame_total_size);
        res["frame_size_hex"] = hex_fr;
        res["locals_size"] = frsize;
        res["saved_regs_size"] = frregs;
        res["args_size"] = argsize;
        res["fpd"] = fpd;

        res["members"] = std::move(members_arr);
        if (include_lvars && !lvars_arr.empty()) {
            res["lvars"] = std::move(lvars_arr);
        }

        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiTypes::ReconstructStruct(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        if (ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }

        std::string target_var_name = tools::utils::GetStringArg(args, "var");
        std::string struct_name = tools::utils::GetStringArg(args, "struct_name");
        int max_depth = static_cast<int>(tools::utils::GetIntArg(args, "scan_depth", 2));
        if (max_depth < 0) max_depth = 0;
        if (max_depth > 5) max_depth = 5;

        bool apply = tools::utils::GetBoolArg(args, "apply", false);
        bool decompile_now = tools::utils::GetBoolArg(args, "decompile_now", false) || apply;

        struct InferredField {
            uint64_t offset = 0;
            size_t size = 4;
            std::string type_name = "uint32_t";
            bool is_float = false;
            bool is_pointer = false;
            bool is_vftable = false;
            ea_t vtable_target = BADADDR;
            size_t access_count = 0;
            bool has_read = false;
            bool has_write = false;
        };

        std::map<uint64_t, InferredField> observed_fields;
        std::string fn_name;
        ea_t fn_start = BADADDR;
        bool found_fn = false;
        bool decompiled_ok = false;
        bool applied_ok = false;
        std::string apply_error;
        uint64_t inferred_total_size = 0;
        std::string inferred_size_source;
        nlohmann::json candidate_vars = nlohmann::json::array();
        std::string updated_decompiled_code;

        auto parse_hexrays_helper = [](const char* helper, size_t& out_offset, size_t& out_size, bool& out_signed) -> bool {
            if (!helper || !*helper) return false;
            std::string h = helper;
            out_signed = false;
            if (h.size() > 1 && h[0] == 'S' && (h[1] == 'L' || h[1] == 'H' || h[1] == 'B' || h[1] == 'W' || h[1] == 'D')) {
                out_signed = true;
                h = h.substr(1);
            }
            if (h == "LOBYTE") { out_offset = 0; out_size = 1; return true; }
            if (h == "HIBYTE") { out_offset = 1; out_size = 1; return true; }
            if (h.rfind("BYTE", 0) == 0 && h.size() > 4) {
                int n = std::atoi(h.c_str() + 4);
                out_offset = n; out_size = 1; return true;
            }
            if (h == "LOWORD") { out_offset = 0; out_size = 2; return true; }
            if (h == "HIWORD" || h == "WORD1") { out_offset = 2; out_size = 2; return true; }
            if (h.rfind("WORD", 0) == 0 && h.size() > 4) {
                int n = std::atoi(h.c_str() + 4);
                out_offset = n * 2; out_size = 2; return true;
            }
            if (h == "LODWORD") { out_offset = 0; out_size = 4; return true; }
            if (h == "HIDWORD" || h == "DWORD1") { out_offset = 4; out_size = 4; return true; }
            if (h.rfind("DWORD", 0) == 0 && h.size() > 5) {
                int n = std::atoi(h.c_str() + 5);
                out_offset = n * 4; out_size = 4; return true;
            }
            if (h == "QWORD1") { out_offset = 8; out_size = 8; return true; }
            return false;
        };

        auto get_callee_name = [](const cexpr_t* call_expr) -> std::string {
            if (!call_expr || call_expr->op != cot_call || !call_expr->x) return "";
            if (call_expr->x->op == cot_obj) {
                qstring qn;
                get_name(&qn, call_expr->x->obj_ea);
                return qn.c_str();
            }
            if (call_expr->x->op == cot_helper && call_expr->x->helper) {
                return call_expr->x->helper;
            }
            return "";
        };

        sync::SyncRead([&]() {
            if (!init_hexrays_plugin()) return;

            func_t* pfn = get_func(ea);
            if (!pfn) return;
            found_fn = true;
            fn_start = pfn->start_ea;

            qstring q_fname;
            get_func_name(&q_fname, fn_start);
            fn_name = q_fname.c_str();

            hexrays_failure_t hf;
            cfuncptr_t cf = decompile(pfn, &hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
            if (!cf) return;
            decompiled_ok = true;

            const lvars_t* lvars = cf->get_lvars();
            if (!lvars || lvars->empty()) return;

            for (size_t i = 0; i < lvars->size(); ++i) {
                const auto& lv = (*lvars)[i];
                qstring tstr;
                lv.type().print(&tstr);
                candidate_vars.push_back({
                    {"name", lv.name.c_str()},
                    {"type", tstr.c_str()},
                    {"is_arg", lv.is_arg_var()},
                    {"is_ptr", lv.type().is_ptr()}
                });
            }

            int target_idx = -1;
            if (!target_var_name.empty()) {
                std::string target_lower = target_var_name;
                for (char& c : target_lower) c = static_cast<char>(std::tolower(c));

                for (size_t i = 0; i < lvars->size(); ++i) {
                    if ((*lvars)[i].name == target_var_name.c_str()) {
                        target_idx = static_cast<int>(i);
                        break;
                    }
                }
                if (target_idx == -1) {
                    for (size_t i = 0; i < lvars->size(); ++i) {
                        std::string ln = (*lvars)[i].name.c_str();
                        for (char& c : ln) c = static_cast<char>(std::tolower(c));
                        if (ln == target_lower) {
                            target_idx = static_cast<int>(i);
                            target_var_name = (*lvars)[i].name.c_str();
                            break;
                        }
                    }
                }
                if (target_idx == -1 && (target_lower == "this" || target_lower == "rcx" || target_lower == "a1")) {
                    for (size_t i = 0; i < lvars->size(); ++i) {
                        if ((*lvars)[i].is_arg_var()) {
                            target_idx = static_cast<int>(i);
                            target_var_name = (*lvars)[i].name.c_str();
                            break;
                        }
                    }
                }
            } else {
                if (ea != fn_start) {
                    struct VarAtEaVisitor : public ctree_visitor_t {
                        ea_t target_ea;
                        int found_idx = -1;
                        VarAtEaVisitor(ea_t a) : ctree_visitor_t(CV_FAST), target_ea(a) {}
                        int idaapi visit_expr(cexpr_t* e) override {
                            if (e->ea == target_ea) {
                                if (e->op == cot_var) {
                                    found_idx = e->v.idx;
                                    return 1;
                                }
                                if ((e->op == cot_ptr || e->op == cot_memptr || e->op == cot_memref) && e->x) {
                                    const cexpr_t* base = e->x;
                                    while (base && (base->op == cot_cast || base->op == cot_ref)) base = base->x;
                                    if (base && base->op == cot_var) {
                                        found_idx = base->v.idx;
                                        return 1;
                                    }
                                }
                            }
                            return 0;
                        }
                    };
                    VarAtEaVisitor var_finder(ea);
                    var_finder.apply_to(&cf->body, nullptr);
                    if (var_finder.found_idx >= 0 && var_finder.found_idx < static_cast<int>(lvars->size())) {
                        target_idx = var_finder.found_idx;
                        target_var_name = (*lvars)[target_idx].name.c_str();
                    }
                }

                if (target_idx == -1) {
                    for (size_t i = 0; i < lvars->size(); ++i) {
                        if ((*lvars)[i].is_arg_var() && (*lvars)[i].type().is_ptr()) {
                            target_idx = static_cast<int>(i);
                            target_var_name = (*lvars)[i].name.c_str();
                            break;
                        }
                    }
                }
                if (target_idx == -1) {
                    for (size_t i = 0; i < lvars->size(); ++i) {
                        if ((*lvars)[i].is_arg_var()) {
                            target_idx = static_cast<int>(i);
                            target_var_name = (*lvars)[i].name.c_str();
                            break;
                        }
                    }
                }
                if (target_idx == -1) {
                    for (size_t i = 0; i < lvars->size(); ++i) {
                        if ((*lvars)[i].type().is_ptr()) {
                            target_idx = static_cast<int>(i);
                            target_var_name = (*lvars)[i].name.c_str();
                            break;
                        }
                    }
                }
                if (target_idx == -1 && !lvars->empty()) {
                    target_idx = 0;
                    target_var_name = (*lvars)[0].name.c_str();
                }
            }

            if (target_idx == -1) return;

            if (struct_name.empty()) {
                std::string clean_fn = fn_name;
                while (!clean_fn.empty() && (clean_fn.front() == '.' || clean_fn.front() == '?' || clean_fn.front() == '@')) clean_fn.erase(clean_fn.begin());
                struct_name = "Struct_" + clean_fn + "_" + target_var_name;
            }

            std::unordered_map<ea_t, std::shared_ptr<cfuncptr_t>> cfunc_cache;
            cfunc_cache[fn_start] = std::make_shared<cfuncptr_t>(cf);

            std::set<std::tuple<ea_t, int, uint64_t>> visited_contexts;
            std::function<void(func_t*, int, int, uint64_t)> scan_fn;

            scan_fn = [&](func_t* cur_fn, int lvar_idx, int current_depth, uint64_t base_offset) {
                if (!cur_fn || current_depth > max_depth) return;
                auto ctx_key = std::make_tuple(cur_fn->start_ea, lvar_idx, base_offset);
                if (visited_contexts.count(ctx_key)) return;
                visited_contexts.insert(ctx_key);

                cfuncptr_t local_cf(nullptr);
                auto it = cfunc_cache.find(cur_fn->start_ea);
                if (it != cfunc_cache.end() && it->second) {
                    local_cf = *(it->second);
                } else {
                    hexrays_failure_t local_hf;
                    local_cf = decompile(cur_fn, &local_hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                    if (local_cf) {
                        cfunc_cache[cur_fn->start_ea] = std::make_shared<cfuncptr_t>(local_cf);
                    }
                }
                if (!local_cf) return;

                // Pass 1: Build alias map (lvar_idx -> offset relative to target base)
                std::map<int, int64_t> aliases;
                aliases[lvar_idx] = 0;

                auto is_alias_base = [&](auto& self, const cexpr_t* e, int64_t& out_off) -> bool {
                    if (!e) return false;
                    if (e->op == cot_var) {
                        auto ait = aliases.find(e->v.idx);
                        if (ait != aliases.end()) {
                            out_off = ait->second;
                            return true;
                        }
                        return false;
                    }
                    if ((e->op == cot_cast || e->op == cot_ref) && e->x) {
                        return self(self, e->x, out_off);
                    }
                    if (e->op == cot_add && e->x && e->y) {
                        int64_t sub_off = 0;
                        size_t scale = 1;
                        if (e->type.is_ptr()) {
                            tinfo_t pointed = e->type.get_pointed_object();
                            if (!pointed.empty()) {
                                size_t s = pointed.get_size();
                                if (s > 1 && s != BADSIZE) scale = s;
                            }
                        }
                        if (self(self, e->x, sub_off) && e->y->op == cot_num) {
                            out_off = sub_off + static_cast<int64_t>(e->y->numval() * scale);
                            return true;
                        }
                        if (self(self, e->y, sub_off) && e->x->op == cot_num) {
                            out_off = sub_off + static_cast<int64_t>(e->x->numval() * scale);
                            return true;
                        }
                    }
                    if (e->op == cot_sub && e->x && e->y) {
                        int64_t sub_off = 0;
                        size_t scale = 1;
                        if (e->type.is_ptr()) {
                            tinfo_t pointed = e->type.get_pointed_object();
                            if (!pointed.empty()) {
                                size_t s = pointed.get_size();
                                if (s > 1 && s != BADSIZE) scale = s;
                            }
                        }
                        if (self(self, e->x, sub_off) && e->y->op == cot_num) {
                            out_off = sub_off - static_cast<int64_t>(e->y->numval() * scale);
                            return true;
                        }
                    }
                    return false;
                };

                for (int round = 0; round < 3; ++round) {
                    bool new_alias = false;
                    struct AliasVisitor : public ctree_visitor_t {
                        std::map<int, int64_t>& al;
                        decltype(is_alias_base)& is_b;
                        bool& changed;
                        AliasVisitor(std::map<int, int64_t>& a, decltype(is_alias_base)& b, bool& c)
                            : ctree_visitor_t(CV_FAST), al(a), is_b(b), changed(c) {}
                        int idaapi visit_expr(cexpr_t* e) override {
                            if (e->op == cot_asg && e->x && e->y) {
                                if (e->x->op == cot_var) {
                                    int64_t off = 0;
                                    if (is_b(is_b, e->y, off)) {
                                        if (al.find(e->x->v.idx) == al.end()) {
                                            al[e->x->v.idx] = off;
                                            changed = true;
                                        }
                                    }
                                }
                            }
                            return 0;
                        }
                    };
                    AliasVisitor av(aliases, is_alias_base, new_alias);
                    av.apply_to(&local_cf->body, nullptr);
                    if (!new_alias) break;
                }

                // Pass 2: Extract field accesses
                struct StructVisitor : public ctree_visitor_t {
                    const cfunc_t* cf;
                    decltype(is_alias_base)& is_target;
                    decltype(parse_hexrays_helper)& parse_helper;
                    decltype(get_callee_name)& get_cname;
                    std::map<uint64_t, InferredField>& fields;
                    int depth;
                    int max_d;
                    uint64_t base_off;
                    uint64_t& total_sz;
                    std::string& total_sz_src;
                    std::function<void(func_t*, int, int, uint64_t)> recurse_fn;

                    StructVisitor(const cfunc_t* f, decltype(is_alias_base)& it,
                                  decltype(parse_hexrays_helper)& ph, decltype(get_callee_name)& gc,
                                  std::map<uint64_t, InferredField>& flds,
                                  int d, int md, uint64_t bo, uint64_t& tsz, std::string& tsrc,
                                  std::function<void(func_t*, int, int, uint64_t)> rf)
                        : ctree_visitor_t(CV_FAST), cf(f), is_target(it), parse_helper(ph), get_cname(gc),
                          fields(flds), depth(d), max_d(md), base_off(bo), total_sz(tsz), total_sz_src(tsrc),
                          recurse_fn(rf) {}

                    void record_access(uint64_t f_off, size_t sz, tinfo_t tif, bool is_write,
                                       const std::string& type_override = "", ea_t vtbl_ea = BADADDR) {
                        if (sz == 0 || sz > 128) sz = inf_is_64bit() ? 8 : 4;
                        auto fit = fields.find(f_off);
                        if (fit == fields.end()) {
                            InferredField f;
                            f.offset = f_off;
                            f.size = sz;
                            f.access_count = 1;
                            if (is_write) f.has_write = true;
                            else f.has_read = true;

                            if (!type_override.empty()) {
                                f.type_name = type_override;
                            } else if (!tif.empty()) {
                                qstring qn;
                                tif.print(&qn);
                                f.type_name = qn.c_str();
                            }

                            if (vtbl_ea != BADADDR) {
                                f.is_vftable = true;
                                f.vtable_target = vtbl_ea;
                                f.type_name = "void**";
                                f.size = inf_is_64bit() ? 8 : 4;
                            } else if (tif.is_floating()) {
                                f.is_float = true;
                                f.type_name = (sz == 8 ? "double" : "float");
                            } else if (tif.is_ptr()) {
                                f.is_pointer = true;
                                if (f.type_name.empty() || f.type_name == "_QWORD" || f.type_name == "_DWORD") {
                                    f.type_name = "void*";
                                }
                            }
                            fields[f_off] = f;
                        } else {
                            fit->second.access_count++;
                            if (is_write) fit->second.has_write = true;
                            else fit->second.has_read = true;
                            if (sz > fit->second.size) fit->second.size = sz;
                            if (vtbl_ea != BADADDR) {
                                fit->second.is_vftable = true;
                                fit->second.vtable_target = vtbl_ea;
                                fit->second.type_name = "void**";
                                fit->second.size = inf_is_64bit() ? 8 : 4;
                            }
                            if (!type_override.empty()) {
                                fit->second.type_name = type_override;
                            } else if ((fit->second.type_name.empty() || fit->second.type_name == "uint32_t" || fit->second.type_name == "_QWORD") && !tif.empty()) {
                                qstring qn;
                                tif.print(&qn);
                                fit->second.type_name = qn.c_str();
                            }
                        }
                    }

                    int idaapi visit_expr(cexpr_t* e) override {
                        bool is_write = false;
                        const citem_t* p = parent_expr();
                        if (p && p->is_expr() && p->op == cot_asg) {
                            const cexpr_t* asg = reinterpret_cast<const cexpr_t*>(p);
                            if (asg->x == e) is_write = true;
                        }

                        // 1. Pointer dereference: *(type*)(var + offset)
                        if (e->op == cot_ptr && e->x) {
                            int64_t off = 0;
                            if (is_target(is_target, e->x, off)) {
                                int64_t signed_final = static_cast<int64_t>(base_off) + off;
                                if (signed_final >= 0) {
                                    uint64_t final_off = static_cast<uint64_t>(signed_final);
                                    size_t sz = e->ptrsize > 0 ? static_cast<size_t>(e->ptrsize) : e->type.get_size();
                                    record_access(final_off, sz, e->type, is_write);
                                }
                            }
                        }

                        // 2. Member pointer or reference: var->member or var.member
                        if ((e->op == cot_memptr || e->op == cot_memref) && e->x) {
                            int64_t off = 0;
                            if (is_target(is_target, e->x, off)) {
                                int64_t signed_final = static_cast<int64_t>(base_off) + off + static_cast<int64_t>(e->m);
                                if (signed_final >= 0) {
                                    uint64_t final_off = static_cast<uint64_t>(signed_final);
                                    size_t sz = e->ptrsize > 0 ? static_cast<size_t>(e->ptrsize) : e->type.get_size();
                                    record_access(final_off, sz, e->type, is_write);
                                }
                            }
                        }

                        // 3. Array indexing: var[i]
                        if (e->op == cot_idx && e->x && e->y && e->y->op == cot_num) {
                            int64_t off = 0;
                            if (is_target(is_target, e->x, off)) {
                                size_t elem_sz = e->type.get_size();
                                if (elem_sz <= 0 || elem_sz == BADSIZE) elem_sz = 1;
                                int64_t signed_final = static_cast<int64_t>(base_off) + off + static_cast<int64_t>(e->y->numval() * elem_sz);
                                if (signed_final >= 0) {
                                    uint64_t final_off = static_cast<uint64_t>(signed_final);
                                    record_access(final_off, elem_sz, e->type, is_write);
                                }
                            }
                        }

                        // 4. Hex-Rays helper functions (LODWORD, HIDWORD, BYTE4, etc.)
                        if (e->op == cot_call && e->x && e->x->op == cot_helper && e->a && !e->a->empty()) {
                            size_t h_off = 0, h_sz = 0;
                            bool h_signed = false;
                            if (parse_helper(e->x->helper, h_off, h_sz, h_signed)) {
                                int64_t off = 0;
                                if (is_target(is_target, &(*e->a)[0], off)) {
                                    int64_t signed_final = static_cast<int64_t>(base_off) + off + static_cast<int64_t>(h_off);
                                    if (signed_final >= 0) {
                                        uint64_t final_off = static_cast<uint64_t>(signed_final);
                                        std::string t = h_signed ? ("int" + std::to_string(h_sz * 8) + "_t") : ("uint" + std::to_string(h_sz * 8) + "_t");
                                        record_access(final_off, h_sz, tinfo_t(), is_write, t);
                                    }
                                }
                            }
                        }

                        // 5. Assignment inspection: check RHS for vtable, string literals, float constants, allocation
                        if (e->op == cot_asg && e->x && e->y) {
                            int64_t off = 0;
                            size_t sz = 0;
                            bool is_field_write = false;

                            if (e->x->op == cot_ptr && e->x->x && is_target(is_target, e->x->x, off)) {
                                sz = e->x->ptrsize > 0 ? static_cast<size_t>(e->x->ptrsize) : e->x->type.get_size();
                                is_field_write = true;
                            } else if ((e->x->op == cot_memptr || e->x->op == cot_memref) && e->x->x && is_target(is_target, e->x->x, off)) {
                                off += e->x->m;
                                sz = e->x->ptrsize > 0 ? static_cast<size_t>(e->x->ptrsize) : e->x->type.get_size();
                                is_field_write = true;
                            } else if (e->x->op == cot_idx && e->x->x && is_target(is_target, e->x->x, off) && e->x->y && e->x->y->op == cot_num) {
                                size_t elem_sz = e->x->type.get_size();
                                if (elem_sz <= 0 || elem_sz == BADSIZE) elem_sz = 1;
                                off += e->x->y->numval() * elem_sz;
                                sz = elem_sz;
                                is_field_write = true;
                            }

                            if (is_field_write) {
                                int64_t signed_final = static_cast<int64_t>(base_off) + off;
                                if (signed_final >= 0) {
                                    uint64_t final_off = static_cast<uint64_t>(signed_final);
                                    const cexpr_t* r = e->y;
                                    while (r && r->op == cot_cast) r = r->x;

                                    ea_t vtbl_ea = BADADDR;
                                    if (r) {
                                        if (r->op == cot_obj) vtbl_ea = r->obj_ea;
                                        else if (r->op == cot_ref && r->x && r->x->op == cot_obj) vtbl_ea = r->x->obj_ea;
                                    }

                                    if (vtbl_ea != BADADDR) {
                                        bool is_vtbl = false;
                                        segment_t* seg = getseg(vtbl_ea);
                                        if (seg && !(seg->perm & SEGPERM_WRITE)) {
                                            ea_t first_method = get_qword(vtbl_ea);
                                            if (first_method != 0 && first_method != BADADDR && get_func(first_method)) {
                                                is_vtbl = true;
                                            }
                                        }
                                        qstring sym_name;
                                        get_name(&sym_name, vtbl_ea);
                                        std::string sname = sym_name.c_str();
                                        if (sname.find("vtbl") != std::string::npos ||
                                            sname.find("vftable") != std::string::npos ||
                                            sname.find("vtable") != std::string::npos ||
                                            sname.find("??_7") != std::string::npos) {
                                            is_vtbl = true;
                                        }

                                        if (is_vtbl) {
                                            record_access(final_off, inf_is_64bit() ? 8 : 4, tinfo_t(), true, "void**", vtbl_ea);
                                        }
                                    } else if (r && (r->op == cot_str || (r->op == cot_obj && is_strlit(get_flags(r->obj_ea))))) {
                                        record_access(final_off, inf_is_64bit() ? 8 : 4, tinfo_t(), true, "const char*");
                                    } else if (r && (r->op == cot_fnum || r->type.is_floating())) {
                                        record_access(final_off, sz == 8 ? 8 : 4, tinfo_t(), true, sz == 8 ? "double" : "float");
                                    }
                                }
                            }

                            // Sniff allocation size: var = operator new(N) or malloc(N)
                            int64_t target_off = 0;
                            if (is_target(is_target, e->x, target_off) && target_off == 0) {
                                const cexpr_t* rhs_call = e->y;
                                while (rhs_call && rhs_call->op == cot_cast) rhs_call = rhs_call->x;
                                if (rhs_call && rhs_call->op == cot_call && rhs_call->a) {
                                    std::string cname = get_cname(rhs_call);
                                    if (!cname.empty()) {
                                        std::string lc = cname;
                                        for (char& c : lc) c = static_cast<char>(std::tolower(c));
                                        uint64_t alloc_sz = 0;
                                        if (lc.find("new") != std::string::npos || lc.find("malloc") != std::string::npos) {
                                            if (!rhs_call->a->empty() && (*rhs_call->a)[0].op == cot_num) {
                                                alloc_sz = (*rhs_call->a)[0].numval();
                                            }
                                        } else if (lc.find("calloc") != std::string::npos) {
                                            if (rhs_call->a->size() >= 2 && (*rhs_call->a)[0].op == cot_num && (*rhs_call->a)[1].op == cot_num) {
                                                alloc_sz = (*rhs_call->a)[0].numval() * (*rhs_call->a)[1].numval();
                                            }
                                        } else if (lc.find("heapalloc") != std::string::npos) {
                                            if (rhs_call->a->size() >= 3 && (*rhs_call->a)[2].op == cot_num) {
                                                alloc_sz = (*rhs_call->a)[2].numval();
                                            }
                                        }
                                        if (alloc_sz > 0 && alloc_sz < 0x200000) {
                                            total_sz = std::max(total_sz, base_off + alloc_sz);
                                            total_sz_src = "allocation (" + cname + ")";
                                        }
                                    }
                                }
                            }
                        }

                        // 6. Sniff memset / memcpy / ZeroMemory
                        if (e->op == cot_call && e->a) {
                            std::string call_name = get_cname(e);
                            if (!call_name.empty()) {
                                std::string lc = call_name;
                                for (char& c : lc) c = static_cast<char>(std::tolower(c));

                                if (lc.find("memset") != std::string::npos ||
                                    lc.find("memzero") != std::string::npos ||
                                    lc.find("bzero") != std::string::npos ||
                                    lc.find("zeromemory") != std::string::npos) {
                                    if (e->a->size() >= 3) {
                                        int64_t off = 0;
                                        if (is_target(is_target, &(*e->a)[0], off)) {
                                            if ((*e->a)[2].op == cot_num) {
                                                uint64_t set_sz = (*e->a)[2].numval();
                                                if (set_sz > 0 && set_sz < 0x200000) {
                                                    total_sz = std::max(total_sz, static_cast<uint64_t>(base_off + off + set_sz));
                                                    total_sz_src = "memset";
                                                }
                                            }
                                        }
                                    }
                                } else if (lc.find("memcpy") != std::string::npos ||
                                           lc.find("memmove") != std::string::npos ||
                                           lc.find("qmemcpy") != std::string::npos) {
                                    if (e->a->size() >= 3) {
                                        int64_t off_dst = 0, off_src = 0;
                                        if (is_target(is_target, &(*e->a)[0], off_dst)) {
                                            if ((*e->a)[2].op == cot_num) {
                                                uint64_t cpy_sz = (*e->a)[2].numval();
                                                if (cpy_sz > 0 && cpy_sz < 0x200000) {
                                                    total_sz = std::max(total_sz, static_cast<uint64_t>(base_off + off_dst + cpy_sz));
                                                    total_sz_src = "memcpy";
                                                }
                                            }
                                        } else if (is_target(is_target, &(*e->a)[1], off_src)) {
                                            if ((*e->a)[2].op == cot_num) {
                                                uint64_t cpy_sz = (*e->a)[2].numval();
                                                if (cpy_sz > 0 && cpy_sz < 0x200000) {
                                                    total_sz = std::max(total_sz, static_cast<uint64_t>(base_off + off_src + cpy_sz));
                                                    total_sz_src = "memcpy";
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // 7. Inter-procedural propagation into called functions
                        if (e->op == cot_call && e->a && depth < max_d) {
                            ea_t callee_ea = (e->x && e->x->op == cot_obj) ? e->x->obj_ea : BADADDR;
                            if (callee_ea != BADADDR) {
                                func_t* callee_fn = get_func(callee_ea);
                                if (callee_fn) {
                                    for (size_t a_idx = 0; a_idx < e->a->size(); ++a_idx) {
                                        int64_t off = 0;
                                        if (is_target(is_target, &(*e->a)[a_idx], off)) {
                                            int64_t next_base = static_cast<int64_t>(base_off) + off;
                                            if (next_base >= 0) {
                                                hexrays_failure_t c_hf;
                                                cfuncptr_t callee_cf = decompile(callee_fn, &c_hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                                                if (callee_cf) {
                                                    const lvars_t* callee_lvars = callee_cf->get_lvars();
                                                    if (callee_lvars) {
                                                        size_t arg_counter = 0;
                                                        for (size_t k = 0; k < callee_lvars->size(); ++k) {
                                                            if ((*callee_lvars)[k].is_arg_var()) {
                                                                if (arg_counter == a_idx) {
                                                                    recurse_fn(callee_fn, static_cast<int>(k), depth + 1, static_cast<uint64_t>(next_base));
                                                                    break;
                                                                }
                                                                arg_counter++;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        return 0;
                    }
                };

                StructVisitor visitor(local_cf, is_alias_base, parse_hexrays_helper, get_callee_name,
                                      observed_fields, current_depth, max_depth, base_offset,
                                      inferred_total_size, inferred_size_source, scan_fn);
                visitor.apply_to(&local_cf->body, nullptr);
            };

            scan_fn(pfn, target_idx, 0, 0);
        });

        if (!found_fn) {
            return tools::utils::MakeToolErrorJson(id, "No function found containing address " + tools::utils::FormatAddress(ea), "function_not_found");
        }
        if (!decompiled_ok) {
            return tools::utils::MakeToolErrorJson(id, "Decompilation failed for function", "decompile_failed");
        }

        // Reconcile overlapping fields: split larger primitives when sub-accesses occur inside them
        for (auto it = observed_fields.begin(); it != observed_fields.end(); ++it) {
            auto next_it = std::next(it);
            if (next_it != observed_fields.end()) {
                uint64_t cur_end = it->first + it->second.size;
                if (next_it->first < cur_end) {
                    if (!it->second.is_pointer && !it->second.is_vftable && next_it->first > it->first) {
                        it->second.size = next_it->first - it->first;
                    }
                }
            }
        }

        // Build clean non-overlapping C struct representation
        nlohmann::json fields_arr = nlohmann::json::array();
        std::ostringstream css;
        css << "#pragma pack(push, 1)\n";
        css << "struct " << struct_name << " {\n";

        uint64_t cur_offset = 0;
        for (const auto& [off, field] : observed_fields) {
            if (off < cur_offset) {
                // Sub-access inside an already emitted field (e.g. pointer/vftable) - do not duplicate
                continue;
            }

            if (off > cur_offset) {
                uint64_t gap = off - cur_offset;
                std::ostringstream pss;
                pss << "0x" << std::hex << cur_offset;
                css << "    /* " << pss.str() << " */ uint8_t _pad_" << pss.str() << "[" << std::dec << gap << "];\n";
                fields_arr.push_back({
                    {"offset", cur_offset},
                    {"offset_hex", pss.str()},
                    {"size", gap},
                    {"type", "uint8_t[]"},
                    {"name", "_pad_" + pss.str()},
                    {"is_padding", true}
                });
                cur_offset = off;
            }

            std::ostringstream oss;
            oss << "0x" << std::hex << off;
            std::string f_type = field.type_name;
            std::string f_name;

            if (field.is_vftable) {
                f_type = "void**";
                f_name = (off == 0) ? "__vftable" : ("__vftable_" + oss.str());
            } else if (f_type == "const char*" || f_type == "char*") {
                f_name = "str_" + oss.str();
            } else if (field.is_pointer) {
                if (f_type.empty() || f_type == "_QWORD" || f_type == "_DWORD") f_type = "void*";
                f_name = "ptr_" + oss.str();
            } else if (field.is_float) {
                f_type = (field.size == 8 ? "double" : "float");
                f_name = "flt_" + oss.str();
            } else {
                if (f_type.empty() || f_type == "_BYTE" || f_type == "_WORD" || f_type == "_DWORD" || f_type == "_QWORD") {
                    switch (field.size) {
                        case 1: f_type = "uint8_t"; break;
                        case 2: f_type = "uint16_t"; break;
                        case 8: f_type = "uint64_t"; break;
                        default: f_type = "uint32_t"; break;
                    }
                }
                f_name = "field_" + oss.str();
            }

            css << "    /* " << oss.str() << " */ " << f_type << " " << f_name << ";\n";
            nlohmann::ordered_json fj;
            fj["offset"] = off;
            fj["offset_hex"] = oss.str();
            fj["size"] = field.size;
            fj["type"] = f_type;
            fj["name"] = f_name;
            fj["is_padding"] = false;
            fj["is_pointer"] = field.is_pointer;
            fj["is_vftable"] = field.is_vftable;
            if (field.vtable_target != BADADDR) {
                fj["vtable_target"] = tools::utils::FormatAddress(field.vtable_target);
            }
            fj["access_count"] = field.access_count;
            nlohmann::json atypes = nlohmann::json::array();
            if (field.has_read) atypes.push_back("read");
            if (field.has_write) atypes.push_back("write");
            fj["access_types"] = atypes;
            fields_arr.push_back(std::move(fj));

            cur_offset = off + field.size;
        }

        if (inferred_total_size > cur_offset) {
            uint64_t gap = inferred_total_size - cur_offset;
            std::ostringstream pss;
            pss << "0x" << std::hex << cur_offset;
            css << "    /* " << pss.str() << " */ uint8_t _pad_tail[" << std::dec << gap << "];\n";
            fields_arr.push_back({
                {"offset", cur_offset},
                {"offset_hex", pss.str()},
                {"size", gap},
                {"type", "uint8_t[]"},
                {"name", "_pad_tail"},
                {"is_padding", true}
            });
            cur_offset = inferred_total_size;
        }

        if (fields_arr.empty()) {
            css << "    /* 0x0 */ uint8_t _dummy;\n";
        }

        css << "};\n";
        css << "#pragma pack(pop)\n";

        // If apply requested: compile to TIL and update lvar under SyncWrite
        if (apply && !observed_fields.empty()) {
            g_parse_errors.clear();
            sync::SyncWrite([&]() {
                int parse_err = parse_decls(get_idati(), css.str().c_str(), DeclPrinter, HTI_DCL | HTI_SEMICOLON | HTI_RELAXED | HTI_PAK1);
                if (parse_err == 0) {
                    lvar_saved_info_t info;
                    if (locate_lvar(&info.ll, fn_start, target_var_name.c_str())) {
                        tinfo_t tif;
                        qstring nbuf;
                        std::string decl_str = "struct " + struct_name + "*;";
                        if (parse_decl(&tif, &nbuf, get_idati(), decl_str.c_str(), PT_SIL | PT_TYP)) {
                            info.type = tif;
                            applied_ok = modify_user_lvar_info(fn_start, MLI_TYPE, info);
                            if (applied_ok) {
                                mark_cfunc_dirty(fn_start, false);
                            }
                        }
                    } else {
                        apply_error = "Could not locate local variable '" + target_var_name + "' in Hex-Rays";
                    }
                } else {
                    apply_error = "TIL parse_decls failed";
                    if (!g_parse_errors.empty()) {
                        apply_error += ": " + tools::utils::SanitizeUtf8(g_parse_errors.c_str());
                    }
                }
            });

            if (applied_ok) {
                cache::InvalidateIDBAnalysis();
            }
        }

        if (decompile_now && applied_ok) {
            sync::SyncRead([&]() {
                func_t* pfn = get_func(fn_start);
                if (pfn) {
                    hexrays_failure_t hf;
                    cfuncptr_t fresh_cf = decompile(pfn, &hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                    if (fresh_cf) {
                        const strvec_t& sv = fresh_cf->get_pseudocode();
                        for (size_t i = 0; i < sv.size(); ++i) {
                            qstring clean;
                            tag_remove(&clean, sv[i].line);
                            updated_decompiled_code += clean.c_str();
                            updated_decompiled_code += "\n";
                        }
                    }
                }
            });
        }

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["function"] = fn_name;
        res["function_addr"] = tools::utils::FormatAddress(fn_start);
        res["var"] = target_var_name;
        res["struct_name"] = struct_name;
        res["fields_count"] = observed_fields.size();
        res["total_size"] = cur_offset;
        res["total_size_hex"] = tools::utils::FormatAddress(cur_offset);
        if (!inferred_size_source.empty()) {
            res["size_source"] = inferred_size_source;
        }
        res["applied"] = applied_ok;
        if (!apply_error.empty()) {
            res["apply_error"] = apply_error;
        }
        res["candidate_vars"] = candidate_vars;
        res["fields"] = fields_arr;
        res["c_code"] = css.str();
        if (!updated_decompiled_code.empty()) {
            res["decompiled_code"] = updated_decompiled_code;
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }
}
