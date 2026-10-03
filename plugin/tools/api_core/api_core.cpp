#include <string>
#include <vector>
#include <algorithm>
#include <chrono>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "api_core.h"
#include "server/status_tracker.h"
#include "tools/utils/utils.h"
#include "sync/sync.h"

#include <ida.hpp>
#include <nalt.hpp>
#include <loader.hpp>
#include <auto.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <name.hpp>
#include <typeinf.hpp>
#include <strlist.hpp>
#include <entry.hpp>
#include <kernwin.hpp>

namespace tools::core {

    bool ApiCore::CanHandle(const std::string& name) const {
        return name == "idb_save" ||
               name == "list_funcs" ||
               name == "list_globals" ||
               name == "imports_query" ||
               name == "get_exports" ||
               name == "get_segments" ||
               name == "search_strings";
    }

    nlohmann::json ApiCore::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "idb_save") return IdbSave(id);
        if (name == "list_funcs") return ListFuncs(id, args);
        if (name == "list_globals") return ListGlobals(id, args);
        if (name == "imports_query") return ImportsQuery(id, args);
        if (name == "get_exports") return GetExports(id);
        if (name == "get_segments") return GetSegments(id);
        if (name == "search_strings") return SearchStrings(id, args);

        return tools::utils::MakeToolErrorJson(id, "Method not found: " + name, "method_not_found");
    }

    nlohmann::json ApiCore::IdbSave(const nlohmann::json& id) {
        bool ok = false;
        bool sync_ok = sync::SyncWrite([&]() {
            ok = save_database(nullptr, 0);
        }, 600000);

        if (!sync_ok || !ok) {
            return tools::utils::MakeToolErrorJson(id, "Failed to save IDB database to disk", "idb_save_failed");
        }

        return tools::utils::MakeToolSuccessJson(id);
    }

    nlohmann::json ApiCore::ListFuncs(const nlohmann::json& id, const nlohmann::json& args) {
        int offset = static_cast<int>(tools::utils::GetIntArg(args, "offset", 0));
        int count = static_cast<int>(tools::utils::GetIntArg(args, "count", 100));
        if (count <= 0) count = 100;
        if (count > 2000) count = 2000;

        std::string pattern = tools::utils::GetStringArg(args, "pattern", "");
        ea_t cursor_ea = tools::utils::GetAddressArg(args, "cursor", BADADDR);
        size_t min_size = static_cast<size_t>(tools::utils::GetIntArg(args, "min_size", 0));
        size_t max_size = static_cast<size_t>(tools::utils::GetIntArg(args, "max_size", static_cast<int64_t>(-1)));

        // Flatten fallback for legacy queries object if passed
        if (args.contains("queries") && args["queries"].is_object()) {
            const auto& q = args["queries"];
            if (q.contains("offset")) offset = static_cast<int>(tools::utils::GetIntArg(q, "offset", offset));
            if (q.contains("count")) count = static_cast<int>(tools::utils::GetIntArg(q, "count", count));
            if (q.contains("pattern")) pattern = tools::utils::GetStringArg(q, "pattern", pattern);
        }

        nlohmann::json funcs_arr = nlohmann::json::array();
        size_t total = 0;
        int next_offset = -1;
        ea_t next_cursor_ea = BADADDR;

        sync::SyncRead([&]() {
            total = get_func_qty();
            size_t start_idx = static_cast<size_t>(std::max(0, offset));

            if (cursor_ea != BADADDR) {
                func_t* f_cur = get_func(cursor_ea);
                if (f_cur) {
                    for (size_t k = 0; k < total; ++k) {
                        func_t* fn = getn_func(k);
                        if (fn && fn->start_ea >= cursor_ea) {
                            start_idx = k;
                            break;
                        }
                    }
                }
            }

            int fetched = 0;
            for (size_t i = start_idx; i < total && fetched < count; ++i) {
                func_t* fn = getn_func(i);
                if (!fn) continue;

                size_t sz = fn->size();
                if (sz < min_size || sz > max_size) continue;

                qstring name_buf;
                get_func_name(&name_buf, fn->start_ea);
                std::string fn_name = tools::utils::SanitizeUtf8(name_buf.c_str());

                if (!pattern.empty() && !tools::utils::PatternMatch(fn_name, pattern)) {
                    continue;
                }

                funcs_arr.push_back({
                    {"address", tools::utils::FormatAddress(fn->start_ea)},
                    {"name", fn_name},
                    {"size", sz}
                });

                fetched++;
                next_offset = static_cast<int>(i + 1);
                if (i + 1 < total) {
                    func_t* nxt = getn_func(i + 1);
                    if (nxt) next_cursor_ea = nxt->start_ea;
                }
            }

            if (next_offset >= static_cast<int>(total)) {
                next_offset = -1;
                next_cursor_ea = BADADDR;
            }
        });

        nlohmann::json res = {
            {"status", "success"},
            {"total", total},
            {"returned", funcs_arr.size()},
            {"functions", funcs_arr}
        };
        if (next_offset != -1) {
            res["next_offset"] = next_offset;
            if (next_cursor_ea != BADADDR) {
                res["next_cursor"] = tools::utils::FormatAddress(next_cursor_ea);
            }
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiCore::ListGlobals(const nlohmann::json& id, const nlohmann::json& args) {
        int offset = static_cast<int>(tools::utils::GetIntArg(args, "offset", 0));
        int count = static_cast<int>(tools::utils::GetIntArg(args, "count", 100));
        if (count <= 0) count = 100;
        if (count > 2000) count = 2000;

        std::string pattern = tools::utils::GetStringArg(args, "pattern", "");
        ea_t cursor_ea = tools::utils::GetAddressArg(args, "cursor", BADADDR);

        nlohmann::json globals_arr = nlohmann::json::array();
        size_t total = 0;
        int next_offset = -1;
        ea_t next_cursor_ea = BADADDR;

        sync::SyncRead([&]() {
            total = get_nlist_size();
            size_t start_idx = static_cast<size_t>(std::max(0, offset));

            if (cursor_ea != BADADDR) {
                for (size_t k = 0; k < total; ++k) {
                    ea_t ea = get_nlist_ea(k);
                    if (ea >= cursor_ea) {
                        start_idx = k;
                        break;
                    }
                }
            }

            int fetched = 0;
            for (size_t i = start_idx; i < total && fetched < count; ++i) {
                ea_t ea = get_nlist_ea(i);
                if (ea == BADADDR || get_func(ea) != nullptr) continue;

                const char* name = get_nlist_name(i);
                if (!name || !*name) continue;

                std::string sym_name = tools::utils::SanitizeUtf8(name);
                if (!pattern.empty() && !tools::utils::PatternMatch(sym_name, pattern)) continue;

                size_t item_size = get_item_size(ea);

                globals_arr.push_back({
                    {"address", tools::utils::FormatAddress(ea)},
                    {"name", sym_name},
                    {"size", item_size}
                });

                fetched++;
                next_offset = static_cast<int>(i + 1);
                if (i + 1 < total) {
                    next_cursor_ea = get_nlist_ea(i + 1);
                }
            }

            if (next_offset >= static_cast<int>(total)) {
                next_offset = -1;
                next_cursor_ea = BADADDR;
            }
        });

        nlohmann::json res = {
            {"status", "success"},
            {"total", total},
            {"returned", globals_arr.size()},
            {"globals", globals_arr}
        };
        if (next_offset != -1) {
            res["next_offset"] = next_offset;
            if (next_cursor_ea != BADADDR) {
                res["next_cursor"] = tools::utils::FormatAddress(next_cursor_ea);
            }
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiCore::ImportsQuery(const nlohmann::json& id, const nlohmann::json& args) {
        int offset = static_cast<int>(tools::utils::GetIntArg(args, "offset", 0));
        std::string cursor_str = tools::utils::GetStringArg(args, "cursor");
        if (!cursor_str.empty()) {
            try { offset = std::stoi(cursor_str); } catch (...) {}
        }
        int count = static_cast<int>(tools::utils::GetIntArg(args, "count", 50));
        if (count <= 0) count = 50;
        if (count > 1000) count = 1000;

        std::string mod_filter = tools::utils::GetStringArg(args, "module", tools::utils::GetStringArg(args, "module_pattern", ""));
        std::string pat_filter = tools::utils::GetStringArg(args, "pattern", "");

        nlohmann::json imports_arr = nlohmann::json::array();
        int next_offset = -1;

        sync::SyncRead([&]() {
            int mod_qty = get_import_module_qty();
            int current_idx = 0;
            int fetched = 0;

            for (int i = 0; i < mod_qty && fetched < count; ++i) {
                qstring mod_name;
                get_import_module_name(&mod_name, i);
                std::string mod_str = mod_name.c_str();

                if (!mod_filter.empty() && !tools::utils::PatternMatch(mod_str, mod_filter)) continue;

                struct Ctx {
                    std::string mod;
                    std::string pat;
                    int offset;
                    int count;
                    int& cur_idx;
                    int& fetched;
                    int& next_offset;
                    nlohmann::json& arr;
                } ctx{mod_str, pat_filter, offset, count, current_idx, fetched, next_offset, imports_arr};

                enum_import_names(i, [](ea_t ea, const char* name, uval_t ord, void* param) -> int {
                    auto& c = *static_cast<Ctx*>(param);
                    if (c.fetched >= c.count) return 0;

                    std::string sym = name ? name : ("ord_" + std::to_string(ord));
                    if (!c.pat.empty() && !tools::utils::PatternMatch(sym, c.pat)) return 1;

                    if (c.cur_idx >= c.offset) {
                        c.arr.push_back({
                            {"module", c.mod},
                            {"address", tools::utils::FormatAddress(ea)},
                            {"name", sym}
                        });
                        c.fetched++;
                        c.next_offset = c.cur_idx + 1;
                    }
                    c.cur_idx++;
                    return 1;
                }, &ctx);
            }
        });

        nlohmann::json res = {
            {"status", "success"},
            {"returned", imports_arr.size()},
            {"imports", imports_arr}
        };
        if (next_offset != -1) {
            res["next_offset"] = next_offset;
            res["next_cursor"] = std::to_string(next_offset);
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiCore::GetExports(const nlohmann::json& id) {
        nlohmann::json exports_arr = nlohmann::json::array();
        sync::SyncRead([&]() {
            size_t qty = get_entry_qty();
            for (size_t i = 0; i < qty; ++i) {
                uval_t ord = get_entry_ordinal(i);
                ea_t ea = get_entry(ord);
                qstring name_buf;
                get_entry_name(&name_buf, ord);
                exports_arr.push_back({
                    {"ordinal", ord},
                    {"address", tools::utils::FormatAddress(ea)},
                    {"name", name_buf.c_str()}
                });
            }
        });

        nlohmann::json res = {
            {"status", "success"},
            {"count", exports_arr.size()},
            {"exports", exports_arr}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiCore::GetSegments(const nlohmann::json& id) {
        nlohmann::json segs_arr = nlohmann::json::array();
        sync::SyncRead([&]() {
            int qty = get_segm_qty();
            for (int i = 0; i < qty; ++i) {
                segment_t* s = getnseg(i);
                if (!s) continue;
                qstring name_buf;
                get_segm_name(&name_buf, s);
                std::string perm = "";
                perm += (s->perm & SEGPERM_READ) ? 'R' : '-';
                perm += (s->perm & SEGPERM_WRITE) ? 'W' : '-';
                perm += (s->perm & SEGPERM_EXEC) ? 'X' : '-';

                segs_arr.push_back({
                    {"name", std::string(name_buf.c_str())},
                    {"start", tools::utils::FormatAddress(s->start_ea)},
                    {"end", tools::utils::FormatAddress(s->end_ea)},
                    {"size", s->size()},
                    {"perm", perm}
                });
            }
        });

        nlohmann::json res = {
            {"status", "success"},
            {"count", segs_arr.size()},
            {"segments", segs_arr}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiCore::SearchStrings(const nlohmann::json& id, const nlohmann::json& args) {
        std::string pattern = tools::utils::GetStringArg(args, "pattern", "");
        if (pattern.empty()) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'pattern' is required", "pattern_required");
        }

        bool rebuild = tools::utils::GetBoolArg(args, "rebuild", false);
        int offset = static_cast<int>(tools::utils::GetIntArg(args, "offset", 0));
        int count = static_cast<int>(tools::utils::GetIntArg(args, "count", 100));
        if (count <= 0) count = 100;
        if (count > 2000) count = 2000;

        ea_t cursor_ea = tools::utils::GetAddressArg(args, "cursor", BADADDR);

        nlohmann::json matches = nlohmann::json::array();
        size_t total_strings = 0;
        int next_offset = -1;
        ea_t next_cursor_ea = BADADDR;

        sync::SyncRead([&]() {
            // Rebuild string list only if explicitly requested or if string list is empty
            if (rebuild || get_strlist_qty() == 0) {
                build_strlist();
            }

            total_strings = get_strlist_qty();
            size_t start_idx = static_cast<size_t>(std::max(0, offset));

            if (cursor_ea != BADADDR) {
                for (size_t k = 0; k < total_strings; ++k) {
                    string_info_t si;
                    if (get_strlist_item(&si, k) && si.ea >= cursor_ea) {
                        start_idx = k;
                        break;
                    }
                }
            }

            int fetched = 0;
            for (size_t i = start_idx; i < total_strings && fetched < count; ++i) {
                if (i % 1000 == 0) {
                    server::PluginStatusTracker::Instance().UpdateProgress(
                        i, total_strings, "Searching strings..."
                    );
                }

                string_info_t si;
                if (!get_strlist_item(&si, i)) continue;

                qstring qstr;
                get_strlit_contents(&qstr, si.ea, si.length, si.type);
                std::string s = tools::utils::SanitizeUtf8(qstr.c_str());

                if (!tools::utils::PatternMatch(s, pattern)) continue;

                matches.push_back({
                    {"address", tools::utils::FormatAddress(si.ea)},
                    {"length", si.length},
                    {"string", s}
                });

                fetched++;
                next_offset = static_cast<int>(i + 1);
                if (i + 1 < total_strings) {
                    string_info_t nxt;
                    if (get_strlist_item(&nxt, i + 1)) {
                        next_cursor_ea = nxt.ea;
                    }
                }
            }

            if (next_offset >= static_cast<int>(total_strings)) {
                next_offset = -1;
                next_cursor_ea = BADADDR;
            }
        });

        nlohmann::json res = {
            {"status", "success"},
            {"total_in_idb", total_strings},
            {"matches_found", matches.size()},
            {"results", matches}
        };
        if (next_offset != -1) {
            res["next_offset"] = next_offset;
            if (next_cursor_ea != BADADDR) {
                res["next_cursor"] = tools::utils::FormatAddress(next_cursor_ea);
            }
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }
}
