#include <string>
#include <vector>
#include <algorithm>
#include <chrono>
#include <filesystem>

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
        return name == "strings" ||
               name == "idb_save" ||
               name == "list_funcs" ||
               name == "list_globals" ||
               name == "imports_query" ||
               name == "get_exports" ||
               name == "get_segments";
    }

    nlohmann::json ApiCore::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "strings") return Strings(id, args);
        if (name == "idb_save") return IdbSave(id, args);
        if (name == "list_funcs") return ListFuncs(id, args);
        if (name == "list_globals") return ListGlobals(id, args);
        if (name == "imports_query") return ImportsQuery(id, args);
        if (name == "get_exports") return GetExports(id, args);
        if (name == "get_segments") return GetSegments(id, args);

        return tools::utils::MakeToolErrorJson(id, "Method not found: " + name, "method_not_found");
    }

    nlohmann::json ApiCore::IdbSave(const nlohmann::json& id, const nlohmann::json& args) {
        bool compact = tools::utils::GetBoolArg(args, "compact", false);
        bool backup = tools::utils::GetBoolArg(args, "backup", false);
        std::string outfile_arg = tools::utils::GetStringArg(args, "outfile", "");

        uint32 flags = 0;
        if (compact) flags |= DBFL_COMP;
        if (backup) flags |= DBFL_BAK;

        bool ok = false;
        std::string idb_path;
        std::string file_name;
        uint64_t db_size = 0;

        bool sync_ok = sync::SyncWrite([&]() {
            const char* out_ptr = outfile_arg.empty() ? nullptr : outfile_arg.c_str();
            ok = save_database(out_ptr, flags);
            if (ok) {
                const char* p = get_path(PATH_TYPE_IDB);
                if (p) idb_path = p;
                char root_buf[QMAXPATH];
                if (get_root_filename(root_buf, sizeof(root_buf)) > 0) {
                    file_name = root_buf;
                }
            }
        }, 600000);

        if (!sync_ok || !ok) {
            return tools::utils::MakeToolErrorJson(id, "Failed to save IDB database to disk", "idb_save_failed");
        }

        if (!idb_path.empty()) {
            std::error_code ec;
            db_size = std::filesystem::file_size(idb_path, ec);
        }

        nlohmann::ordered_json res;
        res["status"] = "success";
        if (!idb_path.empty()) res["path"] = idb_path;
        if (!file_name.empty()) res["file_name"] = file_name;
        if (db_size > 0) {
            res["size"] = db_size;
            res["size_formatted"] = tools::utils::FormatSize(db_size);
        }
        res["compacted"] = compact;
        res["backup_created"] = backup;

        return tools::utils::MakeToolSuccessJson(id, res);
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

        bool do_demangle = tools::utils::GetBoolArg(args, "demangle", true);
        bool named_only = tools::utils::GetBoolArg(args, "named_only", tools::utils::GetBoolArg(args, "user_only", false));
        bool no_thunks = tools::utils::GetBoolArg(args, "no_thunks", false);

        // Flatten fallback for legacy queries object if passed
        if (args.contains("queries") && args["queries"].is_object()) {
            const auto& q = args["queries"];
            if (q.contains("offset")) offset = static_cast<int>(tools::utils::GetIntArg(q, "offset", offset));
            if (q.contains("count")) count = static_cast<int>(tools::utils::GetIntArg(q, "count", count));
            if (q.contains("pattern")) pattern = tools::utils::GetStringArg(q, "pattern", pattern);
        }

        nlohmann::ordered_json funcs_arr = nlohmann::ordered_json::array();
        size_t total = 0;
        int next_offset = -1;
        ea_t next_cursor_ea = BADADDR;

        sync::SyncRead([&]() {
            total = get_func_qty();
            size_t start_idx = static_cast<size_t>(std::max(0, offset));

            if (cursor_ea != BADADDR) {
                int fn_num = get_func_num(cursor_ea);
                if (fn_num >= 0) {
                    start_idx = static_cast<size_t>(fn_num);
                } else {
                    func_t* nxt = get_next_func(cursor_ea);
                    if (nxt) {
                        int nxt_num = get_func_num(nxt->start_ea);
                        if (nxt_num >= 0) start_idx = static_cast<size_t>(nxt_num);
                    }
                }
            }

            int fetched = 0;
            for (size_t i = start_idx; i < total && fetched < count; ++i) {
                func_t* fn = getn_func(i);
                if (!fn) continue;

                size_t sz = fn->size();
                if (sz < min_size || sz > max_size) continue;

                bool is_thunk = (fn->flags & FUNC_THUNK) != 0;
                if (no_thunks && is_thunk) continue;

                qstring name_buf;
                get_func_name(&name_buf, fn->start_ea);
                std::string fn_name = tools::utils::SanitizeUtf8(name_buf.c_str());

                if (named_only) {
                    if (fn_name.rfind("sub_", 0) == 0 || fn_name.rfind("nullsub_", 0) == 0) {
                        continue;
                    }
                }

                std::string demangled_str;
                if (do_demangle) {
                    qstring dem_buf;
                    if (demangle_name(&dem_buf, fn_name.c_str(), 0, DQT_FULL) > 0) {
                        demangled_str = tools::utils::SanitizeUtf8(dem_buf.c_str());
                    }
                }

                if (!pattern.empty()) {
                    bool match_raw = tools::utils::PatternMatch(fn_name, pattern);
                    bool match_dem = !demangled_str.empty() && tools::utils::PatternMatch(demangled_str, pattern);
                    if (!match_raw && !match_dem) {
                        continue;
                    }
                }

                nlohmann::ordered_json item;
                item["address"] = tools::utils::FormatAddress(fn->start_ea);
                item["name"] = fn_name;
                if (!demangled_str.empty()) {
                    item["demangled"] = demangled_str;
                }
                item["size"] = sz;
                if (is_thunk) {
                    item["is_thunk"] = true;
                }
                if (fn->flags & FUNC_LIB) {
                    item["is_lib"] = true;
                }

                funcs_arr.push_back(std::move(item));

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

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["total"] = total;
        res["returned"] = funcs_arr.size();
        res["functions"] = funcs_arr;

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

        std::string seg_name_arg = tools::utils::GetStringArg(args, "segment", tools::utils::GetStringArg(args, "seg"));
        bool data_only = tools::utils::GetBoolArg(args, "data_only", false);
        bool writable_only = tools::utils::GetBoolArg(args, "writable_only", false);
        bool do_demangle = tools::utils::GetBoolArg(args, "demangle", true);
        bool include_code_labels = tools::utils::GetBoolArg(args, "include_code_labels", false);

        nlohmann::ordered_json globals_arr = nlohmann::ordered_json::array();
        size_t total = 0;
        int next_offset = -1;
        ea_t next_cursor_ea = BADADDR;

        sync::SyncRead([&]() {
            total = get_nlist_size();
            size_t start_idx = static_cast<size_t>(std::max(0, offset));

            // Fast binary search to find cursor index instead of linear O(N) scan
            if (cursor_ea != BADADDR && total > 0) {
                size_t low = 0;
                size_t high = total;
                while (low < high) {
                    size_t mid = low + (high - low) / 2;
                    ea_t mid_ea = get_nlist_ea(mid);
                    if (mid_ea < cursor_ea) {
                        low = mid + 1;
                    } else {
                        high = mid;
                    }
                }
                start_idx = low;
            }

            int fetched = 0;
            for (size_t i = start_idx; i < total && fetched < count; ++i) {
                ea_t ea = get_nlist_ea(i);
                if (ea == BADADDR || get_func(ea) != nullptr) continue;

                const char* name = get_nlist_name(i);
                if (!name || !*name) continue;

                // Check segment filters
                segment_t* seg = getseg(ea);
                qstring seg_name;
                if (seg) get_segm_name(&seg_name, seg);

                if (!seg_name_arg.empty()) {
                    if (seg_name.c_str() != seg_name_arg && !tools::utils::PatternMatch(seg_name.c_str(), seg_name_arg)) {
                        continue;
                    }
                }

                bool is_exec = (seg && (seg->perm & SEGPERM_EXEC));
                bool is_writable = (seg && (seg->perm & SEGPERM_WRITE));

                if (writable_only && !is_writable) continue;
                if (data_only && is_exec) continue;

                std::string sym_name = tools::utils::SanitizeUtf8(name);

                // By default, filter out switch jump tables and case labels unless explicitly requested
                if (!include_code_labels && seg_name_arg.empty()) {
                    if (sym_name.rfind("jpt_", 0) == 0 || sym_name.rfind("def_", 0) == 0 || sym_name.rfind("loc_", 0) == 0) {
                        continue;
                    }
                }

                std::string demangled_str;
                if (do_demangle) {
                    qstring dem_buf;
                    if (demangle_name(&dem_buf, sym_name.c_str(), 0, DQT_FULL) > 0) {
                        demangled_str = tools::utils::SanitizeUtf8(dem_buf.c_str());
                    }
                }

                if (!pattern.empty()) {
                    bool match_raw = tools::utils::PatternMatch(sym_name, pattern);
                    bool match_dem = !demangled_str.empty() && tools::utils::PatternMatch(demangled_str, pattern);
                    if (!match_raw && !match_dem) continue;
                }

                size_t item_size = get_item_size(ea);

                nlohmann::ordered_json item;
                item["address"] = tools::utils::FormatAddress(ea);
                item["name"] = sym_name;
                if (!demangled_str.empty()) {
                    item["demangled"] = demangled_str;
                }

                tinfo_t tif;
                if (get_tinfo(&tif, ea)) {
                    qstring qtyp;
                    if (tif.print(&qtyp)) {
                        item["type"] = tools::utils::SanitizeUtf8(qtyp.c_str());
                    }
                }

                item["size"] = item_size;
                if (seg) {
                    item["segment"] = seg_name.c_str();
                    if (is_writable) item["writable"] = true;
                }

                globals_arr.push_back(std::move(item));

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

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["total"] = total;
        res["returned"] = globals_arr.size();
        res["globals"] = globals_arr;

        if (next_offset != -1) {
            res["next_offset"] = next_offset;
            if (next_cursor_ea != BADADDR) {
                res["next_cursor"] = tools::utils::FormatAddress(next_cursor_ea);
            }
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiCore::ImportsQuery(const nlohmann::json& id, const nlohmann::json& args) {
        bool modules_only = tools::utils::GetBoolArg(args, "modules_only", false);
        if (modules_only) {
            nlohmann::ordered_json mods_arr = nlohmann::ordered_json::array();
            sync::SyncRead([&]() {
                int mod_qty = get_import_module_qty();
                for (int i = 0; i < mod_qty; ++i) {
                    qstring mod_name;
                    get_import_module_name(&mod_name, i);
                    mods_arr.push_back(mod_name.c_str());
                }
            });
            nlohmann::ordered_json res;
            res["status"] = "success";
            res["count"] = mods_arr.size();
            res["modules"] = mods_arr;
            return tools::utils::MakeToolSuccessJson(id, res);
        }

        int offset = static_cast<int>(tools::utils::GetIntArg(args, "offset", 0));
        std::string cursor_str = tools::utils::GetStringArg(args, "cursor");
        if (!cursor_str.empty()) {
            try { offset = std::stoi(cursor_str); } catch (...) {}
        }
        if (offset < 0) offset = 0;

        int count = static_cast<int>(tools::utils::GetIntArg(args, "count", 50));
        if (count <= 0) count = 50;
        if (count > 1000) count = 1000;

        std::string mod_filter = tools::utils::GetStringArg(args, "module", tools::utils::GetStringArg(args, "module_pattern", ""));
        std::string pat_filter = tools::utils::GetStringArg(args, "pattern", "");
        ea_t target_ea = tools::utils::GetAddressArg(args, "addr", BADADDR);

        nlohmann::ordered_json imports_arr = nlohmann::ordered_json::array();
        size_t total_matched = 0;
        int next_offset = -1;

        sync::SyncRead([&]() {
            int mod_qty = get_import_module_qty();
            size_t match_idx = 0;

            for (int i = 0; i < mod_qty; ++i) {
                qstring mod_name;
                get_import_module_name(&mod_name, i);
                std::string mod_str = mod_name.c_str();

                if (!mod_filter.empty() && !tools::utils::PatternMatch(mod_str, mod_filter)) continue;

                struct Ctx {
                    std::string mod;
                    std::string pat;
                    ea_t target_ea;
                    size_t offset;
                    size_t count;
                    size_t& match_idx;
                    nlohmann::ordered_json& arr;
                } ctx{mod_str, pat_filter, target_ea, static_cast<size_t>(offset), static_cast<size_t>(count), match_idx, imports_arr};

                enum_import_names(i, [](ea_t ea, const char* name, uval_t ord, void* param) -> int {
                    auto& c = *static_cast<Ctx*>(param);

                    if (c.target_ea != BADADDR && ea != c.target_ea) {
                        return 1;
                    }

                    std::string sym = name ? name : ("ord_" + std::to_string(ord));
                    if (!c.pat.empty() && !tools::utils::PatternMatch(sym, c.pat)) {
                        return 1;
                    }

                    if (c.match_idx >= c.offset && c.arr.size() < c.count) {
                        nlohmann::ordered_json item;
                        item["module"] = c.mod;
                        item["name"] = sym;
                        item["address"] = tools::utils::FormatAddress(ea);
                        c.arr.push_back(std::move(item));
                    }
                    c.match_idx++;
                    return 1;
                }, &ctx);
            }

            total_matched = match_idx;
            if (static_cast<size_t>(offset) + imports_arr.size() < total_matched) {
                next_offset = offset + static_cast<int>(imports_arr.size());
            }
        });

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["total"] = total_matched;
        res["count"] = imports_arr.size();
        res["imports"] = imports_arr;
        if (next_offset != -1) {
            res["next_offset"] = next_offset;
        }

        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiCore::GetExports(const nlohmann::json& id, const nlohmann::json& args) {
        int offset = static_cast<int>(tools::utils::GetIntArg(args, "offset", 0));
        if (offset < 0) offset = 0;
        int count = static_cast<int>(tools::utils::GetIntArg(args, "count", 100));
        if (count <= 0) count = 100;
        if (count > 2000) count = 2000;

        std::string pattern = tools::utils::GetStringArg(args, "pattern", "");
        ea_t target_ea = tools::utils::GetAddressArg(args, "addr", BADADDR);
        int64_t target_ord = tools::utils::GetIntArg(args, "ordinal", -1);
        bool do_demangle = tools::utils::GetBoolArg(args, "demangle", true);

        nlohmann::ordered_json exports_arr = nlohmann::ordered_json::array();
        size_t total_matched = 0;
        int next_offset = -1;

        sync::SyncRead([&]() {
            size_t qty = get_entry_qty();
            size_t match_idx = 0;

            for (size_t i = 0; i < qty; ++i) {
                uval_t ord = get_entry_ordinal(i);
                if (target_ord >= 0 && static_cast<int64_t>(ord) != target_ord) {
                    continue;
                }

                ea_t ea = get_entry(ord);
                if (target_ea != BADADDR && ea != target_ea) {
                    continue;
                }

                qstring name_buf;
                get_entry_name(&name_buf, ord);
                std::string name_str = name_buf.c_str();

                qstring dem_buf;
                bool has_demangled = false;
                if (do_demangle && demangle_name(&dem_buf, name_str.c_str(), 0, DQT_FULL) > 0) {
                    has_demangled = true;
                }

                if (!pattern.empty()) {
                    bool matched = tools::utils::PatternMatch(name_str, pattern, false);
                    if (!matched && has_demangled) {
                        matched = tools::utils::PatternMatch(dem_buf.c_str(), pattern, false);
                    }
                    if (!matched) {
                        continue;
                    }
                }

                if (match_idx >= static_cast<size_t>(offset) && exports_arr.size() < static_cast<size_t>(count)) {
                    nlohmann::ordered_json item;
                    item["name"] = name_str;
                    if (has_demangled) {
                        item["demangled"] = std::string(dem_buf.c_str());
                    }
                    item["address"] = tools::utils::FormatAddress(ea);
                    item["ordinal"] = ord;
                    exports_arr.push_back(std::move(item));
                }

                match_idx++;
            }

            total_matched = match_idx;
            if (static_cast<size_t>(offset) + exports_arr.size() < total_matched) {
                next_offset = offset + static_cast<int>(exports_arr.size());
            }
        });

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["total"] = total_matched;
        res["count"] = exports_arr.size();
        res["exports"] = exports_arr;
        if (next_offset != -1) {
            res["next_offset"] = next_offset;
        }

        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiCore::GetSegments(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t target_ea = tools::utils::GetAddressArg(args, "addr", BADADDR);
        std::string name_filter = tools::utils::GetStringArg(args, "name", "");

        nlohmann::ordered_json segs_arr = nlohmann::ordered_json::array();
        sync::SyncRead([&]() {
            if (target_ea != BADADDR) {
                segment_t* s = getseg(target_ea);
                if (s) {
                    qstring name_buf;
                    get_segm_name(&name_buf, s);
                    std::string perm = "";
                    perm += (s->perm & SEGPERM_READ) ? 'R' : '-';
                    perm += (s->perm & SEGPERM_WRITE) ? 'W' : '-';
                    perm += (s->perm & SEGPERM_EXEC) ? 'X' : '-';

                    nlohmann::ordered_json item;
                    item["name"] = std::string(name_buf.c_str());
                    item["start"] = tools::utils::FormatAddress(s->start_ea);
                    item["end"] = tools::utils::FormatAddress(s->end_ea);
                    item["size"] = s->size();
                    item["perm"] = perm;
                    segs_arr.push_back(std::move(item));
                }
                return;
            }

            int qty = get_segm_qty();
            for (int i = 0; i < qty; ++i) {
                segment_t* s = getnseg(i);
                if (!s) continue;
                qstring name_buf;
                get_segm_name(&name_buf, s);
                std::string sname = name_buf.c_str();

                if (!name_filter.empty() && !tools::utils::PatternMatch(sname, name_filter, false)) {
                    continue;
                }

                std::string perm = "";
                perm += (s->perm & SEGPERM_READ) ? 'R' : '-';
                perm += (s->perm & SEGPERM_WRITE) ? 'W' : '-';
                perm += (s->perm & SEGPERM_EXEC) ? 'X' : '-';

                nlohmann::ordered_json item;
                item["name"] = sname;
                item["start"] = tools::utils::FormatAddress(s->start_ea);
                item["end"] = tools::utils::FormatAddress(s->end_ea);
                item["size"] = s->size();
                item["perm"] = perm;
                segs_arr.push_back(std::move(item));
            }
        });

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["count"] = segs_arr.size();
        res["segments"] = segs_arr;

        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiCore::SearchStrings(const nlohmann::json& id, const nlohmann::json& args) {
        std::string pattern = tools::utils::GetStringArg(args, "pattern", "*");
        if (pattern.empty()) pattern = "*";

        bool rebuild = tools::utils::GetBoolArg(args, "rebuild", false);
        int offset = static_cast<int>(tools::utils::GetIntArg(args, "offset", 0));
        int count = static_cast<int>(tools::utils::GetIntArg(args, "count", 100));
        if (count <= 0) count = 100;
        if (count > 2000) count = 2000;

        std::string req_type = tools::utils::GetStringArg(args, "type", "");
        std::transform(req_type.begin(), req_type.end(), req_type.begin(), ::tolower);

        ea_t cursor_ea = tools::utils::GetAddressArg(args, "cursor", BADADDR);

        nlohmann::ordered_json matches = nlohmann::ordered_json::array();
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

            if (cursor_ea != BADADDR && total_strings > 0) {
                size_t low = 0;
                size_t high = total_strings;
                while (low < high) {
                    size_t mid = low + (high - low) / 2;
                    string_info_t si;
                    if (get_strlist_item(&si, mid) && si.ea < cursor_ea) {
                        low = mid + 1;
                    } else {
                        high = mid;
                    }
                }
                start_idx = low;
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

                uchar code = get_str_type_code(si.type);
                if (!req_type.empty() && req_type != "all" && req_type != "any") {
                    if ((req_type == "utf16" || req_type == "utf-16" || req_type == "wide") && code != 1) continue;
                    if ((req_type == "ascii" || req_type == "utf8" || req_type == "utf-8" || req_type == "c") && code != 0) continue;
                    if ((req_type == "utf32" || req_type == "utf-32") && code != 2) continue;
                    if (req_type == "pascal" && (code < 3 || code > 5)) continue;
                }

                qstring qstr;
                get_strlit_contents(&qstr, si.ea, si.length, si.type);
                std::string s = tools::utils::SanitizeUtf8(qstr.c_str());

                if (pattern != "*" && !tools::utils::PatternMatch(s, pattern)) continue;

                std::string type_name = "ascii/utf-8";
                if (code == 1) type_name = "utf-16";
                else if (code == 2) type_name = "utf-32";
                else if (code == 3) type_name = "pascal";
                else if (code == 4) type_name = "pascal-16";
                else if (code == 5) type_name = "pascal-32";

                nlohmann::ordered_json item;
                item["address"] = tools::utils::FormatAddress(si.ea);
                item["string"] = s;
                item["length"] = s.size();
                item["type"] = type_name;
                matches.push_back(std::move(item));

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

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["total_in_idb"] = total_strings;
        res["matches_found"] = matches.size();
        res["results"] = matches;

        if (next_offset != -1) {
            res["next_offset"] = next_offset;
            if (next_cursor_ea != BADADDR) {
                res["next_cursor"] = tools::utils::FormatAddress(next_cursor_ea);
            }
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    namespace {
        bool ReadSingleString(ea_t ea, const std::string& req_type, nlohmann::ordered_json& out_obj, std::string& err_msg) {
            segment_t* seg = nullptr;
            bool loaded = false;
            sync::SyncRead([&]() {
                seg = getseg(ea);
                loaded = is_loaded(ea);
            });

            if (!seg && !loaded) {
                err_msg = "Address " + tools::utils::FormatAddress(ea) + " is outside mapped binary segments";
                return false;
            }
            if (!loaded) {
                err_msg = "Address " + tools::utils::FormatAddress(ea) + " is uninitialized or not loaded in database";
                return false;
            }

            std::string lower_type = req_type;
            std::transform(lower_type.begin(), lower_type.end(), lower_type.begin(), ::tolower);

            std::string str_val;
            int32 effective_st = -1;
            bool ok = false;

            sync::SyncRead([&]() {
                if (lower_type == "utf16" || lower_type == "utf-16" || lower_type == "wide" || lower_type == "wchar") {
                    effective_st = STRTYPE_C_16;
                } else if (lower_type == "utf32" || lower_type == "utf-32") {
                    effective_st = STRTYPE_C_32;
                } else if (lower_type == "pascal") {
                    effective_st = STRTYPE_PASCAL;
                } else if (lower_type == "ascii" || lower_type == "utf8" || lower_type == "utf-8" || lower_type == "c") {
                    effective_st = STRTYPE_C;
                } else {
                    int32 st = get_str_type(ea);
                    if (st != -1 && static_cast<uint32>(st) != 0xFFFFFFFF) {
                        effective_st = st;
                    } else {
                        size_t l_16 = get_max_strlit_length(ea, STRTYPE_C_16, ALOPT_ONLYTERM);
                        size_t l_c = get_max_strlit_length(ea, STRTYPE_C, ALOPT_ONLYTERM);
                        if (l_16 > 2 && (l_c <= 2 || l_16 > l_c * 2)) {
                            effective_st = STRTYPE_C_16;
                        } else if (l_c > 0) {
                            effective_st = STRTYPE_C;
                        } else if (l_16 > 0) {
                            effective_st = STRTYPE_C_16;
                        }
                    }
                }

                if (effective_st != -1) {
                    size_t len = get_max_strlit_length(ea, effective_st, ALOPT_ONLYTERM);
                    if (len == 0) {
                        int32 db_st = get_str_type(ea);
                        if (db_st != -1 && static_cast<uint32>(db_st) != 0xFFFFFFFF) {
                            len = get_max_strlit_length(ea, effective_st, 0);
                        }
                    }

                    constexpr size_t MAX_STR_LEN = 16384;
                    if (len > MAX_STR_LEN) len = MAX_STR_LEN;

                    if (len > 0) {
                        qstring qstr;
                        if (get_strlit_contents(&qstr, ea, len, effective_st) > 0) {
                            ok = true;
                            str_val = tools::utils::SanitizeUtf8(qstr.c_str());
                        }
                    }
                }
            });

            if (!ok) {
                err_msg = "No string literal found at address " + tools::utils::FormatAddress(ea);
                return false;
            }

            std::string type_name = "ascii/utf-8";
            uchar code = get_str_type_code(effective_st);
            if (code == 1) type_name = "utf-16";
            else if (code == 2) type_name = "utf-32";
            else if (code == 3) type_name = "pascal";
            else if (code == 4) type_name = "pascal-16";
            else if (code == 5) type_name = "pascal-32";

            out_obj["address"] = tools::utils::FormatAddress(ea);
            out_obj["string"] = str_val;
            out_obj["length"] = str_val.size();
            out_obj["type"] = type_name;
            return true;
        }
    }

    nlohmann::json ApiCore::Strings(const nlohmann::json& id, const nlohmann::json& args) {
        // 1. Batch read strings at addresses
        if (args.contains("addrs") && args["addrs"].is_array()) {
            std::string req_type = tools::utils::GetStringArg(args, "type", tools::utils::GetStringArg(args, "encoding", "auto"));
            nlohmann::json strings_arr = nlohmann::json::array();
            for (const auto& a : args["addrs"]) {
                ea_t ea = BADADDR;
                if (a.is_string()) ea = tools::utils::ParseAddress(a.get<std::string>());
                else if (a.is_number_integer()) ea = static_cast<ea_t>(a.get<uint64_t>());
                if (ea == BADADDR) continue;

                nlohmann::ordered_json item;
                std::string err;
                if (ReadSingleString(ea, req_type, item, err)) {
                    item["status"] = "success";
                    strings_arr.push_back(std::move(item));
                } else {
                    strings_arr.push_back({
                        {"status", "error"},
                        {"address", tools::utils::FormatAddress(ea)},
                        {"message", err}
                    });
                }
            }

            nlohmann::ordered_json res;
            res["status"] = "success";
            res["count"] = strings_arr.size();
            res["strings"] = strings_arr;
            return tools::utils::MakeToolSuccessJson(id, res);
        }

        // 2. Single address read
        if (args.contains("addr") || args.contains("address")) {
            ea_t ea = tools::utils::GetAddressArg(args, "addr");
            if (ea == BADADDR) ea = tools::utils::GetAddressArg(args, "address");
            if (ea == BADADDR) {
                return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
            }

            std::string req_type = tools::utils::GetStringArg(args, "type", tools::utils::GetStringArg(args, "encoding", "auto"));
            nlohmann::ordered_json item;
            std::string err;
            if (!ReadSingleString(ea, req_type, item, err)) {
                return tools::utils::MakeToolErrorJson(id, err, "read_failed");
            }
            item["status"] = "success";
            return tools::utils::MakeToolSuccessJson(id, item);
        }

        // 3. Search IDB strings list mode (pattern, query, or listing)
        return SearchStrings(id, args);
    }
}
