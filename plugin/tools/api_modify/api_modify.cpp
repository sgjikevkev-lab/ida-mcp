#include <string>
#include <vector>
#include <algorithm>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "api_modify.h"
#include "tools/utils/utils.h"
#include "sync/sync.h"
#include "sync/cache_manager.h"

#include <ida.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <lines.hpp>
#include <xref.hpp>
#include <nalt.hpp>
#include <typeinf.hpp>
#include <hexrays.hpp>
#include <kernwin.hpp>

namespace tools::modify {
    namespace {
        constexpr size_t MAX_INCLUDED_CODE_BYTES = 512 * 1024;

        std::pair<std::string, bool> DecompileFunctionCode(func_t* fn) {
            if (!fn || !init_hexrays_plugin()) return {"", false};
            hexrays_failure_t hf;
            cfuncptr_t cfunc = decompile(fn, &hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
            if (!cfunc) return {"", false};
            std::string code;
            code.reserve((std::min)(MAX_INCLUDED_CODE_BYTES, size_t(64 * 1024)));
            bool truncated = false;
            const strvec_t& sv = cfunc->get_pseudocode();
            for (size_t i = 0; i < sv.size(); ++i) {
                sync::Checkpoint();
                qstring clean_line;
                tag_remove(&clean_line, sv[i].line.c_str());
                const char* line = clean_line.c_str();
                size_t line_size = clean_line.length();
                size_t remaining = MAX_INCLUDED_CODE_BYTES - code.size();
                if (remaining == 0) {
                    truncated = true;
                    break;
                }
                size_t take = (std::min)(line_size, remaining);
                code += tools::utils::SanitizeUtf8(std::string(line, take));
                if (take == line_size && code.size() < MAX_INCLUDED_CODE_BYTES) {
                    code.push_back('\n');
                }
                if (take < line_size || code.size() >= MAX_INCLUDED_CODE_BYTES) {
                    truncated = i + 1 < sv.size() || take < line_size;
                    break;
                }
            }
            return {std::move(code), truncated};
        }
    }

    nlohmann::json ApiModify::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "refactor") return Refactor(id, args);
        return tools::utils::MakeToolErrorJson(id, "Method not found: " + name, "method_not_found");
    }

    nlohmann::json ApiModify::Refactor(const nlohmann::json& id, const nlohmann::json& args) {
        std::vector<nlohmann::json> items;
        bool is_batch = false;

        if (args.contains("items") && args["items"].is_array()) {
            is_batch = true;
            for (const auto& item : args["items"]) {
                sync::Checkpoint();
                if (item.is_object()) items.push_back(item);
            }
        } else {
            items.push_back(args);
        }

        if (args.contains("all") && args["all"].is_boolean() && args["all"].get<bool>()) {
            size_t invalidated_count = 0;
            sync::SyncWrite([&]() {
                if (init_hexrays_plugin()) {
                    size_t total = get_func_qty();
                    for (size_t i = 0; i < total; ++i) {
                        sync::Checkpoint();
                        func_t* fn = getn_func(i);
                        if (fn && fn->start_ea != BADADDR) {
                            mark_cfunc_dirty(fn->start_ea);
                            invalidated_count++;
                        }
                    }
                }
            });
            cache::InvalidateIDBAnalysis();
            nlohmann::ordered_json resp;
            resp["status"] = "success";
            resp["invalidated_count"] = invalidated_count;
            resp["cache_cleared"] = true;
            return tools::utils::MakeToolSuccessJson(id, resp);
        }

        std::set<ea_t> affected_funcs;
        nlohmann::json results = nlohmann::json::array();
        size_t succeeded_count = 0;
        size_t failed_count = 0;
        size_t partial_count = 0;

        sync::SyncWrite([&]() {
            for (const auto& item : items) {
                sync::Checkpoint();
                ea_t ea = tools::utils::GetAddressArg(item, "target");
                if (ea == BADADDR) ea = tools::utils::GetAddressArg(item, "addr");
                if (ea == BADADDR) ea = tools::utils::GetAddressArg(item, "func");
                if (ea == BADADDR) ea = tools::utils::GetAddressArg(item, "address");

                if (ea == BADADDR) {
                    failed_count++;
                    results.push_back({
                        {"status", "error"},
                        {"message", "Target address or symbol name could not be resolved"}
                    });
                    continue;
                }

                func_t* fn = get_func(ea);
                bool is_func_entry = (fn != nullptr && fn->start_ea == ea);
                std::string sym_type = is_func_entry ? "function" : (fn != nullptr ? "instruction" : "data");

                nlohmann::ordered_json item_res;
                bool item_succeeded = false;
                bool item_failed = false;
                item_res["address"] = tools::utils::FormatAddress(ea);
                item_res["symbol_type"] = sym_type;

                // 1. Rename
                if (item.contains("name") || item.contains("reset_name") || item.contains("reset")) {
                    bool reset = tools::utils::GetBoolArg(item, "reset_name", tools::utils::GetBoolArg(item, "reset", false));
                    std::string new_name = reset ? "" : tools::utils::GetStringArg(item, "name");

                    qstring old_buf;
                    get_ea_name(&old_buf, ea);
                    item_res["old_name"] = old_buf.c_str();

                    if (reset || !new_name.empty()) {
                        if (set_name(ea, new_name.c_str(), SN_NOWARN | SN_NOCHECK)) {
                            qstring act_buf;
                            get_ea_name(&act_buf, ea);
                            item_res["new_name"] = act_buf.c_str();
                            qstring dem;
                            if (demangle_name(&dem, act_buf.c_str(), 0, DQT_FULL) > 0) {
                                item_res["demangled"] = dem.c_str();
                            }
                            if (fn) affected_funcs.insert(fn->start_ea);
                            item_succeeded = true;
                        } else {
                            item_res["name_error"] = "set_name failed (already exists or invalid characters)";
                            item_failed = true;
                        }
                    } else {
                        item_res["name_error"] = "A non-empty name or reset_name=true is required";
                        item_failed = true;
                    }
                }

                // 2. Type / Prototype
                if (item.contains("type")) {
                    std::string type_decl = tools::utils::GetStringArg(item, "type");
                    if (!type_decl.empty()) {
                        tinfo_t cur_tif;
                        if (get_tinfo(&cur_tif, ea)) {
                            qstring cur_str;
                            cur_tif.print(&cur_str, nullptr, PRTYPE_1LINE | PRTYPE_SEMI);
                            item_res["old_type"] = cur_str.c_str();
                        }

                        tinfo_t tif;
                        qstring name_buf;
                        std::string decl_to_parse = type_decl;
                        if (decl_to_parse.find(';') == std::string::npos) decl_to_parse += ";";

                        bool parsed = parse_decl(&tif, &name_buf, get_idati(), decl_to_parse.c_str(), PT_SIL | PT_TYP);
                        if (!parsed) {
                            auto paren_pos = type_decl.find('(');
                            if (paren_pos != std::string::npos) {
                                std::string with_dummy = type_decl.substr(0, paren_pos) + " dummy_fn" + type_decl.substr(paren_pos) + ";";
                                parsed = parse_decl(&tif, &name_buf, get_idati(), with_dummy.c_str(), PT_SIL | PT_TYP);
                            } else {
                                std::string with_var = type_decl + " dummy_var;";
                                parsed = parse_decl(&tif, &name_buf, get_idati(), with_var.c_str(), PT_SIL | PT_TYP);
                            }
                        }

                        if (parsed && apply_tinfo(ea, tif, TINFO_DEFINITE)) {
                            qstring new_str;
                            tif.print(&new_str, nullptr, PRTYPE_1LINE | PRTYPE_SEMI);
                            item_res["new_type"] = new_str.c_str();
                            if (fn) affected_funcs.insert(fn->start_ea);
                            item_succeeded = true;
                        } else {
                            item_res["type_error"] = "Failed to parse or apply type";
                            item_failed = true;
                        }
                    } else {
                        item_res["type_error"] = "Type declaration must not be empty";
                        item_failed = true;
                    }
                }

                // 3. Comment
                if (item.contains("comment") || item.contains("clear_comment")) {
                    bool clear_cmt = tools::utils::GetBoolArg(item, "clear_comment", false);
                    std::string cmt = clear_cmt ? "" : tools::utils::GetStringArg(item, "comment");
                    bool repeatable = tools::utils::GetBoolArg(item, "repeatable", false);
                    bool func_cmt = tools::utils::GetBoolArg(item, "func_comment", false);

                    qstring cur_cmt;
                    get_cmt(&cur_cmt, ea, repeatable);
                    item_res["old_comment"] = cur_cmt.c_str();

                    bool comment_ok = std::string(cur_cmt.c_str()) == cmt || set_cmt(ea, cmt.c_str(), repeatable);
                    if (func_cmt && !fn) comment_ok = false;
                    if (fn) {
                        if (func_cmt || fn->start_ea == ea) {
                            qstring old_func_cmt;
                            get_func_cmt(&old_func_cmt, fn, repeatable);
                            if (std::string(old_func_cmt.c_str()) != cmt && !set_func_cmt(fn, cmt.c_str(), repeatable))
                                comment_ok = false;
                        }
                        if (init_hexrays_plugin()) {
                            user_cmts_t* ucmts = restore_user_cmts(fn->start_ea);
                            if (!ucmts) ucmts = user_cmts_new();
                            if (ucmts) {
                                treeloc_t tl;
                                tl.ea = ea;
                                tl.itp = ITP_SEMI;
                                if (cmt.empty()) ucmts->erase(tl);
                                else (*ucmts)[tl] = citem_cmt_t(cmt.c_str());
                                save_user_cmts(fn->start_ea, ucmts);
                                user_cmts_free(ucmts);
                            } else comment_ok = false;
                        }
                        affected_funcs.insert(fn->start_ea);
                    }
                    item_res["new_comment"] = cmt;
                    if (comment_ok) item_succeeded = true;
                    else {
                        item_res["comment_error"] = "IDA failed to apply the requested comment";
                        item_failed = true;
                    }
                }

                // 4. Local variables
                if (item.contains("lvars") && item["lvars"].is_array() && fn != nullptr) {
                    if (init_hexrays_plugin()) {
                        hexrays_failure_t hf;
                        cfuncptr_t cfunc = decompile(fn, &hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                        if (cfunc) {
                            nlohmann::json lvar_results = nlohmann::json::array();
                            for (const auto& lv_item : item["lvars"]) {
                                sync::Checkpoint();
                                if (!lv_item.is_object()) continue;
                                std::string cur_lv_name = tools::utils::GetStringArg(lv_item, "name");
                                std::string new_lv_name = tools::utils::GetStringArg(lv_item, "new_name");
                                std::string lv_type_str = tools::utils::GetStringArg(lv_item, "type");
                                lvar_saved_info_t lv_info;
                                bool found_lvar = false;
                                if (lv_item.contains("index")) {
                                    const auto index = lv_item["index"].get<size_t>();
                                    const auto* lvars = cfunc->get_lvars();
                                    if (lvars && index < lvars->size()) {
                                        const lvar_t& selected = (*lvars)[index];
                                        lv_info.ll = static_cast<const lvar_locator_t&>(selected);
                                        cur_lv_name = selected.name.c_str();
                                        found_lvar = true;
                                    }
                                } else if (!cur_lv_name.empty()) {
                                    found_lvar = locate_lvar(&lv_info.ll, fn->start_ea, cur_lv_name.c_str());
                                }

                                nlohmann::ordered_json lv_r;
                                if (lv_item.contains("index")) lv_r["index"] = lv_item["index"];
                                if (!cur_lv_name.empty()) lv_r["name"] = cur_lv_name;
                                bool lv_succeeded = false;
                                bool lv_failed = false;
                                std::vector<std::string> lv_errors;
                                if (!found_lvar) {
                                    lv_errors.push_back(lv_item.contains("index") ?
                                        "Local variable index is out of range" : "Local variable name was not found");
                                    lv_failed = true;
                                } else if (new_lv_name.empty() && lv_type_str.empty()) {
                                    lv_errors.push_back("At least one of new_name or type is required");
                                    lv_failed = true;
                                } else {
                                    if (!new_lv_name.empty()) {
                                        if (new_lv_name == cur_lv_name) {
                                            lv_succeeded = true;
                                        } else {
                                            lvar_saved_info_t rename_info;
                                            rename_info.ll = lv_info.ll;
                                            rename_info.name = new_lv_name.c_str();
                                            if (modify_user_lvar_info(fn->start_ea, MLI_NAME, rename_info)) {
                                                lv_r["new_name"] = new_lv_name;
                                                lv_succeeded = true;
                                            } else {
                                                lv_errors.push_back("IDA failed to rename the local variable");
                                                lv_failed = true;
                                            }
                                        }
                                    }

                                    if (!lv_type_str.empty()) {
                                        tinfo_t lv_tif;
                                        qstring lv_nbuf;
                                        std::string decl_s = lv_type_str;
                                        if (decl_s.find(';') == std::string::npos) decl_s += ";";
                                        bool parsed = parse_decl(&lv_tif, &lv_nbuf, get_idati(), decl_s.c_str(), PT_SIL | PT_TYP);
                                        if (!parsed) {
                                            std::string with_dummy = lv_type_str + " dummy_var;";
                                            parsed = parse_decl(&lv_tif, &lv_nbuf, get_idati(), with_dummy.c_str(), PT_SIL | PT_TYP);
                                        }
                                        if (!parsed) {
                                            lv_errors.push_back("Failed to parse local variable type");
                                            lv_failed = true;
                                        } else {
                                            lvar_saved_info_t type_info;
                                            type_info.ll = lv_info.ll;
                                            type_info.type = lv_tif;
                                            if (modify_user_lvar_info(fn->start_ea, MLI_TYPE, type_info)) {
                                                qstring app_t;
                                                lv_tif.print(&app_t, nullptr, PRTYPE_1LINE | PRTYPE_SEMI);
                                                lv_r["new_type"] = app_t.c_str();
                                                lv_succeeded = true;
                                            } else {
                                                lv_errors.push_back("IDA failed to apply local variable type");
                                                lv_failed = true;
                                            }
                                        }
                                    }
                                }
                                lv_r["status"] = lv_failed ? (lv_succeeded ? "partial" : "error") : "success";
                                if (!lv_errors.empty()) lv_r["errors"] = lv_errors;
                                lvar_results.push_back(std::move(lv_r));
                                if (lv_succeeded) {
                                    item_succeeded = true;
                                    affected_funcs.insert(fn->start_ea);
                                }
                                if (lv_failed) item_failed = true;
                            }
                            if (!lvar_results.empty()) {
                                item_res["lvars"] = lvar_results;
                            }
                        } else {
                            item_res["lvar_error"] = "Hex-Rays could not decompile the target function";
                            item_failed = true;
                        }
                    } else {
                        item_res["lvar_error"] = "Hex-Rays is unavailable";
                        item_failed = true;
                    }
                } else if (item.contains("lvars")) {
                    item_res["lvar_error"] = "Local variable edits require a function target";
                    item_failed = true;
                }

                // 5. Instruction comments array
                if (item.contains("comments") && item["comments"].is_array()) {
                    nlohmann::json cmt_results = nlohmann::json::array();
                    for (const auto& ci : item["comments"]) {
                        sync::Checkpoint();
                        nlohmann::ordered_json cmt_result;
                        if (!ci.is_object()) {
                            cmt_result["status"] = "error";
                            cmt_result["message"] = "Comment entry must be an object";
                            cmt_results.push_back(std::move(cmt_result));
                            item_failed = true;
                            continue;
                        }
                        ea_t c_ea = tools::utils::GetAddressArg(ci, "addr");
                        if (c_ea == BADADDR) c_ea = tools::utils::GetAddressArg(ci, "target");
                        std::string c_text = tools::utils::GetStringArg(ci, "text", tools::utils::GetStringArg(ci, "comment"));
                        bool c_rep = tools::utils::GetBoolArg(ci, "repeatable", false);
                        func_t* c_fn = c_ea == BADADDR ? nullptr : get_func(c_ea);
                        if (!fn || !c_fn || c_fn->start_ea != fn->start_ea) {
                            cmt_result["status"] = "error";
                            cmt_result["message"] = "Instruction comment address must belong to the target function";
                            if (c_ea != BADADDR) cmt_result["address"] = tools::utils::FormatAddress(c_ea);
                            item_failed = true;
                        } else {
                            qstring current_comment;
                            get_cmt(&current_comment, c_ea, c_rep);
                            bool comment_ok = std::string(current_comment.c_str()) == c_text || set_cmt(c_ea, c_text.c_str(), c_rep);
                            if (comment_ok && init_hexrays_plugin()) {
                                user_cmts_t* ucmts = restore_user_cmts(c_fn->start_ea);
                                if (!ucmts) ucmts = user_cmts_new();
                                if (ucmts) {
                                    treeloc_t tl;
                                    tl.ea = c_ea;
                                    tl.itp = ITP_SEMI;
                                    if (c_text.empty()) ucmts->erase(tl);
                                    else (*ucmts)[tl] = citem_cmt_t(c_text.c_str());
                                    save_user_cmts(c_fn->start_ea, ucmts);
                                    user_cmts_free(ucmts);
                                } else comment_ok = false;
                            }
                            cmt_result["address"] = tools::utils::FormatAddress(c_ea);
                            if (comment_ok) {
                                cmt_result["status"] = "success";
                                cmt_result["comment"] = c_text;
                                item_succeeded = true;
                                affected_funcs.insert(c_fn->start_ea);
                            } else {
                                cmt_result["status"] = "error";
                                cmt_result["message"] = "IDA failed to apply the instruction comment";
                                item_failed = true;
                            }
                        }
                        cmt_results.push_back(std::move(cmt_result));
                    }
                    if (!cmt_results.empty()) {
                        item_res["comments"] = cmt_results;
                    }
                }

                // 6. Explicit Recompile / Cache refresh
                if (item.contains("recompile") || item.contains("refresh") || item.value("action", "") == "recompile" ||
                    (!item.contains("name") && !item.contains("type") && !item.contains("comment") && !item.contains("lvars") && !item.contains("comments"))) {
                    if (fn) {
                        affected_funcs.insert(fn->start_ea);
                        item_res["recompiled"] = true;
                        item_succeeded = true;
                    } else {
                        item_res["recompile_error"] = "Target is not inside a function";
                        item_failed = true;
                    }
                }

                item_res["status"] = item_failed ? (item_succeeded ? "partial" : "error") : "success";
                if (item_succeeded && item_failed) partial_count++;
                else if (item_succeeded) succeeded_count++;
                else if (item_failed) failed_count++;
                results.push_back(std::move(item_res));
            }

            for (ea_t fn_start : affected_funcs) {
                sync::Checkpoint();
                if (init_hexrays_plugin()) {
                    mark_cfunc_dirty(fn_start);
                }
            }
        });

        cache::InvalidateIDBAnalysis();

        // Auto-recompile affected function and attach refreshed C pseudocode
        if (tools::utils::GetBoolArg(args, "include_code", false) && affected_funcs.size() == 1 && !is_batch && !results.empty()) {
            ea_t target_fn_ea = *affected_funcs.begin();
            func_t* rfn = get_func(target_fn_ea);
            if (rfn) {
                auto [code, code_truncated] = DecompileFunctionCode(rfn);
                if (!code.empty()) {
                    results[0]["code"] = code;
                    if (code_truncated) results[0]["code_truncated"] = true;
                }
            }
        }

        if (!is_batch && !results.empty()) {
            return tools::utils::MakeToolSuccessJson(id, results[0]);
        }

        nlohmann::ordered_json resp;
        resp["status"] = failed_count > 0 && succeeded_count == 0 && partial_count == 0 ? "error" :
            (failed_count > 0 || partial_count > 0 ? "partial" : "success");
        resp["total"] = items.size();
        resp["succeeded"] = succeeded_count;
        resp["failed"] = failed_count;
        if (partial_count) resp["partial"] = partial_count;
        resp["results"] = results;
        return tools::utils::MakeToolSuccessJson(id, resp);
    }
}
