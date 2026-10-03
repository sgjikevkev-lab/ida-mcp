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
#include <nalt.hpp>
#include <typeinf.hpp>
#include <hexrays.hpp>
#include <kernwin.hpp>

namespace tools::modify {
    namespace {
        std::pair<std::string, bool> AppendCommentText(const std::string& current, const std::string& addition, bool dedupe) {
            if (addition.empty()) return {current, true};
            if (dedupe && !current.empty() && current.find(addition) != std::string::npos) {
                return {current, true};
            }
            if (current.empty()) return {addition, false};
            return {current + "\n" + addition, false};
        }
    }

    bool ApiModify::CanHandle(const std::string& name) const {
        return name == "rename" ||
               name == "set_type" ||
               name == "set_comment" ||
               name == "rename_lvar" ||
               name == "set_lvar_type" ||
               name == "recompile";
    }

    nlohmann::json ApiModify::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "rename") return Rename(id, args);
        if (name == "set_type") return SetType(id, args);
        if (name == "set_comment") return SetComment(id, args);
        if (name == "rename_lvar") return RenameLvar(id, args);
        if (name == "set_lvar_type") return SetLvarType(id, args);
        if (name == "recompile") return Recompile(id, args);

        return tools::utils::MakeToolErrorJson(id, "Method not found: " + name, "method_not_found");
    }

    nlohmann::json ApiModify::Rename(const nlohmann::json& id, const nlohmann::json& args) {
        // Batch rename support
        if (args.contains("items") && args["items"].is_array()) {
            const auto& items = args["items"];
            nlohmann::json results = nlohmann::json::array();
            size_t succeeded = 0;

            sync::SyncWrite([&]() {
                for (const auto& it : items) {
                    if (!it.is_object()) continue;
                    ea_t ea = tools::utils::GetAddressArg(it, "addr");
                    std::string new_name = tools::utils::GetStringArg(it, "name", tools::utils::GetStringArg(it, "new_name"));

                    if (ea == BADADDR) {
                        results.push_back({
                            {"status", "error"},
                            {"message", "Invalid address"}
                        });
                        continue;
                    }
                    if (new_name.empty()) {
                        results.push_back({
                            {"status", "error"},
                            {"address", tools::utils::FormatAddress(ea)},
                            {"message", "Name cannot be empty"}
                        });
                        continue;
                    }

                    qstring old_buf;
                    get_ea_name(&old_buf, ea);
                    std::string old_name = old_buf.c_str();

                    bool ok = set_name(ea, new_name.c_str(), SN_NOWARN | SN_NOCHECK);
                    if (ok) {
                        succeeded++;
                        results.push_back({
                            {"status", "success"},
                            {"address", tools::utils::FormatAddress(ea)},
                            {"old_name", old_name},
                            {"new_name", new_name}
                        });
                    } else {
                        results.push_back({
                            {"status", "error"},
                            {"address", tools::utils::FormatAddress(ea)},
                            {"old_name", old_name},
                            {"message", "set_name failed (name may already exist or contain invalid characters)"}
                        });
                    }
                }
            });

            if (succeeded > 0) {
                cache::InvalidateIDBAnalysis();
            }

            nlohmann::json res = {
                {"status", "success"},
                {"total", items.size()},
                {"succeeded", succeeded},
                {"results", results}
            };
            return tools::utils::MakeToolSuccessJson(id, res);
        }

        // Single rename
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        std::string new_name = tools::utils::GetStringArg(args, "name", tools::utils::GetStringArg(args, "new_name"));

        if (ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Address could not be resolved", "invalid_addr");
        }
        if (new_name.empty()) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'name' cannot be empty", "name_required");
        }

        bool ok = false;
        std::string old_name;
        sync::SyncWrite([&]() {
            qstring old_buf;
            get_ea_name(&old_buf, ea);
            old_name = old_buf.c_str();
            ok = set_name(ea, new_name.c_str(), SN_NOWARN | SN_NOCHECK);
        });

        if (!ok) {
            return tools::utils::MakeToolErrorJson(
                id,
                "Failed to rename symbol at " + tools::utils::FormatAddress(ea) + " to '" + new_name + "'. Name may already exist or contain invalid characters.",
                "rename_failed"
            );
        }

        cache::InvalidateIDBAnalysis();

        nlohmann::json res = {
            {"status", "success"},
            {"address", tools::utils::FormatAddress(ea)},
            {"old_name", old_name},
            {"new_name", new_name}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiModify::SetType(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        if (ea == BADADDR) {
            ea = tools::utils::GetAddressArg(args, "target");
        }
        std::string type_decl = tools::utils::GetStringArg(args, "type");

        if (ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }
        if (type_decl.empty()) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'type' is required", "type_required");
        }

        bool ok = false;
        std::string old_type;
        std::string new_type;

        sync::SyncWrite([&]() {
            tinfo_t cur_tif;
            if (get_tinfo(&cur_tif, ea)) {
                qstring cur_str;
                cur_tif.print(&cur_str);
                old_type = cur_str.c_str();
            }

            tinfo_t tif;
            qstring name_buf;
            std::string decl_to_parse = type_decl;
            if (decl_to_parse.find(';') == std::string::npos) decl_to_parse += ";";

            if (!parse_decl(&tif, &name_buf, get_idati(), decl_to_parse.c_str(), PT_SIL | PT_TYP)) {
                qstring sym_name;
                get_ea_name(&sym_name, ea);
                if (!sym_name.empty()) {
                    auto paren_pos = type_decl.find('(');
                    if (paren_pos != std::string::npos) {
                        std::string with_name = type_decl.substr(0, paren_pos) + " " + sym_name.c_str() + type_decl.substr(paren_pos) + ";";
                        parse_decl(&tif, &name_buf, get_idati(), with_name.c_str(), PT_SIL | PT_TYP);
                    }
                }
            }

            if (!tif.empty()) {
                ok = apply_tinfo(ea, tif, TINFO_DEFINITE);
                if (ok) {
                    qstring applied_str;
                    tif.print(&applied_str);
                    new_type = applied_str.c_str();
                }
            }
        });

        if (!ok) {
            return tools::utils::MakeToolErrorJson(
                id,
                "Failed to parse or apply type '" + type_decl + "' to address " + tools::utils::FormatAddress(ea),
                "set_type_failed"
            );
        }

        cache::InvalidateIDBAnalysis();

        nlohmann::json res = {
            {"status", "success"},
            {"address", tools::utils::FormatAddress(ea)},
            {"old_type", old_type},
            {"new_type", new_type.empty() ? type_decl : new_type}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiModify::SetComment(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        std::string cmt = tools::utils::GetStringArg(args, "text", tools::utils::GetStringArg(args, "comment"));
        bool repeatable = tools::utils::GetBoolArg(args, "repeatable", false);
        bool append = tools::utils::GetBoolArg(args, "append", false);

        if (ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Address could not be parsed", "invalid_addr");
        }
        if (cmt.empty()) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'text' or 'comment' is required", "comment_required");
        }

        bool asm_ok = false;
        bool hexrays_ok = false;
        std::string old_cmt_str;
        std::string final_cmt = cmt;

        sync::SyncWrite([&]() {
            qstring cur_cmt;
            get_cmt(&cur_cmt, ea, repeatable);
            old_cmt_str = cur_cmt.c_str();

            if (append) {
                auto res = AppendCommentText(old_cmt_str, cmt, true);
                final_cmt = res.first;
            }
            asm_ok = set_cmt(ea, final_cmt.c_str(), repeatable);

            // Pseudocode comment in Hex-Rays if inside function
            if (init_hexrays_plugin()) {
                func_t* fn = get_func(ea);
                if (fn) {
                    user_cmts_t* cmts = restore_user_cmts(fn->start_ea);
                    if (!cmts) cmts = user_cmts_new();

                    treeloc_t tl;
                    tl.ea = ea;
                    tl.itp = ITP_SEMI;
                    (*cmts)[tl] = citem_cmt_t(final_cmt.c_str());
                    save_user_cmts(fn->start_ea, cmts);
                    user_cmts_free(cmts); // Free allocated collection to prevent memory leak
                    hexrays_ok = true;
                }
            }
        });

        if (!asm_ok && !hexrays_ok) {
            return tools::utils::MakeToolErrorJson(id, "Failed to set comment at address " + tools::utils::FormatAddress(ea), "set_comment_failed");
        }

        cache::InvalidateIDBAnalysis();

        nlohmann::json res = {
            {"status", "success"},
            {"address", tools::utils::FormatAddress(ea)},
            {"old_comment", old_cmt_str},
            {"new_comment", final_cmt},
            {"repeatable", repeatable}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiModify::RenameLvar(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        std::string old_name = tools::utils::GetStringArg(args, "old_name");
        std::string new_name = tools::utils::GetStringArg(args, "new_name");

        if (ea == BADADDR) return tools::utils::MakeToolErrorJson(id, "Address could not be resolved", "invalid_addr");
        if (old_name.empty()) return tools::utils::MakeToolErrorJson(id, "Parameter 'old_name' is required", "old_name_required");
        if (new_name.empty()) return tools::utils::MakeToolErrorJson(id, "Parameter 'new_name' is required", "new_name_required");

        bool ok = false;
        std::string reason = "variable_not_found";
        ea_t fn_start = BADADDR;

        sync::SyncWrite([&]() {
            if (!init_hexrays_plugin()) {
                reason = "hexrays_unavailable";
                return;
            }
            func_t* fn = get_func(ea);
            if (!fn) {
                reason = "function_not_found";
                return;
            }
            fn_start = fn->start_ea;

            hexrays_failure_t hf;
            cfuncptr_t cfunc = decompile(fn, &hf, DECOMP_WARNINGS);
            if (!cfunc) {
                reason = "decompilation_failed";
                return;
            }

            lvars_t* lvars = cfunc->get_lvars();
            if (!lvars) return;

            for (size_t i = 0; i < lvars->size(); ++i) {
                if ((*lvars)[i].name == old_name.c_str()) {
                    ok = rename_lvar(fn->start_ea, (*lvars)[i].name.c_str(), new_name.c_str());
                    if (!ok) reason = "rename_rejected";
                    break;
                }
            }
        });

        if (!ok) {
            return tools::utils::MakeToolErrorJson(
                id,
                "Cannot rename local variable '" + old_name + "' to '" + new_name + "' (reason: " + reason + ")",
                "rename_lvar_failed"
            );
        }

        cache::InvalidateIDBAnalysis();

        nlohmann::json res = {
            {"status", "success"},
            {"function", tools::utils::FormatAddress(fn_start)},
            {"old_name", old_name},
            {"new_name", new_name}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiModify::SetLvarType(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        std::string name = tools::utils::GetStringArg(args, "name");
        std::string type_str = tools::utils::GetStringArg(args, "type");

        if (ea == BADADDR) return tools::utils::MakeToolErrorJson(id, "Address could not be resolved", "invalid_addr");
        if (name.empty()) return tools::utils::MakeToolErrorJson(id, "Parameter 'name' is required", "name_required");
        if (type_str.empty()) return tools::utils::MakeToolErrorJson(id, "Parameter 'type' is required", "type_required");

        bool ok = false;
        std::string reason = "variable_not_found";
        ea_t fn_start = BADADDR;

        sync::SyncWrite([&]() {
            if (!init_hexrays_plugin()) {
                reason = "hexrays_unavailable";
                return;
            }
            func_t* fn = get_func(ea);
            if (!fn) {
                reason = "function_not_found";
                return;
            }
            fn_start = fn->start_ea;

            tinfo_t tif;
            qstring name_buf;
            std::string decl_str = type_str;
            if (decl_str.find(';') == std::string::npos) decl_str += ";";
            if (!parse_decl(&tif, &name_buf, get_idati(), decl_str.c_str(), PT_SIL | PT_TYP)) {
                reason = "type_syntax_error";
                return;
            }

            lvar_saved_info_t info;
            if (locate_lvar(&info.ll, fn->start_ea, name.c_str())) {
                info.type = tif;
                ok = modify_user_lvar_info(fn->start_ea, MLI_TYPE, info);
                if (!ok) reason = "type_rejected";
            }
        });

        if (!ok) {
            return tools::utils::MakeToolErrorJson(
                id,
                "Cannot set type of variable '" + name + "' to '" + type_str + "' (reason: " + reason + ")",
                "set_lvar_type_failed"
            );
        }

        cache::InvalidateIDBAnalysis();

        nlohmann::json res = {
            {"status", "success"},
            {"function", tools::utils::FormatAddress(fn_start)},
            {"name", name},
            {"type", type_str}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiModify::Recompile(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t ea = tools::utils::GetAddressArg(args, "addr", BADADDR);

        sync::SyncWrite([&]() {
            if (!init_hexrays_plugin()) return;
            if (ea != BADADDR) {
                func_t* fn = get_func(ea);
                if (fn) {
                    mark_cfunc_dirty(fn->start_ea);
                }
            } else {
                clear_cached_cfuncs();
            }
        });

        cache::InvalidateIDBAnalysis();
        return tools::utils::MakeToolSuccessJson(id);
    }
}
