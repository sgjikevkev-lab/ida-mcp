#include "api_hexrays.h"
#include "ctree_serializer.h"
#include "mba_rules.h"
#include "../utils/utils.h"
#include "../../sync/sync.h"

#include <ida.hpp>
#include <idp.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <kernwin.hpp>
#include <hexrays.hpp>
#include <bytes.hpp>
#include <auto.hpp>
#include <intel.hpp>

namespace tools::hexrays_ast {

    nlohmann::json ApiHexrays::GetSchema() const {
        return nlohmann::json::array();
    }

    bool ApiHexrays::CanHandle(const std::string& name) const {
        return name == "get_ast" ||
               name == "ast_match" ||
               name == "mba_simplify" ||
               name == "simplify_predicate";
    }

    nlohmann::json ApiHexrays::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "get_ast") return GetAst(id, args);
        if (name == "ast_match") return AstMatch(id, args);
        if (name == "mba_simplify") return MbaSimplify(id, args);
        if (name == "simplify_predicate") return SimplifyPredicate(id, args);

        return nlohmann::json({
            {"jsonrpc", "2.0"},
            {"id", id},
            {"error", {{"code", -32601}, {"message", "Method not found"}}}
        });
    }

    nlohmann::json ApiHexrays::GetAst(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        int max_depth = static_cast<int>(tools::utils::GetIntArg(args, "max_depth", 128));

        nlohmann::json full_ast;
        std::string err_code;
        std::string err_msg;

        sync::SyncRead([&]() {
            if (ea == BADADDR) {
                err_code = "invalid_addr";
                err_msg = "Parameter 'addr' could not be resolved";
                return;
            }

            func_t* pfn = get_func(ea);
            if (!pfn) {
                err_code = "func_not_found";
                err_msg = "No function found containing given address " + tools::utils::FormatAddress(ea);
                return;
            }

            if (!init_hexrays_plugin()) {
                err_code = "hexrays_not_available";
                err_msg = "Hex-Rays decompiler is not loaded or not supported for this architecture";
                return;
            }

            hexrays_failure_t hf;
            cfuncptr_t cf = decompile(pfn, &hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
            if (!cf) {
                err_code = "decompilation_failed";
                err_msg = "Decompilation failed: " + tools::utils::SanitizeUtf8(hf.desc().c_str());
                return;
            }

            full_ast = {
                {"status", "success"},
                {"address", tools::utils::FormatAddress(pfn->start_ea)},
                {"lvars", SerializeLvars(cf)},
                {"body", SerializeCItem(&cf->body, cf, max_depth, 0)}
            };
        });

        if (!err_code.empty()) {
            return tools::utils::MakeToolErrorJson(id, err_msg, err_code);
        }

        return tools::utils::MakeToolSuccessJson(id, full_ast);
    }

    nlohmann::json ApiHexrays::AstMatch(const nlohmann::json& id, const nlohmann::json& args) {
        if (!args.contains("pattern")) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'pattern' is required", "pattern_required");
        }

        const nlohmann::json& pattern = args["pattern"];
        std::string addr_str = tools::utils::GetStringArg(args, "addr");
        std::string func_pattern = tools::utils::GetStringArg(args, "func_pattern");
        int limit = static_cast<int>(tools::utils::GetIntArg(args, "limit", 200));
        int max_matches = static_cast<int>(tools::utils::GetIntArg(args, "max_matches", 50));

        nlohmann::json matches = nlohmann::json::array();
        std::string error_code;
        std::string error_msg;

        sync::SyncToMainThread([&]() {
            if (!init_hexrays_plugin()) {
                error_code = "hexrays_not_available";
                error_msg = "Hex-Rays decompiler is not loaded or not supported for this architecture";
                return;
            }

            struct match_visitor_t : public ctree_visitor_t {
                const cfunc_t* cf;
                const nlohmann::json& pattern;
                nlohmann::json& matches;
                int max_matches;
                int count = 0;
                ea_t func_ea;
                std::string func_name;

                match_visitor_t(const cfunc_t* f, const nlohmann::json& pat, nlohmann::json& m, int max_m, ea_t fea, const std::string& fname)
                    : ctree_visitor_t(CV_FAST), cf(f), pattern(pat), matches(m), max_matches(max_m), func_ea(fea), func_name(fname) {}

                int idaapi visit_insn(cinsn_t* insn) override {
                    if (count >= max_matches) return 1;
                    std::map<std::string, nlohmann::json> bindings;
                    if (MatchPattern(insn, cf, pattern, bindings)) {
                        matches.push_back({
                            {"function", func_name},
                            {"address", tools::utils::FormatAddress(insn->ea)},
                            {"op", CTypeToString(insn->op)},
                            {"expr", CleanItemText(insn, cf)}
                        });
                        count++;
                        if (count >= max_matches) return 1;
                    }
                    return 0;
                }

                int idaapi visit_expr(cexpr_t* expr) override {
                    if (count >= max_matches) return 1;
                    std::map<std::string, nlohmann::json> bindings;
                    if (MatchPattern(expr, cf, pattern, bindings)) {
                        matches.push_back({
                            {"function", func_name},
                            {"address", tools::utils::FormatAddress(expr->ea)},
                            {"op", CTypeToString(expr->op)},
                            {"expr", CleanItemText(expr, cf)}
                        });
                        count++;
                        if (count >= max_matches) return 1;
                    }
                    return 0;
                }
            };

            if (!addr_str.empty()) {
                ea_t ea = tools::utils::ParseAddress(addr_str);
                func_t* pfn = (ea != BADADDR) ? get_func(ea) : nullptr;
                if (!pfn) {
                    error_code = "func_not_found";
                    error_msg = "No function found containing given address: " + addr_str;
                    return;
                }

                hexrays_failure_t hf;
                cfuncptr_t cf = decompile(pfn, &hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                if (cf) {
                    qstring fn_name;
                    get_func_name(&fn_name, pfn->start_ea);
                    match_visitor_t visitor(cf, pattern, matches, max_matches, pfn->start_ea, fn_name.c_str());
                    visitor.apply_to(&cf->body, nullptr);
                }
            } else {
                size_t total_funcs = get_func_qty();
                size_t scanned = 0;
                for (size_t i = 0; i < total_funcs && static_cast<int>(scanned) < limit; ++i) {
                    func_t* pfn = getn_func(i);
                    if (!pfn) continue;

                    qstring fn_name;
                    get_func_name(&fn_name, pfn->start_ea);
                    std::string fname_str = fn_name.c_str();

                    if (!func_pattern.empty() && !tools::utils::PatternMatch(fname_str, func_pattern)) continue;

                    scanned++;
                    hexrays_failure_t hf;
                    cfuncptr_t cf = decompile(pfn, &hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                    if (cf) {
                        match_visitor_t visitor(cf, pattern, matches, max_matches, pfn->start_ea, fname_str);
                        visitor.apply_to(&cf->body, nullptr);
                        if (visitor.count >= max_matches) break;
                    }
                }
            }
        });

        if (!error_code.empty()) {
            return tools::utils::MakeToolErrorJson(id, error_msg, error_code);
        }

        nlohmann::json res = {
            {"status", "success"},
            {"matches_count", matches.size()},
            {"matches", matches}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiHexrays::MbaSimplify(const nlohmann::json& id, const nlohmann::json& args) {
        std::string addr_str = tools::utils::GetStringArg(args, "addr");
        std::string expr_addr_str = tools::utils::GetStringArg(args, "expr_addr");

        nlohmann::json matches = nlohmann::json::array();
        std::string error_code;
        std::string error_msg;

        sync::SyncToMainThread([&]() {
            ea_t ea = tools::utils::ParseAddress(addr_str);
            func_t* pfn = (ea != BADADDR) ? get_func(ea) : nullptr;
            if (!pfn) {
                error_code = "func_not_found";
                error_msg = "No function found containing given address: " + addr_str;
                return;
            }

            if (!init_hexrays_plugin()) {
                error_code = "hexrays_not_available";
                error_msg = "Hex-Rays decompiler is not loaded or not supported for this architecture";
                return;
            }

            hexrays_failure_t hf;
            cfuncptr_t cf = decompile(pfn, &hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
            if (!cf) {
                error_code = "decompilation_failed";
                error_msg = "Decompilation failed: " + tools::utils::SanitizeUtf8(hf.desc().c_str());
                return;
            }

            ea_t target_expr_ea = !expr_addr_str.empty() ? tools::utils::ParseAddress(expr_addr_str) : BADADDR;

            // Combine built-in rules with optional custom rules
            std::vector<MbaRule> combined_rules;
            if (args.contains("custom_rules") && args["custom_rules"].is_array()) {
                const auto& cr_arr = args["custom_rules"];
                for (size_t i = 0; i < cr_arr.size(); ++i) {
                    const auto& cr = cr_arr[i];
                    if (!cr.is_object() || !cr.contains("pattern")) continue;
                    std::string rname = cr.value("name", "custom_rule_" + std::to_string(i + 1));
                    std::string simp = cr.value("simplified", "");
                    combined_rules.push_back(MbaRule{
                        static_cast<int>(1000 + i),
                        rname,
                        cr["pattern"],
                        [simp](const std::map<std::string, nlohmann::json>& b) {
                            if (!simp.empty()) return simp;
                            if (b.find("$x") != b.end()) return ExtractBindingName(b.at("$x"));
                            return std::string("");
                        },
                        nullptr
                    });
                }
            }
            for (const auto& r : GetMbaRules()) {
                combined_rules.push_back(r);
            }

            struct mba_visitor_t : public ctree_visitor_t {
                const cfunc_t* cf;
                const std::vector<MbaRule>& rules;
                nlohmann::json& matches;
                ea_t target_expr_ea;

                mba_visitor_t(const cfunc_t* f, const std::vector<MbaRule>& r, nlohmann::json& m, ea_t tea)
                    : ctree_visitor_t(CV_FAST), cf(f), rules(r), matches(m), target_expr_ea(tea) {}

                int idaapi visit_expr(cexpr_t* expr) override {
                    if (target_expr_ea != BADADDR && expr->ea != target_expr_ea) return 0;

                    bool is_candidate = (expr->op == cot_add || expr->op == cot_sub ||
                                         expr->op == cot_bor || expr->op == cot_xor ||
                                         expr->op == cot_band || expr->op == cot_bnot ||
                                         expr->op == cot_shl || expr->op == cot_sshr ||
                                         expr->op == cot_ushr || expr->op == cot_neg ||
                                         expr->op == cot_mul);
                    if (!is_candidate) return 0;

                    // Level 1: Static pattern matching
                    for (const auto& rule : rules) {
                        std::map<std::string, nlohmann::json> bindings;
                        if (MatchPattern(expr, cf, rule.pattern, bindings)) {
                            std::string simplified_text = rule.format_simplified ? rule.format_simplified(bindings) : "";
                            matches.push_back({
                                {"address", tools::utils::FormatAddress(expr->ea)},
                                {"expression", CleanItemText(expr, cf)},
                                {"simplified", simplified_text},
                                {"rule", rule.name},
                                {"confidence", "verified"},
                                {"method", "rule_match"}
                            });
                            return 0;
                        }
                    }

                    // Level 2: Constant folding
                    if (expr->x || expr->y) {
                        auto cf_val = TryConstFold(expr);
                        if (cf_val) {
                            std::ostringstream oss;
                            if (*cf_val == 0) oss << "0";
                            else oss << "0x" << std::hex << *cf_val;
                            matches.push_back({
                                {"address", tools::utils::FormatAddress(expr->ea)},
                                {"expression", CleanItemText(expr, cf)},
                                {"simplified", oss.str()},
                                {"rule", "Constant Folding"},
                                {"confidence", "verified"},
                                {"method", "const_fold"}
                            });
                            return 0;
                        }
                    }

                    // Level 3: Brute-force symbolic verification
                    auto bf_res = BruteForceSimplify(expr, cf);
                    if (bf_res) {
                        matches.push_back({
                            {"address", tools::utils::FormatAddress(expr->ea)},
                            {"expression", CleanItemText(expr, cf)},
                            {"simplified", bf_res->simplified},
                            {"rule", "Algebraic Identity"},
                            {"confidence", bf_res->confidence},
                            {"method", "algebraic_eval"}
                        });
                        return 0;
                    }

                    return 0;
                }
            };

            mba_visitor_t visitor(cf, combined_rules, matches, target_expr_ea);
            visitor.apply_to(&cf->body, nullptr);
        });

        if (!error_code.empty()) {
            return tools::utils::MakeToolErrorJson(id, error_msg, error_code);
        }

        nlohmann::json res = {
            {"status", "success"},
            {"matches_count", matches.size()},
            {"matches", matches}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiHexrays::SimplifyPredicate(const nlohmann::json& id, const nlohmann::json& args) {
        std::string addr_str = tools::utils::GetStringArg(args, "addr");
        bool persist = tools::utils::GetBoolArg(args, "persist", false);
        bool auto_detect = tools::utils::GetBoolArg(args, "auto_detect", false);

        struct PredReq {
            ea_t pred_ea;
            std::string force_branch;
        };
        std::vector<PredReq> requests;

        if (args.contains("predicates") && args["predicates"].is_array()) {
            for (const auto& item : args["predicates"]) {
                if (!item.is_object()) continue;
                ea_t pea = tools::utils::GetAddressArg(item, "predicate_addr");
                std::string fb = tools::utils::GetStringArg(item, "force_branch");
                if (pea != BADADDR && (fb == "always_true" || fb == "always_false")) {
                    requests.push_back({pea, fb});
                }
            }
        } else {
            std::string pred_addr_str = tools::utils::GetStringArg(args, "predicate_addr");
            std::string force_branch = tools::utils::GetStringArg(args, "force_branch");
            if (!pred_addr_str.empty()) {
                if (force_branch != "always_true" && force_branch != "always_false") {
                    return tools::utils::MakeToolErrorJson(id, "Parameter 'force_branch' must be 'always_true' or 'always_false'", "invalid_force_branch");
                }
                ea_t pea = tools::utils::ParseAddress(pred_addr_str);
                if (pea != BADADDR) {
                    requests.push_back({pea, force_branch});
                }
            }
        }

        if (requests.empty() && !auto_detect) {
            return tools::utils::MakeToolErrorJson(id, "Provide 'predicate_addr' with 'force_branch', 'predicates' array, or 'auto_detect: true'", "missing_parameters");
        }

        std::string out_code;
        std::string error_code;
        std::string error_msg;
        ea_t func_start = BADADDR;
        nlohmann::json modifications = nlohmann::json::array();
        nlohmann::json detected_opaques = nlohmann::json::array();

        sync::SyncToMainThread([&]() {
            ea_t ea = tools::utils::ParseAddress(addr_str);
            func_t* pfn = (ea != BADADDR) ? get_func(ea) : nullptr;
            if (!pfn) {
                error_code = "func_not_found";
                error_msg = "No function found containing given address: " + addr_str;
                return;
            }
            func_start = pfn->start_ea;

            if (!init_hexrays_plugin()) {
                error_code = "hexrays_not_available";
                error_msg = "Hex-Rays decompiler is not loaded or not supported for this architecture";
                return;
            }

            hexrays_failure_t hf;
            cfuncptr_t cf = decompile(pfn, &hf, DECOMP_WARNINGS | DECOMP_NO_CACHE | DECOMP_NO_WAIT);
            if (!cf) {
                error_code = "decompilation_failed";
                error_msg = "Decompilation failed: " + tools::utils::SanitizeUtf8(hf.desc().c_str());
                return;
            }

            // Auto-detect opaque predicates if requested
            if (auto_detect) {
                struct opaque_detector_t : public ctree_visitor_t {
                    const cfunc_t* cf;
                    nlohmann::json& detected;
                    opaque_detector_t(const cfunc_t* f, nlohmann::json& d)
                        : ctree_visitor_t(CV_FAST), cf(f), detected(d) {}

                    int idaapi visit_insn(cinsn_t* insn) override {
                        if (insn->op == cit_if && insn->cif) {
                            cexpr_t* cond = &insn->cif->expr;
                            std::string cond_text = CleanItemText(cond, cf);

                            // 1. Const fold
                            auto cf_val = TryConstFold(cond);
                            if (cf_val) {
                                detected.push_back({
                                    {"predicate_addr", tools::utils::FormatAddress(insn->ea)},
                                    {"condition", cond_text},
                                    {"evaluation", (*cf_val != 0) ? "always_true" : "always_false"},
                                    {"confidence", "certain"}
                                });
                                return 0;
                            }

                            // 2. Brute force simplify
                            auto bf_res = BruteForceSimplify(cond, cf);
                            if (bf_res) {
                                if (bf_res->simplified == "0") {
                                    detected.push_back({
                                        {"predicate_addr", tools::utils::FormatAddress(insn->ea)},
                                        {"condition", cond_text},
                                        {"evaluation", "always_false"},
                                        {"confidence", "certain"}
                                    });
                                } else if (bf_res->simplified == "1" || bf_res->simplified == "~0") {
                                    detected.push_back({
                                        {"predicate_addr", tools::utils::FormatAddress(insn->ea)},
                                        {"condition", cond_text},
                                        {"evaluation", "always_true"},
                                        {"confidence", "certain"}
                                    });
                                }
                            }
                        }
                        return 0;
                    }
                };
                opaque_detector_t detector(cf, detected_opaques);
                detector.apply_to(&cf->body, nullptr);
            }

            bool any_idb_patched = false;

            // Apply modifications
            for (const auto& req : requests) {
                struct if_finder_t : public ctree_visitor_t {
                    ea_t target;
                    cinsn_t* found = nullptr;
                    if_finder_t(ea_t t) : ctree_visitor_t(CV_FAST), target(t) {}
                    int idaapi visit_insn(cinsn_t* insn) override {
                        if (insn->op == cit_if && (insn->ea == target || target == BADADDR)) {
                            found = insn;
                            return 1;
                        }
                        return 0;
                    }
                };

                if_finder_t finder(req.pred_ea);
                finder.apply_to(&cf->body, nullptr);
                if (!finder.found) continue;

                cinsn_t* if_insn = finder.found;
                cif_t* cif = if_insn->cif;
                std::string orig_cond = CleanItemText(&cif->expr, (cfunc_t*)cf);

                if (req.force_branch == "always_true") {
                    if (cif->ithen) {
                        cinsn_t* branch = cif->ithen;
                        cif->ithen = nullptr;
                        if_insn->replace_by(branch);
                    } else {
                        if_insn->cleanup();
                        if_insn->op = cit_empty;
                    }
                } else {
                    if (cif->ielse) {
                        cinsn_t* branch = cif->ielse;
                        cif->ielse = nullptr;
                        if_insn->replace_by(branch);
                    } else {
                        if_insn->cleanup();
                        if_insn->op = cit_empty;
                    }
                }

                bool idb_patched = false;
                if (persist) {
                    ea_t jcc_ea = BADADDR;
                    insn_t insn;
                    for (ea_t cur = req.pred_ea; cur <= req.pred_ea + 16 && cur < pfn->end_ea; ) {
                        int len = decode_insn(&insn, cur);
                        if (len <= 0) break;
                        if (insn_jcc(insn)) {
                            jcc_ea = cur;
                            break;
                        }
                        cur += len;
                    }

                    if (jcc_ea != BADADDR) {
                        ea_t taken_ea = insn.Op1.addr;
                        ea_t fallthrough_ea = jcc_ea + insn.size;

                        ea_t then_ea = (cif->ithen ? cif->ithen->ea : BADADDR);
                        ea_t else_ea = (cif->ielse ? cif->ielse->ea : BADADDR);

                        bool taken_is_true = false;
                        if (then_ea != BADADDR && taken_ea == then_ea) {
                            taken_is_true = true;
                        } else if (else_ea != BADADDR && taken_ea == else_ea) {
                            taken_is_true = false;
                        } else if (then_ea != BADADDR && fallthrough_ea == then_ea) {
                            taken_is_true = false;
                        } else if (else_ea != BADADDR && fallthrough_ea == else_ea) {
                            taken_is_true = true;
                        }

                        bool want_true = (req.force_branch == "always_true");
                        bool should_jump = (want_true == taken_is_true);

                        uint8_t op0 = get_byte(jcc_ea);
                        if (op0 >= 0x70 && op0 <= 0x7F) {
                            if (!should_jump) {
                                // Fallthrough: NOP out the 2-byte short Jcc
                                patch_byte(jcc_ea, 0x90);
                                patch_byte(jcc_ea + 1, 0x90);
                            } else {
                                // Taken: Convert short Jcc (7x cb) to short JMP (EB cb)
                                patch_byte(jcc_ea, 0xEB);
                            }
                            idb_patched = true;
                            any_idb_patched = true;
                        } else if (op0 == 0x0F) {
                            uint8_t op1 = get_byte(jcc_ea + 1);
                            if (op1 >= 0x80 && op1 <= 0x8F) {
                                if (!should_jump) {
                                    // Fallthrough: NOP out the 6-byte near Jcc
                                    for (int k = 0; k < 6; ++k) patch_byte(jcc_ea + k, 0x90);
                                } else {
                                    // Taken: Convert near Jcc (0F 8x cd) to near JMP (E9 cd 90)
                                    // Near JMP E9 is 5 bytes; displacement is relative to next insn (jcc_ea + 5)
                                    int32_t new_disp = static_cast<int32_t>(taken_ea - (jcc_ea + 5));
                                    patch_byte(jcc_ea, 0xE9);
                                    patch_dword(jcc_ea + 1, static_cast<uint32>(new_disp));
                                    patch_byte(jcc_ea + 5, 0x90);
                                }
                                idb_patched = true;
                                any_idb_patched = true;
                            }
                        }
                    }
                }

                modifications.push_back({
                    {"predicate_addr", tools::utils::FormatAddress(req.pred_ea)},
                    {"force_branch", req.force_branch},
                    {"original_condition", orig_cond},
                    {"persisted", idb_patched}
                });
            }

            if (any_idb_patched) {
                auto_mark_range(pfn->start_ea, pfn->end_ea, AU_CODE);
                plan_and_wait(pfn->start_ea, pfn->end_ea);
            }

            cf->recalc_item_addresses();
            cf->remove_unused_labels();
            cf->refresh_func_ctext();

            const strvec_t& new_sv = cf->get_pseudocode();
            for (size_t i = 0; i < new_sv.size(); ++i) {
                qstring clean;
                tag_remove(&clean, new_sv[i].line);
                out_code += clean.c_str();
                out_code += "\n";
            }
        });

        if (!error_code.empty()) {
            return tools::utils::MakeToolErrorJson(id, error_msg, error_code);
        }

        nlohmann::json res = {
            {"status", "success"},
            {"address", tools::utils::FormatAddress(func_start)},
            {"modifications", modifications},
            {"detected_opaques", detected_opaques},
            {"code", out_code}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }
}
