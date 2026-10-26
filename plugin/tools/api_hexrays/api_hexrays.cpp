#include "sync/operation.h"
#include "api_hexrays.h"
#include "ctree_serializer.h"
#include "mba_rules.h"
#include "../api_sigmaker/api_sigmaker.h"
#include "../utils/utils.h"
#include "../../sync/sync.h"
#include "../../sync/cache_manager.h"

#include <algorithm>
#include <limits>
#include <set>
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
    namespace {
        constexpr size_t kMaxSimplifyMatches = 256;
        constexpr size_t kMaxCustomRules = 64;
        constexpr size_t kMaxCustomPatternNodes = 256;
        constexpr size_t kMaxCustomPatternDepth = 32;
        constexpr size_t kMaxCustomPatternArgs = 64;
        constexpr size_t kMaxCustomText = 256;

        bool TryRelative32(ea_t target, ea_t next_instruction, int32_t& displacement) {
            if (target >= next_instruction) {
                const uint64_t distance = static_cast<uint64_t>(target - next_instruction);
                if (distance > static_cast<uint64_t>(std::numeric_limits<int32_t>::max())) return false;
                displacement = static_cast<int32_t>(distance);
                return true;
            }
            const uint64_t distance = static_cast<uint64_t>(next_instruction - target);
            const uint64_t min_magnitude = static_cast<uint64_t>(std::numeric_limits<int32_t>::max()) + 1;
            if (distance > min_magnitude) return false;
            displacement = distance == min_magnitude
                ? std::numeric_limits<int32_t>::min()
                : -static_cast<int32_t>(distance);
            return true;
        }

        bool ValidateCustomPattern(const nlohmann::json& node, size_t depth, size_t& nodes) {
            if (++nodes > kMaxCustomPatternNodes || depth > kMaxCustomPatternDepth) return false;
            if (node.is_string()) return node.get_ref<const std::string&>().size() <= kMaxCustomText;
            if (!node.is_object()) return false;
            static const std::set<std::string> allowed = {
                "op", "x", "y", "z", "args", "value", "var_name", "obj_name",
                "callee", "member_offset", "cond", "then", "else", "expr"
            };
            for (auto it = node.begin(); it != node.end(); ++it) {
                if (!allowed.count(it.key())) return false;
                const auto& value = it.value();
                if (it.key() == "args") {
                    if (!value.is_array() || value.size() > kMaxCustomPatternArgs) return false;
                    for (const auto& arg : value)
                        if (!ValidateCustomPattern(arg, depth + 1, nodes)) return false;
                } else if (it.key() == "value") {
                    if (!(value.is_string() || value.is_number_integer())) return false;
                    if (value.is_string() && value.get_ref<const std::string&>().size() > kMaxCustomText) return false;
                } else if (it.key() == "member_offset") {
                    if (value.is_number_unsigned()) continue;
                    if (!value.is_number_integer() || value.get<int64_t>() < 0) return false;
                } else if (it.key() == "op" || it.key() == "var_name" || it.key() == "obj_name" || it.key() == "callee") {
                    if (!value.is_string() || value.get_ref<const std::string&>().size() > kMaxCustomText) return false;
                } else if (!ValidateCustomPattern(value, depth + 1, nodes)) {
                    return false;
                }
            }
            return true;
        }
    }

    nlohmann::json ApiHexrays::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "get_ast") return GetAst(id, args);
        if (name == "mba_simplify") return MbaSimplify(id, args);
        if (name == "simplify_predicate") return SimplifyPredicate(id, args);

        return tools::utils::MakeToolErrorJson(id, "Method not found: " + name, "method_not_found");
    }

    nlohmann::json ApiHexrays::GetAst(const nlohmann::json& id, const nlohmann::json& args) {
        if (args.contains("pattern")) {
            return AstMatch(id, args);
        }

        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        int max_depth = static_cast<int>(tools::utils::GetIntArg(args, "max_depth", 128));
        if (max_depth < 1 || max_depth > 256)
            return tools::utils::MakeToolErrorJson(id, "max_depth must be between 1 and 256", "invalid_max_depth");

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
        if (pattern.is_discarded() || !pattern.is_object())
            return tools::utils::MakeToolErrorJson(id, "Parameter 'pattern' must be an object", "invalid_pattern");
        size_t pattern_nodes = 0;
        if (!ValidateCustomPattern(pattern, 0, pattern_nodes))
            return tools::utils::MakeToolErrorJson(id, "Parameter 'pattern' has an unsupported field, type, depth, or size", "invalid_pattern");
        if (addr_str.empty() && func_pattern.empty())
            return tools::utils::MakeToolErrorJson(id, "Provide addr or func_pattern to bound the AST search", "target_required");
        if (limit < 0 || limit > 4096 || max_matches < 0 || max_matches > 4096)
            return tools::utils::MakeToolErrorJson(id, "limit and max_matches must be between 0 and 4096", "invalid_limit");

        nlohmann::json matches = nlohmann::json::array();
        std::string error_code;
        std::string error_msg;
        size_t decompile_failures = 0;
        std::string first_decompile_error;
        size_t functions_scanned = 0;
        bool search_truncated = false;

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
                bool& matches_truncated;
                int max_matches;
                ea_t func_ea;
                std::string func_name;

                match_visitor_t(const cfunc_t* f, const nlohmann::json& pat, nlohmann::json& m,
                                bool& truncated, int max_m, ea_t fea, const std::string& fname)
                    : ctree_visitor_t(CV_FAST), cf(f), pattern(pat), matches(m), matches_truncated(truncated),
                      max_matches(max_m), func_ea(fea), func_name(fname) {}

                int idaapi visit_insn(cinsn_t* insn) override {
                    try {
                        sync::Checkpoint();
                        std::map<std::string, nlohmann::json> bindings;
                        if (MatchPattern(insn, cf, pattern, bindings)) {
                            if (matches.size() >= static_cast<size_t>(max_matches)) {
                                matches_truncated = true;
                                return 1;
                            }
                            nlohmann::ordered_json match_item = {
                                {"function", func_name},
                                {"address", tools::utils::FormatAddress(insn->ea)},
                                {"op", CTypeToString(insn->op)},
                                {"expr", CleanItemText(insn, cf)}
                            };
                            if (!bindings.empty()) {
                                match_item["bindings"] = bindings;
                            }
                            matches.push_back(std::move(match_item));
                        }
                        return 0;
                    } catch (...) {
                        sync::SaveCallbackException();
                        return 1;
                    }
                }

                int idaapi visit_expr(cexpr_t* expr) override {
                    try {
                        sync::Checkpoint();
                        std::map<std::string, nlohmann::json> bindings;
                        if (MatchPattern(expr, cf, pattern, bindings)) {
                            if (matches.size() >= static_cast<size_t>(max_matches)) {
                                matches_truncated = true;
                                return 1;
                            }
                            nlohmann::ordered_json match_item = {
                                {"function", func_name},
                                {"address", tools::utils::FormatAddress(expr->ea)},
                                {"op", CTypeToString(expr->op)},
                                {"expr", CleanItemText(expr, cf)}
                            };
                            if (!bindings.empty()) {
                                match_item["bindings"] = bindings;
                            }
                            matches.push_back(std::move(match_item));
                        }
                        return 0;
                    } catch (...) {
                        sync::SaveCallbackException();
                        return 1;
                    }
                }
            };

            if (!addr_str.empty()) {
                ea_t ea = tools::utils::ParseAddress(addr_str);
                func_t* pfn = (ea != BADADDR) ? get_func(ea) : nullptr;
                if (!pfn) {
                    error_code = "invalid_addr";
                    error_msg = "No function found containing given address: " + addr_str;
                    return;
                }

                hexrays_failure_t hf;
                cfuncptr_t cf = decompile(pfn, &hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                if (cf) {
                    qstring fn_name;
                    get_func_name(&fn_name, pfn->start_ea);
                    match_visitor_t visitor(cf, pattern, matches, search_truncated, max_matches, pfn->start_ea, fn_name.c_str());
                    visitor.apply_to(&cf->body, nullptr);
                    sync::Checkpoint();
                } else {
                    error_code = "decompilation_failed";
                    error_msg = "Decompilation failed: " + tools::utils::SanitizeUtf8(hf.desc().c_str());
                }
            } else {
                size_t total_funcs = get_func_qty();
                for (size_t i = 0; i < total_funcs && functions_scanned < static_cast<size_t>(limit); ++i) {
                    sync::Checkpoint();
                    func_t* pfn = getn_func(i);
                    if (!pfn) continue;
                    ++functions_scanned;

                    qstring fn_name;
                    get_func_name(&fn_name, pfn->start_ea);
                    std::string fname_str = fn_name.c_str();

                    if (!func_pattern.empty() && !tools::utils::PatternMatch(fname_str, func_pattern)) continue;

                    hexrays_failure_t hf;
                    cfuncptr_t cf = decompile(pfn, &hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                    if (cf) {
                        match_visitor_t visitor(cf, pattern, matches, search_truncated, max_matches, pfn->start_ea, fname_str);
                        visitor.apply_to(&cf->body, nullptr);
                        sync::Checkpoint();
                        if (search_truncated) break;
                    } else {
                        ++decompile_failures;
                        if (first_decompile_error.empty()) first_decompile_error = tools::utils::SanitizeUtf8(hf.desc().c_str());
                    }
                }
                if (functions_scanned < total_funcs) search_truncated = true;
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
        if (!addr_str.empty()) {
            res["functions_scanned"] = 1;
        } else {
            res["functions_scanned"] = functions_scanned;
        }
        if (search_truncated) res["truncated"] = true;
        if (decompile_failures > 0) {
            res["decompile_failures"] = decompile_failures;
            if (!first_decompile_error.empty()) res["first_decompile_error"] = first_decompile_error;
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiHexrays::MbaSimplify(const nlohmann::json& id, const nlohmann::json& args) {
        std::string addr_str = tools::utils::GetStringArg(args, "addr");
        std::string expr_addr_str = tools::utils::GetStringArg(args, "expr_addr");
        if (!expr_addr_str.empty() && tools::utils::ParseAddress(expr_addr_str) == BADADDR)
            return tools::utils::MakeToolErrorJson(id, "Parameter 'expr_addr' could not be resolved", "invalid_expr_addr");

        if (args.contains("custom_rules")) {
            const auto& custom_rules = args["custom_rules"];
            if (!custom_rules.is_array() || custom_rules.size() > kMaxCustomRules)
                return tools::utils::MakeToolErrorJson(id, "custom_rules must be an array of at most 64 entries", "invalid_custom_rules");
            for (size_t i = 0; i < custom_rules.size(); ++i) {
                const auto& rule = custom_rules[i];
                if (!rule.is_object() || !rule.contains("pattern"))
                    return tools::utils::MakeToolErrorJson(id, "Each custom rule must be an object containing pattern", "invalid_custom_rule");
                for (auto it = rule.begin(); it != rule.end(); ++it) {
                    if (it.key() != "name" && it.key() != "pattern" && it.key() != "simplified")
                        return tools::utils::MakeToolErrorJson(id, "Custom rule has an unsupported field: " + it.key(), "invalid_custom_rule");
                }
                if (rule.contains("name") && (!rule["name"].is_string() || rule["name"].get_ref<const std::string&>().size() > kMaxCustomText))
                    return tools::utils::MakeToolErrorJson(id, "Custom rule name must be a string of at most 256 bytes", "invalid_custom_rule");
                if (rule.contains("simplified") && (!rule["simplified"].is_string() || rule["simplified"].get_ref<const std::string&>().size() > kMaxCustomText))
                    return tools::utils::MakeToolErrorJson(id, "Custom rule simplified must be a string of at most 256 bytes", "invalid_custom_rule");
                size_t pattern_nodes = 0;
                if (!ValidateCustomPattern(rule["pattern"], 0, pattern_nodes))
                    return tools::utils::MakeToolErrorJson(id, "Custom rule pattern exceeds its supported shape, depth, or size", "invalid_custom_pattern");
            }
        }

        nlohmann::json matches = nlohmann::json::array();
        std::string error_code;
        std::string error_msg;
        bool matches_truncated = false;

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
                    sync::Checkpoint();
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
                sync::Checkpoint();
                combined_rules.push_back(r);
            }

            struct mba_visitor_t : public ctree_visitor_t {
                const cfunc_t* cf;
                const std::vector<MbaRule>& rules;
                nlohmann::json& matches;
                bool& matches_truncated;
                ea_t target_expr_ea;

                mba_visitor_t(const cfunc_t* f, const std::vector<MbaRule>& r, nlohmann::json& m, bool& tr, ea_t tea)
                    : ctree_visitor_t(CV_FAST), cf(f), rules(r), matches(m), matches_truncated(tr), target_expr_ea(tea) {}

                int idaapi visit_expr(cexpr_t* expr) override {
                    try {
                        sync::Checkpoint();
                        if (matches.size() >= kMaxSimplifyMatches) {
                            matches_truncated = true;
                            return 1;
                        }
                        if (target_expr_ea != BADADDR) {
                            if (expr->ea != target_expr_ea &&
                                (expr->ea == BADADDR || get_item_head(expr->ea) != get_item_head(target_expr_ea))) {
                                return 0;
                            }
                        }

                        bool is_candidate = (expr->op == cot_add || expr->op == cot_sub ||
                                             expr->op == cot_bor || expr->op == cot_xor ||
                                             expr->op == cot_band || expr->op == cot_bnot ||
                                             expr->op == cot_shl || expr->op == cot_sshr ||
                                             expr->op == cot_ushr || expr->op == cot_neg ||
                                             expr->op == cot_mul);
                        if (!is_candidate) return 0;

                        // Level 1: Static pattern matching
                        for (const auto& rule : rules) {
                            sync::Checkpoint();
                            std::map<std::string, nlohmann::json> bindings;
                            if (MatchPattern(expr, cf, rule.pattern, bindings)) {
                                std::string simplified_text = rule.format_simplified ? rule.format_simplified(bindings) : "";
                                matches.push_back({
                                    {"address", tools::utils::FormatAddress(expr->ea)},
                                    {"expression", CleanItemText(expr, cf)},
                                    {"simplified", simplified_text},
                                    {"rule", rule.name},
                                    {"confidence", "rule_verified"},
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
                                    {"confidence", "exact_constant"},
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
                    } catch (...) {
                        sync::SaveCallbackException();
                        return 1;
                    }
                }
            };

            mba_visitor_t visitor(cf, combined_rules, matches, matches_truncated, target_expr_ea);
            visitor.apply_to(&cf->body, nullptr);
            sync::Checkpoint();
        });

        if (!error_code.empty()) {
            return tools::utils::MakeToolErrorJson(id, error_msg, error_code);
        }

        nlohmann::json res = {
            {"status", "success"},
            {"matches_count", matches.size()},
            {"matches", matches}
        };
        if (matches_truncated) res["truncated"] = true;
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
                sync::Checkpoint();
                if (!item.is_object())
                    return tools::utils::MakeToolErrorJson(id, "Each predicate entry must be an object", "invalid_predicate");
                ea_t pea = tools::utils::GetAddressArg(item, "predicate_addr");
                std::string fb = tools::utils::GetStringArg(item, "force_branch");
                if (pea == BADADDR)
                    return tools::utils::MakeToolErrorJson(id, "Predicate address could not be resolved", "invalid_predicate_addr");
                if (fb != "always_true" && fb != "always_false")
                    return tools::utils::MakeToolErrorJson(id, "force_branch must be 'always_true' or 'always_false'", "invalid_force_branch");
                requests.push_back({pea, fb});
            }
        } else {
            std::string pred_addr_str = tools::utils::GetStringArg(args, "predicate_addr");
            std::string force_branch = tools::utils::GetStringArg(args, "force_branch");
            if (!pred_addr_str.empty()) {
                if (force_branch != "always_true" && force_branch != "always_false") {
                    return tools::utils::MakeToolErrorJson(id, "Parameter 'force_branch' must be 'always_true' or 'always_false'", "invalid_force_branch");
                }
                ea_t pea = tools::utils::ParseAddress(pred_addr_str);
                if (pea == BADADDR)
                    return tools::utils::MakeToolErrorJson(id, "Predicate address could not be resolved", "invalid_predicate_addr");
                requests.push_back({pea, force_branch});
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
        bool detections_truncated = false;

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
                    bool& truncated;
                    opaque_detector_t(const cfunc_t* f, nlohmann::json& d, bool& tr)
                        : ctree_visitor_t(CV_FAST), cf(f), detected(d), truncated(tr) {}

                    int idaapi visit_insn(cinsn_t* insn) override {
                        try {
                            sync::Checkpoint();
                            if (detected.size() >= 256) {
                                truncated = true;
                                return 1;
                            }
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
                        } catch (...) {
                            sync::SaveCallbackException();
                            return 1;
                        }
                    }
                };
                opaque_detector_t detector(cf, detected_opaques, detections_truncated);
                detector.apply_to(&cf->body, nullptr);
                sync::Checkpoint();
            }

            // Auto-populate requests from detected opaques if no manual requests were specified
            if (requests.empty() && auto_detect) {
                for (const auto& det : detected_opaques) {
                    sync::Checkpoint();
                    ea_t pea = tools::utils::ParseAddress(det["predicate_addr"].get<std::string>());
                    std::string fb = det["evaluation"].get<std::string>();
                    if (pea != BADADDR && (fb == "always_true" || fb == "always_false")) {
                        requests.push_back({pea, fb});
                    }
                }
            }

            bool any_idb_patched = false;

            // Apply modifications
            for (const auto& req : requests) {
                sync::Checkpoint();
                struct if_finder_t : public ctree_visitor_t {
                    ea_t target;
                    cinsn_t* found = nullptr;
                    if_finder_t(ea_t t) : ctree_visitor_t(CV_FAST), target(t) {}
                    int idaapi visit_insn(cinsn_t* insn) override {
                        try {
                            sync::Checkpoint();
                            if (insn->op == cit_if && (insn->ea == target || target == BADADDR)) {
                                found = insn;
                                return 1;
                            }
                            return 0;
                        } catch (...) {
                            sync::SaveCallbackException();
                            return 1;
                        }
                    }
                };

                if_finder_t finder(req.pred_ea);
                finder.apply_to(&cf->body, nullptr);
                sync::Checkpoint();
                if (!finder.found || !finder.found->cif) {
                    modifications.push_back({
                        {"predicate_addr", tools::utils::FormatAddress(req.pred_ea)},
                        {"force_branch", req.force_branch},
                        {"status", "skipped"},
                        {"reason", "predicate_not_found_in_function"}
                    });
                    continue;
                }

                cinsn_t* if_insn = finder.found;
                cif_t* cif = if_insn->cif;
                std::string orig_cond = CleanItemText(&cif->expr, (cfunc_t*)cf);
                const ea_t original_then_ea = cif->ithen ? cif->ithen->ea : BADADDR;
                const ea_t original_else_ea = cif->ielse ? cif->ielse->ea : BADADDR;

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
                bool patch_failed = false;
                if (persist) {
                    processor_t* processor = get_ph();
                    if (!processor || processor->id != PLFM_386) {
                        modifications.push_back({
                            {"predicate_addr", tools::utils::FormatAddress(req.pred_ea)},
                            {"force_branch", req.force_branch},
                            {"status", "skipped"},
                            {"reason", "persistent patching is currently supported only for x86/x64"}
                        });
                        continue;
                    }
                    ea_t jcc_ea = BADADDR;
                    insn_t insn;
                    const ea_t scan_end = req.pred_ea > BADADDR - 16 ? BADADDR : std::min(pfn->end_ea, req.pred_ea + 16);
                    for (ea_t cur = req.pred_ea; cur < scan_end; ) {
                        sync::Checkpoint();
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

                        ea_t then_ea = original_then_ea;
                        ea_t else_ea = original_else_ea;

                        std::optional<bool> taken_is_true;
                        if (then_ea != BADADDR && taken_ea == then_ea) {
                            taken_is_true = true;
                        } else if (else_ea != BADADDR && taken_ea == else_ea) {
                            taken_is_true = false;
                        } else if (then_ea != BADADDR && fallthrough_ea == then_ea) {
                            taken_is_true = false;
                        } else if (else_ea != BADADDR && fallthrough_ea == else_ea) {
                            taken_is_true = true;
                        }

                        if (!taken_is_true.has_value()) {
                            // Target branch could not be deterministically mapped: DO NOT patch IDB!
                            modifications.push_back({
                                {"predicate_addr", tools::utils::FormatAddress(req.pred_ea)},
                                {"force_branch", req.force_branch},
                                {"status", "skipped"},
                                {"reason", "branch_mapping_failed"}
                            });
                            continue;
                        }

                        bool want_true = (req.force_branch == "always_true");
                        bool should_jump = (want_true == *taken_is_true);

                        uint8_t op0 = get_byte(jcc_ea);
                        if (op0 >= 0x70 && op0 <= 0x7F) {
                            if (!should_jump) {
                                // Fallthrough: NOP out the 2-byte short Jcc
                                const bool first_ok = patch_byte(jcc_ea, 0x90);
                                const bool second_ok = first_ok && patch_byte(jcc_ea + 1, 0x90);
                                if (!second_ok && first_ok) patch_byte(jcc_ea, op0);
                                idb_patched = first_ok && second_ok;
                            } else {
                                // Taken: Convert short Jcc (7x cb) to short JMP (EB cb)
                                idb_patched = patch_byte(jcc_ea, 0xEB);
                            }
                            if (idb_patched) any_idb_patched = true;
                            else patch_failed = true;
                        } else if (op0 == 0x0F) {
                            uint8_t op1 = get_byte(jcc_ea + 1);
                            if (op1 >= 0x80 && op1 <= 0x8F) {
                                if (!should_jump) {
                                    // Fallthrough: NOP out the 6-byte near Jcc
                                    uint8_t original[6]{};
                                    if (get_bytes(original, sizeof(original), jcc_ea, 0) != sizeof(original)) {
                                        patch_failed = true;
                                    } else {
                                        idb_patched = true;
                                        for (size_t k = 0; k < sizeof(original); ++k) {
                                            if (!patch_byte(jcc_ea + k, 0x90)) { idb_patched = false; break; }
                                        }
                                        if (!idb_patched) {
                                            for (size_t k = 0; k < sizeof(original); ++k) patch_byte(jcc_ea + k, original[k]);
                                            patch_failed = true;
                                        }
                                    }
                                } else {
                                    // Taken: Convert near Jcc (0F 8x cd) to near JMP (E9 cd 90)
                                    // Near JMP E9 is 5 bytes; displacement is relative to next insn (jcc_ea + 5)
                                    int32_t delta = 0;
                                    if (jcc_ea > BADADDR - 5 || !TryRelative32(taken_ea, jcc_ea + 5, delta)) {
                                        patch_failed = true;
                                    } else {
                                        uint8_t original[6]{};
                                        if (get_bytes(original, sizeof(original), jcc_ea, 0) != sizeof(original)) {
                                            patch_failed = true;
                                        } else {
                                            idb_patched = patch_byte(jcc_ea, 0xE9)
                                                && patch_dword(jcc_ea + 1, static_cast<uint32>(delta))
                                                && patch_byte(jcc_ea + 5, 0x90);
                                            if (!idb_patched) {
                                                for (size_t k = 0; k < sizeof(original); ++k) patch_byte(jcc_ea + k, original[k]);
                                                patch_failed = true;
                                            }
                                        }
                                    }
                                }
                                if (idb_patched) any_idb_patched = true;
                                else patch_failed = true;
                            } else patch_failed = true;
                        } else {
                            patch_failed = true;
                        }
                    } else patch_failed = true;
                }

                nlohmann::ordered_json receipt = {
                    {"predicate_addr", tools::utils::FormatAddress(req.pred_ea)},
                    {"force_branch", req.force_branch},
                    {"original_condition", orig_cond},
                    {"persisted", idb_patched}
                };
                if (patch_failed) receipt["patch_failed"] = true;
                modifications.push_back(std::move(receipt));
            }

            if (any_idb_patched) {
                auto_mark_range(pfn->start_ea, pfn->end_ea, AU_CODE);
                plan_and_wait(pfn->start_ea, pfn->end_ea);
            }

#if IDA_SDK_VERSION >= 920
            cf->recalc_item_addresses();
#endif
            cf->remove_unused_labels();
            cf->refresh_func_ctext();

            const strvec_t& new_sv = cf->get_pseudocode();
            for (size_t i = 0; i < new_sv.size(); ++i) {
                sync::Checkpoint();
                qstring clean;
                tag_remove(&clean, new_sv[i].line);
                out_code += clean.c_str();
                out_code += "\n";
            }
            if (any_idb_patched) {
                cache::InvalidateIDBDependentCaches();
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
        if (detections_truncated) res["detected_opaques_truncated"] = true;
        return tools::utils::MakeToolSuccessJson(id, res);
    }
}
