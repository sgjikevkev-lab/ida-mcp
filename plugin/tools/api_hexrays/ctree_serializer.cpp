#include "ctree_serializer.h"
#include "../utils/utils.h"
#include <kernwin.hpp>
#include <name.hpp>

namespace tools::hexrays_ast {

    const char* CTypeToString(ctype_t op) {
        switch (op) {
            case cot_empty: return "cot_empty";
            case cot_comma: return "cot_comma";
            case cot_asg: return "cot_asg";
            case cot_asgbor: return "cot_asgbor";
            case cot_asgxor: return "cot_asgxor";
            case cot_asgband: return "cot_asgband";
            case cot_asgadd: return "cot_asgadd";
            case cot_asgsub: return "cot_asgsub";
            case cot_asgmul: return "cot_asgmul";
            case cot_asgsshr: return "cot_asgsshr";
            case cot_asgushr: return "cot_asgushr";
            case cot_asgshl: return "cot_asgshl";
            case cot_asgsdiv: return "cot_asgsdiv";
            case cot_asgudiv: return "cot_asgudiv";
            case cot_asgsmod: return "cot_asgsmod";
            case cot_asgumod: return "cot_asgumod";
            case cot_tern: return "cot_tern";
            case cot_lor: return "cot_lor";
            case cot_land: return "cot_land";
            case cot_bor: return "cot_bor";
            case cot_xor: return "cot_xor";
            case cot_band: return "cot_band";
            case cot_eq: return "cot_eq";
            case cot_ne: return "cot_ne";
            case cot_sge: return "cot_sge";
            case cot_uge: return "cot_uge";
            case cot_sle: return "cot_sle";
            case cot_ule: return "cot_ule";
            case cot_sgt: return "cot_sgt";
            case cot_ugt: return "cot_ugt";
            case cot_slt: return "cot_slt";
            case cot_ult: return "cot_ult";
            case cot_sshr: return "cot_sshr";
            case cot_ushr: return "cot_ushr";
            case cot_shl: return "cot_shl";
            case cot_add: return "cot_add";
            case cot_sub: return "cot_sub";
            case cot_mul: return "cot_mul";
            case cot_sdiv: return "cot_sdiv";
            case cot_udiv: return "cot_udiv";
            case cot_smod: return "cot_smod";
            case cot_umod: return "cot_umod";
            case cot_fadd: return "cot_fadd";
            case cot_fsub: return "cot_fsub";
            case cot_fmul: return "cot_fmul";
            case cot_fdiv: return "cot_fdiv";
            case cot_fneg: return "cot_fneg";
            case cot_neg: return "cot_neg";
            case cot_cast: return "cot_cast";
            case cot_lnot: return "cot_lnot";
            case cot_bnot: return "cot_bnot";
            case cot_ptr: return "cot_ptr";
            case cot_ref: return "cot_ref";
            case cot_postinc: return "cot_postinc";
            case cot_postdec: return "cot_postdec";
            case cot_preinc: return "cot_preinc";
            case cot_predec: return "cot_predec";
            case cot_call: return "cot_call";
            case cot_idx: return "cot_idx";
            case cot_memref: return "cot_memref";
            case cot_memptr: return "cot_memptr";
            case cot_num: return "cot_num";
            case cot_fnum: return "cot_fnum";
            case cot_str: return "cot_str";
            case cot_obj: return "cot_obj";
            case cot_var: return "cot_var";
            case cot_insn: return "cot_insn";
            case cot_sizeof: return "cot_sizeof";
            case cot_helper: return "cot_helper";
            case cot_type: return "cot_type";
            case cit_empty: return "cit_empty";
            case cit_block: return "cit_block";
            case cit_expr: return "cit_expr";
            case cit_if: return "cit_if";
            case cit_for: return "cit_for";
            case cit_while: return "cit_while";
            case cit_do: return "cit_do";
            case cit_switch: return "cit_switch";
            case cit_break: return "cit_break";
            case cit_continue: return "cit_continue";
            case cit_return: return "cit_return";
            case cit_goto: return "cit_goto";
            case cit_asm: return "cit_asm";
            case cit_try: return "cit_try";
            case cit_throw: return "cit_throw";
            default: return "unknown_op";
        }
    }

    ctype_t StringToCType(const std::string& str) {
        static const std::map<std::string, ctype_t> kMap = {
            {"cot_empty", cot_empty},
            {"cot_comma", cot_comma},
            {"cot_asg", cot_asg},
            {"cot_asgbor", cot_asgbor},
            {"cot_asgxor", cot_asgxor},
            {"cot_asgband", cot_asgband},
            {"cot_asgadd", cot_asgadd},
            {"cot_asgsub", cot_asgsub},
            {"cot_asgmul", cot_asgmul},
            {"cot_asgsshr", cot_asgsshr},
            {"cot_asgushr", cot_asgushr},
            {"cot_asgshl", cot_asgshl},
            {"cot_asgsdiv", cot_asgsdiv},
            {"cot_asgudiv", cot_asgudiv},
            {"cot_asgsmod", cot_asgsmod},
            {"cot_asgumod", cot_asgumod},
            {"cot_tern", cot_tern},
            {"cot_lor", cot_lor},
            {"cot_land", cot_land},
            {"cot_bor", cot_bor},
            {"cot_xor", cot_xor},
            {"cot_band", cot_band},
            {"cot_eq", cot_eq},
            {"cot_ne", cot_ne},
            {"cot_sge", cot_sge},
            {"cot_uge", cot_uge},
            {"cot_sle", cot_sle},
            {"cot_ule", cot_ule},
            {"cot_sgt", cot_sgt},
            {"cot_ugt", cot_ugt},
            {"cot_slt", cot_slt},
            {"cot_ult", cot_ult},
            {"cot_sshr", cot_sshr},
            {"cot_ushr", cot_ushr},
            {"cot_shl", cot_shl},
            {"cot_add", cot_add},
            {"cot_sub", cot_sub},
            {"cot_mul", cot_mul},
            {"cot_sdiv", cot_sdiv},
            {"cot_udiv", cot_udiv},
            {"cot_smod", cot_smod},
            {"cot_umod", cot_umod},
            {"cot_fadd", cot_fadd},
            {"cot_fsub", cot_fsub},
            {"cot_fmul", cot_fmul},
            {"cot_fdiv", cot_fdiv},
            {"cot_fneg", cot_fneg},
            {"cot_neg", cot_neg},
            {"cot_cast", cot_cast},
            {"cot_lnot", cot_lnot},
            {"cot_bnot", cot_bnot},
            {"cot_ptr", cot_ptr},
            {"cot_ref", cot_ref},
            {"cot_postinc", cot_postinc},
            {"cot_postdec", cot_postdec},
            {"cot_preinc", cot_preinc},
            {"cot_predec", cot_predec},
            {"cot_call", cot_call},
            {"cot_idx", cot_idx},
            {"cot_memref", cot_memref},
            {"cot_memptr", cot_memptr},
            {"cot_num", cot_num},
            {"cot_fnum", cot_fnum},
            {"cot_str", cot_str},
            {"cot_obj", cot_obj},
            {"cot_var", cot_var},
            {"cot_insn", cot_insn},
            {"cot_sizeof", cot_sizeof},
            {"cot_helper", cot_helper},
            {"cot_type", cot_type},
            {"cit_empty", cit_empty},
            {"cit_block", cit_block},
            {"cit_expr", cit_expr},
            {"cit_if", cit_if},
            {"cit_for", cit_for},
            {"cit_while", cit_while},
            {"cit_do", cit_do},
            {"cit_switch", cit_switch},
            {"cit_break", cit_break},
            {"cit_continue", cit_continue},
            {"cit_return", cit_return},
            {"cit_goto", cit_goto},
            {"cit_asm", cit_asm},
            {"cit_try", cit_try},
            {"cit_throw", cit_throw}
        };
        auto it = kMap.find(str);
        return it != kMap.end() ? it->second : cot_empty;
    }

    std::string CleanItemText(const citem_t* item, const cfunc_t* cf) {
        if (!item || !cf) return "";
        qstring qstr;
        if (item->is_expr()) {
            const cexpr_t* e = static_cast<const cexpr_t*>(item);
            e->print1(&qstr, cf);
        } else {
            const cinsn_t* insn = static_cast<const cinsn_t*>(item);
            insn->print1(&qstr, cf);
        }
        qstring clean;
        tag_remove(&clean, qstr);
        return clean.c_str();
    }

    nlohmann::json SerializeLvars(const cfunc_t* cf) {
        nlohmann::json lvar_array = nlohmann::json::array();
        if (!cf) return lvar_array;

        const lvars_t* lvars = const_cast<cfunc_t*>(cf)->get_lvars();
        if (!lvars) return lvar_array;

        for (size_t i = 0; i < lvars->size(); ++i) {
            const lvar_t& lv = (*lvars)[i];
            qstring type_str;
            lv.type().print(&type_str);
            lvar_array.push_back({
                {"index", i},
                {"name", tools::utils::SafeJsonString(lv.name.c_str())},
                {"type", tools::utils::SafeJsonString(type_str.c_str())},
                {"size", lv.width},
                {"is_arg", lv.is_arg_var()},
                {"is_stk", lv.is_stk_var()},
                {"is_reg", lv.is_reg_var()},
                {"is_used", lv.used()},
                {"location", lv.is_reg_var() ? "reg" : (lv.is_stk_var() ? "stack" : "other")}
            });
        }
        return lvar_array;
    }

    nlohmann::json SerializeCItem(const citem_t* item, const cfunc_t* cf, int max_depth, int current_depth) {
        if (!item) return nullptr;

        nlohmann::json res = nlohmann::json::object();
        res["op"] = CTypeToString(item->op);

        if (item->ea != BADADDR) {
            res["addr"] = tools::utils::FormatAddress(item->ea);
        }

        if (current_depth >= max_depth) {
            res["truncated"] = true;
            return res;
        }

        if (item->is_expr()) {
            const cexpr_t* e = static_cast<const cexpr_t*>(item);
            res["kind"] = "expr";

            qstring type_str;
            e->type.print(&type_str);
            res["type"] = tools::utils::SafeJsonString(type_str.c_str());

            switch (e->op) {
                case cot_num:
                    if (e->n) {
                        res["value"] = e->n->value(e->type);
                    }
                    break;

                case cot_fnum:
                    if (e->fpc) {
                        qstring fstr;
                        e->fpc->print(&fstr);
                        res["fvalue"] = fstr.empty() ? (e->fpc->dstr() ? e->fpc->dstr() : "0.0") : fstr.c_str();
                    }
                    break;

                case cot_str:
                    res["string"] = tools::utils::SafeJsonString(e->string ? e->string : "");
                    break;

                case cot_obj:
                    res["obj_ea"] = tools::utils::FormatAddress(e->obj_ea);
                    {
                        qstring name_buf;
                        if (is_mapped(e->obj_ea)) {
                            get_name(&name_buf, e->obj_ea);
                        }
                        res["obj_name"] = tools::utils::SafeJsonString(name_buf.c_str());
                    }
                    break;

                case cot_var:
                    res["var_idx"] = e->v.idx;
                    if (cf) {
                        const lvars_t* lvs = const_cast<cfunc_t*>(cf)->get_lvars();
                        if (lvs && e->v.idx < lvs->size()) {
                            res["var_name"] = tools::utils::SafeJsonString((*lvs)[e->v.idx].name.c_str());
                        }
                    }
                    break;

                case cot_helper:
                    res["helper"] = tools::utils::SafeJsonString(e->helper ? e->helper : "");
                    break;


                case cot_memptr:
                case cot_memref:
                    res["member_offset"] = e->m;
                    res["ptrsize"] = e->ptrsize;
                    if (e->x) {
                        res["x"] = SerializeCItem(e->x, cf, max_depth, current_depth + 1);
                    }
                    break;

                case cot_ptr:
                    res["ptrsize"] = e->ptrsize;
                    if (e->x) {
                        res["x"] = SerializeCItem(e->x, cf, max_depth, current_depth + 1);
                    }
                    break;

                case cot_call:
                    if (e->x) {
                        res["x"] = SerializeCItem(e->x, cf, max_depth, current_depth + 1);
                    }
                    if (e->a) {
                        nlohmann::json args_arr = nlohmann::json::array();
                        for (size_t i = 0; i < e->a->size(); ++i) {
                            const carg_t& arg = (*e->a)[i];
                            args_arr.push_back(SerializeCItem(&arg, cf, max_depth, current_depth + 1));
                        }
                        res["args"] = args_arr;
                    }
                    break;

                default:
                    if (op_uses_x(e->op) && e->x) {
                        res["x"] = SerializeCItem(e->x, cf, max_depth, current_depth + 1);
                    }
                    if (op_uses_y(e->op) && e->y) {
                        res["y"] = SerializeCItem(e->y, cf, max_depth, current_depth + 1);
                    }
                    if (op_uses_z(e->op) && e->z) {
                        res["z"] = SerializeCItem(e->z, cf, max_depth, current_depth + 1);
                    }
                    break;
            }
        } else {
            const cinsn_t* insn = static_cast<const cinsn_t*>(item);
            res["kind"] = "stmt";

            switch (insn->op) {
                case cit_block:
                    if (insn->cblock) {
                        nlohmann::json body_arr = nlohmann::json::array();
                        for (const auto& child : *insn->cblock) {
                            body_arr.push_back(SerializeCItem(&child, cf, max_depth, current_depth + 1));
                        }
                        res["body"] = body_arr;
                    }
                    break;

                case cit_expr:
                    if (insn->cexpr) {
                        res["expr"] = SerializeCItem(insn->cexpr, cf, max_depth, current_depth + 1);
                    }
                    break;

                case cit_if:
                    if (insn->cif) {
                        res["cond"] = SerializeCItem(&insn->cif->expr, cf, max_depth, current_depth + 1);
                        if (insn->cif->ithen) {
                            res["then"] = SerializeCItem(insn->cif->ithen, cf, max_depth, current_depth + 1);
                        }
                        if (insn->cif->ielse) {
                            res["else"] = SerializeCItem(insn->cif->ielse, cf, max_depth, current_depth + 1);
                        }
                    }
                    break;

                case cit_for:
                    if (insn->cfor) {
                        res["init"] = SerializeCItem(&insn->cfor->init, cf, max_depth, current_depth + 1);
                        res["cond"] = SerializeCItem(&insn->cfor->expr, cf, max_depth, current_depth + 1);
                        res["step"] = SerializeCItem(&insn->cfor->step, cf, max_depth, current_depth + 1);
                        if (insn->cfor->body) {
                            res["body"] = SerializeCItem(insn->cfor->body, cf, max_depth, current_depth + 1);
                        }
                    }
                    break;

                case cit_while:
                case cit_do:
                    if (insn->cwhile) {
                        res["cond"] = SerializeCItem(&insn->cwhile->expr, cf, max_depth, current_depth + 1);
                        if (insn->cwhile->body) {
                            res["body"] = SerializeCItem(insn->cwhile->body, cf, max_depth, current_depth + 1);
                        }
                    }
                    break;

                case cit_return:
                    if (insn->creturn) {
                        res["expr"] = SerializeCItem(&insn->creturn->expr, cf, max_depth, current_depth + 1);
                    }
                    break;

                case cit_goto:
                    if (insn->cgoto) {
                        res["target_label"] = insn->cgoto->label_num;
                    }
                    break;

                case cit_switch:
                    if (insn->cswitch) {
                        res["expr"] = SerializeCItem(&insn->cswitch->expr, cf, max_depth, current_depth + 1);
                        nlohmann::json cases_arr = nlohmann::json::array();
                        for (const auto& cs : insn->cswitch->cases) {
                            nlohmann::json case_json = nlohmann::json::object();
                            nlohmann::json vals = nlohmann::json::array();
                            for (size_t vi = 0; vi < cs.size(); ++vi) {
                                vals.push_back(cs.value(static_cast<int>(vi)));
                            }
                            case_json["values"] = vals;
                            case_json["body"] = SerializeCItem(&cs, cf, max_depth, current_depth + 1);
                            cases_arr.push_back(case_json);
                        }
                        res["cases"] = cases_arr;
                    }
                    break;

                default:
                    break;
            }
        }

        return res;
    }

    bool MatchPattern(
        const citem_t* node,
        const cfunc_t* cf,
        const nlohmann::json& pattern,
        std::map<std::string, nlohmann::json>& bindings
    ) {
        if (!node) return false;

        // String pattern
        if (pattern.is_string()) {
            std::string pat_str = pattern.get<std::string>();
            if (pat_str == "$_") {
                return true; // Wildcard matches anything
            }
            if (pat_str.rfind("$", 0) == 0) {
                // Template variable capture
                nlohmann::json serialized = SerializeCItem(node, cf, 8);
                auto it = bindings.find(pat_str);
                if (it != bindings.end()) {
                    return it->second == serialized;
                } else {
                    bindings[pat_str] = serialized;
                    return true;
                }
            }
            // Literal opcode name check
            return CTypeToString(node->op) == pat_str;
        }

        // Object pattern
        if (pattern.is_object()) {
            if (pattern.contains("op")) {
                std::string op_str = pattern["op"].is_string() ? pattern["op"].get<std::string>() : "";
                if (!op_str.empty() && op_str != "$_" && op_str.rfind("$", 0) != 0) {
                    if (CTypeToString(node->op) != op_str) {
                        return false;
                    }
                }
            }

            if (node->is_expr()) {
                const cexpr_t* e = static_cast<const cexpr_t*>(node);

                if (pattern.contains("value") && e->op == cot_num) {
                    if (pattern["value"].is_number()) {
                        uint64 v = pattern["value"].get<uint64>();
                        if (e->n && e->n->value(e->type) != v) return false;
                    }
                }

                if (pattern.contains("var_name") && e->op == cot_var) {
                    std::string expected_var = pattern["var_name"].get<std::string>();
                    std::string actual_var = "";
                    if (cf) {
                        const lvars_t* lvs = const_cast<cfunc_t*>(cf)->get_lvars();
                        if (lvs && e->v.idx < lvs->size()) {
                            actual_var = (*lvs)[e->v.idx].name.c_str();
                        }
                    }
                    if (expected_var.rfind("$", 0) == 0 && expected_var != "$_") {
                        auto it = bindings.find(expected_var);
                        if (it != bindings.end()) {
                            if (it->second != actual_var) return false;
                        } else {
                            bindings[expected_var] = actual_var;
                        }
                    } else if (expected_var != "$_" && expected_var != actual_var) {
                        return false;
                    }
                }

                if (pattern.contains("obj_name") && e->op == cot_obj) {
                    qstring name_buf;
                    get_name(&name_buf, e->obj_ea);
                    std::string actual_name = name_buf.c_str();
                    std::string expected_name = pattern["obj_name"].get<std::string>();
                    if (expected_name.rfind("$", 0) == 0 && expected_name != "$_") {
                        auto it = bindings.find(expected_name);
                        if (it != bindings.end()) {
                            if (it->second != actual_name) return false;
                        } else {
                            bindings[expected_name] = actual_name;
                        }
                    } else if (expected_name != "$_" && expected_name != actual_name) {
                        return false;
                    }
                }

                // Handle commutative binary expressions
                if (is_commutative(e->op) && pattern.contains("x") && pattern.contains("y")) {
                    auto saved_bindings = bindings;
                    bool direct = MatchPattern(e->x, cf, pattern["x"], bindings) &&
                                  MatchPattern(e->y, cf, pattern["y"], bindings);
                    if (direct) return true;

                    bindings = saved_bindings;
                    bool swapped = MatchPattern(e->x, cf, pattern["y"], bindings) &&
                                   MatchPattern(e->y, cf, pattern["x"], bindings);
                    if (swapped) return true;

                    bindings = saved_bindings;
                    return false;
                }

                if (pattern.contains("x")) {
                    if (!e->x || !MatchPattern(e->x, cf, pattern["x"], bindings)) return false;
                }
                if (pattern.contains("y")) {
                    if (!e->y || !MatchPattern(e->y, cf, pattern["y"], bindings)) return false;
                }
                if (pattern.contains("z")) {
                    if (!e->z || !MatchPattern(e->z, cf, pattern["z"], bindings)) return false;
                }

                if (pattern.contains("args") && e->op == cot_call) {
                    if (!pattern["args"].is_array()) return false;
                    const auto& pat_args = pattern["args"];
                    size_t actual_count = e->a ? e->a->size() : 0;

                    for (size_t ai = 0; ai < pat_args.size(); ++ai) {
                        if (pat_args[ai].is_string() && pat_args[ai].get<std::string>() == "$_") {
                            // Wildcard at the end of args allows remaining arguments
                            if (ai == pat_args.size() - 1) return true;
                        }
                        if (ai >= actual_count) return false;
                        const carg_t& arg = (*e->a)[ai];
                        if (!MatchPattern(&arg, cf, pat_args[ai], bindings)) return false;
                    }
                    if (pat_args.size() < actual_count && !(pat_args.back().is_string() && pat_args.back().get<std::string>() == "$_")) {
                        return false;
                    }
                }

                return true;
            } else {
                const cinsn_t* insn = static_cast<const cinsn_t*>(node);

                if (pattern.contains("cond")) {
                    const cexpr_t* cnd = nullptr;
                    if (insn->op == cit_if && insn->cif) cnd = &insn->cif->expr;
                    else if (insn->op == cit_for && insn->cfor) cnd = &insn->cfor->expr;
                    else if ((insn->op == cit_while || insn->op == cit_do) && insn->cwhile) cnd = &insn->cwhile->expr;

                    if (!cnd || !MatchPattern(cnd, cf, pattern["cond"], bindings)) return false;
                }

                if (pattern.contains("then") && insn->op == cit_if && insn->cif) {
                    if (!insn->cif->ithen || !MatchPattern(insn->cif->ithen, cf, pattern["then"], bindings)) return false;
                }

                if (pattern.contains("else") && insn->op == cit_if && insn->cif) {
                    if (!insn->cif->ielse || !MatchPattern(insn->cif->ielse, cf, pattern["else"], bindings)) return false;
                }

                if (pattern.contains("expr")) {
                    const cexpr_t* exp = nullptr;
                    if (insn->op == cit_expr && insn->cexpr) exp = insn->cexpr;
                    else if (insn->op == cit_return && insn->creturn) exp = &insn->creturn->expr;
                    else if (insn->op == cit_switch && insn->cswitch) exp = &insn->cswitch->expr;

                    if (!exp || !MatchPattern(exp, cf, pattern["expr"], bindings)) return false;
                }

                return true;
            }
        }

        return false;
    }
}
