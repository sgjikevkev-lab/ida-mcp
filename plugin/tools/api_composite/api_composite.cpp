#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <set>
#include <queue>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "api_composite.h"
#include "tools/utils/utils.h"
#include "sync/sync.h"

#include <ida.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <lines.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <entry.hpp>
#include <xref.hpp>
#include <typeinf.hpp>
#include <functional>
#include <hexrays.hpp>
#include "tools/api_hexrays/ctree_serializer.h"

namespace tools::composite {
    bool ApiComposite::CanHandle(const std::string& name) const {
        return name == "survey_binary" ||
               name == "analyze_function" ||
               name == "trace_data_flow";
    }

    nlohmann::json ApiComposite::GetSchema() const {
        return nlohmann::json::array();
    }

    nlohmann::json ApiComposite::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "survey_binary") return SurveyBinary(id, args);
        if (name == "analyze_function") return AnalyzeFunction(id, args);
        if (name == "trace_data_flow") return TraceDataFlow(id, args);

        return tools::utils::MakeToolErrorJson(id, "Method not found: " + name, "method_not_found");
    }

    nlohmann::json ApiComposite::SurveyBinary(const nlohmann::json& id, const nlohmann::json& /*args*/) {
        nlohmann::json res;

        sync::SyncRead([&]() {
            char path_buf[QMAXPATH];
            get_input_file_path(path_buf, sizeof(path_buf));
            std::string file_path = path_buf;

            std::string mod_name = file_path;
            size_t sep = mod_name.find_last_of("\\/");
            if (sep != std::string::npos) mod_name = mod_name.substr(sep + 1);

            char proc_buf[32];
            inf_get_procname(proc_buf, sizeof(proc_buf));
            std::string arch = proc_buf;
            if (inf_is_64bit()) arch += " (64-bit)";
            else if (inf_is_32bit_or_higher()) arch += " (32-bit)";

            ea_t base_ea = get_imagebase();
            size_t total_funcs = get_func_qty();

            nlohmann::json segs_arr = nlohmann::json::array();
            int nsegs = get_segm_qty();
            for (int i = 0; i < nsegs; ++i) {
                segment_t* s = getnseg(i);
                if (!s) continue;
                qstring sname;
                get_segm_name(&sname, s);
                std::string perms = "";
                if (s->perm & SEGPERM_READ) perms += "R";
                if (s->perm & SEGPERM_WRITE) perms += "W";
                if (s->perm & SEGPERM_EXEC) perms += "X";

                segs_arr.push_back({
                    {"name", std::string(sname.c_str())},
                    {"start", tools::utils::FormatAddress(s->start_ea)},
                    {"end", tools::utils::FormatAddress(s->end_ea)},
                    {"size", s->size()},
                    {"perm", perms}
                });
            }

            nlohmann::json entries_arr = nlohmann::json::array();
            size_t nentries = get_entry_qty();
            for (size_t i = 0; i < nentries; ++i) {
                uval_t ord = get_entry_ordinal(i);
                ea_t e_ea = get_entry(ord);
                qstring ename;
                get_entry_name(&ename, ord);
                entries_arr.push_back({
                    {"ordinal", ord},
                    {"address", tools::utils::FormatAddress(e_ea)},
                    {"name", ename.c_str()}
                });
            }

            res = {
                {"status", "success"},
                {"module", mod_name},
                {"arch", arch},
                {"image_base", tools::utils::FormatAddress(base_ea)},
                {"total_functions", total_funcs},
                {"segments", segs_arr},
                {"entrypoints", entries_arr}
            };
        });

        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiComposite::AnalyzeFunction(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t target_ea = tools::utils::GetAddressArg(args, "addr");
        if (target_ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }

        nlohmann::json res;
        bool found = false;

        sync::SyncRead([&]() {
            func_t* fn = get_func(target_ea);
            if (!fn) return;
            found = true;

            qstring name_buf;
            get_func_name(&name_buf, fn->start_ea);

            tinfo_t tif;
            std::string proto = "";
            if (get_tinfo(&tif, fn->start_ea)) {
                qstring proto_buf;
                if (tif.print(&proto_buf, name_buf.c_str())) {
                    proto = proto_buf.c_str();
                }
            }

            int callers_count = 0;
            xrefblk_t xb_to;
            for (bool ok = xb_to.first_to(fn->start_ea, XREF_ALL); ok; ok = xb_to.next_to()) {
                if (xb_to.iscode) callers_count++;
            }

            nlohmann::json callees_arr = nlohmann::json::array();
            std::set<ea_t> callees_seen;
            for (ea_t cur = fn->start_ea; cur < fn->end_ea; cur = get_item_end(cur)) {
                xrefblk_t xb_from;
                for (bool ok = xb_from.first_from(cur, XREF_ALL); ok; ok = xb_from.next_from()) {
                    if (xb_from.iscode && xb_from.type == fl_CN && callees_seen.find(xb_from.to) == callees_seen.end()) {
                        callees_seen.insert(xb_from.to);
                        qstring callee_name;
                        get_ea_name(&callee_name, xb_from.to);
                        callees_arr.push_back({
                            {"address", tools::utils::FormatAddress(xb_from.to)},
                            {"name", callee_name.empty() ? tools::utils::FormatAddress(xb_from.to) : std::string(callee_name.c_str())}
                        });
                    }
                }
            }

            res = {
                {"status", "success"},
                {"function", std::string(name_buf.c_str())},
                {"start", tools::utils::FormatAddress(fn->start_ea)},
                {"end", tools::utils::FormatAddress(fn->end_ea)},
                {"size", fn->size()},
                {"prototype", proto},
                {"callers_count", callers_count},
                {"callees", callees_arr}
            };
        });

        if (!found) {
            return tools::utils::MakeToolErrorJson(
                id,
                "No function found containing address " + tools::utils::FormatAddress(target_ea),
                "function_not_found"
            );
        }

        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiComposite::TraceDataFlow(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t start_ea = tools::utils::GetAddressArg(args, "addr");
        if (start_ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }

        std::string target_var = tools::utils::GetStringArg(args, "var");
        std::string direction = tools::utils::GetStringArg(args, "direction", "forward");
        if (direction != "forward" && direction != "backward") direction = "forward";

        int max_depth = static_cast<int>(tools::utils::GetIntArg(args, "depth", 2));
        if (max_depth <= 0) max_depth = 2;
        if (max_depth > 5) max_depth = 5;

        bool include_calls = tools::utils::GetBoolArg(args, "include_calls", true);

        nlohmann::json flow_arr = nlohmann::json::array();
        std::string root_var_name = target_var;
        bool used_hexrays = false;
        std::string error_code;
        std::string error_msg;

        sync::SyncToMainThread([&]() {
            func_t* pfn = get_func(start_ea);
            // If Hex-Rays is available and we are inside a function, perform ctree-based data flow analysis
            if (pfn && init_hexrays_plugin()) {
                hexrays_failure_t hf;
                cfuncptr_t cf = decompile(pfn, &hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                if (cf) {
                    used_hexrays = true;

                    // If target_var is empty, try to deduce it from start_ea or function arguments
                    if (target_var.empty()) {
                        const lvars_t* lvars = cf->get_lvars();
                        if (lvars && !lvars->empty()) {
                            for (size_t i = 0; i < lvars->size(); ++i) {
                                if ((*lvars)[i].is_arg_var()) {
                                    target_var = (*lvars)[i].name.c_str();
                                    break;
                                }
                            }
                            if (target_var.empty()) {
                                target_var = (*lvars)[0].name.c_str();
                            }
                        }
                    }
                    root_var_name = target_var;

                    // Trace function with recursion for inter-procedural calls
                    std::set<ea_t> visited_funcs;
                    std::function<void(func_t*, const std::string&, int)> trace_fn;

                    trace_fn = [&](func_t* fn, const std::string& var_name, int current_depth) {
                        if (!fn || visited_funcs.count(fn->start_ea) || current_depth > max_depth) return;
                        visited_funcs.insert(fn->start_ea);

                        hexrays_failure_t local_hf;
                        cfuncptr_t local_cf = decompile(fn, &local_hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                        if (!local_cf) return;

                        std::set<std::string> active_vars = {var_name};

                        if (direction == "forward") {
                            struct ForwardVisitor : public ctree_visitor_t {
                                const cfunc_t* cf;
                                std::set<std::string>& active_vars;
                                nlohmann::json& flow;
                                int depth;
                                bool inc_calls;
                                int max_d;
                                std::function<void(func_t*, const std::string&, int)> recurse_fn;

                                ForwardVisitor(const cfunc_t* f, std::set<std::string>& av, nlohmann::json& fl,
                                               int d, bool ic, int md, std::function<void(func_t*, const std::string&, int)> rf)
                                    : ctree_visitor_t(CV_FAST), cf(f), active_vars(av), flow(fl),
                                      depth(d), inc_calls(ic), max_d(md), recurse_fn(rf) {}

                                bool UsesActiveVar(const cexpr_t* e, std::string& out_name) {
                                    if (!e) return false;
                                    if (e->op == cot_var) {
                                        const lvars_t* lvars = const_cast<cfunc_t*>(cf)->get_lvars();
                                        if (lvars && e->v.idx >= 0 && e->v.idx < static_cast<int>(lvars->size())) {
                                            std::string vname = (*lvars)[e->v.idx].name.c_str();
                                            if (active_vars.count(vname)) {
                                                out_name = vname;
                                                return true;
                                            }
                                        }
                                        return false;
                                    }
                                    if (op_uses_x(e->op) && e->x && UsesActiveVar(e->x, out_name)) return true;
                                    if (op_uses_y(e->op) && e->y && UsesActiveVar(e->y, out_name)) return true;
                                    if (op_uses_z(e->op) && e->z && UsesActiveVar(e->z, out_name)) return true;
                                    if (e->op == cot_call && e->a) {
                                        for (const auto& arg : *e->a) {
                                            if (UsesActiveVar(&arg, out_name)) return true;
                                        }
                                    }
                                    return false;
                                }

                                int idaapi visit_expr(cexpr_t* e) override {
                                    if (flow.size() >= 100) return 1;

                                    // 1. Assignment: lhs = rhs
                                    if (e->op == cot_asg || e->op == cot_asgbor || e->op == cot_asgband ||
                                        e->op == cot_asgadd || e->op == cot_asgsub || e->op == cot_asgmul) {
                                        std::string used_var;
                                        if (UsesActiveVar(e->y, used_var)) {
                                            if (e->x && e->x->op == cot_var) {
                                                const lvars_t* lvars = const_cast<cfunc_t*>(cf)->get_lvars();
                                                if (lvars && e->x->v.idx >= 0 && e->x->v.idx < static_cast<int>(lvars->size())) {
                                                    std::string to_var = (*lvars)[e->x->v.idx].name.c_str();
                                                    flow.push_back({
                                                        {"depth", depth},
                                                        {"address", tools::utils::FormatAddress(e->ea)},
                                                        {"type", "assign"},
                                                        {"from", used_var},
                                                        {"to", to_var}
                                                    });
                                                    active_vars.insert(to_var);
                                                }
                                            } else if (e->x && (e->x->op == cot_ptr || e->x->op == cot_memptr || e->x->op == cot_memref || e->x->op == cot_obj)) {
                                                flow.push_back({
                                                    {"depth", depth},
                                                    {"address", tools::utils::FormatAddress(e->ea)},
                                                    {"type", "store"},
                                                    {"from", used_var},
                                                    {"target", hexrays_ast::CleanItemText(e->x, cf)}
                                                });
                                            }
                                        }
                                    }

                                    // 2. Call argument: callee(..., arg, ...)
                                    if (e->op == cot_call && e->a) {
                                        std::string callee_name = hexrays_ast::CleanItemText(e->x, cf);
                                        ea_t callee_ea = (e->x && e->x->op == cot_obj) ? e->x->obj_ea : BADADDR;

                                        for (size_t i = 0; i < e->a->size(); ++i) {
                                            const cexpr_t* arg_expr = &(*e->a)[i];
                                            std::string used_var;
                                            if (UsesActiveVar(arg_expr, used_var)) {
                                                flow.push_back({
                                                    {"depth", depth},
                                                    {"address", tools::utils::FormatAddress(e->ea)},
                                                    {"type", "call_arg"},
                                                    {"from", used_var},
                                                    {"callee", callee_name},
                                                    {"arg_index", i}
                                                });

                                                if (inc_calls && depth < max_d && callee_ea != BADADDR) {
                                                    func_t* callee_fn = get_func(callee_ea);
                                                    if (callee_fn) {
                                                        hexrays_failure_t cf_hf;
                                                        cfuncptr_t callee_cf = decompile(callee_fn, &cf_hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                                                        if (callee_cf) {
                                                            const lvars_t* callee_lvars = callee_cf->get_lvars();
                                                            std::string param_name;
                                                            size_t arg_cnt = 0;
                                                            if (callee_lvars) {
                                                                for (size_t k = 0; k < callee_lvars->size(); ++k) {
                                                                    if ((*callee_lvars)[k].is_arg_var()) {
                                                                        if (arg_cnt == i) {
                                                                            param_name = (*callee_lvars)[k].name.c_str();
                                                                            break;
                                                                        }
                                                                        arg_cnt++;
                                                                    }
                                                                }
                                                            }
                                                            if (!param_name.empty()) {
                                                                flow.push_back({
                                                                    {"depth", depth + 1},
                                                                    {"address", tools::utils::FormatAddress(callee_fn->start_ea)},
                                                                    {"type", "param_use"},
                                                                    {"function", callee_name},
                                                                    {"param", param_name}
                                                                });
                                                                recurse_fn(callee_fn, param_name, depth + 1);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // 3. Array indexing: arr[var]
                                    if (e->op == cot_idx) {
                                        std::string used_var;
                                        if (UsesActiveVar(e->y, used_var)) {
                                            flow.push_back({
                                                {"depth", depth},
                                                {"address", tools::utils::FormatAddress(e->ea)},
                                                {"type", "index_use"},
                                                {"from", used_var},
                                                {"array", hexrays_ast::CleanItemText(e->x, cf)}
                                            });
                                        }
                                    }

                                    return 0;
                                }

                                int idaapi visit_insn(cinsn_t* insn) override {
                                    if (flow.size() >= 100) return 1;
                                    if (insn->op == cit_if && insn->cif) {
                                        std::string used_var;
                                        if (UsesActiveVar(&insn->cif->expr, used_var)) {
                                            flow.push_back({
                                                {"depth", depth},
                                                {"address", tools::utils::FormatAddress(insn->ea)},
                                                {"type", "condition"},
                                                {"from", used_var},
                                                {"condition", hexrays_ast::CleanItemText(&insn->cif->expr, cf)}
                                            });
                                        }
                                    }
                                    if (insn->op == cit_return && insn->creturn && insn->creturn->expr.op != cot_empty) {
                                        std::string used_var;
                                        if (UsesActiveVar(&insn->creturn->expr, used_var)) {
                                            flow.push_back({
                                                {"depth", depth},
                                                {"address", tools::utils::FormatAddress(insn->ea)},
                                                {"type", "return"},
                                                {"from", used_var}
                                            });
                                        }
                                    }
                                    return 0;
                                }
                            };

                            ForwardVisitor visitor(local_cf, active_vars, flow_arr, current_depth, include_calls, max_depth, trace_fn);
                            visitor.apply_to(&local_cf->body, nullptr);
                        } else {
                            // Backward direction: use -> def
                            struct BackwardVisitor : public ctree_visitor_t {
                                const cfunc_t* cf;
                                std::set<std::string>& active_vars;
                                nlohmann::json& flow;
                                int depth;

                                BackwardVisitor(const cfunc_t* f, std::set<std::string>& av, nlohmann::json& fl, int d)
                                    : ctree_visitor_t(CV_FAST), cf(f), active_vars(av), flow(fl), depth(d) {}

                                int idaapi visit_expr(cexpr_t* e) override {
                                    if (flow.size() >= 100) return 1;

                                    if (e->op == cot_asg || e->op == cot_asgbor || e->op == cot_asgband ||
                                        e->op == cot_asgadd || e->op == cot_asgsub || e->op == cot_asgmul) {
                                        if (e->x && e->x->op == cot_var) {
                                            const lvars_t* lvars = const_cast<cfunc_t*>(cf)->get_lvars();
                                            if (lvars && e->x->v.idx >= 0 && e->x->v.idx < static_cast<int>(lvars->size())) {
                                                std::string lhs_name = (*lvars)[e->x->v.idx].name.c_str();
                                                if (active_vars.count(lhs_name)) {
                                                    std::string rhs_text = hexrays_ast::CleanItemText(e->y, cf);
                                                    flow.push_back({
                                                        {"depth", depth},
                                                        {"address", tools::utils::FormatAddress(e->ea)},
                                                        {"type", "assign_def"},
                                                        {"to", lhs_name},
                                                        {"from", rhs_text}
                                                    });
                                                    if (e->y && e->y->op == cot_call) {
                                                        flow.push_back({
                                                            {"depth", depth},
                                                            {"address", tools::utils::FormatAddress(e->y->ea)},
                                                            {"type", "call_return"},
                                                            {"to", lhs_name},
                                                            {"callee", hexrays_ast::CleanItemText(e->y->x, cf)}
                                                        });
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    return 0;
                                }
                            };

                            BackwardVisitor visitor(local_cf, active_vars, flow_arr, current_depth);
                            visitor.apply_to(&local_cf->body, nullptr);
                        }
                    };

                    trace_fn(pfn, target_var, 0);
                }
            }

            // Fallback for non-decompiled / data addresses if Hex-Rays wasn't used
            if (!used_hexrays) {
                if (!is_mapped(start_ea)) {
                    error_code = "invalid_addr";
                    error_msg = "Address " + tools::utils::FormatAddress(start_ea) + " is not mapped in memory";
                    return;
                }

                std::set<ea_t> visited;
                std::queue<std::pair<ea_t, int>> q;
                q.push({start_ea, 0});
                visited.insert(start_ea);

                while (!q.empty() && visited.size() < 100) {
                    auto [cur_ea, depth] = q.front();
                    q.pop();

                    qstring name_buf;
                    get_ea_name(&name_buf, cur_ea);

                    flow_arr.push_back({
                        {"depth", depth},
                        {"address", tools::utils::FormatAddress(cur_ea)},
                        {"name", name_buf.c_str()}
                    });

                    if (depth >= max_depth) continue;

                    xrefblk_t xb;
                    for (bool ok = xb.first_from(cur_ea, XREF_DATA); ok && visited.size() < 100; ok = xb.next_from()) {
                        if (xb.to != BADADDR && is_mapped(xb.to) && visited.find(xb.to) == visited.end()) {
                            visited.insert(xb.to);
                            q.push({xb.to, depth + 1});
                        }
                    }

                    ea_t deref = inf_is_64bit() ? get_qword(cur_ea) : get_dword(cur_ea);
                    if (deref != BADADDR && is_mapped(deref) && visited.find(deref) == visited.end() && visited.size() < 100) {
                        visited.insert(deref);
                        q.push({deref, depth + 1});
                    }
                }
            }
        });

        if (!error_code.empty()) {
            return tools::utils::MakeToolErrorJson(id, error_msg, error_code);
        }

        nlohmann::json res = {
            {"status", "success"},
            {"root", {
                {"address", tools::utils::FormatAddress(start_ea)},
                {"var", root_var_name}
            }},
            {"direction", direction},
            {"flow_count", flow_arr.size()},
            {"flow", flow_arr}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }
}
