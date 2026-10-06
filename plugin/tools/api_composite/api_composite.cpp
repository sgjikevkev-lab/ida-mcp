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
#include <gdl.hpp>
#include <map>
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

            std::string file_name = file_path;
            size_t sep = file_name.find_last_of("\\/");
            if (sep != std::string::npos) file_name = file_name.substr(sep + 1);

            char proc_buf[32];
            inf_get_procname(proc_buf, sizeof(proc_buf));
            std::string proc = proc_buf;
            std::string arch = proc;
            int bits = 32;
            if (proc == "metapc") {
                arch = inf_is_64bit() ? "x86_64" : "x86";
                bits = inf_is_64bit() ? 64 : 32;
            } else if (proc == "arm") {
                arch = inf_is_64bit() ? "arm64" : "arm";
                bits = inf_is_64bit() ? 64 : 32;
            } else {
                bits = inf_is_64bit() ? 64 : (inf_is_32bit_or_higher() ? 32 : 16);
            }

            ea_t base_ea = get_imagebase();
            size_t total_funcs = get_func_qty();
            int nsegs = get_segm_qty();

            ea_t entry_ea = BADADDR;
            if (get_entry_qty() > 0) {
                uval_t ord = get_entry_ordinal(0);
                entry_ea = get_entry(ord);
            }

            res = {
                {"status", "success"},
                {"file_name", file_name},
                {"arch", arch},
                {"bits", bits},
                {"image_base", tools::utils::FormatAddress(base_ea)},
                {"entry_point", entry_ea != BADADDR ? tools::utils::FormatAddress(entry_ea) : nullptr},
                {"segment_count", nsegs},
                {"function_count", total_funcs}
            };
        });

        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiComposite::AnalyzeFunction(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t target_ea = tools::utils::GetAddressArg(args, "addr");
        if (target_ea == BADADDR) {
            target_ea = tools::utils::GetAddressArg(args, "function");
        }
        if (target_ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }

        size_t max_callers = static_cast<size_t>(tools::utils::GetIntArg(args, "max_callers", 50));
        if (max_callers > 500) max_callers = 500;
        size_t max_callees = static_cast<size_t>(tools::utils::GetIntArg(args, "max_callees", 100));
        if (max_callees > 500) max_callees = 500;

        nlohmann::ordered_json res;
        bool found = false;

        sync::SyncRead([&]() {
            func_t* fn = get_func(target_ea);
            if (!fn) return;
            found = true;

            qstring raw_name;
            get_func_name(&raw_name, fn->start_ea);
            std::string name_str = tools::utils::SanitizeUtf8(raw_name.c_str());

            std::string demangled_str = tools::utils::Demangle(name_str);

            qstring seg_name_buf;
            segment_t* seg = getseg(fn->start_ea);
            if (seg) get_segm_name(&seg_name_buf, seg);
            std::string seg_name = seg_name_buf.c_str();

            // Function characteristics / flags
            nlohmann::ordered_json flags_obj;
            flags_obj["is_thunk"] = (fn->flags & FUNC_THUNK) != 0;
            flags_obj["is_library"] = (fn->flags & FUNC_LIB) != 0;
            flags_obj["is_no_return"] = (fn->flags & FUNC_NORET) != 0;
            flags_obj["has_frame"] = (fn->flags & FUNC_FRAME) != 0;
            flags_obj["is_hidden"] = (fn->flags & FUNC_HIDDEN) != 0;

            // Stack Frame Layout
            nlohmann::ordered_json frame_obj;
            frame_obj["frame_size"] = fn->frsize;
            frame_obj["regs_size"] = fn->frregs;
            frame_obj["arg_size"] = fn->argsize;

            // Flowchart basic blocks & instruction heads count
            qflow_chart_t fc("", fn, fn->start_ea, fn->end_ea, FC_NOEXT);
            size_t blocks_count = fc.size();

            size_t insn_count = 0;
            func_item_iterator_t fii_insn;
            for (bool ok = fii_insn.set(fn, fn->start_ea); ok; ok = fii_insn.next_head()) {
                insn_count++;
            }

            // Type information & Prototype
            tinfo_t tif;
            std::string proto = "";
            std::string ret_type = "";
            std::string calling_conv = "";
            nlohmann::json args_arr = nlohmann::json::array();

            if (get_tinfo(&tif, fn->start_ea)) {
                qstring proto_buf;
                if (tif.print(&proto_buf, raw_name.c_str())) {
                    proto = tools::utils::SanitizeUtf8(proto_buf.c_str());
                }

                if (tif.is_func()) {
                    func_type_data_t ftd;
                    if (tif.get_func_details(&ftd)) {
                        qstring ret_buf;
                        if (ftd.rettype.print(&ret_buf)) {
                            ret_type = tools::utils::SanitizeUtf8(ret_buf.c_str());
                        }

                        callcnv_t cc = ftd.get_cc() & CM_CC_MASK;
                        if (cc == CM_CC_FASTCALL) calling_conv = "__fastcall";
                        else if (cc == CM_CC_CDECL) calling_conv = "__cdecl";
                        else if (cc == CM_CC_STDCALL) calling_conv = "__stdcall";
                        else if (cc == CM_CC_THISCALL) calling_conv = "__thiscall";
                        else if (cc == CM_CC_SWIFT) calling_conv = "__swift";
                        else if (cc == CM_CC_GOLANG) calling_conv = "__golang";

                        for (size_t a = 0; a < ftd.size(); ++a) {
                            qstring arg_type_buf;
                            ftd[a].type.print(&arg_type_buf);
                            nlohmann::ordered_json arg_item;
                            arg_item["index"] = a;
                            arg_item["name"] = ftd[a].name.c_str();
                            arg_item["type"] = tools::utils::SanitizeUtf8(arg_type_buf.c_str());
                            args_arr.push_back(std::move(arg_item));
                        }
                    }
                }
            }

            // Callers (incoming references)
            xrefblk_t xb_to;
            size_t total_callers_count = 0;
            std::map<ea_t, std::vector<ea_t>> caller_map;
            for (bool ok = xb_to.first_to(fn->start_ea, XREF_ALL); ok; ok = xb_to.next_to()) {
                if (!xb_to.iscode) continue;
                total_callers_count++;
                uint8_t base_type = xb_to.type & XREF_MASK;
                if (base_type == fl_CN || base_type == fl_CF || base_type == fl_JN || base_type == fl_JF) {
                    func_t* caller_fn = get_func(xb_to.from);
                    ea_t c_start = caller_fn ? caller_fn->start_ea : xb_to.from;
                    caller_map[c_start].push_back(xb_to.from);
                }
            }

            nlohmann::json callers_arr = nlohmann::json::array();
            size_t caller_idx = 0;
            for (const auto& [c_ea, sites] : caller_map) {
                if (caller_idx++ >= max_callers) break;
                qstring c_name;
                get_ea_name(&c_name, c_ea);
                std::string c_name_str = tools::utils::SanitizeUtf8(c_name.c_str());
                std::string c_dem = tools::utils::Demangle(c_name_str);

                nlohmann::ordered_json c_item;
                c_item["address"] = tools::utils::FormatAddress(c_ea);
                c_item["name"] = c_name_str;
                if (!c_dem.empty() && c_dem != c_name_str) c_item["demangled"] = c_dem;
                c_item["call_sites_count"] = sites.size();
                nlohmann::json sites_json = nlohmann::json::array();
                for (size_t s = 0; s < std::min<size_t>(sites.size(), 5); ++s) {
                    sites_json.push_back(tools::utils::FormatAddress(sites[s]));
                }
                c_item["call_sites"] = std::move(sites_json);
                callers_arr.push_back(std::move(c_item));
            }

            // Callees (outgoing calls & jumps)
            struct CalleeInfo {
                ea_t target_ea;
                std::string type;
                std::vector<ea_t> call_sites;
            };
            std::map<ea_t, CalleeInfo> callee_map;

            func_item_iterator_t fii;
            for (bool ok = fii.set(fn, fn->start_ea); ok; ok = fii.next_head()) {
                ea_t cur = fii.current();
                xrefblk_t xb_from;
                for (bool xok = xb_from.first_from(cur, XREF_ALL); xok; xok = xb_from.next_from()) {
                    if (!xb_from.iscode) continue;
                    uint8_t base_type = xb_from.type & XREF_MASK;
                    if (base_type == fl_CN || base_type == fl_CF || base_type == fl_JN || base_type == fl_JF) {
                        if (xb_from.to >= fn->start_ea && xb_from.to < fn->end_ea) continue;

                        std::string call_type = (base_type == fl_CN || base_type == fl_CF) ? "call" : "tailcall";
                        auto& ci = callee_map[xb_from.to];
                        ci.target_ea = xb_from.to;
                        if (ci.type.empty()) ci.type = call_type;
                        ci.call_sites.push_back(cur);
                    }
                }
            }

            nlohmann::json callees_arr = nlohmann::json::array();
            size_t callee_idx = 0;
            for (const auto& [callee_ea, ci] : callee_map) {
                if (callee_idx++ >= max_callees) break;
                qstring c_name;
                get_ea_name(&c_name, callee_ea);
                std::string c_name_str = tools::utils::SanitizeUtf8(c_name.c_str());
                std::string c_dem = tools::utils::Demangle(c_name_str);

                nlohmann::ordered_json ci_item;
                ci_item["address"] = tools::utils::FormatAddress(callee_ea);
                ci_item["name"] = c_name_str.empty() ? tools::utils::FormatAddress(callee_ea) : c_name_str;
                if (!c_dem.empty() && c_dem != c_name_str) ci_item["demangled"] = c_dem;
                ci_item["type"] = ci.type;
                ci_item["call_sites_count"] = ci.call_sites.size();
                nlohmann::json sites_json = nlohmann::json::array();
                for (size_t s = 0; s < std::min<size_t>(ci.call_sites.size(), 5); ++s) {
                    sites_json.push_back(tools::utils::FormatAddress(ci.call_sites[s]));
                }
                ci_item["call_sites"] = std::move(sites_json);
                callees_arr.push_back(std::move(ci_item));
            }

            res["status"] = "success";
            res["address"] = tools::utils::FormatAddress(fn->start_ea);
            res["name"] = name_str;
            if (!demangled_str.empty() && demangled_str != name_str) {
                res["demangled"] = demangled_str;
            }
            if (!seg_name.empty()) {
                res["segment"] = seg_name;
            }
            res["start"] = tools::utils::FormatAddress(fn->start_ea);
            res["end"] = tools::utils::FormatAddress(fn->end_ea);
            res["size"] = fn->size();
            res["instructions_count"] = insn_count;
            res["basic_blocks_count"] = blocks_count;
            res["flags"] = std::move(flags_obj);
            res["frame"] = std::move(frame_obj);
            if (!proto.empty()) res["prototype"] = proto;
            if (!calling_conv.empty()) res["calling_convention"] = calling_conv;
            if (!ret_type.empty()) res["return_type"] = ret_type;
            if (!args_arr.empty()) res["arguments"] = std::move(args_arr);

            res["callers_count"] = total_callers_count;
            res["unique_callers"] = caller_map.size();
            res["callers"] = std::move(callers_arr);

            res["callees_count"] = callee_map.size();
            res["callees"] = std::move(callees_arr);
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
                    // If target_var is empty or index, try to deduce it from start_ea or function arguments
                    const lvars_t* lvars = cf->get_lvars();
                    if (lvars && !lvars->empty()) {
                        bool var_found = false;
                        if (!target_var.empty()) {
                            for (size_t i = 0; i < lvars->size(); ++i) {
                                if ((*lvars)[i].name == target_var.c_str()) {
                                    var_found = true;
                                    break;
                                }
                            }
                            if (!var_found) {
                                int arg_idx = -1;
                                if (target_var.rfind("arg", 0) == 0) {
                                    try { arg_idx = std::stoi(target_var.substr(3)); } catch (...) {}
                                } else if (std::all_of(target_var.begin(), target_var.end(), ::isdigit)) {
                                    try { arg_idx = std::stoi(target_var); } catch (...) {}
                                }
                                if (arg_idx >= 0) {
                                    int cur_arg = 0;
                                    for (size_t i = 0; i < lvars->size(); ++i) {
                                        if ((*lvars)[i].is_arg_var()) {
                                            if (cur_arg == arg_idx) {
                                                target_var = (*lvars)[i].name.c_str();
                                                var_found = true;
                                                break;
                                            }
                                            cur_arg++;
                                        }
                                    }
                                }
                            }
                        }
                        if (target_var.empty() || !var_found) {
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
                                    if (flow.size() >= 150) return 1;

                                    // 1. Assignment / Store: lhs = rhs
                                    if (e->op == cot_asg || e->op == cot_asgbor || e->op == cot_asgband ||
                                        e->op == cot_asgadd || e->op == cot_asgsub || e->op == cot_asgmul) {
                                        std::string used_var_rhs;
                                        // Case A: Active var on RHS -> propagates into lhs
                                        if (UsesActiveVar(e->y, used_var_rhs)) {
                                            if (e->x && e->x->op == cot_var) {
                                                const lvars_t* lvars = const_cast<cfunc_t*>(cf)->get_lvars();
                                                if (lvars && e->x->v.idx >= 0 && e->x->v.idx < static_cast<int>(lvars->size())) {
                                                    std::string to_var = (*lvars)[e->x->v.idx].name.c_str();
                                                    flow.push_back({
                                                        {"depth", depth},
                                                        {"address", tools::utils::FormatAddress(e->ea)},
                                                        {"type", "assign"},
                                                        {"from", used_var_rhs},
                                                        {"to", to_var},
                                                        {"expr", hexrays_ast::CleanItemText(e, cf)}
                                                    });
                                                    active_vars.insert(to_var);
                                                }
                                            } else if (e->x && (e->x->op == cot_ptr || e->x->op == cot_memptr || e->x->op == cot_memref || e->x->op == cot_obj)) {
                                                flow.push_back({
                                                    {"depth", depth},
                                                    {"address", tools::utils::FormatAddress(e->ea)},
                                                    {"type", "store"},
                                                    {"from", used_var_rhs},
                                                    {"target", hexrays_ast::CleanItemText(e->x, cf)},
                                                    {"expr", hexrays_ast::CleanItemText(e, cf)}
                                                });
                                            }
                                        }

                                        // Case B: Active var on LHS -> member store, pointer store, or variable re-assignment
                                        std::string used_var_lhs;
                                        if (UsesActiveVar(e->x, used_var_lhs)) {
                                            if (e->x->op == cot_ptr || e->x->op == cot_memptr || e->x->op == cot_memref) {
                                                flow.push_back({
                                                    {"depth", depth},
                                                    {"address", tools::utils::FormatAddress(e->ea)},
                                                    {"type", "member_store"},
                                                    {"base_var", used_var_lhs},
                                                    {"target", hexrays_ast::CleanItemText(e->x, cf)},
                                                    {"value", hexrays_ast::CleanItemText(e->y, cf)},
                                                    {"expr", hexrays_ast::CleanItemText(e, cf)}
                                                });
                                            } else if (e->x->op == cot_var) {
                                                flow.push_back({
                                                    {"depth", depth},
                                                    {"address", tools::utils::FormatAddress(e->ea)},
                                                    {"type", "reassign"},
                                                    {"var", used_var_lhs},
                                                    {"value", hexrays_ast::CleanItemText(e->y, cf)},
                                                    {"expr", hexrays_ast::CleanItemText(e, cf)}
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
                                                    {"arg_index", i},
                                                    {"expr", hexrays_ast::CleanItemText(e, cf)}
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

                                    // 3. Array indexing: arr[var] or var[i]
                                    if (e->op == cot_idx) {
                                        std::string used_var;
                                        if (UsesActiveVar(e->y, used_var)) {
                                            flow.push_back({
                                                {"depth", depth},
                                                {"address", tools::utils::FormatAddress(e->ea)},
                                                {"type", "index_use"},
                                                {"from", used_var},
                                                {"array", hexrays_ast::CleanItemText(e->x, cf)},
                                                {"expr", hexrays_ast::CleanItemText(e, cf)}
                                            });
                                        }
                                        if (UsesActiveVar(e->x, used_var)) {
                                            flow.push_back({
                                                {"depth", depth},
                                                {"address", tools::utils::FormatAddress(e->ea)},
                                                {"type", "array_access"},
                                                {"from", used_var},
                                                {"index", hexrays_ast::CleanItemText(e->y, cf)},
                                                {"expr", hexrays_ast::CleanItemText(e, cf)}
                                            });
                                        }
                                    }

                                    // 4. Increment / Decrement: var++, var--, ++var, --var
                                    if (e->op == cot_postinc || e->op == cot_postdec || e->op == cot_preinc || e->op == cot_predec) {
                                        std::string used_var;
                                        if (UsesActiveVar(e->x, used_var)) {
                                            flow.push_back({
                                                {"depth", depth},
                                                {"address", tools::utils::FormatAddress(e->ea)},
                                                {"type", (e->op == cot_postinc || e->op == cot_preinc) ? "increment" : "decrement"},
                                                {"var", used_var},
                                                {"expr", hexrays_ast::CleanItemText(e, cf)}
                                            });
                                        }
                                    }

                                    return 0;
                                }

                                int idaapi visit_insn(cinsn_t* insn) override {
                                    if (flow.size() >= 150) return 1;
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
                                                {"from", used_var},
                                                {"expr", hexrays_ast::CleanItemText(&insn->creturn->expr, cf)}
                                            });
                                        }
                                    }
                                    return 0;
                                }
                            };

                            ForwardVisitor visitor(local_cf, active_vars, flow_arr, current_depth, include_calls, max_depth, trace_fn);
                            visitor.apply_to(&local_cf->body, nullptr);
                        } else {
                            // Backward direction: use -> def with deep reverse-AST evaluation
                            std::set<std::string> active_globals;
                            std::set<ea_t> active_objs;

                            auto UsesActiveVar = [&](const cexpr_t* e, std::string& out_name) -> bool {
                                std::function<bool(const cexpr_t*)> check = [&](const cexpr_t* sub) -> bool {
                                    if (!sub) return false;
                                    if (sub->op == cot_var) {
                                        const lvars_t* lvars = local_cf->get_lvars();
                                        if (lvars && sub->v.idx >= 0 && sub->v.idx < static_cast<int>(lvars->size())) {
                                            std::string vname = (*lvars)[sub->v.idx].name.c_str();
                                            if (active_vars.count(vname)) {
                                                out_name = vname;
                                                return true;
                                            }
                                        }
                                        return false;
                                    }
                                    if (op_uses_x(sub->op) && sub->x && check(sub->x)) return true;
                                    if (op_uses_y(sub->op) && sub->y && check(sub->y)) return true;
                                    if (op_uses_z(sub->op) && sub->z && check(sub->z)) return true;
                                    if (sub->op == cot_call && sub->a) {
                                        for (const auto& arg : *sub->a) {
                                            if (check(&arg)) return true;
                                        }
                                    }
                                    return false;
                                };
                                return check(e);
                            };

                            auto ExtractSources = [&](const cexpr_t* e, std::vector<std::string>& out_vars, std::vector<std::string>& out_globals) {
                                std::function<void(const cexpr_t*)> walk = [&](const cexpr_t* sub) {
                                    if (!sub) return;
                                    if (sub->op == cot_var) {
                                        const lvars_t* lvars = local_cf->get_lvars();
                                        if (lvars && sub->v.idx >= 0 && sub->v.idx < static_cast<int>(lvars->size())) {
                                            std::string vn = (*lvars)[sub->v.idx].name.c_str();
                                            if (std::find(out_vars.begin(), out_vars.end(), vn) == out_vars.end()) {
                                                out_vars.push_back(vn);
                                            }
                                        }
                                    } else if (sub->op == cot_obj && is_mapped(sub->obj_ea)) {
                                        qstring oname;
                                        get_name(&oname, sub->obj_ea);
                                        std::string oname_str = oname.c_str();
                                        if (!oname_str.empty() && std::find(out_globals.begin(), out_globals.end(), oname_str) == out_globals.end()) {
                                            out_globals.push_back(oname_str);
                                        }
                                        active_objs.insert(sub->obj_ea);
                                    }
                                    if (op_uses_x(sub->op) && sub->x) walk(sub->x);
                                    if (op_uses_y(sub->op) && sub->y) walk(sub->y);
                                    if (op_uses_z(sub->op) && sub->z) walk(sub->z);
                                    if (sub->op == cot_call && sub->a) {
                                        for (const auto& arg : *sub->a) walk(&arg);
                                    }
                                };
                                walk(e);
                            };

                            struct citem_collector_t : public ctree_visitor_t {
                                std::vector<citem_t*> items;
                                citem_collector_t() : ctree_visitor_t(CV_FAST) {}
                                int idaapi visit_insn(cinsn_t* in) override {
                                    items.push_back(in);
                                    return 0;
                                }
                                int idaapi visit_expr(cexpr_t* ex) override {
                                    items.push_back(ex);
                                    return 0;
                                }
                            } collector;
                            collector.apply_to(&local_cf->body, nullptr);

                            // Traverse collected items in reverse execution order (from bottom to top)
                            for (auto it = collector.items.rbegin(); it != collector.items.rend(); ++it) {
                                if (flow_arr.size() >= 150) break;
                                citem_t* item = *it;

                                if (item->is_expr()) {
                                    cexpr_t* e = static_cast<cexpr_t*>(item);

                                    // 1. Assignments: lhs = rhs
                                    if (e->op == cot_asg || e->op == cot_asgbor || e->op == cot_asgband ||
                                        e->op == cot_asgadd || e->op == cot_asgsub || e->op == cot_asgmul) {
                                        bool matched = false;
                                        std::string def_target;

                                        // Case A: local variable assignment
                                        if (e->x && e->x->op == cot_var) {
                                            const lvars_t* lvars = local_cf->get_lvars();
                                            if (lvars && e->x->v.idx >= 0 && e->x->v.idx < static_cast<int>(lvars->size())) {
                                                std::string lhs_name = (*lvars)[e->x->v.idx].name.c_str();
                                                if (active_vars.count(lhs_name)) {
                                                    matched = true;
                                                    def_target = lhs_name;
                                                }
                                            }
                                        }
                                        // Case B: global data object assignment
                                        else if (e->x && e->x->op == cot_obj) {
                                            qstring oname;
                                            get_name(&oname, e->x->obj_ea);
                                            std::string obj_name = oname.c_str();
                                            if (active_objs.count(e->x->obj_ea) || (!obj_name.empty() && active_globals.count(obj_name))) {
                                                matched = true;
                                                def_target = obj_name.empty() ? tools::utils::FormatAddress(e->x->obj_ea) : obj_name;
                                            }
                                        }
                                        // Case C: struct member / pointer dereference assignment
                                        else if (e->x && (e->x->op == cot_ptr || e->x->op == cot_memptr || e->x->op == cot_memref)) {
                                            std::string base_var;
                                            if (UsesActiveVar(e->x, base_var)) {
                                                flow_arr.push_back({
                                                    {"depth", current_depth},
                                                    {"address", tools::utils::FormatAddress(e->ea)},
                                                    {"type", "member_def"},
                                                    {"target", hexrays_ast::CleanItemText(e->x, local_cf)},
                                                    {"from", hexrays_ast::CleanItemText(e->y, local_cf)},
                                                    {"base_var", base_var},
                                                    {"expr", hexrays_ast::CleanItemText(e, local_cf)}
                                                });
                                            }
                                        }

                                        if (matched) {
                                            std::vector<std::string> src_vars;
                                            std::vector<std::string> src_globals;
                                            ExtractSources(e->y, src_vars, src_globals);

                                            nlohmann::ordered_json flow_item = {
                                                {"depth", current_depth},
                                                {"address", tools::utils::FormatAddress(e->ea)},
                                                {"type", "assign_def"},
                                                {"to", def_target},
                                                {"from", hexrays_ast::CleanItemText(e->y, local_cf)},
                                                {"expr", hexrays_ast::CleanItemText(e, local_cf)}
                                            };
                                            if (!src_vars.empty()) {
                                                flow_item["sources"] = src_vars;
                                                for (const auto& sv : src_vars) active_vars.insert(sv);
                                            }
                                            if (!src_globals.empty()) {
                                                flow_item["global_sources"] = src_globals;
                                                for (const auto& sg : src_globals) active_globals.insert(sg);
                                            }
                                            flow_arr.push_back(std::move(flow_item));

                                            // If defined by a call, inspect callee return and recurse
                                            if (e->y && e->y->op == cot_call) {
                                                std::string callee_name = hexrays_ast::CleanItemText(e->y->x, local_cf);
                                                ea_t callee_ea = (e->y->x && e->y->x->op == cot_obj) ? e->y->x->obj_ea : BADADDR;

                                                flow_arr.push_back({
                                                    {"depth", current_depth},
                                                    {"address", tools::utils::FormatAddress(e->y->ea)},
                                                    {"type", "call_return"},
                                                    {"to", def_target},
                                                    {"callee", callee_name}
                                                });

                                                if (include_calls && current_depth < max_depth && callee_ea != BADADDR) {
                                                    func_t* callee_fn = get_func(callee_ea);
                                                    if (callee_fn) {
                                                        hexrays_failure_t c_hf;
                                                        cfuncptr_t callee_cf = decompile(callee_fn, &c_hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                                                        if (callee_cf) {
                                                            struct ret_finder_t : public ctree_visitor_t {
                                                                const cfunc_t* c_cf;
                                                                std::vector<std::pair<ea_t, std::string>> rets;
                                                                ret_finder_t(const cfunc_t* f) : ctree_visitor_t(CV_FAST), c_cf(f) {}
                                                                int idaapi visit_insn(cinsn_t* in) override {
                                                                    if (in->op == cit_return && in->creturn && in->creturn->expr.op != cot_empty) {
                                                                        std::string ret_var;
                                                                        if (in->creturn->expr.op == cot_var) {
                                                                            const lvars_t* clvs = const_cast<cfunc_t*>(c_cf)->get_lvars();
                                                                            if (clvs && in->creturn->expr.v.idx >= 0 && in->creturn->expr.v.idx < static_cast<int>(clvs->size())) {
                                                                                ret_var = (*clvs)[in->creturn->expr.v.idx].name.c_str();
                                                                            }
                                                                        }
                                                                        if (ret_var.empty()) {
                                                                            ret_var = hexrays_ast::CleanItemText(&in->creturn->expr, c_cf);
                                                                        }
                                                                        rets.push_back({in->ea, ret_var});
                                                                    }
                                                                    return 0;
                                                                }
                                                            } rf(callee_cf);
                                                            rf.apply_to(&callee_cf->body, nullptr);

                                                            for (const auto& [ret_ea, ret_str] : rf.rets) {
                                                                flow_arr.push_back({
                                                                    {"depth", current_depth + 1},
                                                                    {"address", tools::utils::FormatAddress(ret_ea)},
                                                                    {"type", "callee_return_expr"},
                                                                    {"function", callee_name},
                                                                    {"returned", ret_str}
                                                                });
                                                                trace_fn(callee_fn, ret_str, current_depth + 1);
                                                                break;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            // Memory load definition
                                            else if (e->y && (e->y->op == cot_ptr || e->y->op == cot_memptr || e->y->op == cot_memref)) {
                                                flow_arr.push_back({
                                                    {"depth", current_depth},
                                                    {"address", tools::utils::FormatAddress(e->ea)},
                                                    {"type", "load"},
                                                    {"to", def_target},
                                                    {"source", hexrays_ast::CleanItemText(e->y, local_cf)},
                                                    {"expr", hexrays_ast::CleanItemText(e, local_cf)}
                                                });
                                            }
                                            // Array load definition
                                            else if (e->y && e->y->op == cot_idx) {
                                                flow_arr.push_back({
                                                    {"depth", current_depth},
                                                    {"address", tools::utils::FormatAddress(e->ea)},
                                                    {"type", "array_load"},
                                                    {"to", def_target},
                                                    {"array", hexrays_ast::CleanItemText(e->y->x, local_cf)},
                                                    {"index", hexrays_ast::CleanItemText(e->y->y, local_cf)},
                                                    {"expr", hexrays_ast::CleanItemText(e, local_cf)}
                                                });
                                            }
                                        }
                                    }

                                    // 2. Out-parameter call detection: callee(..., &var, ...)
                                    if (e->op == cot_call && e->a) {
                                        std::string callee_name = hexrays_ast::CleanItemText(e->x, local_cf);
                                        ea_t callee_ea = (e->x && e->x->op == cot_obj) ? e->x->obj_ea : BADADDR;
                                        for (size_t ai = 0; ai < e->a->size(); ++ai) {
                                            const carg_t& arg = (*e->a)[ai];
                                            std::string used_var;
                                            bool is_ref = false;
                                            if (arg.op == cot_ref && arg.x && arg.x->op == cot_var) {
                                                const lvars_t* lvs = local_cf->get_lvars();
                                                if (lvs && arg.x->v.idx >= 0 && arg.x->v.idx < static_cast<int>(lvs->size())) {
                                                    std::string vn = (*lvs)[arg.x->v.idx].name.c_str();
                                                    if (active_vars.count(vn)) {
                                                        used_var = vn;
                                                        is_ref = true;
                                                    }
                                                }
                                            } else if (arg.op == cot_cast && arg.x && arg.x->op == cot_ref && arg.x->x && arg.x->x->op == cot_var) {
                                                const lvars_t* lvs = local_cf->get_lvars();
                                                if (lvs && arg.x->x->v.idx >= 0 && arg.x->x->v.idx < static_cast<int>(lvs->size())) {
                                                    std::string vn = (*lvs)[arg.x->x->v.idx].name.c_str();
                                                    if (active_vars.count(vn)) {
                                                        used_var = vn;
                                                        is_ref = true;
                                                    }
                                                }
                                            }

                                            if (is_ref && !used_var.empty()) {
                                                flow_arr.push_back({
                                                    {"depth", current_depth},
                                                    {"address", tools::utils::FormatAddress(e->ea)},
                                                    {"type", "call_out_arg"},
                                                    {"var", used_var},
                                                    {"callee", callee_name},
                                                    {"arg_index", ai},
                                                    {"expr", hexrays_ast::CleanItemText(e, local_cf)}
                                                });

                                                if (include_calls && current_depth < max_depth && callee_ea != BADADDR) {
                                                    func_t* callee_fn = get_func(callee_ea);
                                                    if (callee_fn) {
                                                        hexrays_failure_t c_hf;
                                                        cfuncptr_t callee_cf = decompile(callee_fn, &c_hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                                                        if (callee_cf) {
                                                            const lvars_t* callee_lvars = callee_cf->get_lvars();
                                                            std::string param_name;
                                                            size_t p_cnt = 0;
                                                            if (callee_lvars) {
                                                                for (size_t k = 0; k < callee_lvars->size(); ++k) {
                                                                    if ((*callee_lvars)[k].is_arg_var()) {
                                                                        if (p_cnt == ai) {
                                                                            param_name = (*callee_lvars)[k].name.c_str();
                                                                            break;
                                                                        }
                                                                        p_cnt++;
                                                                    }
                                                                }
                                                            }
                                                            if (!param_name.empty()) {
                                                                trace_fn(callee_fn, param_name, current_depth + 1);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // 3. Increment / Decrement
                                    if (e->op == cot_postinc || e->op == cot_postdec || e->op == cot_preinc || e->op == cot_predec) {
                                        std::string used_var;
                                        if (UsesActiveVar(e->x, used_var)) {
                                            flow_arr.push_back({
                                                {"depth", current_depth},
                                                {"address", tools::utils::FormatAddress(e->ea)},
                                                {"type", (e->op == cot_postinc || e->op == cot_preinc) ? "increment" : "decrement"},
                                                {"var", used_var},
                                                {"expr", hexrays_ast::CleanItemText(e, local_cf)}
                                            });
                                        }
                                    }
                                } else {
                                    // 4. Instructions: Guard conditions (if-statements)
                                    const cinsn_t* insn = static_cast<const cinsn_t*>(item);
                                    if (insn->op == cit_if && insn->cif) {
                                        std::string used_var;
                                        if (UsesActiveVar(&insn->cif->expr, used_var)) {
                                            flow_arr.push_back({
                                                {"depth", current_depth},
                                                {"address", tools::utils::FormatAddress(insn->ea)},
                                                {"type", "guard_condition"},
                                                {"from", used_var},
                                                {"condition", hexrays_ast::CleanItemText(&insn->cif->expr, local_cf)}
                                            });
                                        }
                                    }
                                }
                            }

                            // 5. Caller Argument Resolution: If any active variable is an incoming argument, find callers
                            if (include_calls && current_depth < max_depth) {
                                const lvars_t* fn_lvars = local_cf->get_lvars();
                                if (fn_lvars) {
                                    for (size_t li = 0; li < fn_lvars->size(); ++li) {
                                        const lvar_t& lv = (*fn_lvars)[li];
                                        if (lv.is_arg_var() && active_vars.count(lv.name.c_str())) {
                                            size_t param_idx = 0;
                                            for (size_t k = 0; k < li; ++k) {
                                                if ((*fn_lvars)[k].is_arg_var()) param_idx++;
                                            }

                                            std::set<ea_t> caller_funcs_seen;
                                            xrefblk_t xb;
                                            for (bool ok = xb.first_to(fn->start_ea, XREF_ALL); ok && caller_funcs_seen.size() < 3; ok = xb.next_to()) {
                                                if (!xb.iscode) continue;
                                                func_t* caller_pfn = get_func(xb.from);
                                                if (!caller_pfn || caller_pfn->start_ea == fn->start_ea) continue;
                                                if (caller_funcs_seen.count(caller_pfn->start_ea)) continue;
                                                caller_funcs_seen.insert(caller_pfn->start_ea);

                                                hexrays_failure_t c_hf;
                                                cfuncptr_t caller_cf = decompile(caller_pfn, &c_hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                                                if (!caller_cf) continue;

                                                qstring caller_name_buf;
                                                get_func_name(&caller_name_buf, caller_pfn->start_ea);
                                                std::string caller_name = caller_name_buf.c_str();

                                                struct caller_call_finder_t : public ctree_visitor_t {
                                                    const cfunc_t* c_cf;
                                                    ea_t target_fn_ea;
                                                    size_t p_idx;
                                                    std::string p_name;
                                                    std::string c_name;
                                                    int d;
                                                    nlohmann::json& fl;
                                                    std::function<void(func_t*, const std::string&, int)> r_fn;
                                                    caller_call_finder_t(const cfunc_t* f, ea_t tea, size_t pi, const std::string& pn, const std::string& cn, int cd, nlohmann::json& flow_arr, std::function<void(func_t*, const std::string&, int)> rf)
                                                        : ctree_visitor_t(CV_FAST), c_cf(f), target_fn_ea(tea), p_idx(pi), p_name(pn), c_name(cn), d(cd), fl(flow_arr), r_fn(rf) {}

                                                    int idaapi visit_expr(cexpr_t* ce) override {
                                                        if (ce->op == cot_call && ce->x && ce->x->op == cot_obj && ce->x->obj_ea == target_fn_ea && ce->a) {
                                                            if (p_idx < ce->a->size()) {
                                                                const carg_t& passed_arg = (*ce->a)[p_idx];
                                                                std::string passed_str = hexrays_ast::CleanItemText(&passed_arg, c_cf);
                                                                fl.push_back({
                                                                    {"depth", d + 1},
                                                                    {"address", tools::utils::FormatAddress(ce->ea)},
                                                                    {"type", "caller_arg_passed"},
                                                                    {"caller", c_name},
                                                                    {"param", p_name},
                                                                    {"arg_index", p_idx},
                                                                    {"passed_expr", passed_str}
                                                                });
                                                                if (passed_arg.op == cot_var) {
                                                                    const lvars_t* clvs = const_cast<cfunc_t*>(c_cf)->get_lvars();
                                                                    if (clvs && passed_arg.v.idx >= 0 && passed_arg.v.idx < static_cast<int>(clvs->size())) {
                                                                        std::string caller_var = (*clvs)[passed_arg.v.idx].name.c_str();
                                                                        r_fn(get_func(c_cf->entry_ea), caller_var, d + 1);
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        return 0;
                                                    }
                                                } ccf(caller_cf, fn->start_ea, param_idx, lv.name.c_str(), caller_name, current_depth, flow_arr, trace_fn);
                                                ccf.apply_to(&caller_cf->body, nullptr);
                                            }
                                        }
                                    }
                                }
                            }
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
