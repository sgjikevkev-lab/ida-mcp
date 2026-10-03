#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <set>
#include <queue>
#include <unordered_map>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "api_analysis.h"
#include "tools/utils/utils.h"
#include "sync/sync.h"

#include <ida.hpp>
#include <funcs.hpp>
#include <lines.hpp>
#include <xref.hpp>
#include <gdl.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <typeinf.hpp>
#include <allins.hpp>
#include <auto.hpp>
#include <hexrays.hpp>
#include <segment.hpp>

namespace tools::analysis {
    namespace {
        std::string CleanDisasmLine(ea_t ea) {
            qstring buf;
            generate_disasm_line(&buf, ea, GENDSM_REMOVE_TAGS);
            std::string s = tools::utils::SanitizeUtf8(buf.c_str());
            size_t first = s.find_first_not_of(" \t");
            if (first != std::string::npos) s = s.substr(first);
            return s;
        }

        std::string GetCleanPseudocode(func_t* pfn, std::string* err_out = nullptr) {
            if (!init_hexrays_plugin()) {
                if (err_out) *err_out = "Hex-Rays decompiler is not loaded or not supported for this architecture";
                return "";
            }
            hexrays_failure_t hf;
            cfuncptr_t cfunc = decompile(pfn, &hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
            if (!cfunc) {
                if (err_out) {
                    *err_out = "Decompilation failed (code " + std::to_string(hf.code) +
                               " at " + tools::utils::FormatAddress(hf.errea) +
                               "): " + tools::utils::SanitizeUtf8(hf.desc().c_str());
                }
                return "";
            }

            const strvec_t& sv = cfunc->get_pseudocode();
            std::string code;
            for (size_t i = 0; i < sv.size(); ++i) {
                qstring clean_line;
                tag_remove(&clean_line, sv[i].line);
                code += tools::utils::SanitizeUtf8(clean_line.c_str()) + "\n";
            }
            return code;
        }
    }

    bool ApiAnalysis::CanHandle(const std::string& name) const {
        return name == "decompile" ||
               name == "disasm" ||
               name == "basic_blocks" ||
               name == "xref_query" ||
               name == "callgraph" ||
               name == "find_bytes" ||
               name == "insn_query" ||
               name == "find_path";
    }

    nlohmann::json ApiAnalysis::GetSchema() const {
        return nlohmann::json::array();
    }

    nlohmann::json ApiAnalysis::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "decompile") return Decompile(id, args);
        if (name == "disasm") return Disasm(id, args);
        if (name == "basic_blocks") return BasicBlocks(id, args);
        if (name == "xref_query") return XrefQuery(id, args);
        if (name == "callgraph") return Callgraph(id, args);
        if (name == "find_bytes") return FindBytes(id, args);
        if (name == "insn_query") return InsnQuery(id, args);
        if (name == "find_path") return FindPath(id, args);

        return tools::utils::MakeToolErrorJson(id, "Method not found: " + name, "method_not_found");
    }

    nlohmann::json ApiAnalysis::Decompile(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        if (ea == BADADDR && args.contains("queries")) {
            if (args["queries"].is_string()) {
                ea = tools::utils::ParseAddress(args["queries"].get<std::string>());
            } else if (args["queries"].is_array() && !args["queries"].empty() && args["queries"][0].is_string()) {
                ea = tools::utils::ParseAddress(args["queries"][0].get<std::string>());
            }
        }

        if (ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }

        std::string code;
        std::string err_msg;
        bool found_fn = false;

        sync::SyncRead([&]() {
            func_t* fn = get_func(ea);
            if (!fn) return;
            found_fn = true;
            code = GetCleanPseudocode(fn, &err_msg);
        });

        if (!found_fn) {
            return tools::utils::MakeToolErrorJson(
                id,
                "Address " + tools::utils::FormatAddress(ea) + " is not inside any recognized function",
                "function_not_found"
            );
        }

        if (code.empty()) {
            return tools::utils::MakeToolErrorJson(
                id,
                err_msg.empty() ? "Decompilation failed" : err_msg,
                "decompilation_failed"
            );
        }

        // Return clean structured JSON with C pseudocode
        nlohmann::json res = {
            {"status", "success"},
            {"address", tools::utils::FormatAddress(ea)},
            {"code", code}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiAnalysis::Disasm(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t start_ea = tools::utils::GetAddressArg(args, "addr");
        size_t count = static_cast<size_t>(tools::utils::GetIntArg(args, "count", 50));
        if (count <= 0) count = 50;
        if (count > 2000) count = 2000;

        if (start_ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }

        std::vector<std::string> instructions;
        bool decoded_any = false;

        sync::SyncRead([&]() {
            func_t* fn = get_func(start_ea);
            size_t fetched = 0;

            if (fn) {
                func_item_iterator_t fii;
                for (bool ok = fii.set(fn, start_ea); ok && fetched < count; ok = fii.next_head()) {
                    ea_t cur = fii.current();
                    if (!is_mapped(cur)) break;
                    std::string dis = CleanDisasmLine(cur);
                    if (dis.empty()) break;

                    instructions.push_back(tools::utils::FormatAddress(cur) + ":  " + dis);
                    decoded_any = true;
                    fetched++;
                }
            } else {
                ea_t cur = start_ea;
                while (cur != BADADDR && is_mapped(cur) && fetched < count) {
                    std::string dis = CleanDisasmLine(cur);
                    if (dis.empty()) break;

                    instructions.push_back(tools::utils::FormatAddress(cur) + ":  " + dis);
                    decoded_any = true;
                    fetched++;

                    cur = get_item_end(cur);
                }
            }
        });

        if (!decoded_any) {
            return tools::utils::MakeToolErrorJson(
                id,
                "No instructions could be decoded at address " + tools::utils::FormatAddress(start_ea),
                "no_instructions"
            );
        }

        // Return clean structured JSON with instructions array
        nlohmann::json res = {
            {"status", "success"},
            {"address", tools::utils::FormatAddress(start_ea)},
            {"count", instructions.size()},
            {"instructions", instructions}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiAnalysis::BasicBlocks(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t start_ea = tools::utils::GetAddressArg(args, "addr");
        if (start_ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }

        nlohmann::json blocks_arr = nlohmann::json::array();
        ea_t fn_start = BADADDR;
        bool found_fn = false;

        sync::SyncRead([&]() {
            func_t* fn = get_func(start_ea);
            if (!fn) return;
            found_fn = true;
            fn_start = fn->start_ea;

            qflow_chart_t fc("", fn, fn->start_ea, fn->end_ea, 0);
            for (size_t i = 0; i < fc.blocks.size(); ++i) {
                const qbasic_block_t& b = fc.blocks[i];
                size_t blk_size = (b.end_ea >= b.start_ea) ? (b.end_ea - b.start_ea) : 0;

                nlohmann::json succs = nlohmann::json::array();
                int n_succ = fc.nsucc(static_cast<int>(i));
                for (int s = 0; s < n_succ; ++s) {
                    int succ_idx = fc.succ(static_cast<int>(i), s);
                    succs.push_back(tools::utils::FormatAddress(fc.blocks[succ_idx].start_ea));
                }

                blocks_arr.push_back({
                    {"id", i},
                    {"start", tools::utils::FormatAddress(b.start_ea)},
                    {"end", tools::utils::FormatAddress(b.end_ea)},
                    {"size", blk_size},
                    {"successors", succs}
                });
            }
        });

        if (!found_fn) {
            return tools::utils::MakeToolErrorJson(
                id,
                "No function found containing address " + tools::utils::FormatAddress(start_ea),
                "function_not_found"
            );
        }

        nlohmann::json res = {
            {"status", "success"},
            {"function", tools::utils::FormatAddress(fn_start)},
            {"block_count", blocks_arr.size()},
            {"blocks", blocks_arr}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiAnalysis::XrefQuery(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t target_ea = tools::utils::GetAddressArg(args, "addr");
        if (target_ea == BADADDR) target_ea = tools::utils::GetAddressArg(args, "target");

        if (target_ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }

        std::string direction = tools::utils::GetStringArg(args, "direction", "to");
        std::string type_filter = tools::utils::GetStringArg(args, "type", tools::utils::GetStringArg(args, "xref_type", "all"));
        size_t offset = static_cast<size_t>(tools::utils::GetIntArg(args, "offset", 0));
        size_t count = static_cast<size_t>(tools::utils::GetIntArg(args, "count", 100));
        if (count <= 0) count = 100;
        if (count > 2000) count = 2000;

        nlohmann::json xrefs_arr = nlohmann::json::array();
        size_t total_matches = 0;
        int next_offset = -1;

        sync::SyncRead([&]() {
            std::vector<nlohmann::json> all_xrefs;

            if (direction == "to" || direction == "both") {
                xrefblk_t xb;
                for (bool ok = xb.first_to(target_ea, XREF_ALL); ok; ok = xb.next_to()) {
                    if (type_filter == "code" && !xb.iscode) continue;
                    if (type_filter == "data" && xb.iscode) continue;

                    qstring from_name;
                    get_ea_name(&from_name, xb.from);

                    all_xrefs.push_back({
                        {"direction", "to"},
                        {"from", tools::utils::FormatAddress(xb.from)},
                        {"to", tools::utils::FormatAddress(target_ea)},
                        {"type", xb.iscode ? "code" : "data"},
                        {"from_name", from_name.empty() ? "" : from_name.c_str()}
                    });
                }
            }

            if (direction == "from" || direction == "both") {
                xrefblk_t xb;
                for (bool ok = xb.first_from(target_ea, XREF_ALL); ok; ok = xb.next_from()) {
                    if (type_filter == "code" && !xb.iscode) continue;
                    if (type_filter == "data" && xb.iscode) continue;

                    qstring to_name;
                    get_ea_name(&to_name, xb.to);

                    all_xrefs.push_back({
                        {"direction", "from"},
                        {"from", tools::utils::FormatAddress(target_ea)},
                        {"to", tools::utils::FormatAddress(xb.to)},
                        {"type", xb.iscode ? "code" : "data"},
                        {"to_name", to_name.empty() ? "" : to_name.c_str()}
                    });
                }
            }

            total_matches = all_xrefs.size();
            for (size_t i = offset; i < all_xrefs.size() && xrefs_arr.size() < count; ++i) {
                xrefs_arr.push_back(std::move(all_xrefs[i]));
                next_offset = static_cast<int>(i + 1);
            }

            if (next_offset >= static_cast<int>(total_matches)) {
                next_offset = -1;
            }
        });

        nlohmann::json res = {
            {"status", "success"},
            {"target", tools::utils::FormatAddress(target_ea)},
            {"total", total_matches},
            {"returned", xrefs_arr.size()},
            {"xrefs", xrefs_arr}
        };
        if (next_offset != -1) {
            res["next_offset"] = next_offset;
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiAnalysis::Callgraph(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t root_ea = tools::utils::GetAddressArg(args, "addr");
        if (root_ea == BADADDR) root_ea = tools::utils::GetAddressArg(args, "root");

        if (root_ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }

        int max_depth = static_cast<int>(tools::utils::GetIntArg(args, "depth", 3));
        if (max_depth <= 0) max_depth = 3;
        if (max_depth > 10) max_depth = 10;

        nlohmann::json edges_arr = nlohmann::json::array();
        std::set<ea_t> visited_nodes;
        bool found_fn = false;

        sync::SyncRead([&]() {
            func_t* root_fn = get_func(root_ea);
            if (!root_fn) return;
            found_fn = true;

            struct QItem {
                ea_t ea;
                int depth;
            };

            std::queue<QItem> q;
            q.push({root_fn->start_ea, 0});
            visited_nodes.insert(root_fn->start_ea);

            while (!q.empty() && visited_nodes.size() < 500) {
                auto item = q.front();
                q.pop();

                if (item.depth >= max_depth) continue;

                func_t* fn = get_func(item.ea);
                if (!fn) continue;

                qstring caller_name;
                get_func_name(&caller_name, fn->start_ea);

                func_item_iterator_t fii;
                for (bool ok = fii.set(fn, fn->start_ea); ok; ok = fii.next_head()) {
                    ea_t cur = fii.current();
                    xrefblk_t xb;
                    for (bool xok = xb.first_from(cur, XREF_ALL); xok; xok = xb.next_from()) {
                        if (xb.iscode && xb.type == fl_CN) {
                            qstring target_name;
                            get_func_name(&target_name, xb.to);

                            edges_arr.push_back({
                                {"caller", caller_name.c_str()},
                                {"caller_addr", tools::utils::FormatAddress(fn->start_ea)},
                                {"callee", target_name.c_str()},
                                {"callee_addr", tools::utils::FormatAddress(xb.to)},
                                {"depth", item.depth + 1}
                            });

                            if (visited_nodes.find(xb.to) == visited_nodes.end()) {
                                visited_nodes.insert(xb.to);
                                q.push({xb.to, item.depth + 1});
                            }
                        }
                    }
                }
            }
        });

        if (!found_fn) {
            return tools::utils::MakeToolErrorJson(
                id,
                "No function found containing address " + tools::utils::FormatAddress(root_ea),
                "function_not_found"
            );
        }

        nlohmann::json res = {
            {"status", "success"},
            {"root", tools::utils::FormatAddress(root_ea)},
            {"node_count", visited_nodes.size()},
            {"edge_count", edges_arr.size()},
            {"edges", edges_arr}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiAnalysis::FindBytes(const nlohmann::json& id, const nlohmann::json& args) {
        std::string pattern_str = tools::utils::GetStringArg(args, "pattern");
        if (pattern_str.empty()) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'pattern' is required", "pattern_required");
        }

        size_t offset = static_cast<size_t>(tools::utils::GetIntArg(args, "offset", 0));
        ea_t cursor_ea = tools::utils::GetAddressArg(args, "cursor", BADADDR);
        std::string cursor_str = tools::utils::GetStringArg(args, "cursor");
        if (cursor_ea == BADADDR && !cursor_str.empty()) {
            try { offset = static_cast<size_t>(std::stoul(cursor_str)); } catch (...) {}
        }

        size_t count = static_cast<size_t>(tools::utils::GetIntArg(args, "count", 50));
        if (count <= 0) count = 50;
        if (count > 1000) count = 1000;

        nlohmann::json matches = nlohmann::json::array();
        int next_offset = -1;
        ea_t next_cursor_ea = BADADDR;
        std::string parse_err;

        sync::SyncRead([&]() {
            compiled_binpat_vec_t bbv;
            qstring errbuf;
            ea_t start_scope = (cursor_ea != BADADDR) ? cursor_ea : inf_get_min_ea();
            if (!parse_binpat_str(&bbv, start_scope, pattern_str.c_str(), 16, PBSENC_DEF1BPU, &errbuf)) {
                parse_err = errbuf.empty() ? "Failed to parse binary pattern string" : errbuf.c_str();
                return;
            }

            ea_t search_cur = start_scope;
            ea_t max_ea = inf_get_max_ea();
            size_t current_idx = 0;
            size_t fetched = 0;

            while (search_cur != BADADDR && search_cur < max_ea && fetched < count) {
                ea_t match_ea = bin_search(search_cur, max_ea, bbv, BIN_SEARCH_FORWARD | BIN_SEARCH_NOBREAK | BIN_SEARCH_NOSHOW);
                if (match_ea == BADADDR) break;

                if (current_idx >= offset) {
                    segment_t* seg = getseg(match_ea);
                    qstring seg_name;
                    if (seg) get_segm_name(&seg_name, seg);

                    matches.push_back({
                        {"address", tools::utils::FormatAddress(match_ea)},
                        {"segment", seg_name.c_str()}
                    });
                    fetched++;
                    next_offset = static_cast<int>(current_idx + 1);
                    next_cursor_ea = match_ea + 1;
                }
                current_idx++;
                search_cur = match_ea + 1;
            }
        });

        if (!parse_err.empty()) {
            return tools::utils::MakeToolErrorJson(id, parse_err, "invalid_pattern");
        }

        nlohmann::json res = {
            {"status", "success"},
            {"pattern", pattern_str},
            {"matches_count", matches.size()},
            {"matches", matches}
        };
        if (next_offset != -1) {
            res["next_offset"] = next_offset;
            if (next_cursor_ea != BADADDR) {
                res["next_cursor"] = tools::utils::FormatAddress(next_cursor_ea);
            }
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiAnalysis::InsnQuery(const nlohmann::json& id, const nlohmann::json& args) {
        std::string mnem_filter = tools::utils::GetStringArg(args, "mnemonic", tools::utils::GetStringArg(args, "mnem"));
        ea_t fn_ea = tools::utils::GetAddressArg(args, "addr");
        if (fn_ea == BADADDR) fn_ea = tools::utils::GetAddressArg(args, "func");
        size_t count = static_cast<size_t>(tools::utils::GetIntArg(args, "count", 50));
        if (count <= 0) count = 50;
        if (count > 1000) count = 1000;

        nlohmann::json insns_arr = nlohmann::json::array();

        sync::SyncRead([&]() {
            size_t fetched = 0;
            if (fn_ea != BADADDR) {
                func_t* fn = get_func(fn_ea);
                if (fn) {
                    for (ea_t cur = fn->start_ea; cur < fn->end_ea && fetched < count; cur = get_item_end(cur)) {
                        qstring mnem;
                        print_insn_mnem(&mnem, cur);
                        if (mnem_filter.empty() || tools::utils::PatternMatch(mnem.c_str(), mnem_filter)) {
                            insns_arr.push_back({
                                {"address", tools::utils::FormatAddress(cur)},
                                {"mnemonic", mnem.c_str()},
                                {"disasm", CleanDisasmLine(cur)}
                            });
                            fetched++;
                        }
                    }
                }
            } else {
                size_t total_funcs = get_func_qty();
                for (size_t f = 0; f < total_funcs && fetched < count; ++f) {
                    func_t* fn = getn_func(f);
                    if (!fn) continue;
                    for (ea_t cur = fn->start_ea; cur < fn->end_ea && fetched < count; cur = get_item_end(cur)) {
                        qstring mnem;
                        print_insn_mnem(&mnem, cur);
                        if (mnem_filter.empty() || tools::utils::PatternMatch(mnem.c_str(), mnem_filter)) {
                            insns_arr.push_back({
                                {"address", tools::utils::FormatAddress(cur)},
                                {"mnemonic", mnem.c_str()},
                                {"disasm", CleanDisasmLine(cur)}
                            });
                            fetched++;
                        }
                    }
                }
            }
        });

        nlohmann::json res = {
            {"status", "success"},
            {"count", insns_arr.size()},
            {"instructions", insns_arr}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiAnalysis::FindPath(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t from_ea = tools::utils::GetAddressArg(args, "from");
        if (from_ea == BADADDR) from_ea = tools::utils::GetAddressArg(args, "src");
        if (from_ea == BADADDR) from_ea = tools::utils::GetAddressArg(args, "start");

        ea_t to_ea = tools::utils::GetAddressArg(args, "to");
        if (to_ea == BADADDR) to_ea = tools::utils::GetAddressArg(args, "dst");
        if (to_ea == BADADDR) to_ea = tools::utils::GetAddressArg(args, "target");

        if (from_ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'from' could not be resolved to a valid address or function", "invalid_from_addr");
        }
        if (to_ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'to' could not be resolved to a valid address or function", "invalid_to_addr");
        }

        int max_depth = static_cast<int>(tools::utils::GetIntArg(args, "max_depth", 100));
        if (max_depth <= 0) max_depth = 100;
        if (max_depth > 2000) max_depth = 2000;

        int max_paths = static_cast<int>(tools::utils::GetIntArg(args, "max_paths", 1));
        if (max_paths <= 0) max_paths = 1;
        if (max_paths > 10) max_paths = 10;

        size_t budget = static_cast<size_t>(tools::utils::GetIntArg(args, "budget", 100000));
        if (budget > 1000000) budget = 1000000;

        struct PathEdge {
            ea_t caller_start_ea = BADADDR;
            ea_t call_site_ea = BADADDR;
            ea_t callee_start_ea = BADADDR;
            bool is_thunk = false;
            std::string caller_name;
            std::string callee_name;
        };

        ea_t start_func_ea = BADADDR;
        ea_t target_func_ea = BADADDR;
        qstring start_func_name;
        qstring target_func_name;
        std::vector<std::vector<PathEdge>> all_found_paths;
        std::set<std::pair<ea_t, ea_t>> banned_edges;

        sync::SyncRead([&]() {
            func_t* f_from = get_func(from_ea);
            func_t* f_to = get_func(to_ea);
            if (!f_from || !f_to) return;

            start_func_ea = f_from->start_ea;
            target_func_ea = f_to->start_ea;
            get_func_name(&start_func_name, start_func_ea);
            get_func_name(&target_func_name, target_func_ea);

            if (start_func_ea == target_func_ea) {
                all_found_paths.push_back({});
                return;
            }

            auto get_out_edges = [&](func_t* fn) -> std::vector<PathEdge> {
                std::vector<PathEdge> edges;
                if (!fn) return edges;

                func_item_iterator_t fii;
                for (bool ok = fii.set(fn); ok; ok = fii.next_code()) {
                    ea_t cur = fii.current();
                    xrefblk_t xb;
                    for (bool xok = xb.first_from(cur, XREF_ALL); xok; xok = xb.next_from()) {
                        if (xb.iscode) {
                            bool is_call = (xb.type == fl_CN || xb.type == fl_CF);
                            bool is_tail = (xb.type == fl_JN || xb.type == fl_JF);
                            if (is_call || is_tail) {
                                func_t* callee = get_func(xb.to);
                                if (callee && callee->start_ea != fn->start_ea && (!is_tail || callee->start_ea == xb.to)) {
                                    bool thunk = (callee->flags & FUNC_THUNK) != 0;
                                    edges.push_back({fn->start_ea, cur, callee->start_ea, thunk});
                                }
                            }
                        }
                    }
                }
                return edges;
            };

            auto get_in_edges = [&](func_t* fn) -> std::vector<PathEdge> {
                std::vector<PathEdge> edges;
                if (!fn) return edges;

                xrefblk_t xb;
                for (bool ok = xb.first_to(fn->start_ea, XREF_ALL); ok; ok = xb.next_to()) {
                    if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF || xb.type == fl_JN || xb.type == fl_JF)) {
                        func_t* caller = get_func(xb.from);
                        if (caller && caller->start_ea != fn->start_ea) {
                            bool thunk = (caller->flags & FUNC_THUNK) != 0;
                            edges.push_back({caller->start_ea, xb.from, fn->start_ea, thunk});
                        }
                    }
                }
                return edges;
            };

            for (int path_idx = 0; path_idx < max_paths; ++path_idx) {
                std::unordered_map<ea_t, PathEdge> parent_fwd;
                std::unordered_map<ea_t, PathEdge> parent_bwd;
                std::unordered_map<ea_t, int> dist_fwd;
                std::unordered_map<ea_t, int> dist_bwd;
                std::queue<ea_t> q_fwd;
                std::queue<ea_t> q_bwd;

                q_fwd.push(start_func_ea);
                dist_fwd[start_func_ea] = 0;

                q_bwd.push(target_func_ea);
                dist_bwd[target_func_ea] = 0;

                ea_t intersection = BADADDR;
                size_t nodes_explored = 0;

                while (!q_fwd.empty() && !q_bwd.empty() && nodes_explored < budget) {
                    if (q_fwd.size() <= q_bwd.size()) {
                        ea_t cur_ea = q_fwd.front();
                        q_fwd.pop();
                        nodes_explored++;
                        int cur_d = dist_fwd[cur_ea];
                        if (cur_d >= max_depth) continue;

                        func_t* cur_fn = get_func(cur_ea);
                        auto edges = get_out_edges(cur_fn);
                        for (const auto& e : edges) {
                            if (banned_edges.count({e.caller_start_ea, e.callee_start_ea})) continue;

                            if (parent_bwd.count(e.callee_start_ea) || e.callee_start_ea == target_func_ea) {
                                parent_fwd[e.callee_start_ea] = e;
                                intersection = e.callee_start_ea;
                                break;
                            }

                            if (!dist_fwd.count(e.callee_start_ea)) {
                                dist_fwd[e.callee_start_ea] = cur_d + 1;
                                parent_fwd[e.callee_start_ea] = e;
                                q_fwd.push(e.callee_start_ea);
                            }
                        }
                    } else {
                        ea_t cur_ea = q_bwd.front();
                        q_bwd.pop();
                        nodes_explored++;
                        int cur_d = dist_bwd[cur_ea];
                        if (cur_d >= max_depth) continue;

                        func_t* cur_fn = get_func(cur_ea);
                        auto edges = get_in_edges(cur_fn);
                        for (const auto& e : edges) {
                            if (banned_edges.count({e.caller_start_ea, e.callee_start_ea})) continue;

                            if (parent_fwd.count(e.caller_start_ea) || e.caller_start_ea == start_func_ea) {
                                parent_bwd[e.caller_start_ea] = e;
                                intersection = e.caller_start_ea;
                                break;
                            }

                            if (!dist_bwd.count(e.caller_start_ea)) {
                                dist_bwd[e.caller_start_ea] = cur_d + 1;
                                parent_bwd[e.caller_start_ea] = e;
                                q_bwd.push(e.caller_start_ea);
                            }
                        }
                    }

                    if (intersection != BADADDR) break;
                }

                if (intersection == BADADDR) break;

                std::vector<PathEdge> path_left;
                ea_t trace_ea = intersection;
                while (trace_ea != start_func_ea && parent_fwd.count(trace_ea)) {
                    const auto& e = parent_fwd[trace_ea];
                    path_left.push_back(e);
                    trace_ea = e.caller_start_ea;
                }
                std::reverse(path_left.begin(), path_left.end());

                std::vector<PathEdge> path_right;
                trace_ea = intersection;
                while (trace_ea != target_func_ea && parent_bwd.count(trace_ea)) {
                    const auto& e = parent_bwd[trace_ea];
                    path_right.push_back(e);
                    trace_ea = e.callee_start_ea;
                }

                std::vector<PathEdge> full_path = std::move(path_left);
                full_path.insert(full_path.end(), path_right.begin(), path_right.end());

                if (full_path.empty() && start_func_ea != target_func_ea) break;

                for (auto& edge : full_path) {
                    qstring c_name, t_name;
                    get_func_name(&c_name, edge.caller_start_ea);
                    get_func_name(&t_name, edge.callee_start_ea);
                    edge.caller_name = c_name.c_str();
                    edge.callee_name = t_name.c_str();
                }

                all_found_paths.push_back(full_path);

                if (!full_path.empty()) {
                    size_t mid_idx = full_path.size() / 2;
                    banned_edges.insert({full_path[mid_idx].caller_start_ea, full_path[mid_idx].callee_start_ea});
                }
            }
        });

        if (start_func_ea == BADADDR || target_func_ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Could not locate function objects for given addresses", "function_not_found");
        }

        nlohmann::json paths_arr = nlohmann::json::array();
        for (const auto& path : all_found_paths) {
            nlohmann::json steps = nlohmann::json::array();
            for (size_t i = 0; i < path.size(); ++i) {
                const auto& edge = path[i];
                steps.push_back({
                    {"step", i},
                    {"caller", edge.caller_name},
                    {"caller_addr", tools::utils::FormatAddress(edge.caller_start_ea)},
                    {"call_site", tools::utils::FormatAddress(edge.call_site_ea)},
                    {"callee", edge.callee_name},
                    {"callee_addr", tools::utils::FormatAddress(edge.callee_start_ea)},
                    {"is_thunk", edge.is_thunk}
                });
            }
            paths_arr.push_back({
                {"length", path.size()},
                {"steps", steps}
            });
        }

        nlohmann::json res = {
            {"status", "success"},
            {"found", !all_found_paths.empty()},
            {"from", start_func_name.c_str()},
            {"from_addr", tools::utils::FormatAddress(start_func_ea)},
            {"to", target_func_name.c_str()},
            {"to_addr", tools::utils::FormatAddress(target_func_ea)},
            {"paths_count", paths_arr.size()},
            {"paths", paths_arr}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }
}
