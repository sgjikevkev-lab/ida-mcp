#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <set>
#include <queue>
#include <unordered_map>
#include <limits>
#include <stdexcept>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "api_analysis.h"
#include "tools/utils/utils.h"
#include "sync/sync.h"
#include "sync/cache_manager.h"

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
#include <idp.hpp>

namespace tools::analysis {
    namespace {
        constexpr size_t kMaxPseudocodeBytes = 512 * 1024;
        constexpr size_t kMaxLocalVariables = 128;
        constexpr size_t kMaxDecompileResponseEstimate = mcp::limits::result_bytes - 128 * 1024;

        std::string Utf8Prefix(const std::string& value, size_t max_bytes) {
            size_t length = std::min(value.size(), max_bytes);
            while (length > 0 && length < value.size() &&
                   (static_cast<unsigned char>(value[length]) & 0xC0) == 0x80) {
                --length;
            }
            return value.substr(0, length);
        }

        std::string ReadItemBytes(ea_t ea, size_t item_size, size_t byte_limit, bool& truncated) {
            std::string hex;
            const size_t requested = std::min(item_size, byte_limit);
            if (item_size > requested) truncated = true;
            segment_t* segment = getseg(ea);
            for (size_t index = 0; index < requested; ++index) {
                sync::Checkpoint();
                if (index > BADADDR - ea) { truncated = true; break; }
                const ea_t byte_ea = ea + index;
                if (!segment || byte_ea >= segment->end_ea || !is_loaded(byte_ea)) {
                    truncated = true;
                    break;
                }
                char byte_text[4]{};
                qsnprintf(byte_text, sizeof(byte_text), "%02X", get_byte(byte_ea));
                if (!hex.empty()) hex.push_back(' ');
                hex += byte_text;
            }
            return hex;
        }

        struct PathEdge {
            ea_t caller_start_ea = BADADDR;
            ea_t call_site_ea = BADADDR;
            ea_t callee_start_ea = BADADDR;
            bool is_thunk = false;
            bool is_tail_call = false;
            bool is_indirect = false;
            std::string edge_type = "call"; // "call", "tail_call", "vtable_verified", "vtable_heuristic", "callback", "indirect_ptr", "indirect_vcall"
            ea_t vtable_ea = BADADDR;
            std::string vtable_name;
            std::string caller_name;
            std::string caller_demangled;
            std::string callee_name;
            std::string callee_demangled;
            std::string disasm;
        };

        class FunctionEdgeCache {
        public:
            struct CacheEntry {
                uint64_t generation = 0;
                bool out_ready = false;
                bool in_ready = false;
                std::vector<PathEdge> out_edges;
                std::vector<PathEdge> in_edges;
            };

            static FunctionEdgeCache& Instance() {
                static FunctionEdgeCache inst;
                return inst;
            }

            bool GetOut(ea_t ea, uint64_t gen, std::vector<PathEdge>& out) {
                std::lock_guard<std::mutex> lock(mtx_);
                auto it = entries_.find(ea);
                if (it != entries_.end() && it->second.generation == gen && it->second.out_ready) {
                    out = it->second.out_edges;
                    return true;
                }
                return false;
            }

            void PutOut(ea_t ea, uint64_t gen, std::vector<PathEdge> edges) {
                std::lock_guard<std::mutex> lock(mtx_);
                if (entries_.size() >= 4096 && !entries_.contains(ea)) entries_.clear();
                auto& e = entries_[ea];
                if (e.generation != gen) e = CacheEntry{};
                e.generation = gen;
                e.out_ready = true;
                e.out_edges = std::move(edges);
            }

            bool GetIn(ea_t ea, uint64_t gen, std::vector<PathEdge>& in) {
                std::lock_guard<std::mutex> lock(mtx_);
                auto it = entries_.find(ea);
                if (it != entries_.end() && it->second.generation == gen && it->second.in_ready) {
                    in = it->second.in_edges;
                    return true;
                }
                return false;
            }

            void PutIn(ea_t ea, uint64_t gen, std::vector<PathEdge> edges) {
                std::lock_guard<std::mutex> lock(mtx_);
                if (entries_.size() >= 4096 && !entries_.contains(ea)) entries_.clear();
                auto& e = entries_[ea];
                if (e.generation != gen) e = CacheEntry{};
                e.generation = gen;
                e.in_ready = true;
                e.in_edges = std::move(edges);
            }

            void Clear() {
                std::lock_guard<std::mutex> lock(mtx_);
                entries_.clear();
            }

        private:
            std::mutex mtx_;
            std::unordered_map<ea_t, CacheEntry> entries_;
        };

        struct EdgeCacheAutoReg {
            EdgeCacheAutoReg() {
                cache::CacheManager::Instance().RegisterAnalysisInvalidator([]() {
                    FunctionEdgeCache::Instance().Clear();
                });
                cache::CacheManager::Instance().RegisterByteInvalidator([]() {
                    FunctionEdgeCache::Instance().Clear();
                });
            }
        } s_edge_cache_auto_reg;
        std::string CleanDisasmLine(ea_t ea) {
            qstring buf;
            generate_disasm_line(&buf, ea, GENDSM_REMOVE_TAGS);
            std::string s = tools::utils::SanitizeUtf8(buf.c_str());
            size_t first = s.find_first_not_of(" \t");
            if (first != std::string::npos) s = s.substr(first);
            return s;
        }

        std::string GetXrefTypeString(const xrefblk_t& xb) {
            uint8_t base_type = xb.type & XREF_MASK;
            if (xb.iscode) {
                switch (base_type) {
                    case fl_CF:
                    case fl_CN: return "call";
                    case fl_JF:
                    case fl_JN: return "jump";
                    case fl_F:  return "flow";
                    default:    return "code";
                }
            } else {
                switch (base_type) {
                    case dr_O: return "offset";
                    case dr_W: return "write";
                    case dr_R: return "read";
                    case dr_T: return "text";
                    case dr_I: return "info";
                    case dr_S: return "enum";
                    default:   return "data";
                }
            }
        }

        bool MatchXrefType(const xrefblk_t& xb, const std::string& filter, const std::string& type_str) {
            if (filter.empty() || filter == "all" || filter == "*") return true;
            if (filter == "code") return xb.iscode;
            if (filter == "data") return !xb.iscode;
            return filter == type_str;
        }

        std::string GetSymbolName(ea_t ea) {
            qstring buf;
            get_ea_name(&buf, ea);
            if (buf.empty()) {
                func_t* fn = get_func(ea);
                if (fn) {
                    get_func_name(&buf, fn->start_ea);
                }
            }
            return tools::utils::SanitizeUtf8(buf.c_str());
        }

        bool SanitizePatternString(const std::string& input, std::string& output, std::string& err) {
            std::string s = input;
            size_t start = s.find_first_not_of(" \t\r\n");
            if (start == std::string::npos) {
                err = "Parameter 'pattern' cannot be empty";
                return false;
            }
            size_t end = s.find_last_not_of(" \t\r\n");
            s = s.substr(start, end - start + 1);

            // Fast path: if continuous hex string without spaces (e.g. "48895C2408")
            bool all_hex = true;
            for (char c : s) {
                sync::Checkpoint();
                if (!isxdigit(static_cast<unsigned char>(c))) {
                    all_hex = false;
                    break;
                }
            }
            if (all_hex && s.size() >= 2 && s.size() % 2 == 0) {
                std::string formatted;
                for (size_t i = 0; i < s.size(); i += 2) {
                    sync::Checkpoint();
                    if (i > 0) formatted += " ";
                    formatted += s.substr(i, 2);
                }
                output = formatted;
                return true;
            }

            // Replace commas and semicolons with spaces
            for (char& c : s) {
                sync::Checkpoint();
                if (c == ',' || c == ';') c = ' ';
            }

            // Normalize \x or \X
            std::string preprocessed;
            for (size_t i = 0; i < s.size(); ++i) {
                sync::Checkpoint();
                if (i + 1 < s.size() && s[i] == '\\' && (s[i + 1] == 'x' || s[i + 1] == 'X')) {
                    preprocessed += ' ';
                    i++; // skip 'x'
                } else {
                    preprocessed += s[i];
                }
            }

            std::istringstream iss(preprocessed);
            std::string token;
            std::string result;

            while (iss >> token) {
                sync::Checkpoint();
                // Strip leading 0x or 0X
                if (token.size() >= 3 && (token[0] == '0' && (token[1] == 'x' || token[1] == 'X'))) {
                    token = token.substr(2);
                }

                // Quoted string literal
                if (token.front() == '"' || token.front() == '\'') {
                    std::string qstr = token;
                    char quote_char = token.front();
                    if (qstr.back() != quote_char || qstr.size() == 1) {
                        std::string rest;
                        while (iss >> rest) {
                            sync::Checkpoint();
                            qstr += " " + rest;
                            if (rest.back() == quote_char) break;
                        }
                    }
                    if (!result.empty()) result += " ";
                    if (qstr.front() == '\'') {
                        qstr.front() = '"';
                        if (qstr.back() == '\'') qstr.back() = '"';
                    }
                    result += qstr;
                    continue;
                }

                // Wildcard
                if (token == "?" || token == "??") {
                    if (!result.empty()) result += " ";
                    result += "?";
                    continue;
                }

                // Validate hex byte (1 or 2 hex digits)
                bool valid_hex = (token.size() == 1 || token.size() == 2);
                if (valid_hex) {
                    for (char c : token) {
                        sync::Checkpoint();
                        if (!isxdigit(static_cast<unsigned char>(c))) {
                            valid_hex = false;
                            break;
                        }
                    }
                }

                if (!valid_hex) {
                    err = "Invalid token in byte pattern: '" + token + "'. Expected 1-2 hex digits, wildcard ('?'), or quoted string (\"text\").";
                    return false;
                }

                if (!result.empty()) result += " ";
                result += token;
            }

            if (result.empty()) {
                err = "Pattern contained no valid byte tokens";
                return false;
            }

            output = result;
            return true;
        }

        std::string GetCleanPseudocode(func_t* pfn, std::string* err_out = nullptr, nlohmann::json* out_lvars = nullptr,
                                       size_t code_limit = kMaxPseudocodeBytes, bool* code_truncated = nullptr,
                                       bool* lvars_truncated = nullptr) {
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
                sync::Checkpoint();
                qstring clean_line;
                tag_remove(&clean_line, sv[i].line);
                std::string line = tools::utils::SanitizeUtf8(clean_line.c_str());
                line.push_back('\n');
                const size_t remaining = code_limit > code.size() ? code_limit - code.size() : 0;
                if (line.size() > remaining) {
                    code += Utf8Prefix(line, remaining);
                    if (code_truncated) *code_truncated = true;
                    break;
                }
                code += line;
            }

            if (out_lvars) {
                *out_lvars = nlohmann::json::array();
                const lvars_t* lvs = cfunc->get_lvars();
                if (lvs) {
                    const size_t variable_limit = std::min(lvs->size(), kMaxLocalVariables);
                    if (lvs->size() > variable_limit && lvars_truncated) *lvars_truncated = true;
                    for (size_t i = 0; i < variable_limit; ++i) {
                        sync::Checkpoint();
                        const lvar_t& v = (*lvs)[i];
                        if (v.name.empty() && !v.used()) continue;
                        qstring tbuf;
                        v.tif.print(&tbuf, nullptr, PRTYPE_1LINE | PRTYPE_SEMI);
                        nlohmann::ordered_json v_obj;
                        v_obj["index"] = i;
                        v_obj["name"] = Utf8Prefix(tools::utils::SanitizeUtf8(v.name.c_str()), 512);
                        v_obj["type"] = Utf8Prefix(tools::utils::SanitizeUtf8(tbuf.c_str()), 1024);
                        v_obj["is_arg"] = v.is_arg_var();
                        v_obj["location"] = v.is_stk_var() ? "stack" : (v.is_reg_var() ? "reg" : "other");
                        out_lvars->push_back(std::move(v_obj));
                    }
                }
            }

            return code;
        }
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
        const bool batched = args.contains("addrs");
        if (batched && (!args["addrs"].is_array() || args["addrs"].empty() || args["addrs"].size() > 64))
            return tools::utils::MakeToolErrorJson(id, "addrs must contain between 1 and 64 addresses", "invalid_addrs");
        if (!batched && (!args.contains("addr") || !args["addr"].is_string()))
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' must be a string", "invalid_addr");
        const bool include_lvars = tools::utils::GetBoolArg(args, "include_lvars", false);
        const nlohmann::json addresses = batched ? args["addrs"] : nlohmann::json::array({args["addr"]});
        nlohmann::json results = nlohmann::json::array();
        size_t failed = 0;
        size_t output_estimate = 0;
        for (const auto& address : addresses) {
            sync::Checkpoint();
            nlohmann::json item;
            if (!address.is_string() || address.get_ref<const std::string&>().size() > 4096) {
                item["address"] = "<invalid address>";
                item["error_code"] = "invalid_addr";
                item["message"] = "Address must be a string of at most 4096 characters";
                results.push_back(std::move(item));
                ++failed;
                continue;
            }
            const std::string& address_text = address.get_ref<const std::string&>();
            const ea_t ea = tools::utils::ParseAddress(address_text);
            func_t* function = ea == BADADDR ? nullptr : get_func(ea);
            item["address"] = function ? tools::utils::FormatAddress(function->start_ea) : address_text;
            if (!function) {
                item["error_code"] = "function_not_found";
                item["message"] = "Address is not inside a recognized function";
                ++failed;
            } else {
                std::string error;
                nlohmann::json lvars;
                const size_t remaining = output_estimate < kMaxDecompileResponseEstimate
                    ? kMaxDecompileResponseEstimate - output_estimate : 0;
                const size_t code_limit = std::min(kMaxPseudocodeBytes, remaining / 2);
                if (code_limit < 1024) {
                    item["error_code"] = "result_limit_reached";
                    item["message"] = "Decompilation output limit reached for this request";
                    ++failed;
                    results.push_back(std::move(item));
                    continue;
                }
                bool code_truncated = false;
                bool lvars_truncated = false;
                auto code = GetCleanPseudocode(function, &error, include_lvars ? &lvars : nullptr,
                                               code_limit, &code_truncated, &lvars_truncated);
                if (code.empty()) {
                    item["error_code"] = "decompilation_failed";
                    item["message"] = Utf8Prefix(error, 4096);
                    ++failed;
                } else {
                    item["code"] = std::move(code);
                    if (include_lvars) item["lvars"] = std::move(lvars);
                    if (code_truncated) item["code_truncated"] = true;
                    if (lvars_truncated) item["lvars_truncated"] = true;

                    size_t item_estimate = item.dump().size();
                    const size_t item_budget = kMaxDecompileResponseEstimate - output_estimate;
                    if (item_estimate > item_budget && include_lvars) {
                        item.erase("lvars");
                        item["lvars_truncated"] = true;
                        item_estimate = item.dump().size();
                    }
                    if (item_estimate > item_budget) {
                        std::string bounded_code = item["code"].get<std::string>();
                        const size_t allowed = item_budget / 2;
                        item["code"] = Utf8Prefix(bounded_code, allowed);
                        item["code_truncated"] = true;
                        item_estimate = item.dump().size();
                    }
                    if (item_estimate > item_budget) {
                        item = {
                            {"address", tools::utils::FormatAddress(function->start_ea)},
                            {"error_code", "result_limit_reached"},
                            {"message", "Decompilation output limit reached for this request"}
                        };
                        ++failed;
                        item_estimate = item.dump().size();
                    }
                    output_estimate += item_estimate;
                }
            }
            results.push_back(std::move(item));
        }
        if (!batched) return tools::utils::MakeToolResultJson(id, results[0], failed != 0);
        nlohmann::json response = {{"functions", std::move(results)}};
        if (failed) response["failed"] = failed;
        return tools::utils::MakeToolResultJson(id, response, failed == addresses.size());
    }

    nlohmann::json ApiAnalysis::Disasm(const nlohmann::json& id, const nlohmann::json& args) {
        // 1. Batch disassembly support
        const bool batched = args.contains("targets");
        if (batched) {
            if (!args["targets"].is_array() || args["targets"].empty() || args["targets"].size() > 64)
                return tools::utils::MakeToolErrorJson(id, "targets must contain between 1 and 64 addresses", "invalid_targets");
        } else if (!args.contains("addr") || !args["addr"].is_string()) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' must be a string", "invalid_addr");
        }

        int64_t count_arg = batched ? 5 : 50;
        if (args.contains("count")) {
            const auto& value = args["count"];
            if (value.is_number_unsigned()) {
                const uint64_t parsed = value.get<uint64_t>();
                if (parsed > 1000) return tools::utils::MakeToolErrorJson(id, "count must not exceed 1000", "invalid_count");
                count_arg = static_cast<int64_t>(parsed);
            } else if (value.is_number_integer()) {
                count_arg = value.get<int64_t>();
            } else {
                return tools::utils::MakeToolErrorJson(id, "count must be an integer", "invalid_count");
            }
        }
        if (count_arg < 0 || count_arg > 1000)
            return tools::utils::MakeToolErrorJson(id, "count must be between 0 and 1000", "invalid_count");
        if (batched && count_arg > 100)
            return tools::utils::MakeToolErrorJson(id, "Batch disassembly count must not exceed 100 per target", "invalid_count");

        const size_t count = count_arg == 0 ? (batched ? 5 : 50) : static_cast<size_t>(count_arg);
        if (batched) {
            const auto& t_arr = args["targets"];
            const size_t count_per_target = count;
            bool show_bytes = tools::utils::GetBoolArg(args, "bytes", false);
            std::string mnem_filter = tools::utils::GetStringArg(args, "mnemonic");
            if (mnem_filter.size() > 1024)
                return tools::utils::MakeToolErrorJson(id, "mnemonic must not exceed 1024 characters", "invalid_mnemonic");
            mnem_filter = mcp::LowerAscii(std::move(mnem_filter));

            nlohmann::json batch_res = nlohmann::json::array();
            size_t batch_failed = 0;
            sync::SyncRead([&]() {
                for (const auto& t : t_arr) {
                    sync::Checkpoint();
                    ea_t t_ea = BADADDR;
                    if (t.is_string() && t.get_ref<const std::string&>().size() <= 4096)
                        t_ea = tools::utils::ParseAddress(t.get_ref<const std::string&>());
                    else if (t.is_number_unsigned()) t_ea = static_cast<ea_t>(t.get<uint64_t>());
                    else if (t.is_number_integer()) {
                        const int64_t numeric = t.get<int64_t>();
                        if (numeric >= 0) t_ea = static_cast<ea_t>(numeric);
                    }

                    nlohmann::ordered_json item;
                    if (t_ea == BADADDR || !is_mapped(t_ea)) {
                        item["address"] = t.is_string() && t.get_ref<const std::string&>().size() <= 4096
                            ? t.get<std::string>() : "<invalid address>";
                        item["error_code"] = "invalid_addr";
                        item["message"] = "Target address could not be resolved to mapped memory";
                        batch_res.push_back(std::move(item));
                        ++batch_failed;
                        continue;
                    }

                    ea_t head = get_item_head(t_ea);
                    if (head != BADADDR && is_mapped(head) && head <= t_ea) {
                        t_ea = head;
                    }

                    std::vector<std::string> insns;
                    bool bytes_truncated = false;
                    ea_t cur = t_ea;
                    size_t fetched = 0;
                    while (fetched < count_per_target && cur != BADADDR && is_mapped(cur)) {
                        sync::Checkpoint();
                        std::string dis = CleanDisasmLine(cur);
                        if (dis.empty()) break;

                        bool keep = true;
                        if (!mnem_filter.empty()) {
                            qstring mn_buf;
                            print_insn_mnem(&mn_buf, cur);
                            std::string mn = mn_buf.c_str();
                            mn = mcp::LowerAscii(std::move(mn));
                            if (mn != mnem_filter) keep = false;
                        }

                        if (keep) {
                            if (show_bytes) {
                                ea_t sz = get_item_size(cur);
                                if (sz == 0) sz = 1;
                                std::string hex_col = ReadItemBytes(cur, static_cast<size_t>(sz), 8, bytes_truncated);
                                if (get_item_size(cur) > 8) hex_col += " ...";
                                insns.push_back(tools::utils::FormatAddress(cur) + ":  " + hex_col + "  " + dis);
                            } else {
                                insns.push_back(tools::utils::FormatAddress(cur) + ":  " + dis);
                            }
                            fetched++;
                        }

                        ea_t nxt = get_item_end(cur);
                        if (nxt == BADADDR || nxt <= cur) break;
                        cur = nxt;
                    }

                    item["address"] = tools::utils::FormatAddress(t_ea);
                    item["count"] = insns.size();
                    item["instructions"] = insns;
                    if (bytes_truncated) item["bytes_truncated"] = true;
                    batch_res.push_back(std::move(item));
                }
            });

            nlohmann::ordered_json res;
            res["status"] = "success";
            res["count"] = batch_res.size();
            res["results"] = batch_res;
            return tools::utils::MakeToolResultJson(id, res, !batch_res.empty() && batch_failed == batch_res.size());
        }

        // 2. Single address disassembly
        ea_t start_ea = tools::utils::GetAddressArg(args, "addr");

        bool show_bytes = tools::utils::GetBoolArg(args, "bytes", false);
        bool stop_at_func_end = tools::utils::GetBoolArg(args, "stop_at_func_end", true);
        bool detailed = tools::utils::GetBoolArg(args, "detailed", false);
        std::string mnem_filter = tools::utils::GetStringArg(args, "mnemonic");
        if (mnem_filter.size() > 1024)
            return tools::utils::MakeToolErrorJson(id, "mnemonic must not exceed 1024 characters", "invalid_mnemonic");
        mnem_filter = mcp::LowerAscii(std::move(mnem_filter));

        if (start_ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }

        std::vector<std::string> instructions;
        std::vector<nlohmann::ordered_json> items;
        bool decoded_any = false;
        bool bytes_truncated = false;
        ea_t next_ea = BADADDR;
        std::string func_name;

        sync::SyncRead([&]() {
            if (is_mapped(start_ea)) {
                ea_t head = get_item_head(start_ea);
                if (head != BADADDR && is_mapped(head) && head <= start_ea) {
                    start_ea = head;
                }
            }

            func_t* fn = get_func(start_ea);
            if (fn) {
                qstring fn_buf;
                get_func_name(&fn_buf, fn->start_ea);
                std::string raw = fn_buf.c_str();
                std::string dem = tools::utils::Demangle(raw);
                func_name = dem.empty() ? raw : dem;
            }

            size_t fetched = 0;

            if (fn && stop_at_func_end) {
                func_item_iterator_t fii;
                bool ok = fii.set(fn, start_ea);
                while (ok && fetched < count) {
                    sync::Checkpoint();
                    ea_t cur = fii.current();
                    if (!is_mapped(cur)) break;
                    std::string dis = CleanDisasmLine(cur);
                    if (dis.empty()) break;

                    bool keep = true;
                    if (!mnem_filter.empty()) {
                        qstring mn_buf;
                        print_insn_mnem(&mn_buf, cur);
                        std::string mn = mn_buf.c_str();
                        mn = mcp::LowerAscii(std::move(mn));
                        if (mn != mnem_filter) keep = false;
                    }

                    if (keep) {
                        ea_t item_size = get_item_size(cur);
                        if (item_size == 0) item_size = 1;

                        std::string hex_str;
                        bool item_bytes_truncated = false;
                        if (show_bytes || detailed) {
                            hex_str = ReadItemBytes(cur, static_cast<size_t>(item_size), 15, item_bytes_truncated);
                            if (item_size > 15) {
                                hex_str += " ...";
                            }
                            bytes_truncated = bytes_truncated || item_bytes_truncated;
                        }

                        if (show_bytes) {
                            std::string hex_col = hex_str;
                            if (hex_col.length() < 24) {
                                hex_col.append(24 - hex_col.length(), ' ');
                            }
                            instructions.push_back(tools::utils::FormatAddress(cur) + ":  " + hex_col + "  " + dis);
                        } else {
                            instructions.push_back(tools::utils::FormatAddress(cur) + ":  " + dis);
                        }

                        if (detailed) {
                            nlohmann::ordered_json item;
                            item["address"] = tools::utils::FormatAddress(cur);
                            item["size"] = item_size;
                            item["bytes"] = hex_str;
                            item["disasm"] = dis;
                            if (item_bytes_truncated) item["bytes_truncated"] = true;
                            items.push_back(std::move(item));
                        }

                        decoded_any = true;
                        fetched++;
                    }

                    ok = fii.next_head();
                }

                if (ok && fetched >= count) {
                    ea_t cand = fii.current();
                    if (cand != BADADDR && is_mapped(cand)) {
                        next_ea = cand;
                    }
                }
            } else {
                ea_t cur = start_ea;
                ea_t seg_end = BADADDR;
                segment_t* seg = getseg(start_ea);
                if (seg) seg_end = seg->end_ea;

                while (cur != BADADDR && is_mapped(cur) && fetched < count) {
                    sync::Checkpoint();
                    if (seg_end != BADADDR && cur >= seg_end) break;

                    std::string dis = CleanDisasmLine(cur);
                    if (dis.empty()) break;

                    bool keep = true;
                    if (!mnem_filter.empty()) {
                        qstring mn_buf;
                        print_insn_mnem(&mn_buf, cur);
                        std::string mn = mn_buf.c_str();
                        mn = mcp::LowerAscii(std::move(mn));
                        if (mn != mnem_filter) keep = false;
                    }

                    if (keep) {
                        ea_t item_size = get_item_size(cur);
                        if (item_size == 0) item_size = 1;

                        std::string hex_str;
                        bool item_bytes_truncated = false;
                        if (show_bytes || detailed) {
                            hex_str = ReadItemBytes(cur, static_cast<size_t>(item_size), 15, item_bytes_truncated);
                            if (item_size > 15) {
                                hex_str += " ...";
                            }
                            bytes_truncated = bytes_truncated || item_bytes_truncated;
                        }

                        if (show_bytes) {
                            std::string hex_col = hex_str;
                            if (hex_col.length() < 24) {
                                hex_col.append(24 - hex_col.length(), ' ');
                            }
                            instructions.push_back(tools::utils::FormatAddress(cur) + ":  " + hex_col + "  " + dis);
                        } else {
                            instructions.push_back(tools::utils::FormatAddress(cur) + ":  " + dis);
                        }

                        if (detailed) {
                            nlohmann::ordered_json item;
                            item["address"] = tools::utils::FormatAddress(cur);
                            item["size"] = item_size;
                            item["bytes"] = hex_str;
                            item["disasm"] = dis;
                            if (item_bytes_truncated) item["bytes_truncated"] = true;
                            items.push_back(std::move(item));
                        }

                        decoded_any = true;
                        fetched++;
                    }

                    ea_t nxt = get_item_end(cur);
                    if (nxt == BADADDR || nxt <= cur) break;
                    cur = nxt;
                }

                if (fetched >= count && cur != BADADDR && is_mapped(cur) && (seg_end == BADADDR || cur < seg_end)) {
                    next_ea = cur;
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

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["address"] = tools::utils::FormatAddress(start_ea);
        if (!func_name.empty()) {
            res["function"] = func_name;
        }
        res["count"] = instructions.size();
        res["instructions"] = instructions;
        if (detailed) {
            res["items"] = items;
        }
        if (bytes_truncated) res["bytes_truncated"] = true;
        if (next_ea != BADADDR && is_mapped(next_ea)) {
            res["next_cursor"] = tools::utils::FormatAddress(next_ea);
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiAnalysis::BasicBlocks(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t start_ea = tools::utils::GetAddressArg(args, "addr");
        if (start_ea == BADADDR) {
            std::string raw = tools::utils::GetStringArg(args, "addr");
            std::string msg = "Parameter 'addr' could not be resolved";
            if (!raw.empty()) msg += ": " + raw;
            return tools::utils::MakeToolErrorJson(id, msg, "invalid_addr");
        }

        constexpr size_t kMaxBasicBlocks = 512;
        constexpr size_t kMaxInstructions = 2048;
        constexpr size_t kMaxInstructionTextBytes = 512 * 1024;
        bool no_external = tools::utils::GetBoolArg(args, "no_external", false);
        bool include_instructions = tools::utils::GetBoolArg(args, "include_instructions", false);

        std::vector<nlohmann::ordered_json> blocks_arr;
        ea_t fn_start = BADADDR;
        std::string fn_name;
        std::string demangled_str;
        bool found_fn = false;
        size_t total_edges = 0;
        int cyclomatic_complexity = 1;
        size_t total_blocks = 0;
        size_t instruction_count = 0;
        size_t instruction_text_bytes = 0;
        bool blocks_truncated = false;
        bool instructions_truncated = false;

        sync::SyncRead([&]() {
            func_t* fn = get_func(start_ea);
            if (!fn) return;

            found_fn = true;
            fn_start = fn->start_ea;

            qstring name_buf;
            get_func_name(&name_buf, fn->start_ea);
            fn_name = tools::utils::SanitizeUtf8(name_buf.c_str());

            qstring dem_buf;
            if (demangle_name(&dem_buf, fn_name.c_str(), 0, DQT_FULL) > 0) {
                demangled_str = tools::utils::SanitizeUtf8(dem_buf.c_str());
            }

            int fc_flags = 0;
            if (no_external) fc_flags |= FC_NOEXT;

            qflow_chart_t fc("", fn, fn->start_ea, fn->end_ea, fc_flags);
            total_blocks = fc.blocks.size();
            const size_t emitted_blocks = std::min(total_blocks, kMaxBasicBlocks);
            blocks_truncated = total_blocks > emitted_blocks;

            // 1. Identify loop headers across the flow chart
            std::set<int> loop_header_ids;
            total_edges = 0;
            for (size_t i = 0; i < fc.blocks.size(); ++i) {
                sync::Checkpoint();
                const qbasic_block_t& b = fc.blocks[i];
                int n_succ = fc.nsucc(static_cast<int>(i));
                if (static_cast<size_t>(n_succ) > std::numeric_limits<size_t>::max() - total_edges)
                    total_edges = std::numeric_limits<size_t>::max();
                else
                    total_edges += static_cast<size_t>(n_succ);
                for (int s = 0; s < n_succ; ++s) {
                    sync::Checkpoint();
                    int succ_idx = fc.succ(static_cast<int>(i), s);
                    if (succ_idx >= 0 && succ_idx < static_cast<int>(fc.blocks.size())) {
                        if (fc.blocks[succ_idx].start_ea <= b.start_ea) {
                            loop_header_ids.insert(succ_idx);
                        }
                    }
                }
            }

            cyclomatic_complexity = 1;
            if (!fc.blocks.empty()) {
                const int64_t complexity = total_edges > static_cast<size_t>(std::numeric_limits<int64_t>::max())
                    ? std::numeric_limits<int64_t>::max()
                    : static_cast<int64_t>(total_edges) - static_cast<int64_t>(fc.blocks.size()) + 2;
                cyclomatic_complexity = static_cast<int>(std::clamp<int64_t>(complexity, 1, std::numeric_limits<int>::max()));
                if (cyclomatic_complexity < 1) cyclomatic_complexity = 1;
            }

            for (size_t i = 0; i < emitted_blocks; ++i) {
                sync::Checkpoint();
                const qbasic_block_t& b = fc.blocks[i];
                size_t blk_size = (b.end_ea >= b.start_ea) ? (b.end_ea - b.start_ea) : 0;

                fc_block_type_t btype = fc.calc_block_type(i);
                std::string type_name = "normal";
                switch (btype) {
                    case fcb_normal:  type_name = "normal"; break;
                    case fcb_indjump: type_name = "indjump"; break;
                    case fcb_ret:     type_name = "ret"; break;
                    case fcb_cndret:  type_name = "cndret"; break;
                    case fcb_noret:   type_name = "noret"; break;
                    case fcb_enoret:  type_name = "enoret"; break;
                    case fcb_extern:  type_name = "extern"; break;
                    case fcb_error:   type_name = "error"; break;
                    default:          type_name = "unknown"; break;
                }

                nlohmann::json succs = nlohmann::json::array();
                nlohmann::json succ_ids = nlohmann::json::array();
                int n_succ = fc.nsucc(static_cast<int>(i));
                for (int s = 0; s < n_succ; ++s) {
                    sync::Checkpoint();
                    int succ_idx = fc.succ(static_cast<int>(i), s);
                    if (succ_idx >= 0 && succ_idx < static_cast<int>(fc.blocks.size())) {
                        succs.push_back(tools::utils::FormatAddress(fc.blocks[succ_idx].start_ea));
                        succ_ids.push_back(succ_idx);
                    }
                }

                nlohmann::json preds = nlohmann::json::array();
                nlohmann::json pred_ids = nlohmann::json::array();
                int n_pred = fc.npred(static_cast<int>(i));
                for (int p = 0; p < n_pred; ++p) {
                    sync::Checkpoint();
                    int pred_idx = fc.pred(static_cast<int>(i), p);
                    if (pred_idx >= 0 && pred_idx < static_cast<int>(fc.blocks.size())) {
                        preds.push_back(tools::utils::FormatAddress(fc.blocks[pred_idx].start_ea));
                        pred_ids.push_back(pred_idx);
                    }
                }

                nlohmann::ordered_json block_obj;
                block_obj["id"] = i;
                block_obj["start"] = tools::utils::FormatAddress(b.start_ea);
                block_obj["end"] = tools::utils::FormatAddress(b.end_ea);
                block_obj["size"] = blk_size;
                block_obj["type"] = type_name;
                if (btype == fcb_ret || btype == fcb_cndret) {
                    block_obj["is_ret"] = true;
                }
                if (btype == fcb_noret || btype == fcb_enoret) {
                    block_obj["is_noret"] = true;
                }
                if (loop_header_ids.find(static_cast<int>(i)) != loop_header_ids.end()) {
                    block_obj["is_loop_header"] = true;
                }

                // Check for back-edge / loop edge
                for (int s = 0; s < n_succ; ++s) {
                    sync::Checkpoint();
                    int succ_idx = fc.succ(static_cast<int>(i), s);
                    if (succ_idx >= 0 && succ_idx < static_cast<int>(fc.blocks.size())) {
                        if (fc.blocks[succ_idx].start_ea <= b.start_ea) {
                            block_obj["is_back_edge"] = true;
                            block_obj["loop_target"] = tools::utils::FormatAddress(fc.blocks[succ_idx].start_ea);
                            block_obj["loop_target_id"] = succ_idx;
                            break;
                        }
                    }
                }

                block_obj["successor_ids"] = succ_ids;
                block_obj["predecessor_ids"] = pred_ids;

                // Branch condition and true/false target resolution
                if (n_succ == 2 && b.end_ea > b.start_ea) {
                    insn_t insn;
                    ea_t last_insn_ea = decode_prev_insn(&insn, b.end_ea);
                    if (last_insn_ea != BADADDR && last_insn_ea >= b.start_ea) {
                        qstring mn_buf;
                        print_insn_mnem(&mn_buf, last_insn_ea);
                        std::string mnem = mn_buf.c_str();

                        ea_t target_branch = BADADDR;
                        if (insn.ops[0].type == o_near || insn.ops[0].type == o_far) {
                            target_branch = insn.ops[0].addr;
                        }

                        int s0 = fc.succ(static_cast<int>(i), 0);
                        int s1 = fc.succ(static_cast<int>(i), 1);
                        ea_t s0_ea = (s0 >= 0 && s0 < static_cast<int>(fc.blocks.size())) ? fc.blocks[s0].start_ea : BADADDR;
                        ea_t s1_ea = (s1 >= 0 && s1 < static_cast<int>(fc.blocks.size())) ? fc.blocks[s1].start_ea : BADADDR;

                        nlohmann::ordered_json br;
                        br["condition"] = mnem;
                        br["insn"] = CleanDisasmLine(last_insn_ea);
                        if (target_branch != BADADDR) {
                            if (target_branch == s0_ea) {
                                br["true_target"] = tools::utils::FormatAddress(s0_ea);
                                br["true_id"] = s0;
                                br["false_target"] = tools::utils::FormatAddress(s1_ea);
                                br["false_id"] = s1;
                            } else if (target_branch == s1_ea) {
                                br["true_target"] = tools::utils::FormatAddress(s1_ea);
                                br["true_id"] = s1;
                                br["false_target"] = tools::utils::FormatAddress(s0_ea);
                                br["false_id"] = s0;
                            } else {
                                br["branch_target"] = tools::utils::FormatAddress(target_branch);
                            }
                        }
                        block_obj["branch"] = std::move(br);
                    }
                }

                if (include_instructions && b.start_ea != BADADDR && b.end_ea > b.start_ea) {
                    std::vector<std::string> insns;
                    ea_t cur = b.start_ea;
                    while (cur < b.end_ea && cur != BADADDR && is_mapped(cur)) {
                        sync::Checkpoint();
                        if (instruction_count >= kMaxInstructions || instruction_text_bytes >= kMaxInstructionTextBytes) {
                            instructions_truncated = true;
                            break;
                        }
                        std::string dis = CleanDisasmLine(cur);
                        if (!dis.empty()) {
                            std::string line = tools::utils::FormatAddress(cur) + ":  " + dis;
                            if (line.size() > kMaxInstructionTextBytes - instruction_text_bytes) {
                                instructions_truncated = true;
                                break;
                            }
                            instruction_text_bytes += line.size();
                            ++instruction_count;
                            insns.push_back(std::move(line));
                        }
                        ea_t nxt = get_item_end(cur);
                        if (nxt == BADADDR || nxt <= cur) break;
                        cur = nxt;
                    }
                    block_obj["instructions"] = insns;
                }

                blocks_arr.push_back(std::move(block_obj));
            }
        });

        if (!found_fn) {
            return tools::utils::MakeToolErrorJson(
                id,
                "No function found containing address " + tools::utils::FormatAddress(start_ea),
                "function_not_found"
            );
        }

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["address"] = tools::utils::FormatAddress(fn_start);
        res["name"] = fn_name;
        if (!demangled_str.empty()) {
            res["demangled"] = demangled_str;
        }
        res["block_count"] = blocks_arr.size();
        if (blocks_truncated) {
            res["total_block_count"] = total_blocks;
            res["blocks_truncated"] = true;
        }
        res["edge_count"] = total_edges;
        res["cyclomatic_complexity"] = cyclomatic_complexity;
        res["blocks"] = blocks_arr;
        if (instructions_truncated) {
            res["instruction_count"] = instruction_count;
            res["instructions_truncated"] = true;
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiAnalysis::XrefQuery(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t target_ea = tools::utils::GetAddressArg(args, "addr");

        if (target_ea == BADADDR) {
            std::string raw = tools::utils::GetStringArg(args, "addr");
            std::string msg = "Parameter 'addr' could not be resolved";
            if (!raw.empty()) msg += ": " + raw;
            return tools::utils::MakeToolErrorJson(id, msg, "invalid_addr");
        }

        std::string direction = tools::utils::GetStringArg(args, "direction", "to");
        std::string type_filter = tools::utils::GetStringArg(args, "type", "all");
        type_filter = mcp::LowerAscii(std::move(type_filter));
        if (direction != "to" && direction != "from" && direction != "both")
            return tools::utils::MakeToolErrorJson(id, "Direction must be 'to', 'from', or 'both'", "invalid_direction");
        if (type_filter != "all" && type_filter != "*" && type_filter != "code" && type_filter != "data"
            && type_filter != "call" && type_filter != "jump" && type_filter != "read" && type_filter != "write" && type_filter != "offset")
            return tools::utils::MakeToolErrorJson(id, "Unsupported xref type: " + type_filter, "invalid_xref_type");

        bool include_flow = tools::utils::GetBoolArg(args, "include_flow", false);

        size_t offset = 0;
        const std::string cursor_str = tools::utils::GetStringArg(args, "cursor");
        if (!cursor_str.empty()) {
            try {
                if (cursor_str.find_first_not_of("0123456789") != std::string::npos) throw std::invalid_argument("cursor");
                size_t consumed = 0;
                const unsigned long long parsed = std::stoull(cursor_str, &consumed, 10);
                if (consumed != cursor_str.size() || parsed > std::numeric_limits<size_t>::max()) throw std::invalid_argument("cursor");
                offset = static_cast<size_t>(parsed);
            } catch (...) {
                return tools::utils::MakeToolErrorJson(id, "Cursor must be a non-negative integer offset", "invalid_cursor");
            }
        }

        size_t count = 100;
        if (args.contains("count")) {
            const auto& count_arg = args["count"];
            if (!count_arg.is_number_integer()) {
                return tools::utils::MakeToolErrorJson(id, "Count must be an integer from 1 to 2000", "invalid_count");
            }
            if (count_arg.is_number_unsigned()) {
                const uint64_t parsed = count_arg.get<uint64_t>();
                if (parsed < 1 || parsed > 2000)
                    return tools::utils::MakeToolErrorJson(id, "Count must be an integer from 1 to 2000", "invalid_count");
                count = static_cast<size_t>(parsed);
            } else {
                const int64_t parsed = count_arg.get<int64_t>();
                if (parsed < 1 || parsed > 2000)
                    return tools::utils::MakeToolErrorJson(id, "Count must be an integer from 1 to 2000", "invalid_count");
                count = static_cast<size_t>(parsed);
            }
        }

        std::vector<nlohmann::ordered_json> paged_xrefs;
        size_t total_matches = 0;
        auto append_xref = [&](nlohmann::ordered_json&& item) {
            if (total_matches >= offset && paged_xrefs.size() < count)
                paged_xrefs.push_back(std::move(item));
            ++total_matches;
        };
        std::string target_name;
        std::string target_demangled;

        sync::SyncRead([&]() {
            qstring t_name;
            get_ea_name(&t_name, target_ea);
            if (!t_name.empty()) {
                target_name = tools::utils::SanitizeUtf8(t_name.c_str());
                target_demangled = tools::utils::Demangle(target_name);
            } else {
                func_t* fn = get_func(target_ea);
                if (fn) {
                    qstring fn_buf;
                    get_func_name(&fn_buf, fn->start_ea);
                    target_name = tools::utils::SanitizeUtf8(fn_buf.c_str());
                    target_demangled = tools::utils::Demangle(target_name);
                }
            }

            if (direction == "to" || direction == "both") {
                xrefblk_t xb;
                for (bool ok = xb.first_to(target_ea, XREF_ALL); ok; ok = xb.next_to()) {
                    sync::Checkpoint();
                    if (!include_flow && xb.iscode && (xb.type & XREF_MASK) == fl_F) continue;

                    std::string type_str = GetXrefTypeString(xb);
                    if (!MatchXrefType(xb, type_filter, type_str)) continue;

                    nlohmann::ordered_json item;
                    item["direction"] = "to";
                    item["from"] = tools::utils::FormatAddress(xb.from);
                    item["to"] = tools::utils::FormatAddress(target_ea);
                    item["type"] = type_str;
                    if ((xb.type & XREF_USER) != 0) {
                        item["user"] = true;
                    }

                    qstring from_name;
                    get_ea_name(&from_name, xb.from);
                    if (!from_name.empty()) {
                        std::string raw_name = tools::utils::SanitizeUtf8(from_name.c_str());
                        item["from_name"] = raw_name;
                        std::string dem = tools::utils::Demangle(raw_name);
                        if (!dem.empty()) {
                            item["demangled"] = dem;
                        }
                    }

                    func_t* fn = get_func(xb.from);
                    if (fn) {
                        qstring fn_buf;
                        get_func_name(&fn_buf, fn->start_ea);
                        std::string fn_raw = tools::utils::SanitizeUtf8(fn_buf.c_str());
                        item["function"] = fn_raw;
                        std::string dem = tools::utils::Demangle(fn_raw);
                        if (!dem.empty()) {
                            item["function_demangled"] = dem;
                        }
                        item["caller_offset"] = tools::utils::FormatAddress(xb.from - fn->start_ea);
                    }

                    if (xb.iscode) {
                        std::string dis = CleanDisasmLine(xb.from);
                        if (!dis.empty()) {
                            item["disasm"] = dis;
                        }

                        // Extract preceding 2-3 instructions (argument preparation context)
                        std::vector<std::string> ctx_insns;
                        ea_t prev_ea = xb.from;
                        for (int step = 0; tools::utils::GetBoolArg(args, "context", false) && step < 3; ++step) {
                            sync::Checkpoint();
                            insn_t prev_insn;
                            prev_ea = decode_prev_insn(&prev_insn, prev_ea);
                            if (prev_ea == BADADDR || !is_mapped(prev_ea)) break;
                            if (fn && prev_ea < fn->start_ea) break;
                            std::string prev_dis = CleanDisasmLine(prev_ea);
                            if (!prev_dis.empty()) {
                                ctx_insns.insert(ctx_insns.begin(), tools::utils::FormatAddress(prev_ea) + ":  " + prev_dis);
                            }
                        }
                        if (!ctx_insns.empty()) {
                            item["context_asm"] = ctx_insns;
                        }
                    }

                    append_xref(std::move(item));
                }
            }

            if (direction == "from" || direction == "both") {
                xrefblk_t xb;
                for (bool ok = xb.first_from(target_ea, XREF_ALL); ok; ok = xb.next_from()) {
                    sync::Checkpoint();
                    if (!include_flow && xb.iscode && (xb.type & XREF_MASK) == fl_F) continue;

                    std::string type_str = GetXrefTypeString(xb);
                    if (!MatchXrefType(xb, type_filter, type_str)) continue;

                    nlohmann::ordered_json item;
                    item["direction"] = "from";
                    item["from"] = tools::utils::FormatAddress(target_ea);
                    item["to"] = tools::utils::FormatAddress(xb.to);
                    item["type"] = type_str;
                    if ((xb.type & XREF_USER) != 0) {
                        item["user"] = true;
                    }

                    qstring to_name;
                    get_ea_name(&to_name, xb.to);
                    if (!to_name.empty()) {
                        std::string raw_name = tools::utils::SanitizeUtf8(to_name.c_str());
                        item["to_name"] = raw_name;
                        std::string dem = tools::utils::Demangle(raw_name);
                        if (!dem.empty()) {
                            item["demangled"] = dem;
                        }
                    }

                    func_t* fn = get_func(xb.to);
                    if (fn) {
                        qstring fn_buf;
                        get_func_name(&fn_buf, fn->start_ea);
                        std::string fn_raw = tools::utils::SanitizeUtf8(fn_buf.c_str());
                        item["function"] = fn_raw;
                        std::string dem = tools::utils::Demangle(fn_raw);
                        if (!dem.empty()) {
                            item["function_demangled"] = dem;
                        }
                        item["callee_func"] = fn_raw;
                        item["callee_offset"] = tools::utils::FormatAddress(xb.to - fn->start_ea);
                    }

                    if (xb.iscode) {
                        std::string dis = CleanDisasmLine(xb.from);
                        if (!dis.empty()) {
                            item["disasm"] = dis;
                        }
                    }

                    append_xref(std::move(item));
                }
            }
        });

        const bool has_next_page = !paged_xrefs.empty() && offset + paged_xrefs.size() < total_matches;

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["target"] = tools::utils::FormatAddress(target_ea);
        if (!target_name.empty()) {
            res["target_name"] = target_name;
            if (!target_demangled.empty()) {
                res["target_demangled"] = target_demangled;
            }
        }
        res["total"] = total_matches;

        res["xrefs"] = paged_xrefs;
        if (has_next_page) res["next_cursor"] = std::to_string(offset + paged_xrefs.size());
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiAnalysis::Callgraph(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t root_ea = tools::utils::GetAddressArg(args, "addr");

        if (root_ea == BADADDR) {
            std::string raw = tools::utils::GetStringArg(args, "addr", tools::utils::GetStringArg(args, "root"));
            std::string msg = "Parameter 'addr' could not be resolved";
            if (!raw.empty()) msg += ": " + raw;
            return tools::utils::MakeToolErrorJson(id, msg, "invalid_addr");
        }

        int max_depth = static_cast<int>(tools::utils::GetIntArg(args, "depth", 3));
        if (max_depth <= 0) max_depth = 3;
        if (max_depth > 10) max_depth = 10;

        int max_nodes = static_cast<int>(tools::utils::GetIntArg(args, "max_nodes", 500));
        if (max_nodes <= 0) max_nodes = 500;
        if (max_nodes > 2000) max_nodes = 2000;

        std::string direction = tools::utils::GetStringArg(args, "direction", "callees");
        direction = mcp::LowerAscii(std::move(direction));
        if (direction != "callees" && direction != "callers" && direction != "both") {
            return tools::utils::MakeToolErrorJson(id, "Direction must be 'callees', 'callers', or 'both'", "invalid_direction");
        }

        bool include_nodes = tools::utils::GetBoolArg(args, "include_nodes", true);

        struct EdgeKey {
            ea_t caller;
            ea_t callee;
            bool operator<(const EdgeKey& o) const {
                if (caller != o.caller) return caller < o.caller;
                return callee < o.callee;
            }
        };

        struct EdgeInfo {
            std::string caller_name;
            std::string caller_demangled;
            std::string callee_name;
            std::string callee_demangled;
            int depth = 0;
            std::vector<std::string> call_sites;
        };

        struct NodeInfo {
            ea_t ea = BADADDR;
            std::string name;
            std::string demangled;
            bool is_root = false;
            bool is_import = false;
        };

        std::map<EdgeKey, EdgeInfo> edge_map;
        std::map<ea_t, NodeInfo> node_map;
        constexpr size_t MAX_GRAPH_EDGES = 4096;
        constexpr size_t MAX_CALL_SITES_PER_EDGE = 16;
        constexpr size_t MAX_GRAPH_STEPS = 200000;
        size_t graph_steps = 0;
        bool graph_truncated = false;
        ea_t root_fn_ea = BADADDR;
        std::string root_name;
        std::string root_demangled;
        bool found_fn = false;

        sync::SyncRead([&]() {
            func_t* root_fn = get_func(root_ea);
            if (!root_fn) return;

            found_fn = true;
            root_fn_ea = root_fn->start_ea;
            root_name = GetSymbolName(root_fn_ea);
            root_demangled = tools::utils::Demangle(root_name);

            node_map[root_fn_ea] = NodeInfo{root_fn_ea, root_name, root_demangled, true, false};

            struct QItem {
                ea_t ea;
                int depth;
            };

            auto traverse_callees = [&]() {
                std::queue<QItem> q;
                std::set<ea_t> visited_callees;

                q.push({root_fn_ea, 0});
                visited_callees.insert(root_fn_ea);

                while (!q.empty() && node_map.size() < static_cast<size_t>(max_nodes) && !graph_truncated) {
                    sync::Checkpoint();
                    auto item = q.front();
                    q.pop();

                    if (item.depth >= max_depth) continue;

                    func_t* fn = get_func(item.ea);
                    if (!fn) continue;

                    std::string caller_name = GetSymbolName(fn->start_ea);
                    std::string caller_dem = tools::utils::Demangle(caller_name);

                    func_item_iterator_t fii;
                    for (bool ok = fii.set(fn, fn->start_ea); ok && !graph_truncated; ok = fii.next_head()) {
                        sync::Checkpoint();
                        ea_t cur = fii.current();
                        xrefblk_t xb;
                        for (bool xok = xb.first_from(cur, XREF_ALL); xok && !graph_truncated; xok = xb.next_from()) {
                            sync::Checkpoint();
                            if (++graph_steps > MAX_GRAPH_STEPS) { graph_truncated = true; break; }
                            uint8_t base_type = xb.type & XREF_MASK;
                            if (xb.iscode && (base_type == fl_CN || base_type == fl_CF)) {
                                ea_t target = xb.to;
                                std::string target_name = GetSymbolName(target);
                                std::string target_dem = tools::utils::Demangle(target_name);

                                bool target_is_import = false;
                                segment_t* seg = getseg(target);
                                if (seg) {
                                    qstring sname;
                                    get_segm_name(&sname, seg);
                                    if (sname == ".idata" || seg->type == SEG_XTRN) {
                                        target_is_import = true;
                                    }
                                }

                                if (node_map.find(target) == node_map.end() && node_map.size() >= static_cast<size_t>(max_nodes)) {
                                    graph_truncated = true;
                                    break;
                                }
                                if (node_map.find(target) == node_map.end()) {
                                    node_map[target] = NodeInfo{target, target_name, target_dem, false, target_is_import};
                                }

                                EdgeKey key{fn->start_ea, target};
                                auto it = edge_map.find(key);
                                if (it == edge_map.end()) {
                                    if (edge_map.size() >= MAX_GRAPH_EDGES) { graph_truncated = true; break; }
                                    EdgeInfo einfo;
                                    einfo.caller_name = caller_name;
                                    einfo.caller_demangled = caller_dem;
                                    einfo.callee_name = target_name;
                                    einfo.callee_demangled = target_dem;
                                    einfo.depth = item.depth + 1;
                                    einfo.call_sites.push_back(tools::utils::FormatAddress(cur));
                                    edge_map[key] = std::move(einfo);
                                } else {
                                    if (it->second.call_sites.size() < MAX_CALL_SITES_PER_EDGE)
                                        it->second.call_sites.push_back(tools::utils::FormatAddress(cur));
                                }

                                if (!target_is_import && visited_callees.find(target) == visited_callees.end()) {
                                    visited_callees.insert(target);
                                    q.push({target, item.depth + 1});
                                }
                            }
                        }
                    }
                }
                if (!q.empty() && node_map.size() >= static_cast<size_t>(max_nodes)) graph_truncated = true;
            };

            auto traverse_callers = [&]() {
                std::queue<QItem> q;
                std::set<ea_t> visited_callers;

                q.push({root_fn_ea, 0});
                visited_callers.insert(root_fn_ea);

                while (!q.empty() && node_map.size() < static_cast<size_t>(max_nodes) && !graph_truncated) {
                    sync::Checkpoint();
                    auto item = q.front();
                    q.pop();

                    if (item.depth >= max_depth) continue;

                    std::string callee_name = GetSymbolName(item.ea);
                    std::string callee_dem = tools::utils::Demangle(callee_name);

                    xrefblk_t xb;
                    for (bool ok = xb.first_to(item.ea, XREF_ALL); ok && !graph_truncated; ok = xb.next_to()) {
                        sync::Checkpoint();
                        if (++graph_steps > MAX_GRAPH_STEPS) { graph_truncated = true; break; }
                        uint8_t base_type = xb.type & XREF_MASK;
                        if (xb.iscode && (base_type == fl_CN || base_type == fl_CF)) {
                            func_t* caller_fn = get_func(xb.from);
                            if (!caller_fn) continue;
                            ea_t caller_ea = caller_fn->start_ea;

                            std::string caller_name = GetSymbolName(caller_ea);
                            std::string caller_dem = tools::utils::Demangle(caller_name);

                            if (node_map.find(caller_ea) == node_map.end() && node_map.size() >= static_cast<size_t>(max_nodes)) {
                                graph_truncated = true;
                                break;
                            }
                            if (node_map.find(caller_ea) == node_map.end()) {
                                node_map[caller_ea] = NodeInfo{caller_ea, caller_name, caller_dem, false, false};
                            }

                            EdgeKey key{caller_ea, item.ea};
                            auto it = edge_map.find(key);
                            if (it == edge_map.end()) {
                                if (edge_map.size() >= MAX_GRAPH_EDGES) { graph_truncated = true; break; }
                                EdgeInfo einfo;
                                einfo.caller_name = caller_name;
                                einfo.caller_demangled = caller_dem;
                                einfo.callee_name = callee_name;
                                einfo.callee_demangled = callee_dem;
                                einfo.depth = item.depth + 1;
                                einfo.call_sites.push_back(tools::utils::FormatAddress(xb.from));
                                edge_map[key] = std::move(einfo);
                            } else {
                                if (it->second.call_sites.size() < MAX_CALL_SITES_PER_EDGE)
                                    it->second.call_sites.push_back(tools::utils::FormatAddress(xb.from));
                            }

                            if (visited_callers.find(caller_ea) == visited_callers.end()) {
                                visited_callers.insert(caller_ea);
                                q.push({caller_ea, item.depth + 1});
                            }
                        }
                    }
                }
                if (!q.empty() && node_map.size() >= static_cast<size_t>(max_nodes)) graph_truncated = true;
            };

            if (direction == "callees" || direction == "both") {
                traverse_callees();
            }
            if (direction == "callers" || direction == "both") {
                traverse_callers();
            }
        });

        if (!found_fn) {
            return tools::utils::MakeToolErrorJson(
                id,
                "No function found containing address " + tools::utils::FormatAddress(root_ea),
                "function_not_found"
            );
        }

        nlohmann::json edges_arr = nlohmann::json::array();
        for (const auto& [ekey, einfo] : edge_map) {
            sync::Checkpoint();
            nlohmann::ordered_json eobj;
            if (!include_nodes) eobj["caller"] = einfo.caller_demangled.empty() ? einfo.caller_name : einfo.caller_demangled;
            eobj["caller_addr"] = tools::utils::FormatAddress(ekey.caller);
            if (!include_nodes) eobj["callee"] = einfo.callee_demangled.empty() ? einfo.callee_name : einfo.callee_demangled;
            eobj["callee_addr"] = tools::utils::FormatAddress(ekey.callee);
            eobj["depth"] = einfo.depth;
            eobj["call_sites"] = einfo.call_sites;
            edges_arr.push_back(std::move(eobj));
        }

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["root"] = tools::utils::FormatAddress(root_fn_ea);
        if (!include_nodes) {
            res["root_name"] = root_demangled.empty() ? root_name : root_demangled;
            res["node_count"] = node_map.size();
        }
        if (include_nodes) {
            nlohmann::json nodes_arr = nlohmann::json::array();
            for (const auto& [node_ea, ninfo] : node_map) {
                sync::Checkpoint();
                nlohmann::ordered_json nobj;
                nobj["address"] = tools::utils::FormatAddress(node_ea);
                nobj["name"] = ninfo.demangled.empty() ? ninfo.name : ninfo.demangled;
                if (ninfo.is_import) {
                    nobj["is_import"] = true;
                }
                nodes_arr.push_back(std::move(nobj));
            }
            res["nodes"] = nodes_arr;
        }
        res["edges"] = edges_arr;
        if (graph_truncated) res["truncated"] = true;
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiAnalysis::FindBytes(const nlohmann::json& id, const nlohmann::json& args) {
        std::string raw_pattern = tools::utils::GetStringArg(args, "pattern");
        if (raw_pattern.empty()) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'pattern' is required", "pattern_required");
        }
        if (raw_pattern.size() > 1024) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'pattern' must not exceed 1024 characters", "invalid_pattern");
        }

        std::string pattern_str;
        std::string sanitize_err;
        if (!SanitizePatternString(raw_pattern, pattern_str, sanitize_err)) {
            return tools::utils::MakeToolErrorJson(id, sanitize_err, "invalid_pattern");
        }

        ea_t cursor_ea = tools::utils::GetAddressArg(args, "cursor", BADADDR);
        if (args.contains("cursor") && cursor_ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Cursor is not a valid address", "invalid_cursor");
        }

        int64_t count_arg = 50;
        if (args.contains("count")) {
            const auto& count_value = args["count"];
            if (count_value.is_number_unsigned()) {
                const uint64_t value = count_value.get<uint64_t>();
                if (value > 1000) return tools::utils::MakeToolErrorJson(id, "count must be between 1 and 1000", "invalid_count");
                count_arg = static_cast<int64_t>(value);
            } else if (count_value.is_number_integer()) {
                count_arg = count_value.get<int64_t>();
            } else {
                return tools::utils::MakeToolErrorJson(id, "count must be an integer", "invalid_count");
            }
        }
        if (count_arg < 1 || count_arg > 1000)
            return tools::utils::MakeToolErrorJson(id, "count must be between 1 and 1000", "invalid_count");
        const size_t count = static_cast<size_t>(count_arg);

        ea_t start_scope = BADADDR;
        ea_t max_ea = BADADDR;
        std::string scope_error;

        std::string seg_name_arg = tools::utils::GetStringArg(args, "segment");
        ea_t fn_ea = tools::utils::GetAddressArg(args, "func");
        ea_t explicit_start = tools::utils::GetAddressArg(args, "start");
        ea_t explicit_end = tools::utils::GetAddressArg(args, "end");
        if (args.contains("segment") && args.contains("func"))
            return tools::utils::MakeToolErrorJson(id, "Specify either 'segment' or 'func' as the base scope", "conflicting_scope");
        if (args.contains("func") && fn_ea == BADADDR)
            return tools::utils::MakeToolErrorJson(id, "Function address or name could not be resolved", "invalid_function");
        if (args.contains("start") && explicit_start == BADADDR)
            return tools::utils::MakeToolErrorJson(id, "Start address could not be resolved", "invalid_start");
        if (args.contains("end") && explicit_end == BADADDR)
            return tools::utils::MakeToolErrorJson(id, "End address could not be resolved", "invalid_end");

        sync::SyncRead([&]() {
            if (!seg_name_arg.empty()) {
                segment_t* s = get_segm_by_name(seg_name_arg.c_str());
                if (s) {
                    start_scope = s->start_ea;
                    max_ea = s->end_ea;
                } else {
                    scope_error = "Segment '" + seg_name_arg + "' was not found";
                }
            } else if (fn_ea != BADADDR) {
                func_t* f = get_func(fn_ea);
                if (f) {
                    start_scope = f->start_ea;
                    max_ea = f->end_ea;
                } else {
                    scope_error = "Function target does not belong to a recognized function";
                }
            }

            if (start_scope == BADADDR) start_scope = inf_get_min_ea();
            if (max_ea == BADADDR) max_ea = inf_get_max_ea();
            const ea_t scope_start = start_scope;
            const ea_t scope_end = max_ea;
            if (explicit_start != BADADDR) {
                if (explicit_start < scope_start || explicit_start >= scope_end)
                    scope_error = "Start address lies outside the selected search scope";
                else start_scope = explicit_start;
            }
            if (explicit_end != BADADDR) {
                if (explicit_end > scope_end || explicit_end <= scope_start)
                    scope_error = "End address lies outside the selected search scope";
                else max_ea = explicit_end;
            }
            if (start_scope >= max_ea) scope_error = "Search range must have start < end";
            if (cursor_ea != BADADDR) {
                if (cursor_ea < start_scope || cursor_ea >= max_ea)
                    scope_error = "Cursor lies outside the selected search range";
                else start_scope = cursor_ea;
            }
        });
        if (!scope_error.empty()) return tools::utils::MakeToolErrorJson(id, scope_error, "invalid_scope");

        nlohmann::ordered_json matches = nlohmann::ordered_json::array();
        ea_t next_cursor_ea = BADADDR;
        std::string parse_err;

        sync::SyncRead([&]() {
            compiled_binpat_vec_t bbv;
            qstring errbuf;
            if (!parse_binpat_str(&bbv, start_scope, pattern_str.c_str(), 16, PBSENC_DEF1BPU, &errbuf)) {
                parse_err = errbuf.empty() ? "Failed to parse binary pattern string" : errbuf.c_str();
                return;
            }

            ea_t search_cur = start_scope;
            size_t fetched = 0;

            while (search_cur != BADADDR && search_cur < max_ea && fetched < count) {
                sync::Checkpoint();
                ea_t match_ea = bin_search(search_cur, max_ea, bbv, BIN_SEARCH_FORWARD | BIN_SEARCH_NOBREAK | BIN_SEARCH_NOSHOW);
                if (match_ea == BADADDR) break;

                nlohmann::ordered_json item;
                item["address"] = tools::utils::FormatAddress(match_ea);

                segment_t* seg = getseg(match_ea);
                if (seg) {
                    qstring seg_name;
                    get_segm_name(&seg_name, seg);
                    item["segment"] = seg_name.c_str();
                }

                func_t* fn = get_func(match_ea);
                if (fn) {
                    qstring fn_name;
                    get_func_name(&fn_name, fn->start_ea);
                    item["function"] = fn_name.c_str();
                }

                qstring sym;
                if (get_name(&sym, match_ea)) {
                    item["symbol"] = sym.c_str();
                }

                matches.push_back(std::move(item));
                fetched++;
                if (match_ea == BADADDR - 1) {
                    next_cursor_ea = BADADDR;
                    break;
                }
                search_cur = match_ea + 1;
            }
            if (fetched == count && search_cur != BADADDR && search_cur < max_ea) {
                sync::Checkpoint();
                if (bin_search(search_cur, max_ea, bbv, BIN_SEARCH_FORWARD | BIN_SEARCH_NOBREAK | BIN_SEARCH_NOSHOW) != BADADDR)
                    next_cursor_ea = search_cur;
            }
        });

        if (!parse_err.empty()) {
            return tools::utils::MakeToolErrorJson(id, parse_err, "invalid_pattern");
        }

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["pattern"] = pattern_str;
        res["matches_count"] = matches.size();
        res["matches"] = matches;

        if (next_cursor_ea != BADADDR) {
            res["next_cursor"] = tools::utils::FormatAddress(next_cursor_ea);
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiAnalysis::InsnQuery(const nlohmann::json& id, const nlohmann::json& args) {
        std::string mnem_filter = tools::utils::GetStringArg(args, "mnemonic", "*");
        if (mnem_filter.empty()) mnem_filter = "*";

        std::string query_filter = tools::utils::GetStringArg(args, "query");
        if (mnem_filter.size() > 1024 || query_filter.size() > 1024)
            return tools::utils::MakeToolErrorJson(id, "mnemonic and query filters must not exceed 1024 characters", "invalid_filter");

        ea_t fn_ea = tools::utils::GetAddressArg(args, "func");

        int64_t count_arg = 50;
        if (args.contains("count")) {
            const auto& value = args["count"];
            if (value.is_number_unsigned()) {
                const uint64_t parsed = value.get<uint64_t>();
                if (parsed > 1000) return tools::utils::MakeToolErrorJson(id, "count must not exceed 1000", "invalid_count");
                count_arg = static_cast<int64_t>(parsed);
            } else if (value.is_number_integer()) {
                count_arg = value.get<int64_t>();
            } else {
                return tools::utils::MakeToolErrorJson(id, "count must be an integer", "invalid_count");
            }
        }
        if (count_arg < 0 || count_arg > 1000)
            return tools::utils::MakeToolErrorJson(id, "count must be between 0 and 1000", "invalid_count");
        const size_t count = count_arg == 0 ? 50 : static_cast<size_t>(count_arg);

        int64_t max_scan_arg = 250000;
        if (args.contains("max_scan")) {
            const auto& value = args["max_scan"];
            if (value.is_number_unsigned()) {
                const uint64_t parsed = value.get<uint64_t>();
                if (parsed > 1000000) return tools::utils::MakeToolErrorJson(id, "max_scan must not exceed 1000000", "invalid_max_scan");
                max_scan_arg = static_cast<int64_t>(parsed);
            } else if (value.is_number_integer()) {
                max_scan_arg = value.get<int64_t>();
            } else {
                return tools::utils::MakeToolErrorJson(id, "max_scan must be an integer", "invalid_max_scan");
            }
        }
        if (max_scan_arg < 0 || max_scan_arg > 1000000)
            return tools::utils::MakeToolErrorJson(id, "max_scan must be between 0 and 1000000", "invalid_max_scan");
        const size_t max_scan = max_scan_arg == 0 ? 250000 : static_cast<size_t>(max_scan_arg);

        ea_t cursor_ea = tools::utils::GetAddressArg(args, "cursor", BADADDR);
        if (args.contains("cursor") && cursor_ea == BADADDR)
            return tools::utils::MakeToolErrorJson(id, "Cursor is not a valid address", "invalid_cursor");
        std::string seg_name_arg = tools::utils::GetStringArg(args, "segment");
        ea_t explicit_start = tools::utils::GetAddressArg(args, "start");
        ea_t explicit_end = tools::utils::GetAddressArg(args, "end");
        if (args.contains("segment") && args.contains("func"))
            return tools::utils::MakeToolErrorJson(id, "Specify either 'segment' or 'func' as the base scope", "conflicting_scope");
        if (args.contains("func") && fn_ea == BADADDR)
            return tools::utils::MakeToolErrorJson(id, "Function address or name could not be resolved", "invalid_function");
        if (args.contains("start") && explicit_start == BADADDR)
            return tools::utils::MakeToolErrorJson(id, "Start address could not be resolved", "invalid_start");
        if (args.contains("end") && explicit_end == BADADDR)
            return tools::utils::MakeToolErrorJson(id, "End address could not be resolved", "invalid_end");

        ea_t start_scope = BADADDR;
        ea_t max_ea = BADADDR;
        bool executable_only = false;
        std::string scope_error;

        sync::SyncRead([&]() {
            if (fn_ea != BADADDR) {
                func_t* fn = get_func(fn_ea);
                if (fn) {
                    start_scope = fn->start_ea;
                    max_ea = fn->end_ea;
                } else scope_error = "Target does not belong to a recognized function";
            } else if (!seg_name_arg.empty()) {
                segment_t* s = get_segm_by_name(seg_name_arg.c_str());
                if (s) {
                    start_scope = s->start_ea;
                    max_ea = s->end_ea;
                } else scope_error = "Segment '" + seg_name_arg + "' was not found";
            } else if (explicit_start != BADADDR || explicit_end != BADADDR) {
                start_scope = (explicit_start != BADADDR) ? explicit_start : inf_get_min_ea();
                max_ea = (explicit_end != BADADDR) ? explicit_end : inf_get_max_ea();
            } else {
                // Default global: scan all executable segments
                executable_only = true;
                for (int i = 0; i < get_segm_qty(); ++i) {
                    sync::Checkpoint();
                    segment_t* s = getnseg(i);
                    if (s && (s->perm & SEGPERM_EXEC)) {
                        if (start_scope == BADADDR) start_scope = s->start_ea;
                        max_ea = s->end_ea;
                    }
                }
                if (start_scope == BADADDR) {
                    scope_error = "No executable segments are available to scan";
                }
            }

            if (fn_ea != BADADDR || !seg_name_arg.empty()) {
                const ea_t base_start = start_scope;
                const ea_t base_end = max_ea;
                if (explicit_start != BADADDR) {
                    if (explicit_start < base_start || explicit_start >= base_end)
                        scope_error = "Start address lies outside the selected search scope";
                    else start_scope = explicit_start;
                }
                if (explicit_end != BADADDR) {
                    if (explicit_end > base_end || explicit_end <= base_start)
                        scope_error = "End address lies outside the selected search scope";
                    else max_ea = explicit_end;
                }
            }

            if (cursor_ea != BADADDR) {
                segment_t* cursor_seg = getseg(cursor_ea);
                if (cursor_ea < start_scope || cursor_ea >= max_ea ||
                    (executable_only && (!cursor_seg || (cursor_seg->perm & SEGPERM_EXEC) == 0)))
                    scope_error = "Cursor lies outside the selected scan range";
                else start_scope = cursor_ea;
            }
            if (start_scope != BADADDR && start_scope >= max_ea) scope_error = "Search range must have start < end";
        });
        if (!scope_error.empty()) return tools::utils::MakeToolErrorJson(id, scope_error, "invalid_scope");

        nlohmann::ordered_json insns_arr = nlohmann::ordered_json::array();
        ea_t next_cursor_ea = BADADDR;

        sync::SyncRead([&]() {
            ea_t cur = start_scope;
            size_t visited_heads = 0;
            size_t fetched = 0;

            while (cur != BADADDR && cur < max_ea && fetched < count && visited_heads < max_scan) {
                sync::Checkpoint();
                if (executable_only) {
                    segment_t* current_seg = getseg(cur);
                    if (!current_seg || (current_seg->perm & SEGPERM_EXEC) == 0) {
                        segment_t* next_seg = current_seg ? get_next_seg(current_seg->start_ea) : get_next_seg(cur);
                        if (!next_seg || next_seg->start_ea >= max_ea) { cur = BADADDR; break; }
                        cur = next_seg->start_ea;
                        continue;
                    }
                }
                ++visited_heads;
                flags_t flags = get_flags(cur);
                if (is_code(flags)) {
                    qstring mnem;
                    print_insn_mnem(&mnem, cur);

                    bool mnem_match = (mnem_filter == "*") ||
                                      tools::utils::PatternMatch(mnem.c_str(), mnem_filter, false);

                    if (mnem_match) {
                        std::string disasm = CleanDisasmLine(cur);
                        bool query_match = query_filter.empty() || query_filter == "*" ||
                                           tools::utils::PatternMatch(disasm, query_filter, false);

                        if (query_match) {
                            nlohmann::ordered_json item;
                            item["address"] = tools::utils::FormatAddress(cur);
                            item["mnemonic"] = mnem.c_str();
                            item["disasm"] = disasm;

                            func_t* fn = get_func(cur);
                            if (fn) {
                                qstring fn_name;
                                get_func_name(&fn_name, fn->start_ea);
                                item["function"] = fn_name.c_str();
                            }

                            insns_arr.push_back(std::move(item));
                            fetched++;
                        }
                    }
                }

                ea_t next = next_head(cur, max_ea);
                if (next == BADADDR || next <= cur) {
                    if (executable_only) {
                        segment_t* current_seg = getseg(cur);
                        segment_t* next_seg = current_seg ? get_next_seg(current_seg->start_ea) : get_next_seg(cur);
                        if (next_seg && next_seg->start_ea < max_ea) {
                            cur = next_seg->start_ea;
                            continue;
                        }
                    }
                    break;
                }
                cur = next;
            }

            if (cur != BADADDR && cur < max_ea && (fetched >= count || visited_heads >= max_scan)) {
                next_cursor_ea = cur;
            }
        });

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["count"] = insns_arr.size();
        res["instructions"] = insns_arr;
        if (next_cursor_ea != BADADDR) {
            res["next_cursor"] = tools::utils::FormatAddress(next_cursor_ea);
        }

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

        size_t max_vtable_methods = static_cast<size_t>(tools::utils::GetIntArg(args, "max_vtable_methods", 64));
        if (max_vtable_methods == 0 || max_vtable_methods > 256) max_vtable_methods = 64;

        ea_t start_func_ea = BADADDR;
        ea_t target_func_ea = BADADDR;
        std::string start_func_name;
        std::string target_func_name;
        std::vector<std::vector<PathEdge>> all_found_paths;
        std::set<std::tuple<ea_t, ea_t, ea_t>> banned_edges; // (caller, callee, call_site)

        bool valid_start = false;
        bool valid_target = false;
        size_t edge_scan_steps = 0;
        size_t total_nodes_explored = 0;
        size_t total_edges_built = 0;
        bool graph_truncated = false;
        constexpr size_t kMaxPathEdgesPerNode = 4096;
        constexpr size_t kMaxPathEdgesPerSearch = 100000;

        sync::SyncRead([&]() {
            func_t* f_from = get_func(from_ea);
            if (!f_from && is_code(get_flags(from_ea))) {
                f_from = get_func(get_item_head(from_ea));
            }
            start_func_ea = f_from ? f_from->start_ea : from_ea;

            func_t* f_to = get_func(to_ea);
            if (!f_to && is_code(get_flags(to_ea))) {
                f_to = get_func(get_item_head(to_ea));
            }
            target_func_ea = f_to ? f_to->start_ea : to_ea;

            valid_start = (start_func_ea != BADADDR && is_mapped(start_func_ea));
            valid_target = (target_func_ea != BADADDR && is_mapped(target_func_ea));
            if (!valid_start || !valid_target) return;

            start_func_name = GetSymbolName(start_func_ea);
            target_func_name = GetSymbolName(target_func_ea);

            if (start_func_ea == target_func_ea) {
                all_found_paths.push_back({});
                return;
            }

            auto ReadLoadedPointer = [](ea_t address) -> ea_t {
                const size_t pointer_size = inf_is_64bit() ? 8 : 4;
                segment_t* seg = getseg(address);
                if (!seg || address > BADADDR - pointer_size || address + pointer_size > seg->end_ea)
                    return BADADDR;
                for (size_t i = 0; i < pointer_size; ++i) {
                    sync::Checkpoint();
                    if (!is_loaded(address + i)) return BADADDR;
                }
                return inf_is_64bit() ? get_qword(address) : static_cast<ea_t>(get_dword(address));
            };

            auto get_out_edges = [&](ea_t caller_ea) -> std::vector<PathEdge> {
                uint64_t cur_gen = cache::CurrentGeneration();
                std::vector<PathEdge> cached;
                if (FunctionEdgeCache::Instance().GetOut(caller_ea, cur_gen, cached)) {
                    return cached;
                }

                std::vector<PathEdge> edges;
                func_t* fn = get_func(caller_ea);
                if (!fn) return edges;

                std::unordered_map<ea_t, PathEdge> unique_edges;
                auto add_edge = [&](PathEdge&& e) {
                    auto it = unique_edges.find(e.callee_start_ea);
                    if (it == unique_edges.end()) {
                        if (unique_edges.size() >= kMaxPathEdgesPerNode || total_edges_built >= kMaxPathEdgesPerSearch) {
                            graph_truncated = true;
                            return;
                        }
                        ++total_edges_built;
                        unique_edges[e.callee_start_ea] = std::move(e);
                    } else {
                        if (it->second.is_indirect && !e.is_indirect) {
                            it->second = std::move(e);
                        }
                    }
                };

                size_t ptr_size = inf_is_64bit() ? 8 : 4;

                func_item_iterator_t fii;
                for (bool ok = fii.set(fn); ok && !graph_truncated; ok = fii.next_code()) {
                    sync::Checkpoint();
                    if (++edge_scan_steps > budget) { graph_truncated = true; break; }
                    ea_t cur = fii.current();
                    xrefblk_t xb;
                    for (bool xok = xb.first_from(cur, XREF_ALL); xok && !graph_truncated; xok = xb.next_from()) {
                        sync::Checkpoint();
                        if (++edge_scan_steps > budget) { graph_truncated = true; break; }
                        uint8_t base_type = xb.type & XREF_MASK;
                        if (xb.iscode) {
                            bool is_call = (base_type == fl_CN || base_type == fl_CF);
                            bool is_tail = (base_type == fl_JN || base_type == fl_JF);
                            if (is_call || is_tail) {
                                ea_t callee_ea = xb.to;
                                func_t* callee = get_func(callee_ea);
                                ea_t target_start = callee ? callee->start_ea : callee_ea;
                                if (target_start != fn->start_ea && (!is_tail || target_start == callee_ea || callee_ea == target_func_ea)) {
                                    bool thunk = callee ? ((callee->flags & FUNC_THUNK) != 0) : false;
                                    PathEdge e;
                                    e.caller_start_ea = fn->start_ea;
                                    e.call_site_ea = cur;
                                    e.callee_start_ea = target_start;
                                    e.is_thunk = thunk;
                                    e.is_tail_call = is_tail;
                                    e.edge_type = is_tail ? "tail_call" : "call";
                                    add_edge(std::move(e));
                                }
                            }
                        } else if (xb.to != BADADDR && xb.to != 0 && is_mapped(xb.to)) {
                            ea_t ref_ea = xb.to;
                            func_t* ref_fn = get_func(ref_ea);
                            if (ref_fn && ref_fn->start_ea == ref_ea && ref_fn->start_ea != fn->start_ea) {
                                PathEdge e;
                                e.caller_start_ea = fn->start_ea;
                                e.call_site_ea = cur;
                                e.callee_start_ea = ref_fn->start_ea;
                                e.is_thunk = (ref_fn->flags & FUNC_THUNK) != 0;
                                e.is_indirect = true;
                                e.edge_type = "callback";
                                add_edge(std::move(e));
                            } else {
                                segment_t* ref_seg = getseg(ref_ea);
                                bool is_data_seg = (ref_seg && (ref_seg->perm & SEGPERM_EXEC) == 0);
                                if (is_data_seg) {
                                    size_t found_in_tbl = 0;
                                    for (size_t mi = 0; mi < max_vtable_methods; ++mi) {
                                        sync::Checkpoint();
                                        const size_t slot_offset = mi * ptr_size;
                                        if (ref_ea > BADADDR - slot_offset) break;
                                        ea_t slot_ea = ref_ea + slot_offset;
                                        ea_t ptr_val = ReadLoadedPointer(slot_ea);
                                        if (ptr_val == 0 || ptr_val == BADADDR || !is_mapped(ptr_val)) break;
                                        func_t* m_fn = get_func(ptr_val);
                                        if (!m_fn || m_fn->start_ea != ptr_val) break;

                                        found_in_tbl++;
                                        if (m_fn->start_ea != fn->start_ea) {
                                            PathEdge e;
                                            e.caller_start_ea = fn->start_ea;
                                            e.call_site_ea = cur;
                                            e.callee_start_ea = m_fn->start_ea;
                                            e.is_thunk = (m_fn->flags & FUNC_THUNK) != 0;
                                            e.is_indirect = true;
                                            std::string vtbl_sym = GetSymbolName(ref_ea);
                                            bool is_verified_vftable = (vtbl_sym.find("vftable") != std::string::npos ||
                                                                        vtbl_sym.find("vtable") != std::string::npos ||
                                                                        vtbl_sym.rfind("??_7", 0) == 0);
                                            e.edge_type = (found_in_tbl > 1 || mi > 0) ? (is_verified_vftable ? "vtable_verified" : "vtable_heuristic") : "indirect_ptr";
                                            e.vtable_ea = ref_ea;
                                            e.vtable_name = vtbl_sym;
                                            add_edge(std::move(e));
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Indirect call disassembly check (call [reg + disp] matching vtable methods)
                    insn_t insn;
                    if (decode_insn(&insn, cur) > 0 && is_call_insn(insn)) {
                        int disp = -1;
                        for (int op_i = 0; op_i < 6; ++op_i) {
                            sync::Checkpoint();
                            if (insn.ops[op_i].type == o_displ) {
                                disp = static_cast<int>(insn.ops[op_i].addr);
                                break;
                            } else if (insn.ops[op_i].type == o_phrase) {
                                disp = 0;
                                break;
                            }
                        }
                        if (disp >= 0) {
                            size_t target_idx = static_cast<size_t>(disp / ptr_size);
                            xrefblk_t fn_xb;
                            for (bool f_ok = fn_xb.first_to(fn->start_ea, XREF_ALL); f_ok && !graph_truncated; f_ok = fn_xb.next_to()) {
                                sync::Checkpoint();
                                if (++edge_scan_steps > budget) { graph_truncated = true; break; }
                                if (!fn_xb.iscode && fn_xb.from != BADADDR && is_mapped(fn_xb.from)) {
                                    ea_t vtbl_curr = fn_xb.from;
                                    for (int back_i = 0; back_i <= 64 && !graph_truncated; ++back_i) {
                                        sync::Checkpoint();
                                        if (++edge_scan_steps > budget) { graph_truncated = true; break; }
                                        if (back_i > 0) {
                                            if (vtbl_curr < ptr_size) break;
                                            ea_t prev_slot = vtbl_curr - ptr_size;
                                            ea_t pval = ReadLoadedPointer(prev_slot);
                                            if (pval == 0 || pval == BADADDR || !is_mapped(pval)) break;
                                            func_t* pfn = get_func(pval);
                                            if (!pfn || pfn->start_ea != pval) break;
                                            vtbl_curr = prev_slot;
                                        }
                                    }
                                    const size_t target_offset = target_idx * ptr_size;
                                    if (vtbl_curr > BADADDR - target_offset) continue;
                                    ea_t call_target_slot = vtbl_curr + target_offset;
                                    if (is_mapped(call_target_slot)) {
                                        ea_t target_fn_ea = ReadLoadedPointer(call_target_slot);
                                        if (target_fn_ea != 0 && target_fn_ea != BADADDR && is_mapped(target_fn_ea)) {
                                            func_t* tfn = get_func(target_fn_ea);
                                            if (tfn && tfn->start_ea == target_fn_ea && tfn->start_ea != fn->start_ea) {
                                                PathEdge e;
                                                e.caller_start_ea = fn->start_ea;
                                                e.call_site_ea = cur;
                                                e.callee_start_ea = tfn->start_ea;
                                                e.is_thunk = (tfn->flags & FUNC_THUNK) != 0;
                                                e.is_indirect = true;
                                                e.edge_type = "indirect_vcall";
                                                e.vtable_ea = vtbl_curr;
                                                e.vtable_name = GetSymbolName(vtbl_curr);
                                                add_edge(std::move(e));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                for (auto& pair : unique_edges) {
                    sync::Checkpoint();
                    edges.push_back(std::move(pair.second));
                }
                if (!graph_truncated) FunctionEdgeCache::Instance().PutOut(caller_ea, cur_gen, edges);
                return edges;
            };

            auto get_in_edges = [&](ea_t target_ea) -> std::vector<PathEdge> {
                uint64_t cur_gen = cache::CurrentGeneration();
                std::vector<PathEdge> cached;
                if (FunctionEdgeCache::Instance().GetIn(target_ea, cur_gen, cached)) {
                    return cached;
                }

                std::vector<PathEdge> edges;
                if (target_ea == BADADDR) return edges;

                std::unordered_map<ea_t, PathEdge> unique_edges;
                auto add_edge = [&](PathEdge&& e) {
                    auto it = unique_edges.find(e.caller_start_ea);
                    if (it == unique_edges.end()) {
                        if (unique_edges.size() >= kMaxPathEdgesPerNode || total_edges_built >= kMaxPathEdgesPerSearch) {
                            graph_truncated = true;
                            return;
                        }
                        ++total_edges_built;
                        unique_edges[e.caller_start_ea] = std::move(e);
                    } else {
                        if (it->second.is_indirect && !e.is_indirect) {
                            it->second = std::move(e);
                        }
                    }
                };

                size_t ptr_size = inf_is_64bit() ? 8 : 4;

                xrefblk_t xb;
                for (bool ok = xb.first_to(target_ea, XREF_ALL); ok && !graph_truncated; ok = xb.next_to()) {
                    sync::Checkpoint();
                    if (++edge_scan_steps > budget) { graph_truncated = true; break; }
                    uint8_t base_type = xb.type & XREF_MASK;
                    if (xb.iscode && (base_type == fl_CN || base_type == fl_CF || base_type == fl_JN || base_type == fl_JF)) {
                        func_t* caller = get_func(xb.from);
                        if (caller && caller->start_ea != target_ea) {
                            bool thunk = (caller->flags & FUNC_THUNK) != 0;
                            bool is_tail = (base_type == fl_JN || base_type == fl_JF);
                            PathEdge e;
                            e.caller_start_ea = caller->start_ea;
                            e.call_site_ea = xb.from;
                            e.callee_start_ea = target_ea;
                            e.is_thunk = thunk;
                            e.is_tail_call = is_tail;
                            e.edge_type = is_tail ? "tail_call" : "call";
                            add_edge(std::move(e));
                        }
                    } else if (!xb.iscode) {
                        func_t* caller = get_func(xb.from);
                        if (caller && caller->start_ea != target_ea) {
                            PathEdge e;
                            e.caller_start_ea = caller->start_ea;
                            e.call_site_ea = xb.from;
                            e.callee_start_ea = target_ea;
                            e.is_thunk = (caller->flags & FUNC_THUNK) != 0;
                            e.is_indirect = true;
                            e.edge_type = "callback";
                            add_edge(std::move(e));
                        } else if (xb.from != BADADDR && is_mapped(xb.from)) {
                            ea_t slot_ea = xb.from;
                            xrefblk_t xb_slot;
                            for (bool sok = xb_slot.first_to(slot_ea, XREF_ALL); sok && !graph_truncated; sok = xb_slot.next_to()) {
                                sync::Checkpoint();
                                if (++edge_scan_steps > budget) { graph_truncated = true; break; }
                                func_t* slot_caller = get_func(xb_slot.from);
                                if (slot_caller && slot_caller->start_ea != target_ea) {
                                    PathEdge e;
                                    e.caller_start_ea = slot_caller->start_ea;
                                    e.call_site_ea = xb_slot.from;
                                    e.callee_start_ea = target_ea;
                                    e.is_indirect = true;
                                    e.edge_type = "indirect_ptr";
                                    add_edge(std::move(e));
                                }
                            }

                            ea_t curr = slot_ea;
                            for (int step = 0; step <= 64 && !graph_truncated; ++step) {
                                sync::Checkpoint();
                                if (++edge_scan_steps > budget) { graph_truncated = true; break; }
                                xrefblk_t xb_tbl;
                                for (bool tok = xb_tbl.first_to(curr, XREF_ALL); tok && !graph_truncated; tok = xb_tbl.next_to()) {
                                    sync::Checkpoint();
                                    if (++edge_scan_steps > budget) { graph_truncated = true; break; }
                                    func_t* tbl_caller = get_func(xb_tbl.from);
                                    if (tbl_caller && tbl_caller->start_ea != target_ea) {
                                        PathEdge e;
                                        e.caller_start_ea = tbl_caller->start_ea;
                                        e.call_site_ea = xb_tbl.from;
                                        e.callee_start_ea = target_ea;
                                        e.is_indirect = true;
                                        std::string vtbl_sym = GetSymbolName(curr);
                                        bool is_verified_vftable = (vtbl_sym.find("vftable") != std::string::npos ||
                                                                    vtbl_sym.find("vtable") != std::string::npos ||
                                                                    vtbl_sym.rfind("??_7", 0) == 0);
                                        e.edge_type = is_verified_vftable ? "vtable_verified" : "vtable_heuristic";
                                        e.vtable_ea = curr;
                                        e.vtable_name = vtbl_sym;
                                        add_edge(std::move(e));
                                    }
                                }

                                if (curr < ptr_size) break;
                                ea_t prev = curr - ptr_size;
                                ea_t val = ReadLoadedPointer(prev);
                                if (val == 0 || val == BADADDR || !is_mapped(val)) break;
                                func_t* prev_fn = get_func(val);
                                if (!prev_fn || prev_fn->start_ea != val) break;
                                curr = prev;
                            }
                        }
                    }
                }

                for (auto& pair : unique_edges) {
                    sync::Checkpoint();
                    edges.push_back(std::move(pair.second));
                }
                if (!graph_truncated) FunctionEdgeCache::Instance().PutIn(target_ea, cur_gen, edges);
                return edges;
            };

            for (int path_idx = 0; path_idx < max_paths; ++path_idx) {
                sync::Checkpoint();
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
                while (!q_fwd.empty() && !q_bwd.empty() && total_nodes_explored < budget && !graph_truncated) {
                    sync::Checkpoint();
                    if (q_fwd.size() <= q_bwd.size()) {
                        ea_t cur_ea = q_fwd.front();
                        q_fwd.pop();
                        total_nodes_explored++;
                        int cur_d = dist_fwd[cur_ea];
                        if (cur_d >= max_depth) continue;

                        auto edges = get_out_edges(cur_ea);
                        for (const auto& e : edges) {
                            sync::Checkpoint();
                            if (banned_edges.count({e.caller_start_ea, e.callee_start_ea, e.call_site_ea})) continue;
                            auto [dist_it, inserted] = dist_fwd.emplace(e.callee_start_ea, cur_d + 1);
                            if (inserted) {
                                parent_fwd[e.callee_start_ea] = e;
                                q_fwd.push(e.callee_start_ea);
                            }
                            auto opposite = dist_bwd.find(e.callee_start_ea);
                            if (opposite != dist_bwd.end() && dist_it->second + opposite->second <= max_depth) {
                                intersection = e.callee_start_ea;
                                break;
                            }
                        }
                    } else {
                        ea_t cur_ea = q_bwd.front();
                        q_bwd.pop();
                        total_nodes_explored++;
                        int cur_d = dist_bwd[cur_ea];
                        if (cur_d >= max_depth) continue;

                        auto edges = get_in_edges(cur_ea);
                        for (const auto& e : edges) {
                            sync::Checkpoint();
                            if (banned_edges.count({e.caller_start_ea, e.callee_start_ea, e.call_site_ea})) continue;
                            auto [dist_it, inserted] = dist_bwd.emplace(e.caller_start_ea, cur_d + 1);
                            if (inserted) {
                                parent_bwd[e.caller_start_ea] = e;
                                q_bwd.push(e.caller_start_ea);
                            }
                            auto opposite = dist_fwd.find(e.caller_start_ea);
                            if (opposite != dist_fwd.end() && dist_it->second + opposite->second <= max_depth) {
                                intersection = e.caller_start_ea;
                                break;
                            }
                        }
                    }

                    if (intersection != BADADDR) break;
                }

                if (intersection == BADADDR) {
                    if (total_nodes_explored >= budget && !q_fwd.empty() && !q_bwd.empty()) graph_truncated = true;
                    break;
                }

                std::vector<PathEdge> path_left;
                ea_t trace_ea = intersection;
                while (trace_ea != start_func_ea && parent_fwd.count(trace_ea)) {
                    sync::Checkpoint();
                    const auto& e = parent_fwd[trace_ea];
                    path_left.push_back(e);
                    trace_ea = e.caller_start_ea;
                }
                std::reverse(path_left.begin(), path_left.end());

                std::vector<PathEdge> path_right;
                trace_ea = intersection;
                while (trace_ea != target_func_ea && parent_bwd.count(trace_ea)) {
                    sync::Checkpoint();
                    const auto& e = parent_bwd[trace_ea];
                    path_right.push_back(e);
                    trace_ea = e.callee_start_ea;
                }

                std::vector<PathEdge> full_path = std::move(path_left);
                full_path.insert(full_path.end(), path_right.begin(), path_right.end());

                if (full_path.empty() && start_func_ea != target_func_ea) break;

                for (auto& edge : full_path) {
                    sync::Checkpoint();
                    edge.caller_name = GetSymbolName(edge.caller_start_ea);
                    edge.caller_demangled = tools::utils::Demangle(edge.caller_name);
                    edge.callee_name = GetSymbolName(edge.callee_start_ea);
                    edge.callee_demangled = tools::utils::Demangle(edge.callee_name);
                    edge.disasm = CleanDisasmLine(edge.call_site_ea);
                }

                all_found_paths.push_back(full_path);

                if (!full_path.empty()) {
                    size_t mid_idx = full_path.size() / 2;
                    banned_edges.insert({full_path[mid_idx].caller_start_ea, full_path[mid_idx].callee_start_ea, full_path[mid_idx].call_site_ea});
                }
            }
        });

        if (!valid_start || !valid_target || start_func_ea == BADADDR || target_func_ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Could not locate valid symbols or code for given addresses", "function_not_found");
        }

        std::string from_demangled = tools::utils::Demangle(start_func_name);
        std::string to_demangled = tools::utils::Demangle(target_func_name);

        nlohmann::json paths_arr = nlohmann::json::array();
        for (const auto& path : all_found_paths) {
            sync::Checkpoint();
            nlohmann::json steps = nlohmann::json::array();
            for (size_t i = 0; i < path.size(); ++i) {
                sync::Checkpoint();
                const auto& edge = path[i];
                nlohmann::ordered_json step_obj;
                step_obj["step"] = i;
                step_obj["caller"] = edge.caller_name;
                if (!edge.caller_demangled.empty()) {
                    step_obj["caller_demangled"] = edge.caller_demangled;
                }
                step_obj["caller_addr"] = tools::utils::FormatAddress(edge.caller_start_ea);
                step_obj["call_site"] = tools::utils::FormatAddress(edge.call_site_ea);
                if (!edge.disasm.empty()) {
                    step_obj["disasm"] = edge.disasm;
                }
                step_obj["callee"] = edge.callee_name;
                if (!edge.callee_demangled.empty()) {
                    step_obj["callee_demangled"] = edge.callee_demangled;
                }
                step_obj["callee_addr"] = tools::utils::FormatAddress(edge.callee_start_ea);
                step_obj["edge_type"] = edge.edge_type;
                if (edge.is_indirect) {
                    step_obj["is_indirect"] = true;
                }
                if (edge.vtable_ea != BADADDR) {
                    step_obj["vtable_addr"] = tools::utils::FormatAddress(edge.vtable_ea);
                    if (!edge.vtable_name.empty()) {
                        step_obj["vtable_name"] = edge.vtable_name;
                    }
                }
                step_obj["is_thunk"] = edge.is_thunk;
                if (edge.is_tail_call) {
                    step_obj["is_tail_call"] = true;
                }
                steps.push_back(std::move(step_obj));
            }
            nlohmann::ordered_json path_obj;
            path_obj["length"] = path.size();
            path_obj["steps"] = steps;
            paths_arr.push_back(std::move(path_obj));
        }

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["found"] = !all_found_paths.empty();
        res["from"] = start_func_name;
        if (!from_demangled.empty()) {
            res["from_demangled"] = from_demangled;
        }
        res["from_addr"] = tools::utils::FormatAddress(start_func_ea);
        res["to"] = target_func_name;
        if (!to_demangled.empty()) {
            res["to_demangled"] = to_demangled;
        }
        res["to_addr"] = tools::utils::FormatAddress(target_func_ea);
        res["paths_count"] = paths_arr.size();
        res["paths"] = paths_arr;
        if (graph_truncated) res["truncated"] = true;
        return tools::utils::MakeToolSuccessJson(id, res);
    }
}
