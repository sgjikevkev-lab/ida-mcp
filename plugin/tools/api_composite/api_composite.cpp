#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <set>
#include <queue>
#include <charconv>
#include <array>
#include <cctype>
#include <deque>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "api_composite.h"
#include "tools/utils/utils.h"
#include "sync/sync.h"
#include "third_party/rax/rax_bridge.h"

#include <ida.hpp>
#include <bytes.hpp>
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
    namespace { constexpr size_t kMaxTraceCollectedItems = 50000; }
    namespace {
        constexpr size_t kMaxRaxFunctionInstructions = 2048;

        struct RaxFunctionSummary {
            size_t instructions_seen = 0;
            size_t analyzed = 0;
            size_t complete = 0;
            size_t partial = 0;
            size_t unsupported = 0;
            size_t invalid = 0;
            size_t mismatched = 0;
            size_t unavailable = 0;
            size_t memory_reads = 0;
            size_t memory_writes = 0;
            bool truncated = false;
            std::set<std::string> registers_read;
            std::set<std::string> registers_written;
            std::set<std::string> flags_read;
            std::set<std::string> flags_written;
            std::map<std::string, size_t> control_flow;

            void Analyze(ea_t ea) {
                sync::Checkpoint();
                if (!is_code(get_full_flags(ea))) return;
                if (++instructions_seen > kMaxRaxFunctionInstructions) {
                    truncated = true;
                    return;
                }
                const size_t item_size = get_item_size(ea);
                segment_t* segment = getseg(ea);
                if (item_size == 0 || item_size > 15 || !segment || ea > BADADDR - item_size ||
                    ea + item_size > segment->end_ea) {
                    ++unavailable;
                    return;
                }
                std::array<uint8_t, 15> bytes{};
                for (size_t i = 0; i < item_size; ++i) {
                    if (!is_loaded(ea + i)) {
                        ++unavailable;
                        return;
                    }
                    bytes[i] = static_cast<uint8_t>(get_byte(ea + i));
                }

                ++analyzed;
                nlohmann::ordered_json semantics = tools::rax::AnalyzeX64(ea, bytes.data(), item_size);
                const std::string status = semantics.value("status", std::string("error"));
                if (status == "complete") ++complete;
                else if (status == "partial") ++partial;
                else if (status == "unsupported") ++unsupported;
                else if (status == "invalid_instruction") ++invalid;
                else ++unavailable;

                if (semantics.contains("size") && semantics["size"].is_number() &&
                    semantics["size"].get<size_t>() != item_size) {
                    ++mismatched;
                    return;
                }
                if (semantics.contains("control_flow") && semantics["control_flow"].is_string())
                    ++control_flow[semantics["control_flow"].get<std::string>()];
                for (const auto& flag : semantics.value("flags_read", nlohmann::ordered_json::array()))
                    if (flag.is_string()) flags_read.insert(flag.get<std::string>());
                for (const auto& flag : semantics.value("flags_written", nlohmann::ordered_json::array()))
                    if (flag.is_string()) flags_written.insert(flag.get<std::string>());
                if (!semantics.contains("effects") || !semantics["effects"].is_array()) return;
                for (const auto& effect : semantics["effects"]) {
                    if (!effect.contains("access") || !effect["access"].is_array()) continue;
                    const bool reads = std::find(effect["access"].begin(), effect["access"].end(), "read") != effect["access"].end();
                    const bool writes = std::find(effect["access"].begin(), effect["access"].end(), "write") != effect["access"].end();
                    if (effect.value("kind", std::string()) == "register" && effect.contains("register") && effect["register"].is_string()) {
                        const auto reg = effect["register"].get<std::string>();
                        if (reads) registers_read.insert(reg);
                        if (writes) registers_written.insert(reg);
                    } else if (effect.value("kind", std::string()) == "memory") {
                        if (reads) ++memory_reads;
                        if (writes) ++memory_writes;
                    }
                }
            }

            nlohmann::ordered_json ToJson() const {
                auto string_array = [](const std::set<std::string>& values) {
                    nlohmann::ordered_json out = nlohmann::ordered_json::array();
                    for (const auto& value : values) out.push_back(value);
                    return out;
                };
                nlohmann::ordered_json flows = nlohmann::ordered_json::object();
                for (const auto& [kind, count] : control_flow) flows[kind] = count;
                return {
                    {"engine", "RAX"},
                    {"architecture", "x86-64"},
                    {"instructions_total", instructions_seen},
                    {"instructions_analyzed", analyzed},
                    {"instructions_complete", complete},
                    {"instructions_partial", partial},
                    {"instructions_unsupported", unsupported},
                    {"instructions_invalid", invalid},
                    {"instructions_unavailable", unavailable},
                    {"decode_mismatches", mismatched},
                    {"registers_read", string_array(registers_read)},
                    {"registers_written", string_array(registers_written)},
                    {"flags_read", string_array(flags_read)},
                    {"flags_written", string_array(flags_written)},
                    {"memory_reads", memory_reads},
                    {"memory_writes", memory_writes},
                    {"control_flow", std::move(flows)},
                    {"truncated", truncated}
                };
            }
        };

        std::string CanonicalX64Register(std::string name) {
            std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            if (name == "rflags" || name == "eflags" || name == "flags" ||
                name == "rip" || name == "eip")
                return name == "rip" || name == "eip" ? "rip" : "flags";
            static const std::map<std::string, std::string> aliases = {
                {"rax", "rax"}, {"eax", "rax"}, {"ax", "rax"}, {"al", "rax"}, {"ah", "rax"},
                {"rcx", "rcx"}, {"ecx", "rcx"}, {"cx", "rcx"}, {"cl", "rcx"}, {"ch", "rcx"},
                {"rdx", "rdx"}, {"edx", "rdx"}, {"dx", "rdx"}, {"dl", "rdx"}, {"dh", "rdx"},
                {"rbx", "rbx"}, {"ebx", "rbx"}, {"bx", "rbx"}, {"bl", "rbx"}, {"bh", "rbx"},
                {"rsp", "rsp"}, {"esp", "rsp"}, {"sp", "rsp"}, {"spl", "rsp"},
                {"rbp", "rbp"}, {"ebp", "rbp"}, {"bp", "rbp"}, {"bpl", "rbp"},
                {"rsi", "rsi"}, {"esi", "rsi"}, {"si", "rsi"}, {"sil", "rsi"},
                {"rdi", "rdi"}, {"edi", "rdi"}, {"di", "rdi"}, {"dil", "rdi"}
            };
            auto found = aliases.find(name);
            if (found != aliases.end()) return found->second;
            if (name.size() >= 2 && name[0] == 'r') {
                size_t digits_end = 1;
                while (digits_end < name.size() && std::isdigit(static_cast<unsigned char>(name[digits_end])))
                    ++digits_end;
                if (digits_end > 1) {
                    int index = 0;
                    try { index = std::stoi(name.substr(1, digits_end - 1)); }
                    catch (...) { return {}; }
                    const std::string suffix = name.substr(digits_end);
                    if (index >= 8 && index <= 31 &&
                        (suffix.empty() || suffix == "d" || suffix == "w" || suffix == "b"))
                        return "r" + std::to_string(index);
                }
            }
            if (name.size() >= 4 && (name.rfind("xmm", 0) == 0 || name.rfind("ymm", 0) == 0 || name.rfind("zmm", 0) == 0)) {
                const size_t digits_start = 3;
                if (std::all_of(name.begin() + digits_start, name.end(), [](unsigned char c) { return std::isdigit(c); })) {
                    try {
                        const int index = std::stoi(name.substr(digits_start));
                        if (index >= 0 && index <= 31) return "vec" + std::to_string(index);
                    } catch (...) {
                        return {};
                    }
                }
            }
            return {};
        }

        struct MachineInstruction {
            ea_t address = BADADDR;
            std::string control_flow = "unknown";
            bool complete = false;
            std::set<std::string> reads;
            std::set<std::string> writes;
            nlohmann::json memory = nlohmann::json::array();
        };

        MachineInstruction AnalyzeMachineInstruction(ea_t ea) {
            MachineInstruction result;
            result.address = ea;
            const size_t item_size = get_item_size(ea);
            segment_t* segment = getseg(ea);
            if (!is_code(get_full_flags(ea)) || item_size == 0 || item_size > 15 || !segment ||
                ea > BADADDR - item_size || ea + item_size > segment->end_ea)
                return result;
            std::array<uint8_t, 15> bytes{};
            for (size_t i = 0; i < item_size; ++i) {
                if (!is_loaded(ea + i)) return result;
                bytes[i] = static_cast<uint8_t>(get_byte(ea + i));
            }

            nlohmann::ordered_json semantics = tools::rax::AnalyzeX64(ea, bytes.data(), item_size);
            result.control_flow = semantics.value("control_flow", std::string("unknown"));
            result.complete = semantics.value("status", std::string()) == "complete" &&
                (!semantics.contains("size") || !semantics["size"].is_number() ||
                 semantics["size"].get<size_t>() == item_size);
            if (!result.complete) return result;

            auto add_read = [&](const std::string& reg) {
                const std::string canonical = CanonicalX64Register(reg);
                if (!canonical.empty()) result.reads.insert(canonical);
            };
            auto add_write = [&](const std::string& reg) {
                const std::string canonical = CanonicalX64Register(reg);
                if (!canonical.empty()) result.writes.insert(canonical);
            };
            for (const auto& flag : semantics.value("flags_read", nlohmann::ordered_json::array()))
                if (flag.is_string()) add_read("flags");
            for (const auto& flag : semantics.value("flags_written", nlohmann::ordered_json::array()))
                if (flag.is_string()) add_write("flags");
            if (semantics.contains("effects") && semantics["effects"].is_array()) {
                for (const auto& effect : semantics["effects"]) {
                    const std::string kind = effect.value("kind", std::string());
                    const bool reads = effect.contains("access") && effect["access"].is_array() &&
                        std::find(effect["access"].begin(), effect["access"].end(), "read") != effect["access"].end();
                    const bool writes = effect.contains("access") && effect["access"].is_array() &&
                        std::find(effect["access"].begin(), effect["access"].end(), "write") != effect["access"].end();
                    if (kind == "register" && effect.contains("register") && effect["register"].is_string()) {
                        const std::string reg = effect["register"].get<std::string>();
                        if (reads) add_read(reg);
                        if (writes) add_write(reg);
                        if (effect.contains("source_register") && effect["source_register"].is_string())
                            add_read(effect["source_register"].get<std::string>());
                    } else if (kind == "memory") {
                        if (reads || writes) result.memory.push_back(effect);
                        if (effect.contains("address") && effect["address"].is_object()) {
                            for (const char* field : {"base", "index"})
                                if (effect["address"].contains(field) && effect["address"][field].is_string())
                                    add_read(effect["address"][field].get<std::string>());
                        }
                        if (effect.contains("source_register") && effect["source_register"].is_string())
                            add_read(effect["source_register"].get<std::string>());
                    }
                }
            }
            return result;
        }

        struct MachineBlock {
            std::vector<MachineInstruction> instructions;
            std::vector<int> successors;
            std::vector<int> predecessors;
        };

        bool BuildMachineRegisterFlow(func_t* fn, ea_t requested_ea, const std::string& requested_register,
                                      const std::string& direction, nlohmann::json& flow,
                                      nlohmann::json& analysis, std::string& error_code,
                                      std::string& error_message) {
            constexpr size_t kMaxMachineBlocks = 256;
            constexpr size_t kMaxMachineInstructions = 4096;
            constexpr size_t kMaxMachineFlowNodes = 200;
            constexpr size_t kMaxMachineWorkItems = 8192;
            const std::string root_register = CanonicalX64Register(requested_register);
            if (root_register.empty()) {
                error_code = "invalid_machine_register";
                error_message = "Machine-level trace requires an x86-64 register name such as rax, rcx, r8, xmm0, or eflags";
                return false;
            }
            char proc_name[32]{};
            inf_get_procname(proc_name, sizeof(proc_name));
            if (!fn || !inf_is_64bit() || std::string(proc_name) != "metapc") {
                error_code = "machine_trace_requires_x64_function";
                error_message = "Machine-level trace requires an address inside an x86-64 function";
                return false;
            }
            const ea_t root_ea = get_item_head(requested_ea);
            if (root_ea < fn->start_ea || root_ea >= fn->end_ea || !is_code(get_full_flags(root_ea))) {
                error_code = "machine_trace_requires_instruction";
                error_message = "Machine-level trace address must resolve to an instruction inside a function";
                return false;
            }

            qflow_chart_t chart("", fn, fn->start_ea, fn->end_ea, FC_NOEXT);
            if (chart.size() == 0 || chart.size() > kMaxMachineBlocks) {
                error_code = "machine_trace_block_limit";
                error_message = "Machine-level trace supports functions with 1 to 256 basic blocks";
                return false;
            }
            std::vector<MachineBlock> blocks(chart.size());
            int root_block = -1;
            size_t instruction_count = 0;
            size_t complete_count = 0;
            for (size_t block_index = 0; block_index < chart.size(); ++block_index) {
                sync::Checkpoint();
                const auto& range = chart.blocks[block_index];
                ea_t cur = range.start_ea;
                while (cur < range.end_ea) {
                    sync::Checkpoint();
                    if (is_code(get_full_flags(cur))) {
                        if (++instruction_count > kMaxMachineInstructions) {
                            error_code = "machine_trace_instruction_limit";
                            error_message = "Machine-level trace is limited to 4096 instructions per function";
                            return false;
                        }
                        MachineInstruction instruction = AnalyzeMachineInstruction(cur);
                        if (instruction.complete) ++complete_count;
                        if (cur == root_ea) root_block = static_cast<int>(block_index);
                        blocks[block_index].instructions.push_back(std::move(instruction));
                        const size_t size = get_item_size(cur);
                        if (size == 0 || cur > BADADDR - size || cur + size > range.end_ea) break;
                        cur += size;
                    } else {
                        ea_t next = next_head(cur, range.end_ea);
                        if (next == BADADDR || next <= cur) break;
                        cur = next;
                    }
                }
            }
            if (root_block < 0) {
                error_code = "machine_trace_instruction_unavailable";
                error_message = "IDA did not expose the requested instruction in the function flow graph";
                return false;
            }
            for (size_t block_index = 0; block_index < chart.size(); ++block_index) {
                for (int i = 0; i < chart.nsucc(static_cast<int>(block_index)); ++i) {
                    int successor = chart.succ(static_cast<int>(block_index), i);
                    if (successor >= 0 && successor < static_cast<int>(chart.size())) {
                        blocks[block_index].successors.push_back(successor);
                        blocks[successor].predecessors.push_back(static_cast<int>(block_index));
                    }
                }
            }
            auto root_it = std::find_if(blocks[root_block].instructions.begin(), blocks[root_block].instructions.end(),
                [&](const MachineInstruction& instruction) { return instruction.address == root_ea; });
            if (root_it == blocks[root_block].instructions.end()) {
                error_code = "machine_trace_instruction_unavailable";
                error_message = "IDA did not expose the requested instruction in the function flow graph";
                return false;
            }
            const size_t root_instruction = static_cast<size_t>(std::distance(blocks[root_block].instructions.begin(), root_it));

            using RegisterSet = std::set<std::string>;
            const bool forward = direction == "forward";
            std::vector<RegisterSet> block_states(blocks.size());
            std::vector<bool> reachable(blocks.size(), false);
            block_states[root_block].insert(root_register);
            reachable[root_block] = true;
            std::deque<int> worklist{root_block};
            size_t work_items = 0;
            bool incomplete = false;
            bool incomplete_lift_boundary = false;
            bool call_boundary = false;
            bool worklist_limit = false;
            bool flow_limit = false;
            auto transfer_block = [&](int block_index, RegisterSet& registers, bool collect,
                                      size_t& node_visits) {
                const auto& instructions = blocks[block_index].instructions;
                auto process = [&](size_t instruction_index) {
                    const auto& instruction = instructions[instruction_index];
                    if (!instruction.complete) {
                        if (!registers.empty()) {
                            incomplete = true;
                            incomplete_lift_boundary = true;
                        }
                        registers.clear();
                        return;
                    }
                    const RegisterSet& sources = forward ? instruction.reads : instruction.writes;
                    const bool dependent = std::any_of(sources.begin(), sources.end(),
                        [&](const std::string& reg) { return registers.count(reg) != 0; });
                    if (collect && dependent) {
                        nlohmann::json node = {
                            {"address", tools::utils::FormatAddress(instruction.address)},
                            {"type", forward ? "register_use" : "register_definition"},
                            {"registers_read", nlohmann::json::array()},
                            {"registers_written", nlohmann::json::array()},
                            {"memory", instruction.memory},
                            {"control_flow", instruction.control_flow}
                        };
                        for (const auto& reg : instruction.reads) node["registers_read"].push_back(reg);
                        for (const auto& reg : instruction.writes) node["registers_written"].push_back(reg);
                        if (node_visits < kMaxMachineFlowNodes) flow.push_back(std::move(node));
                        else { incomplete = true; flow_limit = true; }
                        ++node_visits;
                    }
                    if (instruction.control_flow == "call" || instruction.control_flow == "indirect_call") {
                        const bool has_live_registers = !registers.empty();
                        registers.clear(); // Unknown callee side effects are an interprocedural boundary.
                        if (has_live_registers) { incomplete = true; call_boundary = true; }
                        return;
                    }
                    const RegisterSet& definitions = forward ? instruction.writes : instruction.writes;
                    for (const auto& reg : definitions) registers.erase(reg);
                    if (dependent) {
                        const RegisterSet& propagated = forward ? instruction.writes : instruction.reads;
                        registers.insert(propagated.begin(), propagated.end());
                    }
                };
                if (forward) {
                    const size_t first = block_index == root_block ? root_instruction : 0;
                    for (size_t i = first; i < instructions.size(); ++i) process(i);
                } else {
                    size_t i = block_index == root_block ? root_instruction + 1 : instructions.size();
                    while (i > 0) process(--i);
                }
            };

            while (!worklist.empty()) {
                sync::Checkpoint();
                if (++work_items > kMaxMachineWorkItems) {
                    incomplete = true;
                    worklist_limit = true;
                    break;
                }
                const int block_index = worklist.front();
                worklist.pop_front();
                RegisterSet output = block_states[block_index];
                size_t ignored_nodes = 0;
                transfer_block(block_index, output, false, ignored_nodes);
                if (output.empty()) continue;
                const auto& next_blocks = forward ? blocks[block_index].successors : blocks[block_index].predecessors;
                for (int next : next_blocks) {
                    RegisterSet merged = block_states[next];
                    merged.insert(output.begin(), output.end());
                    if (!reachable[next] || merged != block_states[next]) {
                        reachable[next] = true;
                        block_states[next] = std::move(merged);
                        worklist.push_back(next);
                    }
                }
            }

            std::vector<int> block_depth(blocks.size(), -1);
            std::queue<int> breadth_first;
            block_depth[root_block] = 0;
            breadth_first.push(root_block);
            while (!breadth_first.empty()) {
                const int block_index = breadth_first.front();
                breadth_first.pop();
                const auto& next_blocks = forward ? blocks[block_index].successors : blocks[block_index].predecessors;
                for (int next : next_blocks) {
                    if (block_depth[next] < 0) {
                        block_depth[next] = block_depth[block_index] + 1;
                        breadth_first.push(next);
                    }
                }
            }
            flow = nlohmann::json::array();
            flow.push_back({{"address", tools::utils::FormatAddress(root_ea)}, {"type", "machine_root"},
                            {"register", root_register}, {"direction", direction}});
            size_t node_visits = 0;
            for (size_t block_index = 0; block_index < blocks.size(); ++block_index) {
                if (!reachable[block_index]) continue;
                const size_t first_flow_node = flow.size();
                RegisterSet state = block_states[block_index];
                transfer_block(static_cast<int>(block_index), state, true, node_visits);
                for (size_t i = first_flow_node; i < flow.size(); ++i)
                    flow[i]["depth"] = std::max(0, block_depth[block_index]);
            }
            if (flow.size() > kMaxMachineFlowNodes + 1) {
                while (flow.size() > kMaxMachineFlowNodes + 1) flow.erase(flow.end() - 1);
                incomplete = true;
                flow_limit = true;
            }
            nlohmann::json incomplete_reasons = nlohmann::json::array();
            if (incomplete_lift_boundary) incomplete_reasons.push_back("RAX lift was incomplete on a live register path; propagation stopped there");
            if (call_boundary) incomplete_reasons.push_back("Unknown function calls stop interprocedural register propagation");
            if (worklist_limit) incomplete_reasons.push_back("CFG worklist step limit reached");
            if (flow_limit) incomplete_reasons.push_back("Flow output limit reached");
            analysis = {
                {"engine", "RAX"},
                {"mode", "x86-64 register def-use"},
                {"scope", "intraprocedural CFG; block inputs merged conservatively"},
                {"root_address", tools::utils::FormatAddress(root_ea)},
                {"instructions_total", instruction_count},
                {"instructions_complete", complete_count},
                {"instructions_unmodeled", instruction_count - complete_count},
                {"basic_blocks", blocks.size()},
                {"worklist_steps", work_items},
                {"interprocedural", false},
                {"memory_aliases_tracked", false},
                {"control_dependencies_tracked", false},
                {"dataflow_complete", !incomplete},
                {"incomplete_reasons", std::move(incomplete_reasons)},
                {"truncated", flow_limit || worklist_limit}
            };
            return true;
        }
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
            char path_buf[QMAXPATH]{};
            get_input_file_path(path_buf, sizeof(path_buf));
            std::string file_path = path_buf;

            std::string file_name = file_path;
            size_t sep = file_name.find_last_of("\\/");
            if (sep != std::string::npos) file_name = file_name.substr(sep + 1);
            file_name = tools::utils::SanitizeUtf8(file_name);

            char proc_buf[32]{};
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
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }

        size_t max_callers = static_cast<size_t>(tools::utils::GetIntArg(args, "max_callers", 50));
        if (max_callers > 500) max_callers = 500;
        size_t max_callees = static_cast<size_t>(tools::utils::GetIntArg(args, "max_callees", 100));
        if (max_callees > 500) max_callees = 500;
        const bool semantic_summary = tools::utils::GetBoolArg(args, "semantic_summary", false);
        if (semantic_summary) {
            std::string rax_error;
            if (!tools::rax::Available(rax_error))
                return tools::utils::MakeToolErrorJson(id, rax_error, "rax_unavailable");
        }

        nlohmann::ordered_json res;
        bool found = false;
        bool semantic_arch_unsupported = false;

        sync::SyncRead([&]() {
            if (semantic_summary) {
                char proc_name[32]{};
                inf_get_procname(proc_name, sizeof(proc_name));
                if (!inf_is_64bit() || std::string(proc_name) != "metapc") {
                    semantic_arch_unsupported = true;
                    return;
                }
            }
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
            std::string seg_name = tools::utils::SanitizeUtf8(seg_name_buf.c_str());

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
            RaxFunctionSummary rax_summary;
            func_item_iterator_t fii_insn;
            for (bool ok = fii_insn.set(fn, fn->start_ea); ok; ok = fii_insn.next_head()) {
                sync::Checkpoint();
                insn_count++;
                if (semantic_summary) rax_summary.Analyze(fii_insn.current());
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
                            sync::Checkpoint();
                            qstring arg_type_buf;
                            ftd[a].type.print(&arg_type_buf);
                            nlohmann::ordered_json arg_item;
                            arg_item["index"] = a;
                            arg_item["name"] = tools::utils::SanitizeUtf8(ftd[a].name.c_str());
                            arg_item["type"] = tools::utils::SanitizeUtf8(arg_type_buf.c_str());
                            args_arr.push_back(std::move(arg_item));
                        }
                    }
                }
            }

            // Callers (incoming references)
            xrefblk_t xb_to;
            struct CallerInfo { size_t call_sites_count = 0; std::vector<ea_t> call_sites; };
            constexpr size_t MAX_REFERENCE_VISITS = 200000;
            constexpr size_t MAX_REFERENCE_FUNCTIONS = 5000;
            size_t reference_visits = 0;
            bool references_truncated = false;
            size_t total_callers_count = 0;
            std::map<ea_t, CallerInfo> caller_map;
            for (bool ok = xb_to.first_to(fn->start_ea, XREF_ALL); ok && !references_truncated; ok = xb_to.next_to()) {
                sync::Checkpoint();
                if (++reference_visits > MAX_REFERENCE_VISITS) { references_truncated = true; break; }
                if (!xb_to.iscode) continue;
                uint8_t base_type = xb_to.type & XREF_MASK;
                if (base_type == fl_CN || base_type == fl_CF || base_type == fl_JN || base_type == fl_JF) {
                    total_callers_count++;
                    func_t* caller_fn = get_func(xb_to.from);
                    ea_t c_start = caller_fn ? caller_fn->start_ea : xb_to.from;
                    if (caller_map.find(c_start) == caller_map.end() && caller_map.size() >= MAX_REFERENCE_FUNCTIONS) {
                        references_truncated = true;
                        break;
                    }
                    auto& info = caller_map[c_start];
                    ++info.call_sites_count;
                    if (info.call_sites.size() < 5) info.call_sites.push_back(xb_to.from);
                }
            }

            nlohmann::json callers_arr = nlohmann::json::array();
            size_t caller_idx = 0;
            for (const auto& [c_ea, info] : caller_map) {
                sync::Checkpoint();
                if (caller_idx++ >= max_callers) break;
                qstring c_name;
                get_ea_name(&c_name, c_ea);
                std::string c_name_str = tools::utils::SanitizeUtf8(c_name.c_str());
                std::string c_dem = tools::utils::Demangle(c_name_str);

                nlohmann::ordered_json c_item;
                c_item["address"] = tools::utils::FormatAddress(c_ea);
                c_item["name"] = c_name_str;
                if (!c_dem.empty() && c_dem != c_name_str) c_item["demangled"] = c_dem;
                c_item["call_sites_count"] = info.call_sites_count;
                nlohmann::json sites_json = nlohmann::json::array();
                for (size_t s = 0; s < info.call_sites.size(); ++s) {
                    sync::Checkpoint();
                    sites_json.push_back(tools::utils::FormatAddress(info.call_sites[s]));
                }
                c_item["call_sites"] = std::move(sites_json);
                if (info.call_sites_count > info.call_sites.size()) c_item["call_sites_truncated"] = true;
                callers_arr.push_back(std::move(c_item));
            }

            // Callees (outgoing calls & jumps)
            struct CalleeInfo {
                ea_t target_ea;
                std::string type;
                size_t call_sites_count = 0;
                std::vector<ea_t> call_sites;
            };
            std::map<ea_t, CalleeInfo> callee_map;

            func_item_iterator_t fii;
            for (bool ok = fii.set(fn, fn->start_ea); ok && !references_truncated; ok = fii.next_head()) {
                sync::Checkpoint();
                ea_t cur = fii.current();
                xrefblk_t xb_from;
                for (bool xok = xb_from.first_from(cur, XREF_ALL); xok && !references_truncated; xok = xb_from.next_from()) {
                    sync::Checkpoint();
                    if (++reference_visits > MAX_REFERENCE_VISITS) { references_truncated = true; break; }
                    if (!xb_from.iscode) continue;
                    uint8_t base_type = xb_from.type & XREF_MASK;
                    if (base_type == fl_CN || base_type == fl_CF || base_type == fl_JN || base_type == fl_JF) {
                        if (xb_from.to >= fn->start_ea && xb_from.to < fn->end_ea) continue;

                        std::string call_type = (base_type == fl_CN || base_type == fl_CF) ? "call" : "tailcall";
                        if (callee_map.find(xb_from.to) == callee_map.end() && callee_map.size() >= MAX_REFERENCE_FUNCTIONS) {
                            references_truncated = true;
                            break;
                        }
                        auto& ci = callee_map[xb_from.to];
                        ci.target_ea = xb_from.to;
                        if (ci.type.empty()) ci.type = call_type;
                        ++ci.call_sites_count;
                        if (ci.call_sites.size() < 5) ci.call_sites.push_back(cur);
                    }
                }
            }

            nlohmann::json callees_arr = nlohmann::json::array();
            size_t callee_idx = 0;
            for (const auto& [callee_ea, ci] : callee_map) {
                sync::Checkpoint();
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
                ci_item["call_sites_count"] = ci.call_sites_count;
                nlohmann::json sites_json = nlohmann::json::array();
                for (size_t s = 0; s < ci.call_sites.size(); ++s) {
                    sync::Checkpoint();
                    sites_json.push_back(tools::utils::FormatAddress(ci.call_sites[s]));
                }
                ci_item["call_sites"] = std::move(sites_json);
                if (ci.call_sites_count > ci.call_sites.size()) ci_item["call_sites_truncated"] = true;
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
            if (semantic_summary) res["semantic_summary"] = rax_summary.ToJson();
            res["flags"] = std::move(flags_obj);
            res["frame"] = std::move(frame_obj);
            if (!proto.empty()) res["prototype"] = proto;
            if (!calling_conv.empty()) res["calling_convention"] = calling_conv;
            if (!ret_type.empty()) res["return_type"] = ret_type;
            if (!args_arr.empty()) res["arguments"] = std::move(args_arr);

            res["callers_count"] = total_callers_count;
            res["unique_callers"] = caller_map.size();
            res["callers"] = std::move(callers_arr);
            if (caller_map.size() > max_callers) res["callers_truncated"] = true;

            res["callees_count"] = callee_map.size();
            res["callees"] = std::move(callees_arr);
            if (callee_map.size() > max_callees) res["callees_truncated"] = true;
            if (references_truncated) res["references_truncated"] = true;
        });

        if (semantic_arch_unsupported) {
            return tools::utils::MakeToolErrorJson(
                id, "semantic_summary is available only for x86-64 IDBs", "rax_arch_unsupported");
        }
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
        if (direction != "forward" && direction != "backward")
            return tools::utils::MakeToolErrorJson(id, "Direction must be 'forward' or 'backward'", "invalid_direction");

        int max_depth = static_cast<int>(tools::utils::GetIntArg(args, "depth", 2));
        if (max_depth <= 0) max_depth = 2;
        if (max_depth > 5) max_depth = 5;

        bool include_calls = tools::utils::GetBoolArg(args, "include_calls", true);
        const bool machine_level = tools::utils::GetBoolArg(args, "machine_level", false);
        if (machine_level) {
            std::string rax_error;
            if (!tools::rax::Available(rax_error))
                return tools::utils::MakeToolErrorJson(id, rax_error, "rax_unavailable");
            if (target_var.empty())
                return tools::utils::MakeToolErrorJson(
                    id, "Machine-level trace requires 'var' to name an x86-64 register", "machine_register_required");
        }

        nlohmann::json flow_arr = nlohmann::json::array();
        nlohmann::json machine_analysis;
        std::string root_var_name = target_var;
        bool used_hexrays = false;
        std::string error_code;
        std::string error_msg;
        bool flow_truncated = false;

        sync::SyncToMainThread([&]() {
            func_t* pfn = get_func(start_ea);
            if (machine_level) {
                if (!pfn) {
                    error_code = "machine_trace_requires_function";
                    error_msg = "Machine-level trace requires an instruction inside a function";
                    return;
                }
                BuildMachineRegisterFlow(pfn, start_ea, target_var, direction,
                    flow_arr, machine_analysis, error_code, error_msg);
                root_var_name = CanonicalX64Register(target_var);
                return;
            }
            // If Hex-Rays is available and we are inside a function, perform ctree-based data flow analysis
            if (pfn && init_hexrays_plugin()) {
                hexrays_failure_t hf;
                cfuncptr_t cf = decompile(pfn, &hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                if (cf) {
                    used_hexrays = true;

                    struct VarRef {
                        ea_t func_ea = BADADDR;
                        int lvar_idx = -1;
                        std::string name;

                        bool operator<(const VarRef& o) const {
                            if (func_ea != o.func_ea) return func_ea < o.func_ea;
                            return lvar_idx < o.lvar_idx;
                        }
                        bool operator==(const VarRef& o) const {
                            return func_ea == o.func_ea && lvar_idx == o.lvar_idx;
                        }
                    };

                    VarRef root_var;
                    root_var.func_ea = pfn->start_ea;
                    const lvars_t* lvars = cf->get_lvars();
                    if (lvars && !lvars->empty()) {
                        bool var_found = false;
                        if (!target_var.empty()) {
                            for (size_t i = 0; i < lvars->size(); ++i) {
                                sync::Checkpoint();
                                if ((*lvars)[i].name == target_var.c_str()) {
                                    root_var.lvar_idx = static_cast<int>(i);
                                    root_var.name = (*lvars)[i].name.c_str();
                                    var_found = true;
                                    break;
                                }
                            }
                            if (!var_found) {
                                int arg_idx = -1;
                                std::string index_text = target_var.rfind("arg", 0) == 0 ? target_var.substr(3) : target_var;
                                if (!index_text.empty() && index_text.find_first_not_of("0123456789") == std::string::npos) {
                                    int parsed_index = -1;
                                    const auto parsed = std::from_chars(index_text.data(), index_text.data() + index_text.size(), parsed_index);
                                    if (parsed.ec == std::errc{} && parsed.ptr == index_text.data() + index_text.size())
                                        arg_idx = parsed_index;
                                }
                                if (arg_idx >= 0) {
                                    if (arg_idx < static_cast<int>(cf->argidx.size())) {
                                        root_var.lvar_idx = cf->argidx[arg_idx];
                                        if (root_var.lvar_idx >= 0 && root_var.lvar_idx < static_cast<int>(lvars->size())) {
                                            root_var.name = (*lvars)[root_var.lvar_idx].name.c_str();
                                            var_found = true;
                                        }
                                    } else {
                                        int cur_arg = 0;
                                        for (size_t i = 0; i < lvars->size(); ++i) {
                                            sync::Checkpoint();
                                            if ((*lvars)[i].is_arg_var()) {
                                                if (cur_arg == arg_idx) {
                                                    root_var.lvar_idx = static_cast<int>(i);
                                                    root_var.name = (*lvars)[i].name.c_str();
                                                    var_found = true;
                                                    break;
                                                }
                                                cur_arg++;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if (root_var.lvar_idx < 0 && target_var.empty()) {
                            if (!cf->argidx.empty()) {
                                root_var.lvar_idx = cf->argidx[0];
                                if (root_var.lvar_idx >= 0 && root_var.lvar_idx < static_cast<int>(lvars->size())) {
                                    root_var.name = (*lvars)[root_var.lvar_idx].name.c_str();
                                }
                            } else {
                                for (size_t i = 0; i < lvars->size(); ++i) {
                                    sync::Checkpoint();
                                    if ((*lvars)[i].is_arg_var()) {
                                        root_var.lvar_idx = static_cast<int>(i);
                                        root_var.name = (*lvars)[i].name.c_str();
                                        break;
                                    }
                                }
                                if (root_var.lvar_idx < 0) {
                                    root_var.lvar_idx = 0;
                                    root_var.name = (*lvars)[0].name.c_str();
                                }
                            }
                        }
                    }
                    if (!target_var.empty() && root_var.lvar_idx < 0) {
                        error_code = "variable_not_found";
                        error_msg = "Variable '" + target_var + "' was not found in the decompiled function";
                        return;
                    }
                    root_var_name = root_var.name;

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

                    auto ResolveCallTarget = [&](const cexpr_t* call_expr, const cfunc_t* cf_ptr) -> ea_t {
                        if (!call_expr || call_expr->op != cot_call || !call_expr->x) return BADADDR;
                        if (call_expr->x->op == cot_obj) {
                            if (is_mapped(call_expr->x->obj_ea)) {
                                func_t* f = get_func(call_expr->x->obj_ea);
                                if (f && f->start_ea == call_expr->x->obj_ea) return f->start_ea;
                                segment_t* seg = getseg(call_expr->x->obj_ea);
                                if (seg && !(seg->perm & SEGPERM_EXEC)) {
                                    ea_t target = ReadLoadedPointer(call_expr->x->obj_ea);
                                    if (target != BADADDR && is_mapped(target)) {
                                        func_t* target_fn = get_func(target);
                                        if (target_fn) return target_fn->start_ea;
                                    }
                                }
                            }
                        }
                        if (call_expr->ea != BADADDR && is_mapped(call_expr->ea)) {
                            xrefblk_t xb;
                            for (bool ok = xb.first_from(call_expr->ea, XREF_ALL); ok; ok = xb.next_from()) {
                                sync::Checkpoint();
                                if (xb.iscode && xb.to != BADADDR && xb.to != call_expr->ea) {
                                    func_t* f = get_func(xb.to);
                                    if (f) return f->start_ea;
                                }
                            }
                        }
                        return BADADDR;
                    };

                    auto GetArgLvarIdx = [](const cfunc_t* cf_ptr, size_t arg_i) -> int {
                        if (!cf_ptr) return -1;
                        if (arg_i < cf_ptr->argidx.size()) {
                            return cf_ptr->argidx[arg_i];
                        }
                        const lvars_t* lvs = const_cast<cfunc_t*>(cf_ptr)->get_lvars();
                        if (!lvs) return -1;
                        size_t cur = 0;
                        for (size_t k = 0; k < lvs->size(); ++k) {
                            sync::Checkpoint();
                            if ((*lvs)[k].is_arg_var()) {
                                if (cur == arg_i) return static_cast<int>(k);
                                cur++;
                            }
                        }
                        return -1;
                    };

                    auto GetAbstractMemLoc = [](const cexpr_t* e, const cfunc_t* cf_ptr) -> std::string {
                        if (!e) return "";
                        if (e->op == cot_memptr || e->op == cot_memref) {
                            std::string base = hexrays_ast::CleanItemText(e->x, cf_ptr);
                            std::stringstream ss;
                            ss << "Memory[" << base << " + 0x" << std::hex << e->m << "]";
                            return ss.str();
                        }
                        if (e->op == cot_ptr) {
                            if (e->x && e->x->op == cot_add && e->x->y && e->x->y->op == cot_num) {
                                std::string base = hexrays_ast::CleanItemText(e->x->x, cf_ptr);
                                std::stringstream ss;
                                ss << "Memory[" << base << " + 0x" << std::hex << e->x->y->numval() << "]";
                                return ss.str();
                            }
                            std::string base = hexrays_ast::CleanItemText(e->x, cf_ptr);
                            return "Memory[" + base + "]";
                        }
                        return "";
                    };

                    std::set<std::pair<ea_t, int>> visited_func_vars;
                    std::function<void(func_t*, const VarRef&, int)> trace_fn;

                    trace_fn = [&](func_t* fn, const VarRef& cur_var, int current_depth) {
                        sync::Checkpoint();
                        sync::RecursionGuard recursion;
                        if (flow_arr.size() >= 200) { flow_truncated = true; return; }
                        if (!fn || current_depth > max_depth) return;
                        auto visit_key = std::make_pair(fn->start_ea, cur_var.lvar_idx);
                        if (visited_func_vars.count(visit_key)) return;
                        visited_func_vars.insert(visit_key);

                        hexrays_failure_t local_hf;
                        cfuncptr_t local_cf = decompile(fn, &local_hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                        if (!local_cf) return;

                        std::set<int> active_lvars;
                        if (cur_var.lvar_idx >= 0) active_lvars.insert(cur_var.lvar_idx);
                        std::map<int, int> pointer_aliases;
                        std::set<std::string> active_mem_locs;

                        if (direction == "forward") {
                            struct ForwardVisitor : public ctree_visitor_t {
                                const cfunc_t* cf;
                                std::set<int>& active_lvars;
                                std::map<int, int>& pointer_aliases;
                                std::set<std::string>& active_mem_locs;
                                nlohmann::json& flow;
                                bool& truncated;
                                int depth;
                                bool inc_calls;
                                int max_d;
                                std::function<void(func_t*, const VarRef&, int)> recurse_fn;
                                std::function<ea_t(const cexpr_t*, const cfunc_t*)> resolve_call_fn;
                                std::function<int(const cfunc_t*, size_t)> get_arg_fn;
                                std::function<std::string(const cexpr_t*, const cfunc_t*)> get_mem_loc_fn;

                                ForwardVisitor(const cfunc_t* f,
                                               std::set<int>& al,
                                               std::map<int, int>& pa,
                                               std::set<std::string>& am,
                                               nlohmann::json& fl,
                                               bool& tr,
                                               int d, bool ic, int md,
                                               std::function<void(func_t*, const VarRef&, int)> rf,
                                               std::function<ea_t(const cexpr_t*, const cfunc_t*)> rcf,
                                               std::function<int(const cfunc_t*, size_t)> gaf,
                                               std::function<std::string(const cexpr_t*, const cfunc_t*)> gmf)
                                    : ctree_visitor_t(CV_FAST | CV_PARENTS), cf(f), active_lvars(al),
                                      pointer_aliases(pa), active_mem_locs(am), flow(fl), truncated(tr),
                                      depth(d), inc_calls(ic), max_d(md), recurse_fn(rf),
                                      resolve_call_fn(rcf), get_arg_fn(gaf), get_mem_loc_fn(gmf) {}

                                void BoundedPush(nlohmann::ordered_json item) {
                                    if (flow.size() >= 200) {
                                        truncated = true;
                                        return;
                                    }
                                    flow.push_back(std::move(item));
                                }

                                std::string GetCondition() const {
                                    for (int k = static_cast<int>(parents.size()) - 1; k >= 0; --k) {
                                        sync::Checkpoint();
                                        citem_t* p = parents[k];
                                        // apply_to(..., nullptr) includes a null root parent.
                                        if (!p) continue;
                                        if (!p->is_expr() && static_cast<cinsn_t*>(p)->op == cit_if) {
                                            const cinsn_t* if_insn = static_cast<const cinsn_t*>(p);
                                            if (if_insn->cif) {
                                                std::string cond = hexrays_ast::CleanItemText(&if_insn->cif->expr, cf);
                                                if (k + 1 < static_cast<int>(parents.size())) {
                                                    citem_t* child = parents[k + 1];
                                                    if (if_insn->cif->ielse && child == if_insn->cif->ielse) {
                                                        return "!(" + cond + ")";
                                                    }
                                                }
                                                return cond;
                                            }
                                        }
                                    }
                                    return "";
                                }

                                bool UsesActiveVar(const cexpr_t* e, VarRef& out_v) {
                                    sync::Checkpoint();
                                    sync::RecursionGuard recursion;
                                    if (!e) return false;
                                    if (e->op == cot_var) {
                                        const lvars_t* lvs = const_cast<cfunc_t*>(cf)->get_lvars();
                                        if (lvs && e->v.idx >= 0 && e->v.idx < static_cast<int>(lvs->size())) {
                                            if (active_lvars.count(e->v.idx)) {
                                                out_v = VarRef{ cf->entry_ea, e->v.idx, (*lvs)[e->v.idx].name.c_str() };
                                                return true;
                                            }
                                            auto it = pointer_aliases.find(e->v.idx);
                                            if (it != pointer_aliases.end() && it->second >= 0 &&
                                                it->second < static_cast<int>(lvs->size()) && active_lvars.count(it->second)) {
                                                out_v = VarRef{ cf->entry_ea, it->second, (*lvs)[it->second].name.c_str() };
                                                return true;
                                            }
                                        }
                                        return false;
                                    }
                                    if (op_uses_x(e->op) && e->x && UsesActiveVar(e->x, out_v)) return true;
                                    if (op_uses_y(e->op) && e->y && UsesActiveVar(e->y, out_v)) return true;
                                    if (op_uses_z(e->op) && e->z && UsesActiveVar(e->z, out_v)) return true;
                                    if (e->op == cot_call && e->a) {
                                        for (const auto& arg : *e->a) {
                                            sync::Checkpoint();
                                            if (UsesActiveVar(&arg, out_v)) return true;
                                        }
                                    }
                                    return false;
                                }

                                int idaapi visit_expr(cexpr_t* e) override {
                                    try {
                                        sync::Checkpoint();
                                        if (flow.size() >= 200) { truncated = true; return 1; }

                                        if (e->op == cot_asg || e->op == cot_asgbor || e->op == cot_asgxor ||
                                            e->op == cot_asgband || e->op == cot_asgadd || e->op == cot_asgsub ||
                                            e->op == cot_asgmul || e->op == cot_asgsshr || e->op == cot_asgushr ||
                                            e->op == cot_asgshl) {

                                            // Capture dependencies before killing the previous value of the LHS.
                                            // Compound assignments read the old LHS as well as the RHS.
                                            VarRef rhs_used;
                                            bool rhs_is_active = UsesActiveVar(e->y, rhs_used);
                                            VarRef lhs_used;
                                            bool compound_lhs_is_active = e->op != cot_asg && UsesActiveVar(e->x, lhs_used);
                                            if (!rhs_is_active && compound_lhs_is_active) {
                                                rhs_used = lhs_used;
                                                rhs_is_active = true;
                                            }

                                            if (e->x && e->x->op == cot_var) {
                                                // A new value invalidates both old taint and an old pointer alias.
                                                active_lvars.erase(e->x->v.idx);
                                                pointer_aliases.erase(e->x->v.idx);
                                            }

                                            // Alias creation (p = &x)
                                            if (e->x && e->x->op == cot_var && e->y) {
                                                const cexpr_t* y_val = e->y;
                                                if (y_val->op == cot_cast && y_val->x) y_val = y_val->x;
                                                if (y_val->op == cot_ref && y_val->x && y_val->x->op == cot_var) {
                                                    int p_idx = e->x->v.idx;
                                                    int target_idx = y_val->x->v.idx;
                                                    pointer_aliases[p_idx] = target_idx;
                                                    const lvars_t* lvs = const_cast<cfunc_t*>(cf)->get_lvars();
                                                    if (lvs && active_lvars.count(target_idx)) {
                                                        nlohmann::ordered_json item = {
                                                            {"depth", depth},
                                                            {"address", tools::utils::FormatAddress(e->ea)},
                                                            {"type", "alias_create"},
                                                            {"pointer", (*lvs)[p_idx].name.c_str()},
                                                            {"aliased_var", (*lvs)[target_idx].name.c_str()},
                                                            {"expr", hexrays_ast::CleanItemText(e, cf)}
                                                        };
                                                        std::string cond = GetCondition();
                                                        if (!cond.empty()) item["path_condition"] = cond;
                                                        BoundedPush(std::move(item));
                                                    }
                                                }
                                            }

                                            // Pointer store through alias (*p = val)
                                            if (e->x && e->x->op == cot_ptr && e->x->x && e->x->x->op == cot_var) {
                                                int p_idx = e->x->x->v.idx;
                                                auto it = pointer_aliases.find(p_idx);
                                                if (it != pointer_aliases.end() && active_lvars.count(it->second)) {
                                                    const lvars_t* lvs = const_cast<cfunc_t*>(cf)->get_lvars();
                                                    nlohmann::ordered_json item = {
                                                        {"depth", depth},
                                                        {"address", tools::utils::FormatAddress(e->ea)},
                                                        {"type", "alias_store"},
                                                        {"pointer", (*lvs)[p_idx].name.c_str()},
                                                        {"target_var", (*lvs)[it->second].name.c_str()},
                                                        {"value", hexrays_ast::CleanItemText(e->y, cf)},
                                                        {"expr", hexrays_ast::CleanItemText(e, cf)}
                                                    };
                                                    std::string cond = GetCondition();
                                                    if (!cond.empty()) item["path_condition"] = cond;
                                                    BoundedPush(std::move(item));
                                                }
                                            }

                                            // Abstract memory store (obj->field = val)
                                            std::string mem_loc = get_mem_loc_fn(e->x, cf);
                                            if (!mem_loc.empty() && e->op == cot_asg) {
                                                active_mem_locs.erase(mem_loc);
                                            }
                                            if (rhs_is_active) {
                                                if (!mem_loc.empty()) {
                                                    active_mem_locs.insert(mem_loc);
                                                    nlohmann::ordered_json item = {
                                                        {"depth", depth},
                                                        {"address", tools::utils::FormatAddress(e->ea)},
                                                        {"type", "member_store"},
                                                        {"abstract_loc", mem_loc},
                                                        {"from", rhs_used.name},
                                                        {"target", hexrays_ast::CleanItemText(e->x, cf)},
                                                        {"expr", hexrays_ast::CleanItemText(e, cf)}
                                                    };
                                                    std::string cond = GetCondition();
                                                    if (!cond.empty()) item["path_condition"] = cond;
                                                    BoundedPush(std::move(item));
                                                } else if (e->x && (e->x->op == cot_ptr || e->x->op == cot_memptr || e->x->op == cot_memref || e->x->op == cot_obj)) {
                                                    nlohmann::ordered_json item = {
                                                        {"depth", depth},
                                                        {"address", tools::utils::FormatAddress(e->ea)},
                                                        {"type", "store"},
                                                        {"from", rhs_used.name},
                                                        {"target", hexrays_ast::CleanItemText(e->x, cf)},
                                                        {"expr", hexrays_ast::CleanItemText(e, cf)}
                                                    };
                                                    std::string cond = GetCondition();
                                                    if (!cond.empty()) item["path_condition"] = cond;
                                                    BoundedPush(std::move(item));
                                                }
                                            }

                                            // Abstract memory load propagation (y = obj->field)
                                            if (e->x && e->x->op == cot_var) {
                                                std::string rhs_mem = get_mem_loc_fn(e->y, cf);
                                                if (!rhs_mem.empty() && active_mem_locs.count(rhs_mem)) {
                                                    const lvars_t* lvs = const_cast<cfunc_t*>(cf)->get_lvars();
                                                    if (lvs && e->x->v.idx >= 0 && e->x->v.idx < static_cast<int>(lvs->size())) {
                                                        active_lvars.insert(e->x->v.idx);
                                                        nlohmann::ordered_json item = {
                                                            {"depth", depth},
                                                            {"address", tools::utils::FormatAddress(e->ea)},
                                                            {"type", "memory_propagate"},
                                                            {"from_loc", rhs_mem},
                                                            {"to", (*lvs)[e->x->v.idx].name.c_str()},
                                                            {"expr", hexrays_ast::CleanItemText(e, cf)}
                                                        };
                                                        std::string cond = GetCondition();
                                                        if (!cond.empty()) item["path_condition"] = cond;
                                                        BoundedPush(std::move(item));
                                                    }
                                                }
                                            }

                                            // Standard variable assignment (y = x)
                                            if (rhs_is_active) {
                                                if (e->x && e->x->op == cot_var) {
                                                    const lvars_t* lvs = const_cast<cfunc_t*>(cf)->get_lvars();
                                                    if (lvs && e->x->v.idx >= 0 && e->x->v.idx < static_cast<int>(lvs->size())) {
                                                        std::string to_var = (*lvs)[e->x->v.idx].name.c_str();
                                                        active_lvars.insert(e->x->v.idx);
                                                        nlohmann::ordered_json item = {
                                                            {"depth", depth},
                                                            {"address", tools::utils::FormatAddress(e->ea)},
                                                            {"type", "assign"},
                                                            {"from", rhs_used.name},
                                                            {"to", to_var},
                                                            {"expr", hexrays_ast::CleanItemText(e, cf)}
                                                        };
                                                        std::string cond = GetCondition();
                                                        if (!cond.empty()) item["path_condition"] = cond;
                                                        BoundedPush(std::move(item));
                                                    }
                                                }
                                            }

                                        }

                                        // Call arguments
                                        if (e->op == cot_call && e->a) {
                                            std::string callee_name = hexrays_ast::CleanItemText(e->x, cf);
                                            ea_t callee_ea = resolve_call_fn(e, cf);

                                            for (size_t i = 0; i < e->a->size(); ++i) {
                                                sync::Checkpoint();
                                                if (flow.size() >= 200) { truncated = true; return 1; }
                                                const cexpr_t* arg_expr = &(*e->a)[i];
                                                VarRef used_var;
                                                bool is_out_param = false;

                                                const cexpr_t* unwrap_arg = arg_expr;
                                                if (unwrap_arg->op == cot_cast && unwrap_arg->x) unwrap_arg = unwrap_arg->x;
                                                if (unwrap_arg->op == cot_ref && unwrap_arg->x && unwrap_arg->x->op == cot_var) {
                                                    int v_idx = unwrap_arg->x->v.idx;
                                                    if (active_lvars.count(v_idx)) {
                                                        const lvars_t* lvs = const_cast<cfunc_t*>(cf)->get_lvars();
                                                        if (lvs && v_idx >= 0 && v_idx < static_cast<int>(lvs->size())) {
                                                            used_var = VarRef{ cf->entry_ea, v_idx, (*lvs)[v_idx].name.c_str() };
                                                            is_out_param = true;
                                                        }
                                                    }
                                                }

                                                if (is_out_param || UsesActiveVar(arg_expr, used_var)) {
                                                    nlohmann::ordered_json item = {
                                                        {"depth", depth},
                                                        {"address", tools::utils::FormatAddress(e->ea)},
                                                        {"type", is_out_param ? "out_param_pass" : "call_arg"},
                                                        {"from", used_var.name},
                                                        {"callee", callee_name},
                                                        {"arg_index", i},
                                                        {"expr", hexrays_ast::CleanItemText(e, cf)}
                                                    };
                                                    std::string cond = GetCondition();
                                                    if (!cond.empty()) item["path_condition"] = cond;
                                                    BoundedPush(std::move(item));

                                                    if (inc_calls && depth < max_d && callee_ea != BADADDR) {
                                                        func_t* callee_fn = get_func(callee_ea);
                                                        if (callee_fn) {
                                                            hexrays_failure_t cf_hf;
                                                            cfuncptr_t callee_cf = decompile(callee_fn, &cf_hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                                                            if (callee_cf) {
                                                                int param_lvar_idx = get_arg_fn(callee_cf, i);
                                                                const lvars_t* callee_lvars = callee_cf->get_lvars();
                                                                if (callee_lvars && param_lvar_idx >= 0 && param_lvar_idx < static_cast<int>(callee_lvars->size())) {
                                                                    VarRef callee_ref{ callee_fn->start_ea, param_lvar_idx, (*callee_lvars)[param_lvar_idx].name.c_str() };
                                                                    BoundedPush({
                                                                        {"depth", depth + 1},
                                                                        {"address", tools::utils::FormatAddress(callee_fn->start_ea)},
                                                                        {"type", "param_use"},
                                                                        {"function", callee_name},
                                                                        {"param", callee_ref.name},
                                                                        {"arg_index", i}
                                                                    });
                                                                    recurse_fn(callee_fn, callee_ref, depth + 1);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        // Array indexing
                                        if (e->op == cot_idx) {
                                            VarRef used_var;
                                            if (UsesActiveVar(e->y, used_var)) {
                                                nlohmann::ordered_json item = {
                                                    {"depth", depth},
                                                    {"address", tools::utils::FormatAddress(e->ea)},
                                                    {"type", "index_use"},
                                                    {"from", used_var.name},
                                                    {"array", hexrays_ast::CleanItemText(e->x, cf)},
                                                    {"expr", hexrays_ast::CleanItemText(e, cf)}
                                                };
                                                std::string cond = GetCondition();
                                                if (!cond.empty()) item["path_condition"] = cond;
                                                BoundedPush(std::move(item));
                                            }
                                            if (UsesActiveVar(e->x, used_var)) {
                                                nlohmann::ordered_json item = {
                                                    {"depth", depth},
                                                    {"address", tools::utils::FormatAddress(e->ea)},
                                                    {"type", "array_access"},
                                                    {"from", used_var.name},
                                                    {"index", hexrays_ast::CleanItemText(e->y, cf)},
                                                    {"expr", hexrays_ast::CleanItemText(e, cf)}
                                                };
                                                std::string cond = GetCondition();
                                                if (!cond.empty()) item["path_condition"] = cond;
                                                BoundedPush(std::move(item));
                                            }
                                        }

                                        // Increment / Decrement
                                        if (e->op == cot_postinc || e->op == cot_postdec || e->op == cot_preinc || e->op == cot_predec) {
                                            VarRef used_var;
                                            if (UsesActiveVar(e->x, used_var)) {
                                                nlohmann::ordered_json item = {
                                                    {"depth", depth},
                                                    {"address", tools::utils::FormatAddress(e->ea)},
                                                    {"type", (e->op == cot_postinc || e->op == cot_preinc) ? "increment" : "decrement"},
                                                    {"var", used_var.name},
                                                    {"expr", hexrays_ast::CleanItemText(e, cf)}
                                                };
                                                std::string cond = GetCondition();
                                                if (!cond.empty()) item["path_condition"] = cond;
                                                BoundedPush(std::move(item));
                                            }
                                        }

                                        return 0;
                                    } catch (...) {
                                        sync::SaveCallbackException();
                                        return 1;
                                    }
                                }

                                int idaapi visit_insn(cinsn_t* insn) override {
                                    try {
                                        sync::Checkpoint();
                                        if (flow.size() >= 200) { truncated = true; return 1; }
                                        if (insn->op == cit_if && insn->cif) {
                                            VarRef used_var;
                                            if (UsesActiveVar(&insn->cif->expr, used_var)) {
                                                BoundedPush({
                                                    {"depth", depth},
                                                    {"address", tools::utils::FormatAddress(insn->ea)},
                                                    {"type", "condition"},
                                                    {"from", used_var.name},
                                                    {"condition", hexrays_ast::CleanItemText(&insn->cif->expr, cf)}
                                                });
                                            }
                                        }
                                        if (insn->op == cit_return && insn->creturn && insn->creturn->expr.op != cot_empty) {
                                            VarRef used_var;
                                            if (UsesActiveVar(&insn->creturn->expr, used_var)) {
                                                nlohmann::ordered_json item = {
                                                    {"depth", depth},
                                                    {"address", tools::utils::FormatAddress(insn->ea)},
                                                    {"type", "return"},
                                                    {"from", used_var.name},
                                                    {"expr", hexrays_ast::CleanItemText(&insn->creturn->expr, cf)}
                                                };
                                                std::string cond = GetCondition();
                                                if (!cond.empty()) item["path_condition"] = cond;
                                                BoundedPush(std::move(item));
                                            }
                                        }
                                        return 0;
                                    } catch (...) {
                                        sync::SaveCallbackException();
                                        return 1;
                                    }
                                }
                            };

                            ForwardVisitor visitor(local_cf, active_lvars, pointer_aliases, active_mem_locs, flow_arr, flow_truncated, current_depth, include_calls, max_depth, trace_fn, ResolveCallTarget, GetArgLvarIdx, GetAbstractMemLoc);
                            visitor.apply_to(&local_cf->body, nullptr);
                            sync::Checkpoint();
                        } else {
                            // Backward direction: use -> def with deep reverse-AST evaluation
                            std::set<std::string> active_globals;
                            std::set<ea_t> active_objs;

                            auto UsesActiveVar = [&](const cexpr_t* e, VarRef& out_v) -> bool {
                                std::function<bool(const cexpr_t*)> check = [&](const cexpr_t* sub) -> bool {
                                    sync::Checkpoint();
                                    sync::RecursionGuard recursion;
                                    if (!sub) return false;
                                    if (sub->op == cot_var) {
                                        const lvars_t* lvs = local_cf->get_lvars();
                                        if (lvs && sub->v.idx >= 0 && sub->v.idx < static_cast<int>(lvs->size())) {
                                            if (active_lvars.count(sub->v.idx)) {
                                                out_v = VarRef{ local_cf->entry_ea, sub->v.idx, (*lvs)[sub->v.idx].name.c_str() };
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
                                            sync::Checkpoint();
                                            if (check(&arg)) return true;
                                        }
                                    }
                                    return false;
                                };
                                return check(e);
                            };

                            auto ExtractSources = [&](const cexpr_t* e, std::vector<VarRef>& out_vars, std::vector<std::string>& out_globals) {
                                std::function<void(const cexpr_t*)> walk = [&](const cexpr_t* sub) {
                                    sync::Checkpoint();
                                    sync::RecursionGuard recursion;
                                    if (!sub) return;
                                    if (sub->op == cot_var) {
                                        const lvars_t* lvs = local_cf->get_lvars();
                                        if (lvs && sub->v.idx >= 0 && sub->v.idx < static_cast<int>(lvs->size())) {
                                            VarRef vr{ local_cf->entry_ea, sub->v.idx, (*lvs)[sub->v.idx].name.c_str() };
                                            if (std::find(out_vars.begin(), out_vars.end(), vr) == out_vars.end()) {
                                                out_vars.push_back(vr);
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
                                bool& truncated;
                                explicit citem_collector_t(bool& tr) : ctree_visitor_t(CV_FAST), truncated(tr) {}
                                int idaapi visit_insn(cinsn_t* in) override {
                                    try {
                                        sync::Checkpoint();
                                        if (items.size() >= kMaxTraceCollectedItems) { truncated = true; return 1; }
                                        items.push_back(in);
                                        return 0;
                                    } catch (...) {
                                        sync::SaveCallbackException();
                                        return 1;
                                    }
                                }
                                int idaapi visit_expr(cexpr_t* ex) override {
                                    try {
                                        sync::Checkpoint();
                                        if (items.size() >= kMaxTraceCollectedItems) { truncated = true; return 1; }
                                        items.push_back(ex);
                                        return 0;
                                    } catch (...) {
                                        sync::SaveCallbackException();
                                        return 1;
                                    }
                                }
                            } collector(flow_truncated);
                            collector.apply_to(&local_cf->body, nullptr);
                            sync::Checkpoint();

                            // Traverse collected items in reverse execution order
                            for (auto it = collector.items.rbegin(); it != collector.items.rend(); ++it) {
                                sync::Checkpoint();
                                if (flow_arr.size() >= 200) { flow_truncated = true; break; }
                                citem_t* item = *it;

                                if (item->is_expr()) {
                                    cexpr_t* e = static_cast<cexpr_t*>(item);

                                    // 1. Assignments: lhs = rhs
                                    if (e->op == cot_asg || e->op == cot_asgbor || e->op == cot_asgxor ||
                                        e->op == cot_asgband || e->op == cot_asgadd || e->op == cot_asgsub ||
                                        e->op == cot_asgmul || e->op == cot_asgsshr || e->op == cot_asgushr ||
                                        e->op == cot_asgshl) {
                                        bool matched = false;
                                        std::string def_target;

                                        if (e->x && e->x->op == cot_var) {
                                            if (active_lvars.count(e->x->v.idx)) {
                                                const lvars_t* lvs = local_cf->get_lvars();
                                                if (lvs && e->x->v.idx >= 0 && e->x->v.idx < static_cast<int>(lvs->size())) {
                                                    matched = true;
                                                    def_target = (*lvs)[e->x->v.idx].name.c_str();
                                                }
                                            }
                                        } else if (e->x && e->x->op == cot_obj) {
                                            qstring oname;
                                            get_name(&oname, e->x->obj_ea);
                                            std::string obj_name = oname.c_str();
                                            if (active_objs.count(e->x->obj_ea) || (!obj_name.empty() && active_globals.count(obj_name))) {
                                                matched = true;
                                                def_target = obj_name.empty() ? tools::utils::FormatAddress(e->x->obj_ea) : obj_name;
                                            }
                                        } else if (e->x && (e->x->op == cot_ptr || e->x->op == cot_memptr || e->x->op == cot_memref)) {
                                            VarRef base_var;
                                            if (UsesActiveVar(e->x, base_var)) {
                                                flow_arr.push_back({
                                                    {"depth", current_depth},
                                                    {"address", tools::utils::FormatAddress(e->ea)},
                                                    {"type", "member_def"},
                                                    {"target", hexrays_ast::CleanItemText(e->x, local_cf)},
                                                    {"from", hexrays_ast::CleanItemText(e->y, local_cf)},
                                                    {"base_var", base_var.name},
                                                    {"expr", hexrays_ast::CleanItemText(e, local_cf)}
                                                });
                                            }
                                        }

                                        if (matched) {
                                            // Walking backwards, the current assignment kills the value
                                            // being queried. A compound assignment also reads its old LHS.
                                            if (e->x && e->x->op == cot_var) {
                                                active_lvars.erase(e->x->v.idx);
                                            }
                                            std::vector<VarRef> src_vars;
                                            std::vector<std::string> src_globals;
                                            ExtractSources(e->y, src_vars, src_globals);
                                            if (e->op != cot_asg && e->x && e->x->op == cot_var) {
                                                const lvars_t* lvs = local_cf->get_lvars();
                                                int lhs_idx = e->x->v.idx;
                                                if (lvs && lhs_idx >= 0 && lhs_idx < static_cast<int>(lvs->size())) {
                                                    VarRef lhs_ref{ local_cf->entry_ea, lhs_idx, (*lvs)[lhs_idx].name.c_str() };
                                                    if (std::find(src_vars.begin(), src_vars.end(), lhs_ref) == src_vars.end())
                                                        src_vars.push_back(lhs_ref);
                                                }
                                            }

                                            std::vector<std::string> src_var_names;
                                            for (const auto& sv : src_vars) {
                                                sync::Checkpoint();
                                                src_var_names.push_back(sv.name);
                                                active_lvars.insert(sv.lvar_idx);
                                            }
                                            for (const auto& sg : src_globals) {
                                                sync::Checkpoint();
                                                active_globals.insert(sg);
                                            }

                                            nlohmann::ordered_json flow_item = {
                                                {"depth", current_depth},
                                                {"address", tools::utils::FormatAddress(e->ea)},
                                                {"type", "assign_def"},
                                                {"to", def_target},
                                                {"from", hexrays_ast::CleanItemText(e->y, local_cf)},
                                                {"expr", hexrays_ast::CleanItemText(e, local_cf)}
                                            };
                                            if (!src_var_names.empty()) flow_item["sources"] = src_var_names;
                                            if (!src_globals.empty()) flow_item["global_sources"] = src_globals;
                                            flow_arr.push_back(std::move(flow_item));

                                            // If defined by a call, inspect callee return and recurse
                                            if (e->y && e->y->op == cot_call) {
                                                std::string callee_name = hexrays_ast::CleanItemText(e->y->x, local_cf);
                                                ea_t callee_ea = ResolveCallTarget(e->y, local_cf);

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
                                                                std::vector<std::pair<ea_t, const cexpr_t*>> rets;
                                                                bool& truncated;
                                                                size_t max_returns;
                                                                ret_finder_t(const cfunc_t* f, bool& tr, size_t limit)
                                                                    : ctree_visitor_t(CV_FAST), c_cf(f), truncated(tr), max_returns(limit) {}
                                                                int idaapi visit_insn(cinsn_t* in) override {
                                                                    try {
                                                                        sync::Checkpoint();
                                                                        if (in->op == cit_return && in->creturn && in->creturn->expr.op != cot_empty) {
                                                                            if (rets.size() >= max_returns) { truncated = true; return 1; }
                                                                            rets.push_back({in->ea, &in->creturn->expr});
                                                                        }
                                                                        return 0;
                                                                    } catch (...) {
                                                                        sync::SaveCallbackException();
                                                                        return 1;
                                                                    }
                                                                }
                                                            } rf(callee_cf, flow_truncated, 200 - flow_arr.size());
                                                            rf.apply_to(&callee_cf->body, nullptr);
                                                            sync::Checkpoint();

                                                            // Handle ALL returns (no break), decomposing expressions into source vars
                                                            for (const auto& [ret_ea, ret_expr] : rf.rets) {
                                                                sync::Checkpoint();
                                                                if (flow_arr.size() >= 200) { flow_truncated = true; break; }
                                                                std::string ret_str = hexrays_ast::CleanItemText(ret_expr, callee_cf);
                                                                flow_arr.push_back({
                                                                    {"depth", current_depth + 1},
                                                                    {"address", tools::utils::FormatAddress(ret_ea)},
                                                                    {"type", "callee_return_expr"},
                                                                    {"function", callee_name},
                                                                    {"returned", ret_str}
                                                                });

                                                                std::vector<VarRef> ret_src_vars;
                                                                std::vector<std::string> ret_src_globals;
                                                                std::function<void(const cexpr_t*)> walk_ret = [&](const cexpr_t* sub) {
                                                                    sync::Checkpoint();
                                                                    sync::RecursionGuard recursion;
                                                                    if (!sub) return;
                                                                    if (sub->op == cot_var) {
                                                                        const lvars_t* clvs = callee_cf->get_lvars();
                                                                        if (clvs && sub->v.idx >= 0 && sub->v.idx < static_cast<int>(clvs->size())) {
                                                                            VarRef vr{ callee_cf->entry_ea, sub->v.idx, (*clvs)[sub->v.idx].name.c_str() };
                                                                            if (std::find(ret_src_vars.begin(), ret_src_vars.end(), vr) == ret_src_vars.end()) {
                                                                                ret_src_vars.push_back(vr);
                                                                            }
                                                                        }
                                                                    }
                                                                    if (op_uses_x(sub->op) && sub->x) walk_ret(sub->x);
                                                                    if (op_uses_y(sub->op) && sub->y) walk_ret(sub->y);
                                                                    if (op_uses_z(sub->op) && sub->z) walk_ret(sub->z);
                                                                    if (sub->op == cot_call && sub->a) {
                                                                        for (const auto& arg : *sub->a) walk_ret(&arg);
                                                                    }
                                                                };
                                                                walk_ret(ret_expr);

                                                                for (const auto& rv : ret_src_vars) {
                                                                    sync::Checkpoint();
                                                                    if (flow_arr.size() >= 200) { flow_truncated = true; break; }
                                                                    trace_fn(callee_fn, rv, current_depth + 1);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            } else if (e->y && (e->y->op == cot_ptr || e->y->op == cot_memptr || e->y->op == cot_memref)) {
                                                flow_arr.push_back({
                                                    {"depth", current_depth},
                                                    {"address", tools::utils::FormatAddress(e->ea)},
                                                    {"type", "load"},
                                                    {"to", def_target},
                                                    {"source", hexrays_ast::CleanItemText(e->y, local_cf)},
                                                    {"expr", hexrays_ast::CleanItemText(e, local_cf)}
                                                });
                                            } else if (e->y && e->y->op == cot_idx) {
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

                                    // Out-parameter call detection: callee(..., &var, ...)
                                    if (e->op == cot_call && e->a) {
                                        std::string callee_name = hexrays_ast::CleanItemText(e->x, local_cf);
                                        ea_t callee_ea = ResolveCallTarget(e, local_cf);

                                        for (size_t ai = 0; ai < e->a->size(); ++ai) {
                                            sync::Checkpoint();
                                            if (flow_arr.size() >= 200) { flow_truncated = true; break; }
                                            const carg_t& arg = (*e->a)[ai];
                                            const cexpr_t* unwrap_arg = &arg;
                                            if (unwrap_arg->op == cot_cast && unwrap_arg->x) unwrap_arg = unwrap_arg->x;

                                            if (unwrap_arg->op == cot_ref && unwrap_arg->x && unwrap_arg->x->op == cot_var) {
                                                int v_idx = unwrap_arg->x->v.idx;
                                                if (active_lvars.count(v_idx)) {
                                                    const lvars_t* lvs = local_cf->get_lvars();
                                                    std::string used_var = (lvs && v_idx >= 0 && v_idx < static_cast<int>(lvs->size())) ? (*lvs)[v_idx].name.c_str() : "";

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
                                                                int param_lvar_idx = GetArgLvarIdx(callee_cf, ai);
                                                                const lvars_t* callee_lvars = callee_cf->get_lvars();
                                                                if (callee_lvars && param_lvar_idx >= 0 && param_lvar_idx < static_cast<int>(callee_lvars->size())) {
                                                                    VarRef callee_ref{ callee_fn->start_ea, param_lvar_idx, (*callee_lvars)[param_lvar_idx].name.c_str() };
                                                                    trace_fn(callee_fn, callee_ref, current_depth + 1);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // Increment / Decrement
                                    if (e->op == cot_postinc || e->op == cot_postdec || e->op == cot_preinc || e->op == cot_predec) {
                                        VarRef used_var;
                                        if (UsesActiveVar(e->x, used_var)) {
                                            flow_arr.push_back({
                                                {"depth", current_depth},
                                                {"address", tools::utils::FormatAddress(e->ea)},
                                                {"type", (e->op == cot_postinc || e->op == cot_preinc) ? "increment" : "decrement"},
                                                {"var", used_var.name},
                                                {"expr", hexrays_ast::CleanItemText(e, local_cf)}
                                            });
                                        }
                                    }
                                } else {
                                    // Instructions: Guard conditions (if-statements)
                                    const cinsn_t* insn = static_cast<const cinsn_t*>(item);
                                    if (insn->op == cit_if && insn->cif) {
                                        VarRef used_var;
                                        if (UsesActiveVar(&insn->cif->expr, used_var)) {
                                            flow_arr.push_back({
                                                {"depth", current_depth},
                                                {"address", tools::utils::FormatAddress(insn->ea)},
                                                {"type", "guard_condition"},
                                                {"from", used_var.name},
                                                {"condition", hexrays_ast::CleanItemText(&insn->cif->expr, local_cf)}
                                            });
                                        }
                                    }
                                }
                            }

                            // Caller Argument Resolution in Backward direction
                            if (include_calls && current_depth < max_depth) {
                                const lvars_t* fn_lvars = local_cf->get_lvars();
                                if (fn_lvars) {
                                    for (int active_idx : active_lvars) {
                                        sync::Checkpoint();
                                        if (active_idx >= 0 && active_idx < static_cast<int>(fn_lvars->size())) {
                                            const lvar_t& lv = (*fn_lvars)[active_idx];
                                            if (lv.is_arg_var()) {
                                                int param_idx = -1;
                                                for (size_t ai = 0; ai < local_cf->argidx.size(); ++ai) {
                                                    sync::Checkpoint();
                                                    if (local_cf->argidx[ai] == active_idx) {
                                                        param_idx = static_cast<int>(ai);
                                                        break;
                                                    }
                                                }
                                                if (param_idx < 0) {
                                                    int cur_arg = 0;
                                                    for (size_t k = 0; k < static_cast<size_t>(active_idx); ++k) {
                                                        sync::Checkpoint();
                                                        if ((*fn_lvars)[k].is_arg_var()) cur_arg++;
                                                    }
                                                    param_idx = cur_arg;
                                                }

                                                std::set<ea_t> caller_funcs_seen;
                                                xrefblk_t xb;
                                                for (bool ok = xb.first_to(fn->start_ea, XREF_ALL); ok && caller_funcs_seen.size() < 3; ok = xb.next_to()) {
                                                    sync::Checkpoint();
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
                                                        int p_idx;
                                                        std::string p_name;
                                                        std::string c_name;
                                                        int d;
                                                        nlohmann::json& fl;
                                                        bool& truncated;
                                                        std::function<void(func_t*, const VarRef&, int)> r_fn;
                                                        caller_call_finder_t(const cfunc_t* f, ea_t tea, int pi, const std::string& pn, const std::string& cn, int cd, nlohmann::json& flow_arr, bool& tr, std::function<void(func_t*, const VarRef&, int)> rf)
                                                            : ctree_visitor_t(CV_FAST), c_cf(f), target_fn_ea(tea), p_idx(pi), p_name(pn), c_name(cn), d(cd), fl(flow_arr), truncated(tr), r_fn(rf) {}

                                                        int idaapi visit_expr(cexpr_t* ce) override {
                                                            try {
                                                                sync::Checkpoint();
                                                                if (fl.size() >= 200) { truncated = true; return 1; }
                                                                if (ce->op == cot_call && ce->a) {
                                                                    ea_t resolved_target = BADADDR;
                                                                    if (ce->x && ce->x->op == cot_obj) resolved_target = ce->x->obj_ea;
                                                                    if (resolved_target == target_fn_ea && p_idx >= 0 && static_cast<size_t>(p_idx) < ce->a->size()) {
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
                                                                                VarRef caller_ref{ c_cf->entry_ea, passed_arg.v.idx, (*clvs)[passed_arg.v.idx].name.c_str() };
                                                                                r_fn(get_func(c_cf->entry_ea), caller_ref, d + 1);
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                                return 0;
                                                            } catch (...) {
                                                                sync::SaveCallbackException();
                                                                return 1;
                                                            }
                                                        }
                                                    } ccf(caller_cf, fn->start_ea, param_idx, lv.name.c_str(), caller_name, current_depth, flow_arr, flow_truncated, trace_fn);
                                                    ccf.apply_to(&caller_cf->body, nullptr);
                                                    sync::Checkpoint();
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    };

                    trace_fn(pfn, root_var, 0);
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
                std::map<ea_t, nlohmann::json> incoming_edges;
                constexpr size_t MAX_FALLBACK_NODES = 100;
                constexpr size_t MAX_FALLBACK_XREF_VISITS = 50000;
                size_t fallback_xref_visits = 0;
                q.push({start_ea, 0});
                visited.insert(start_ea);

                while (!q.empty()) {
                    sync::Checkpoint();
                    if (flow_arr.size() >= MAX_FALLBACK_NODES) {
                        flow_truncated = true;
                        break;
                    }
                    auto [cur_ea, depth] = q.front();
                    q.pop();

                    qstring name_buf;
                    get_ea_name(&name_buf, cur_ea);

                    nlohmann::json node = {
                        {"depth", depth},
                        {"address", tools::utils::FormatAddress(cur_ea)},
                        {"name", name_buf.c_str()}
                    };
                    auto incoming = incoming_edges.find(cur_ea);
                    if (incoming != incoming_edges.end()) node["edge"] = incoming->second;
                    flow_arr.push_back(std::move(node));

                    if (depth >= max_depth) continue;

                    xrefblk_t xb;
                    bool has_xref = direction == "forward"
                        ? xb.first_from(cur_ea, XREF_DATA)
                        : xb.first_to(cur_ea, XREF_DATA);
                    for (bool ok = has_xref; ok; ok = direction == "forward" ? xb.next_from() : xb.next_to()) {
                        sync::Checkpoint();
                        if (++fallback_xref_visits > MAX_FALLBACK_XREF_VISITS) {
                            flow_truncated = true;
                            break;
                        }
                        const ea_t neighbor = direction == "forward" ? xb.to : xb.from;
                        if (neighbor != BADADDR && is_mapped(neighbor) && visited.find(neighbor) == visited.end()) {
                            if (visited.size() >= MAX_FALLBACK_NODES) {
                                flow_truncated = true;
                                break;
                            }
                            visited.insert(neighbor);
                            q.push({neighbor, depth + 1});
                            incoming_edges[neighbor] = {
                                {"via", "data_xref"},
                                {"from", tools::utils::FormatAddress(direction == "forward" ? cur_ea : neighbor)},
                                {"to", tools::utils::FormatAddress(direction == "forward" ? neighbor : cur_ea)}
                            };
                        }
                    }
                    if (flow_truncated) break;

                    // Pointer dereferences are outgoing edges; do not traverse
                    // them while walking backward through the xref graph.
                    if (direction != "forward") continue;
                    ea_t deref = BADADDR;
                    const size_t ptr_size = inf_is_64bit() ? 8 : 4;
                    segment_t* memory_segment = getseg(cur_ea);
                    if (memory_segment && cur_ea <= BADADDR - ptr_size &&
                        cur_ea + ptr_size <= memory_segment->end_ea) {
                        bool pointer_loaded = true;
                        for (size_t i = 0; i < ptr_size; ++i) {
                            sync::Checkpoint();
                            if (!is_loaded(cur_ea + i)) { pointer_loaded = false; break; }
                        }
                        if (pointer_loaded)
                            deref = inf_is_64bit() ? get_qword(cur_ea) : get_dword(cur_ea);
                    }
                    if (deref != BADADDR && is_mapped(deref) && visited.find(deref) == visited.end()) {
                        if (visited.size() >= MAX_FALLBACK_NODES) {
                            flow_truncated = true;
                            break;
                        }
                        visited.insert(deref);
                        q.push({deref, depth + 1});
                        incoming_edges[deref] = {
                            {"via", "pointer_deref"},
                            {"from", tools::utils::FormatAddress(cur_ea)},
                            {"to", tools::utils::FormatAddress(deref)}
                        };
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
        if (machine_level) {
            res["root"]["address"] = machine_analysis["root_address"];
            machine_analysis.erase("root_address");
            res["analysis"] = std::move(machine_analysis);
        }
        if (flow_truncated) res["truncated"] = true;
        if (machine_level && res["analysis"].value("truncated", false)) res["truncated"] = true;
        return tools::utils::MakeToolSuccessJson(id, res);
    }
}
