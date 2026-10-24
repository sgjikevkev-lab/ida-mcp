#include "api_analysis.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <map>
#include <numeric>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "tools/utils/utils.h"
#include "sync/sync.h"
#include "third_party/rax/include/rax.h"

#include <ida.hpp>
#include <funcs.hpp>
#include <segment.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <typeinf.hpp>

namespace tools::analysis {
    namespace {
        constexpr uint64_t kPage = 0x1000;
        constexpr uint64_t kStackBase = 0x700000000000ULL;
        constexpr uint64_t kStackSize = 0x100000;
        constexpr uint64_t kReturnSentinel = 0x7fff000000001000ULL;
        constexpr uint64_t kDefaultMappedBytes = 64ULL * 1024 * 1024;
        constexpr uint64_t kHardMaxMappedBytes = 256ULL * 1024 * 1024;
        constexpr uint64_t kBufferBase = 0x600000000000ULL;
        constexpr size_t kMaxSyntheticBytes = 1024 * 1024;
        constexpr uint64_t kMaxInstructions = 5'000'000;
        constexpr uint64_t kMaxTimeoutMs = 30ULL * 60 * 1000;
        constexpr size_t kMaxArguments = 64;
        constexpr size_t kMaxMemoryChanges = 128;
        constexpr size_t kMaxChangedBytes = 16 * 1024;

        struct EngineGuard {
            rax_engine* engine = nullptr;
            ~EngineGuard() { if (engine) rax_engine_close(engine); }
        };

        std::string Hex64(uint64_t value) {
            char text[19]{};
            qsnprintf(text, sizeof(text), "0x%llx", static_cast<unsigned long long>(value));
            return text;
        }

        bool ReadUnsigned(const nlohmann::json& value, uint64_t& out) {
            try {
                if (value.is_number_unsigned()) { out = value.get<uint64_t>(); return true; }
                if (value.is_number_integer()) {
                    const int64_t signed_value = value.get<int64_t>();
                    out = static_cast<uint64_t>(signed_value);
                    return true;
                }
                if (!value.is_string()) return false;
                std::string text = value.get<std::string>();
                if (text.empty() || text.size() > 32) return false;
                size_t consumed = 0;
                out = std::stoull(text, &consumed, 0);
                return consumed == text.size();
            } catch (...) { return false; }
        }

        struct CallArgument {
            uint64_t value = 0;
            bool floating = false;
            double floating_value = 0.0;
            size_t float_width = 8;
            std::array<uint8_t, 8> float_bytes{};
            std::vector<uint8_t> buffer;
            bool has_buffer = false;
        };

        struct StubWrite { uint64_t address = 0; std::vector<uint8_t> bytes; };
        struct CallStub {
            uint64_t address = 0;
            uint64_t return_value = 0;
            std::vector<StubWrite> writes;
            size_t calls = 0;
            size_t write_failures = 0;
        };

        struct ExecutionControl {
            uint64_t code_callbacks = 0;
            bool cancelled = false;
            bool timed_out = false;
        };

        void CheckOperation(rax_engine* engine, uint64_t, uint32_t, void* user) {
            auto* control = static_cast<ExecutionControl*>(user);
            if (!control || (++control->code_callbacks & 0xFF) != 0) return;
            try {
                sync::Checkpoint();
            } catch (const sync::OperationStopped& stopped) {
                control->timed_out = stopped.timed_out;
                control->cancelled = !stopped.timed_out;
                rax_emu_stop(engine);
            } catch (...) {
                control->cancelled = true;
                rax_emu_stop(engine);
            }
        }

        void ApplyCallStub(rax_engine* engine, uint64_t, uint32_t, void* user) {
            auto* stub = static_cast<CallStub*>(user);
            if (!stub) return;
            ++stub->calls;
            for (const auto& write : stub->writes)
                if (!write.bytes.empty() && rax_mem_write(engine, write.address, write.bytes.data(), write.bytes.size()) != RAX_OK)
                    ++stub->write_failures;
            uint64_t return_address = 0, rsp = 0;
            if (rax_reg_read_u64(engine, RAX_X86_REG_RSP, &rsp) != RAX_OK ||
                rax_mem_read(engine, rsp, &return_address, sizeof(return_address)) != RAX_OK) {
                rax_emu_stop(engine);
                return;
            }
            rax_reg_write_u64(engine, RAX_X86_REG_RAX, stub->return_value);
            rax_reg_write_u64(engine, RAX_X86_REG_RSP, rsp + sizeof(uint64_t));
            rax_reg_write_u64(engine, RAX_X86_REG_RIP, return_address);
        }

        bool DecodeHex(const std::string& input, std::vector<uint8_t>& bytes) {
            if ((input.size() & 1) != 0 || input.size() > kMaxSyntheticBytes * 2) return false;
            auto digit = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            bytes.reserve(input.size() / 2);
            for (size_t i = 0; i < input.size(); i += 2) {
                const int hi = digit(input[i]), lo = digit(input[i + 1]);
                if (hi < 0 || lo < 0) return false;
                bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
            }
            return true;
        }

        bool ReadOneArg(const nlohmann::json& item, size_t i, CallArgument& arg, std::string& error) {
                if (item.is_null()) return true;
                if (item.is_boolean()) { arg.value = item.get<bool>() ? 1 : 0; return true; }
                if (item.is_number_float()) {
                    arg.floating = true;
                    arg.floating_value = item.get<double>();
                    return true;
                }
                if (ReadUnsigned(item, arg.value)) {
                    return true;
                }
                if (item.is_string()) {
                    const std::string address = item.get<std::string>();
                    const ea_t ea = tools::utils::ParseAddress(address);
                    if (ea != BADADDR) { arg.value = ea; return true; }
                }
                if (!item.is_object() || item.size() != 1) {
                    error = "arguments[" + std::to_string(i) + "] must be an integer, address, float, or buffer object";
                    return false;
                }
                if (item.contains("address") && item["address"].is_string()) {
                    const std::string address = item["address"].get<std::string>();
                    ea_t ea = tools::utils::ParseAddress(address);
                    if (ea == BADADDR) {
                        error = "arguments[" + std::to_string(i) + "].address does not resolve to an IDB address";
                        return false;
                    }
                    arg.value = ea;
                } else if (item.contains("utf8") && item["utf8"].is_string()) {
                    const std::string text = item["utf8"].get<std::string>();
                    arg.buffer.assign(text.begin(), text.end());
                    arg.buffer.push_back(0);
                    arg.has_buffer = true;
                } else if (item.contains("bytes") && item["bytes"].is_string()) {
                    if (!DecodeHex(item["bytes"].get<std::string>(), arg.buffer)) {
                        error = "arguments[" + std::to_string(i) + "].bytes must be bounded, even-length hex";
                        return false;
                    }
                    arg.has_buffer = true;
                } else if (item.contains("zero_bytes")) {
                    uint64_t size = 0;
                    if (!ReadUnsigned(item["zero_bytes"], size) || size > kMaxSyntheticBytes) {
                        error = "arguments[" + std::to_string(i) + "].zero_bytes must be between 0 and 1048576";
                        return false;
                    }
                    arg.buffer.assign(static_cast<size_t>(size), 0);
                    arg.has_buffer = true;
                } else if (item.contains("float32") || item.contains("float64")) {
                    const auto& number = item.begin().value();
                    if (!number.is_number()) {
                        error = "floating arguments must contain a numeric value";
                        return false;
                    }
                    arg.floating = true;
                    arg.float_width = item.contains("float32") ? 4 : 8;
                    arg.floating_value = number.get<double>();
                } else {
                    error = "unsupported argument object at index " + std::to_string(i);
                    return false;
                }
                return true;
        }

        bool ReadArgs(const nlohmann::json& value, std::vector<CallArgument>& out,
                      const func_type_data_t* prototype, std::string& error) {
            if (prototype && prototype->size() > kMaxArguments) {
                error = "Function prototype has more than 64 parameters";
                return false;
            }
            const size_t count = prototype ? prototype->size() : 0;
            if (!value.is_array() && !value.is_object()) {
                error = "arguments must be an array or an object keyed by prototype parameter name";
                return false;
            }
            if (value.is_object()) {
                if (!prototype) {
                    error = "Named arguments require a function prototype in IDA";
                    return false;
                }
                out.resize(count);
                std::set<std::string> used;
                for (auto it = value.begin(); it != value.end(); ++it) {
                    size_t index = count;
                    for (size_t i = 0; i < count; ++i) {
                        const std::string param_name = (*prototype)[i].name.c_str();
                        if (!param_name.empty() && param_name == it.key()) { index = i; break; }
                    }
                    if (index == count || !used.insert(it.key()).second) {
                        error = "Unknown parameter name in arguments: " + it.key();
                        return false;
                    }
                    if (!ReadOneArg(it.value(), index, out[index], error)) return false;
                }
            } else {
                if (value.size() > kMaxArguments || (prototype && value.size() > count)) {
                    error = prototype ? "arguments contains more values than the function prototype" : "arguments must contain at most 64 values";
                    return false;
                }
                out.resize(std::max(count, value.size()));
                for (size_t i = 0; i < value.size(); ++i)
                    if (!ReadOneArg(value[i], i, out[i], error)) return false;
            }
            if (prototype) {
                for (size_t i = 0; i < count; ++i) {
                    const bool is_float = (*prototype)[i].type.is_floating();
                    if (is_float && !out[i].has_buffer) {
                        if (!out[i].floating) out[i].floating_value = static_cast<double>(static_cast<int64_t>(out[i].value));
                        const size_t width = (*prototype)[i].type.get_size();
                        if (width != 4 && width != 8) {
                            error = "Only 32-bit and 64-bit floating parameters are supported";
                            return false;
                        }
                        out[i].floating = true;
                        out[i].float_width = width;
                    } else if (!is_float && out[i].floating) {
                        error = "A floating-point value was supplied for a non-floating parameter";
                        return false;
                    }
                    if ((*prototype)[i].type.is_ptr() && !out[i].has_buffer && out[i].value == 0 && value.is_array() && i >= value.size())
                        continue; // missing pointer parameters are explicitly NULL
                    if (out[i].has_buffer && !(*prototype)[i].type.is_ptr() && (*prototype)[i].type.get_size() <= 8) {
                        error = "Buffer arguments require a pointer parameter or a by-value parameter wider than 8 bytes";
                        return false;
                    }
                    if ((*prototype)[i].type.get_size() > 8 && !out[i].has_buffer) {
                        error = "By-value parameters wider than 8 bytes require an explicit guest buffer";
                        return false;
                    }
                }
            }
            for (auto& arg : out) {
                if (!arg.floating) continue;
                if (arg.float_width == 4) {
                    const float f = static_cast<float>(arg.floating_value);
                    std::memcpy(arg.float_bytes.data(), &f, sizeof(f));
                } else {
                    const double d = arg.floating_value;
                    std::memcpy(arg.float_bytes.data(), &d, sizeof(d));
                }
            }
            return true;
        }

        uint32_t SegmentPermissions(const segment_t* seg) {
            uint32_t result = RAX_PROT_READ | RAX_PROT_WRITE;
            if (seg && (seg->perm & SEGPERM_EXEC) != 0) result |= RAX_PROT_EXEC;
            return result;
        }

        const char* StopReason(int reason) {
            switch (reason) {
                case RAX_STOP_UNTIL: return "returned";
                case RAX_STOP_COUNT: return "instruction_limit";
                case RAX_STOP_TIMEOUT: return "timeout";
                case RAX_STOP_STOPPED: return "stopped";
                case RAX_STOP_HLT: return "halted";
                case RAX_STOP_IO_IN: return "unhandled_port_input";
                case RAX_STOP_IO_OUT: return "unhandled_port_output";
                case RAX_STOP_MMIO_READ: return "unhandled_mmio_read";
                case RAX_STOP_MMIO_WRITE: return "unhandled_mmio_write";
                case RAX_STOP_EXCEPTION: return "exception";
                case RAX_STOP_DEBUG: return "debug_event";
                case RAX_STOP_SYSCALL: return "syscall";
                case RAX_STOP_ERROR: return "emulator_error";
                default: return "unknown_stop";
            }
        }
    }

    nlohmann::json ApiAnalysis::EmulateFunction(const nlohmann::json& id, const nlohmann::json& args) {
        if (!inf_is_64bit())
            return tools::utils::MakeToolErrorJson(id, "emulate_function currently supports x86-64 IDBs only", "unsupported_architecture");
        if (!args.contains("addr") || !args["addr"].is_string())
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' must be a function name or address string", "invalid_addr");

        const std::string address_text = args["addr"].get<std::string>();
        if (address_text.size() > 4096)
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' is too long", "invalid_addr");
        ea_t ea = tools::utils::ParseAddress(address_text);
        func_t* function = ea == BADADDR ? nullptr : get_func(ea);
        if (!function)
            return tools::utils::MakeToolErrorJson(id, "Address is not inside a recognized function", "function_not_found");

        tinfo_t function_type;
        func_type_data_t function_details;
        const bool has_prototype = get_tinfo(&function_type, function->start_ea) &&
            function_type.get_func_details(&function_details);
        if (has_prototype && function_details.is_vararg_cc())
            return tools::utils::MakeToolErrorJson(id, "Variadic function prototypes are not supported by emulate_function", "unsupported_prototype");
        if (has_prototype && function_details.is_user_cc())
            return tools::utils::MakeToolErrorJson(id, "Custom __usercall prototypes need explicit register-location support", "unsupported_prototype");

        std::vector<CallArgument> arguments;
        std::string parse_error;
        const nlohmann::json empty_arguments = nlohmann::json::array();
        const auto& raw_arguments = args.contains("arguments") ? args["arguments"] : empty_arguments;
        if (!ReadArgs(raw_arguments, arguments, has_prototype ? &function_details : nullptr, parse_error))
            return tools::utils::MakeToolErrorJson(id, parse_error, "invalid_arguments");

        std::vector<CallStub> call_stubs;
        size_t stub_write_bytes = 0;
        if (args.contains("call_stubs")) {
            if (!args["call_stubs"].is_array() || args["call_stubs"].size() > 64)
                return tools::utils::MakeToolErrorJson(id, "call_stubs must be an array with at most 64 entries", "invalid_call_stubs");
            for (size_t i = 0; i < args["call_stubs"].size(); ++i) {
                const auto& item = args["call_stubs"][i];
                uint64_t stub_address = 0, return_value = 0;
                if (!item.is_object() || !item.contains("addr") || !item["addr"].is_string())
                    return tools::utils::MakeToolErrorJson(id, "Each call stub needs an addr function name or address", "invalid_call_stubs");
                const std::string stub_address_text = item["addr"].get<std::string>();
                ea_t resolved = tools::utils::ParseAddress(stub_address_text);
                stub_address = resolved == BADADDR ? 0 : resolved;
                if (stub_address == 0 ||
                    (item.contains("return") && !ReadUnsigned(item["return"], return_value)))
                    return tools::utils::MakeToolErrorJson(id, "Call stub address or return value is invalid", "invalid_call_stubs");
                CallStub stub;
                stub.address = stub_address;
                stub.return_value = return_value;
                if (item.contains("mem_writes")) {
                    if (!item["mem_writes"].is_array() || item["mem_writes"].size() > 32)
                        return tools::utils::MakeToolErrorJson(id, "Each stub may contain at most 32 memory writes", "invalid_call_stubs");
                    for (const auto& write_json : item["mem_writes"]) {
                        uint64_t write_address = 0;
                        std::vector<uint8_t> bytes;
                        if (!write_json.is_object() || !write_json.contains("addr") || !write_json["addr"].is_string() ||
                            !write_json.contains("bytes") || !write_json["bytes"].is_string())
                            return tools::utils::MakeToolErrorJson(id, "Stub memory writes require addr and hex bytes", "invalid_call_stubs");
                        const std::string write_address_text = write_json["addr"].get<std::string>();
                        ea_t write_ea = tools::utils::ParseAddress(write_address_text);
                        if (write_ea == BADADDR || !DecodeHex(write_json["bytes"].get<std::string>(), bytes) || bytes.size() > 4096)
                            return tools::utils::MakeToolErrorJson(id, "Stub memory write has an invalid address or payload", "invalid_call_stubs");
                        write_address = write_ea;
                        stub_write_bytes += bytes.size();
                        if (stub_write_bytes > 64 * 1024)
                            return tools::utils::MakeToolErrorJson(id, "Call stub writes exceed the 64 KiB per-call limit", "invalid_call_stubs");
                        stub.writes.push_back({write_address, std::move(bytes)});
                    }
                }
                for (const auto& prior : call_stubs)
                    if (prior.address == stub.address)
                        return tools::utils::MakeToolErrorJson(id, "Duplicate call stub address", "invalid_call_stubs");
                call_stubs.push_back(std::move(stub));
            }
        }

        uint64_t max_instructions = 100'000;
        uint64_t timeout_ms = 5'000;
        uint64_t max_memory_bytes = kDefaultMappedBytes;
        if (args.contains("max_instructions") && !ReadUnsigned(args["max_instructions"], max_instructions))
            return tools::utils::MakeToolErrorJson(id, "max_instructions must be an integer", "invalid_limit");
        if (args.contains("timeout_ms") && !ReadUnsigned(args["timeout_ms"], timeout_ms))
            return tools::utils::MakeToolErrorJson(id, "timeout_ms must be an integer", "invalid_limit");
        if (args.contains("max_memory_bytes") && !ReadUnsigned(args["max_memory_bytes"], max_memory_bytes))
            return tools::utils::MakeToolErrorJson(id, "max_memory_bytes must be an integer", "invalid_limit");
        if (max_instructions == 0 || max_instructions > kMaxInstructions)
            return tools::utils::MakeToolErrorJson(id, "max_instructions must be between 1 and 5000000", "invalid_limit");
        if (timeout_ms == 0 || timeout_ms > kMaxTimeoutMs)
            return tools::utils::MakeToolErrorJson(id, "timeout_ms must be between 1 and 1800000", "invalid_limit");
        if (max_memory_bytes < 4ULL * 1024 * 1024 || max_memory_bytes > kHardMaxMappedBytes)
            return tools::utils::MakeToolErrorJson(id, "max_memory_bytes must be between 4194304 and 268435456", "invalid_limit");

        std::map<uint64_t, uint32_t> pages;
        std::vector<segment_t*> segments;
        for (int index = 0; index < get_segm_qty(); ++index) {
            sync::Checkpoint();
            segment_t* seg = getnseg(index);
            if (!seg || seg->start_ea >= seg->end_ea || seg->end_ea == BADADDR) continue;
            const uint64_t lo = static_cast<uint64_t>(seg->start_ea) & ~(kPage - 1);
            const uint64_t hi = (static_cast<uint64_t>(seg->end_ea - 1) & ~(kPage - 1)) + kPage;
            if (hi < lo || hi - lo > max_memory_bytes)
                return tools::utils::MakeToolErrorJson(id, "An IDB segment exceeds the selected guest-memory limit", "memory_limit");
            for (uint64_t page = lo; page < hi; page += kPage) pages[page] |= SegmentPermissions(seg);
            segments.push_back(seg);
        }
        if (pages.empty())
            return tools::utils::MakeToolErrorJson(id, "IDB has no mapped memory segments", "memory_unavailable");
        uint64_t buffer_cursor = kBufferBase;
        size_t synthetic_size = 0;
        std::vector<uint64_t> buffer_addresses(arguments.size(), 0);
        for (size_t i = 0; i < arguments.size(); ++i) {
            if (!arguments[i].has_buffer) continue;
            synthetic_size += std::max<size_t>(arguments[i].buffer.size(), 1);
        if (synthetic_size > kMaxSyntheticBytes)
                return tools::utils::MakeToolErrorJson(id, "Input buffers exceed the 1 MiB per-call limit", "memory_limit");
            buffer_cursor = (buffer_cursor + 15) & ~uint64_t(15);
            buffer_addresses[i] = buffer_cursor;
            const uint64_t size = std::max<size_t>(arguments[i].buffer.size(), 1);
            const uint64_t lo = buffer_cursor & ~(kPage - 1);
            const uint64_t hi = ((buffer_cursor + size - 1) & ~(kPage - 1)) + kPage;
            for (uint64_t page = lo; page < hi; page += kPage) {
                if (pages.contains(page))
                    return tools::utils::MakeToolErrorJson(id, "Synthetic buffer address overlaps an IDB segment", "memory_map_failed");
                pages[page] |= RAX_PROT_READ | RAX_PROT_WRITE;
            }
            buffer_cursor += size;
        }
        for (const auto& stub : call_stubs) {
            const uint64_t page = stub.address & ~(kPage - 1);
            pages[page] |= RAX_PROT_READ | RAX_PROT_WRITE | RAX_PROT_EXEC;
        }
        if (pages.size() * kPage + kStackSize > max_memory_bytes)
            return tools::utils::MakeToolErrorJson(id, "IDB segments, input buffers, and stack exceed max_memory_bytes", "memory_limit");
        for (uint64_t page = kStackBase; page < kStackBase + kStackSize; page += kPage)
            if (pages.contains(page))
                return tools::utils::MakeToolErrorJson(id, "Private stack address overlaps an IDB segment or input buffer", "memory_map_failed");
        uint64_t return_sentinel = kReturnSentinel;
        while (pages.contains(return_sentinel & ~(kPage - 1))) {
            if (return_sentinel < kPage) return tools::utils::MakeToolErrorJson(id, "Could not reserve a return sentinel address", "memory_map_failed");
            return_sentinel -= kPage;
        }

        EngineGuard guard;
        rax_engine_config config{};
        config.size = sizeof(config);
        config.arch = RAX_ARCH_X86;
        config.mode = RAX_MODE_64 | RAX_MODE_USER;
        config.backend = RAX_BACKEND_EMULATOR;
        config.flags = RAX_OPEN_NO_DEFAULT_STATE;
        rax_status status = rax_engine_open_config(&config, &guard.engine);
        if (status != RAX_OK || !guard.engine)
            return tools::utils::MakeToolErrorJson(id, std::string("Could not create RAX engine: ") + rax_strerror(status), "emulator_unavailable");

        for (auto it = pages.begin(); it != pages.end();) {
            sync::Checkpoint();
            const uint64_t start = it->first;
            uint64_t end = start + kPage;
            uint32_t perms = it->second;
            auto next = std::next(it);
            while (next != pages.end() && next->first == end) {
                end += kPage;
                perms |= next->second;
                ++next;
            }
            status = rax_mem_map(guard.engine, start, end - start, perms);
            if (status != RAX_OK)
                return tools::utils::MakeToolErrorJson(id, std::string("Could not map IDB memory into RAX: ") + rax_strerror(status), "memory_map_failed");
            it = next;
        }

        for (size_t i = 0; i < arguments.size(); ++i) {
            if (!arguments[i].has_buffer) continue;
            if (!arguments[i].buffer.empty() && rax_mem_write(guard.engine, buffer_addresses[i],
                    arguments[i].buffer.data(), arguments[i].buffer.size()) != RAX_OK)
                return tools::utils::MakeToolErrorJson(id, "Could not initialize an input buffer", "emulator_setup_failed");
        }

        struct SegmentCopy { ea_t start; size_t size; std::vector<uint8_t> before; };
        std::vector<SegmentCopy> originals;
        for (segment_t* seg : segments) {
            sync::Checkpoint();
            const uint64_t size64 = static_cast<uint64_t>(seg->end_ea - seg->start_ea);
            if (size64 == 0 || size64 > max_memory_bytes) continue;
            SegmentCopy copy{seg->start_ea, static_cast<size_t>(size64), std::vector<uint8_t>(static_cast<size_t>(size64), 0)};
            const ssize_t read_size = get_bytes(copy.before.data(), static_cast<ssize_t>(copy.before.size()), copy.start, GMB_READALL);
            if (read_size != static_cast<ssize_t>(copy.before.size()))
                return tools::utils::MakeToolErrorJson(id, "Could not read the full IDB segment into guest memory", "memory_copy_failed");
            status = rax_mem_write(guard.engine, copy.start, copy.before.data(), copy.before.size());
            if (status != RAX_OK)
                return tools::utils::MakeToolErrorJson(id, std::string("Could not copy IDB segment into guest memory: ") + rax_strerror(status), "memory_copy_failed");
            originals.push_back(std::move(copy));
        }

        status = rax_mem_map(guard.engine, kStackBase, kStackSize, RAX_PROT_READ | RAX_PROT_WRITE);
        if (status != RAX_OK)
            return tools::utils::MakeToolErrorJson(id, std::string("Could not map guest stack: ") + rax_strerror(status), "memory_map_failed");
        std::vector<uint32_t> hook_ids;
        hook_ids.reserve(call_stubs.size() + 1);
        ExecutionControl execution_control;
        uint32_t operation_hook_id = 0;
        if (rax_hook_add_code(guard.engine, 1, 0, CheckOperation, &execution_control, &operation_hook_id) != RAX_OK)
            return tools::utils::MakeToolErrorJson(id, "Could not register execution cancellation hook", "emulator_setup_failed");
        hook_ids.push_back(operation_hook_id);
        for (auto& stub : call_stubs) {
            uint32_t hook_id = 0;
            if (rax_hook_add_code(guard.engine, stub.address, stub.address, ApplyCallStub, &stub, &hook_id) != RAX_OK)
                return tools::utils::MakeToolErrorJson(id, "Could not register call stubs", "emulator_setup_failed");
            hook_ids.push_back(hook_id);
        }

        const uint64_t rsp = (kStackBase + kStackSize - 0x100) & ~uint64_t(0xF);
        const uint64_t entry_rsp = rsp + 8; // Windows x64 function-entry alignment.
        status = rax_mem_write(guard.engine, entry_rsp, &return_sentinel, sizeof(return_sentinel));
        if (status != RAX_OK ||
            rax_reg_write_u64(guard.engine, RAX_X86_REG_RSP, entry_rsp) != RAX_OK ||
            rax_reg_write_u64(guard.engine, RAX_X86_REG_RCX, arguments.size() > 0 ? (arguments[0].has_buffer ? buffer_addresses[0] : arguments[0].value) : 0) != RAX_OK ||
            rax_reg_write_u64(guard.engine, RAX_X86_REG_RDX, arguments.size() > 1 ? (arguments[1].has_buffer ? buffer_addresses[1] : arguments[1].value) : 0) != RAX_OK ||
            rax_reg_write_u64(guard.engine, RAX_X86_REG_R8, arguments.size() > 2 ? (arguments[2].has_buffer ? buffer_addresses[2] : arguments[2].value) : 0) != RAX_OK ||
            rax_reg_write_u64(guard.engine, RAX_X86_REG_R9, arguments.size() > 3 ? (arguments[3].has_buffer ? buffer_addresses[3] : arguments[3].value) : 0) != RAX_OK)
            return tools::utils::MakeToolErrorJson(id, "Could not initialize the Windows x64 call frame", "emulator_setup_failed");
        static constexpr std::array<int, 4> arg_regs = {
            RAX_X86_REG_RCX, RAX_X86_REG_RDX, RAX_X86_REG_R8, RAX_X86_REG_R9
        };
        for (size_t i = 0; i < std::min<size_t>(4, arguments.size()); ++i) {
            if (!arguments[i].floating) continue;
            std::array<uint8_t, 16> xmm{};
            std::copy(arguments[i].float_bytes.begin(), arguments[i].float_bytes.end(), xmm.begin());
            if (rax_reg_write(guard.engine, RAX_X86_XMM(static_cast<int>(i)), xmm.data()) != RAX_OK)
                return tools::utils::MakeToolErrorJson(id, "Could not initialize floating-point argument registers", "emulator_setup_failed");
        }
        for (size_t i = 4; i < arguments.size(); ++i) {
            const uint64_t stack_arg = entry_rsp + 0x28 + (i - 4) * sizeof(uint64_t);
            uint64_t value = arguments[i].has_buffer ? buffer_addresses[i] : arguments[i].value;
            if (arguments[i].floating) std::memcpy(&value, arguments[i].float_bytes.data(), sizeof(value));
            if (rax_mem_write(guard.engine, stack_arg, &value, sizeof(value)) != RAX_OK)
                return tools::utils::MakeToolErrorJson(id, "Could not write stack arguments", "emulator_setup_failed");
        }
        for (size_t i = 0; i < std::min<size_t>(4, arguments.size()); ++i) {
            if (arguments[i].floating) continue;
            if (rax_reg_write_u64(guard.engine, arg_regs[i], arguments[i].has_buffer ? buffer_addresses[i] : arguments[i].value) != RAX_OK)
                return tools::utils::MakeToolErrorJson(id, "Could not initialize integer argument registers", "emulator_setup_failed");
        }
        status = rax_emu_start(guard.engine, function->start_ea, return_sentinel,
            timeout_ms * 1000, max_instructions);
        rax_exit exit{};
        const rax_status exit_status = rax_emu_last_exit(guard.engine, &exit);
        uint64_t return_value = 0, final_pc = 0;
        rax_reg_read_u64(guard.engine, RAX_X86_REG_RAX, &return_value);
        rax_reg_read_u64(guard.engine, RAX_X86_REG_RIP, &final_pc);

        nlohmann::json changed = nlohmann::json::array();
        size_t changed_bytes = 0;
        bool changes_truncated = false;
        for (const auto& copy : originals) {
            sync::Checkpoint();
            std::vector<uint8_t> after(copy.size, 0);
            if (rax_mem_read(guard.engine, copy.start, after.data(), after.size()) != RAX_OK) continue;
            size_t pos = 0;
            while (pos < copy.size) {
                if (after[pos] == copy.before[pos]) { ++pos; continue; }
                const size_t begin = pos;
                while (pos < copy.size && after[pos] != copy.before[pos]) ++pos;
                const size_t length = pos - begin;
                if (changed.size() >= kMaxMemoryChanges || changed_bytes + length > kMaxChangedBytes) {
                    changes_truncated = true;
                    continue;
                }
                std::string bytes;
                bytes.reserve(length * 2);
                static constexpr char digits[] = "0123456789abcdef";
                for (size_t i = begin; i < pos; ++i) {
                    bytes.push_back(digits[after[i] >> 4]);
                    bytes.push_back(digits[after[i] & 0xF]);
                }
                changed.push_back({{"address", Hex64(static_cast<uint64_t>(copy.start) + begin)},
                    {"size", length}, {"bytes", std::move(bytes)}});
                changed_bytes += length;
            }
        }

        const char* reason = execution_control.timed_out ? "execution_timeout" :
            execution_control.cancelled ? "cancelled" :
            exit_status == RAX_OK ? StopReason(exit.reason) : "emulator_error";
        nlohmann::json result = {
            {"address", Hex64(function->start_ea)},
            {"outcome", reason},
            {"returned", exit_status == RAX_OK && exit.reason == RAX_STOP_UNTIL},
            {"instructions", rax_emu_icount(guard.engine)},
            {"stopped_at", Hex64(final_pc)},
            {"mapped_bytes", pages.size() * kPage + kStackSize}
        };
        if (!has_prototype || !function_details.rettype.is_floating())
            result["return_value"] = Hex64(return_value);
        if (!changed.empty()) result["memory_writes"] = std::move(changed);
        nlohmann::json modeled_calls = nlohmann::json::array();
        size_t stub_write_failures = 0;
        for (const auto& stub : call_stubs) {
            if (stub.calls != 0) modeled_calls.push_back({{"address", Hex64(stub.address)}, {"calls", stub.calls}, {"return_value", Hex64(stub.return_value)}});
            stub_write_failures += stub.write_failures;
        }
        if (!modeled_calls.empty()) result["modeled_calls"] = std::move(modeled_calls);
        if (stub_write_failures != 0) result["call_stub_write_failures"] = stub_write_failures;
        nlohmann::json buffer_results = nlohmann::json::array();
        size_t buffer_output_bytes = 0;
        for (size_t i = 0; i < arguments.size(); ++i) {
            if (!arguments[i].has_buffer) continue;
            const size_t size = arguments[i].buffer.size();
            const size_t copied = std::min<size_t>(size, kMaxChangedBytes - std::min(buffer_output_bytes, kMaxChangedBytes));
            std::vector<uint8_t> bytes(copied, 0);
            if (copied != 0) rax_mem_read(guard.engine, buffer_addresses[i], bytes.data(), copied);
            std::string hex;
            hex.reserve(copied * 2);
            static constexpr char digits[] = "0123456789abcdef";
            for (uint8_t byte : bytes) { hex.push_back(digits[byte >> 4]); hex.push_back(digits[byte & 0xF]); }
            buffer_results.push_back({{"argument", i}, {"address", Hex64(buffer_addresses[i])},
                {"size", size}, {"bytes", std::move(hex)}});
            buffer_output_bytes += copied;
        }
        if (!buffer_results.empty()) result["buffers"] = std::move(buffer_results);
        if (std::any_of(arguments.begin(), arguments.end(), [](const CallArgument& arg) {
                return arg.has_buffer && arg.buffer.size() > kMaxChangedBytes;
            }) || std::accumulate(arguments.begin(), arguments.end(), size_t{0}, [](size_t total, const CallArgument& arg) {
                return total + (arg.has_buffer ? arg.buffer.size() : 0);
            }) > kMaxChangedBytes) result["buffers_truncated"] = true;
        if (has_prototype && function_details.rettype.is_floating()) {
            std::array<uint8_t, 16> xmm0{};
            size_t xmm_size = 0;
            size_t size = function_details.rettype.get_size();
            if (size > 0 && size <= xmm0.size() &&
                rax_reg_read(guard.engine, RAX_X86_XMM(0), xmm0.data(), &xmm_size) == RAX_OK && xmm_size >= size) {
                std::string hex;
                static constexpr char digits[] = "0123456789abcdef";
                for (size_t i = 0; i < size; ++i) { hex.push_back(digits[xmm0[i] >> 4]); hex.push_back(digits[xmm0[i] & 0xF]); }
                nlohmann::json floating = {{"register", "xmm0"}};
                if (size == sizeof(float)) {
                    float value = 0.0f;
                    std::memcpy(&value, xmm0.data(), sizeof(value));
                    if (std::isfinite(value)) floating["value"] = value;
                } else if (size == sizeof(double)) {
                    double value = 0.0;
                    std::memcpy(&value, xmm0.data(), sizeof(value));
                    if (std::isfinite(value)) floating["value"] = value;
                }
                floating["bytes"] = std::move(hex);
                result["floating_return"] = std::move(floating);
            }
        }
        if (changes_truncated) result["memory_writes_truncated"] = true;
        if (exit_status != RAX_OK) {
            result["error_code"] = "emulation_failed";
            result["message"] = rax_strerror(status);
            result["rax_status"] = static_cast<int>(status);
            if (exit_status == RAX_OK && exit.reason == RAX_STOP_ERROR)
                result["message"] = rax_strerror(exit.status);
            rax_fault_info fault{};
            fault.struct_size = sizeof(fault);
            fault.version = RAX_FAULT_INFO_VERSION;
            if (rax_emu_last_fault(guard.engine, &fault) == RAX_OK && fault.kind != RAX_FAULT_NONE) {
                result["fault"] = {{"kind", fault.kind}, {"pc", Hex64(fault.pc)},
                    {"retired_instructions", fault.retired_instructions}};
                if ((fault.flags & RAX_FAULT_ADDRESS_VALID) != 0) result["fault"]["address"] = Hex64(fault.address);
                if (fault.size != 0) result["fault"]["size"] = fault.size;
                if (fault.access == RAX_FAULT_ACCESS_READ) result["fault"]["access"] = "read";
                else if (fault.access == RAX_FAULT_ACCESS_WRITE) result["fault"]["access"] = "write";
                else if (fault.access == RAX_FAULT_ACCESS_FETCH) result["fault"]["access"] = "execute";
            }
        } else if (exit.reason == RAX_STOP_EXCEPTION) {
            result["exception"] = {{"vector", exit.intno}, {"address", Hex64(exit.address)}};
        }
        return tools::utils::MakeToolResultJson(id, result, false);
    }
}
