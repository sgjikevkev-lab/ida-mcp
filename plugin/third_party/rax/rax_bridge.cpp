#include "rax_bridge.h"

#include <algorithm>
#include <array>
#include <iomanip>
#include <sstream>

#include "include/rax.h"

namespace tools::rax {
    namespace {
        using AnalyzeFn = decltype(&rax_analyze);
        using StrErrorFn = decltype(&rax_strerror);
        using VersionFn = decltype(&rax_version);

        struct Api {
            AnalyzeFn analyze = &rax_analyze;
            StrErrorFn strerror = &rax_strerror;
            VersionFn version = &rax_version;
            std::string error;
        };

        Api& GetApi() {
            static Api api = [] {
                Api result;
                uint32_t major = 0, minor = 0, patch = 0;
                result.version(&major, &minor, &patch);
                (void)patch;
                if (major != RAX_API_MAJOR || minor < RAX_API_MINOR) {
                    result.error = "Statically linked RAX C API version is incompatible with the bundled header";
                    result.analyze = nullptr;
                    result.strerror = nullptr;
                    result.version = nullptr;
                }
                return result;
            }();
            return api;
        }

        std::string Hex(uint64_t value) {
            std::ostringstream out;
            out << "0x" << std::hex << std::nouppercase << value;
            return out.str();
        }

        std::string RegisterName(int32_t reg) {
            if (reg < 0) return {};
            static constexpr std::array<const char*, 32> gpr64 = {
                "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
                "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31"
            };
            static constexpr std::array<const char*, 8> gpr32 = {
                "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"
            };
            static constexpr std::array<const char*, 8> gpr16 = {
                "ax", "cx", "dx", "bx", "sp", "bp", "si", "di"
            };
            static constexpr std::array<const char*, 8> gpr8 = {
                "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"
            };
            const uint32_t value = static_cast<uint32_t>(reg);
            const uint32_t bank = value & 0xff00;
            const size_t index = value & 0xff;
            if (bank == 0x0100 && index < gpr64.size()) return gpr64[index];
            if (bank == 0x0200 && index < 32)
                return index < gpr32.size() ? gpr32[index] : "r" + std::to_string(index) + "d";
            if (bank == 0x0300 && index < 32)
                return index < gpr16.size() ? gpr16[index] : "r" + std::to_string(index) + "w";
            if (bank == 0x0400 && index < 32)
                return index < gpr8.size() ? gpr8[index] : "r" + std::to_string(index) + "b";
            if (bank == 0x0500 && index < 4) {
                static constexpr std::array<const char*, 4> high8 = {"ah", "ch", "dh", "bh"};
                return high8[index];
            }
            if (bank == 0x0b00 && index < 32) return "xmm" + std::to_string(index);
            if (bank == 0x0c00 && index < 32) return "ymm" + std::to_string(index);
            if (bank == 0x0d00 && index < 32) return "zmm" + std::to_string(index);
            if (bank == 0x0e00 && index < 8) return "k" + std::to_string(index);
            if (bank == 0x0f00 && index < 8) return "mm" + std::to_string(index);
            if (value >= 0x0600 && value < 0x0606) {
                static constexpr std::array<const char*, 6> segments = {"es", "cs", "ss", "ds", "fs", "gs"};
                return segments[value - 0x0600];
            }
            switch (value) {
                case RAX_X86_REG_RIP: return "rip";
                case RAX_X86_REG_EIP: return "eip";
                case RAX_X86_REG_RFLAGS: return "rflags";
                case RAX_X86_REG_EFLAGS: return "eflags";
                case RAX_X86_REG_FLAGS: return "flags";
                default: return "reg_" + Hex(value);
            }
        }

        nlohmann::ordered_json FlagNames(uint32_t flags) {
            nlohmann::ordered_json result = nlohmann::ordered_json::array();
            static constexpr std::array<std::pair<uint32_t, const char*>, 7> names = {{
                {RAX_FLAG_C, "CF"}, {RAX_FLAG_Z, "ZF"}, {RAX_FLAG_N, "SF"},
                {RAX_FLAG_V, "OF"}, {RAX_FLAG_P, "PF"}, {RAX_FLAG_A, "AF"},
                {RAX_FLAG_D, "DF"}
            }};
            for (const auto& [bit, name] : names) if ((flags & bit) != 0) result.push_back(name);
            return result;
        }

        nlohmann::ordered_json AccessNames(uint32_t access) {
            nlohmann::ordered_json result = nlohmann::ordered_json::array();
            if ((access & RAX_EFFECT_READ) != 0) result.push_back("read");
            if ((access & RAX_EFFECT_WRITE) != 0) result.push_back("write");
            if ((access & RAX_EFFECT_CONDITIONAL) != 0) result.push_back("conditional");
            if ((access & RAX_EFFECT_ATOMIC) != 0) result.push_back("atomic");
            if ((access & RAX_EFFECT_REPEATED) != 0) result.push_back("repeated");
            if ((access & RAX_EFFECT_ORDERED) != 0) result.push_back("ordered");
            if ((access & RAX_EFFECT_IMPLICIT) != 0) result.push_back("implicit");
            if ((access & RAX_EFFECT_ADDRESS_COMPLETE) != 0) result.push_back("address_complete");
            if ((access & RAX_EFFECT_VALUE_COMPLETE) != 0) result.push_back("value_complete");
            return result;
        }

        const char* AddressKind(uint32_t kind) {
            switch (kind) {
                case RAX_ADDRESS_NONE: return "none";
                case RAX_ADDRESS_UNKNOWN: return "unknown";
                case RAX_ADDRESS_ABSOLUTE: return "absolute";
                case RAX_ADDRESS_REGISTER: return "register";
                case RAX_ADDRESS_BASE_DISP: return "base_disp";
                case RAX_ADDRESS_BASE_INDEX_DISP: return "base_index_disp";
                case RAX_ADDRESS_PC_RELATIVE: return "pc_relative";
                case RAX_ADDRESS_GP_RELATIVE: return "gp_relative";
                case RAX_ADDRESS_SEGMENT_RELATIVE: return "segment_relative";
                default: return "unknown";
            }
        }

        const char* FlowKind(int32_t flow) {
            switch (flow) {
                case RAX_FLOW_FALLTHROUGH: return "fallthrough";
                case RAX_FLOW_BRANCH: return "branch";
                case RAX_FLOW_COND_BRANCH: return "conditional_branch";
                case RAX_FLOW_INDIRECT_JUMP: return "indirect_jump";
                case RAX_FLOW_CALL: return "call";
                case RAX_FLOW_INDIRECT_CALL: return "indirect_call";
                case RAX_FLOW_RETURN: return "return";
                case RAX_FLOW_TRAP: return "trap";
                case RAX_FLOW_SYSCALL: return "syscall";
                default: return "unknown";
            }
        }

        nlohmann::ordered_json EffectJson(const rax_analysis_effect& effect) {
            nlohmann::ordered_json item;
            item["kind"] = effect.kind == RAX_EFFECT_REGISTER ? "register" : "memory";
            item["access"] = AccessNames(effect.access);
            if (effect.kind == RAX_EFFECT_REGISTER) {
                item["register"] = RegisterName(effect.reg);
                item["width_bits"] = effect.width_bits;
                if (effect.value_kind == RAX_VALUE_CONSTANT) item["value"] = Hex(effect.value);
                else if (effect.value_kind == RAX_VALUE_REGISTER) item["source_register"] = RegisterName(effect.source_reg);
                else if (effect.value_kind == RAX_VALUE_UNKNOWN) item["value"] = "unknown";
            } else {
                nlohmann::ordered_json address = {{"kind", AddressKind(effect.address_kind)}};
                const std::string base = RegisterName(effect.base_reg);
                const std::string index = RegisterName(effect.index_reg);
                const std::string segment = RegisterName(effect.segment_reg);
                if (!base.empty()) address["base"] = base;
                if (!index.empty()) address["index"] = index;
                if (!segment.empty()) address["segment"] = segment;
                if (effect.scale != 0) address["scale"] = effect.scale;
                if (effect.displacement != 0) address["displacement"] = effect.displacement;
                if (effect.address != 0) address["resolved"] = Hex(effect.address);
                item["address"] = std::move(address);
                item["width_bits"] = effect.width_bits;
                if (effect.value_kind == RAX_VALUE_CONSTANT) item["value"] = Hex(effect.value);
                else if (effect.value_kind == RAX_VALUE_REGISTER) item["source_register"] = RegisterName(effect.source_reg);
                else if (effect.value_kind == RAX_VALUE_UNKNOWN) item["value"] = "unknown";
            }
            return item;
        }
    }

    bool Available(std::string& error) {
        Api& api = GetApi();
        error = api.error;
        return api.analyze != nullptr;
    }

    nlohmann::ordered_json AnalyzeX64(uint64_t address, const uint8_t* bytes, size_t size) {
        Api& api = GetApi();
        if (!api.analyze) return {{"status", "unavailable"}, {"message", api.error}};
        if (!bytes || size == 0) return {{"status", "invalid_input"}};

        rax_analysis summary{};
        summary.struct_size = sizeof(summary);
        summary.abi_version = RAX_ANALYSIS_ABI_VERSION;
        size_t required = 0;
        rax_status status = api.analyze(RAX_ARCH_X86, RAX_MODE_64, address, bytes,
            std::min<size_t>(size, 15), &summary, nullptr, 0, &required);
        if (status != RAX_OK) {
            const char* message = api.strerror(status);
            return {{"status", "error"}, {"code", static_cast<int>(status)},
                    {"message", message ? message : "RAX analysis failed"}};
        }

        std::array<rax_analysis_effect, 64> effects{};
        const size_t capacity = std::min(required, effects.size());
        if (capacity != 0) {
            summary = {};
            summary.struct_size = sizeof(summary);
            summary.abi_version = RAX_ANALYSIS_ABI_VERSION;
            size_t copied = 0;
            status = api.analyze(RAX_ARCH_X86, RAX_MODE_64, address, bytes,
                std::min<size_t>(size, 15), &summary, effects.data(), capacity, &copied);
            if (status != RAX_OK && status != RAX_ERR_BOUNDS) {
                const char* message = api.strerror(status);
                return {{"status", "error"}, {"code", static_cast<int>(status)},
                        {"message", message ? message : "RAX analysis failed"}};
            }
        }

        nlohmann::ordered_json result;
        if ((summary.flags & RAX_ANALYSIS_VALID) == 0) result["status"] = "invalid_instruction";
        else if ((summary.flags & RAX_ANALYSIS_UNSUPPORTED) != 0) result["status"] = "unsupported";
        else if ((summary.flags & RAX_ANALYSIS_PARTIAL) != 0) result["status"] = "partial";
        else result["status"] = "complete";
        if (summary.decoded.valid != 0) result["size"] = summary.decoded.size;
        result["control_flow"] = FlowKind(summary.decoded.flow);
        if (summary.decoded.has_target != 0) result["target"] = Hex(summary.decoded.target);
        if (summary.decoded.flow == RAX_FLOW_COND_BRANCH) result["fallthrough"] = Hex(summary.decoded.fallthrough);
        result["flags_read"] = FlagNames(summary.flags_read);
        result["flags_written"] = FlagNames(summary.flags_written);
        result["flags_undefined"] = FlagNames(summary.flags_undefined);
        nlohmann::ordered_json effect_list = nlohmann::ordered_json::array();
        for (size_t i = 0; i < summary.effect_count; ++i) effect_list.push_back(EffectJson(effects[i]));
        result["effects"] = std::move(effect_list);
        if (required > effects.size() || (summary.flags & RAX_ANALYSIS_TRUNCATED) != 0)
            result["effects_truncated"] = true;
        if (summary.smir_op_count != 0) result["smir_op_count"] = summary.smir_op_count;
        return result;
    }
}
