#include <string>
#include <vector>
#include <sstream>
#include <format>
#include <algorithm>

#pragma warning(push, 0)
#include "json.h"
#include "qis/signature.hpp"
#pragma warning(pop)

#include "api_sigmaker.h"
#include "tools/utils/utils.h"
#include "sync/sync.h"

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <lines.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <ua.hpp>
#include <allins.hpp>

namespace tools::sigmaker {
    namespace {
        struct SignatureByte {
            uint8_t value = 0;
            bool isWildcard = false;
        };

        using Signature = std::vector<SignatureByte>;

        constexpr auto BIT(uint8_t index) {
            return 1LLU << index;
        }
        constexpr auto SET_BIT(auto x, uint8_t index) {
            return x | BIT(index);
        }
        constexpr bool GET_BIT(auto x, uint8_t index) {
            return x & BIT(index);
        }

        std::string BuildIDASignatureString(const Signature& signature, bool doubleQM = false) {
            std::ostringstream result;
            for (const auto& byte : signature) {
                if (byte.isWildcard) {
                    result << (doubleQM ? "??" : "?");
                } else {
                    result << std::format("{:02X}", byte.value);
                }
                result << " ";
            }
            auto str = result.str();
            if (!str.empty()) {
                str.pop_back();
            }
            return str;
        }

        bool GetOperandWildcardBits(const insn_t& instruction, uint32_t* wildcardBits) {
            if (!wildcardBits) return false;
            *wildcardBits = 0;
            for (int i = 0; i < UA_MAXOP; ++i) {
                const auto& op = instruction.ops[i];
                if (op.type == o_void) break;
                if (op.offb != 0) {
                    for (int b = 0; b < 4; ++b) {
                        if (op.offb + b < instruction.size) {
                            *wildcardBits = SET_BIT(*wildcardBits, op.offb + b);
                        }
                    }
                }
            }
            return *wildcardBits != 0;
        }

        void AddBytesToSignature(Signature& signature, ea_t address, size_t count, uint32_t wildcardBits) {
            for (size_t i = 0; i < count; ++i) {
                SignatureByte byte;
                byte.value = get_byte(address + i);
                byte.isWildcard = GET_BIT(wildcardBits, i);
                signature.push_back(byte);
            }
        }

        void AddByteToSignature(Signature& signature, ea_t address, bool wildcard) {
            SignatureByte byte;
            byte.value = get_byte(address);
            byte.isWildcard = wildcard;
            signature.push_back(byte);
        }

        void TrimSignature(Signature& signature) {
            auto it = std::find_if(signature.rbegin(), signature.rend(), [](const auto& byte) {
                return !byte.isWildcard;
            });
            if (it != signature.rend()) {
                signature.erase(it.base(), signature.end());
            }
        }

        std::vector<uint8_t> ReadSegmentsToBuffer() {
            std::vector<uint8_t> buffer;
            auto count = get_segm_qty();
            for (int i = 0; i < count; ++i) {
                auto seg = getnseg(i);
                if (!seg || !(seg->perm & SEGPERM_EXEC)) continue;
                auto size = seg->end_ea - seg->start_ea;
                if (size == 0 || size > 100 * 1024 * 1024) continue;
                auto current_pos = buffer.size();
                buffer.resize(current_pos + size);
                get_bytes(buffer.data() + current_pos, size, seg->start_ea);
            }
            return buffer;
        }

        bool IsSignatureUnique(const std::string& signature, const std::vector<uint8_t>& buffer) {
            try {
                qis::signature sig(signature);
                size_t first = qis::scan(buffer.data(), buffer.size(), sig);
                if (first == qis::npos) return false;
                size_t second = qis::scan(buffer.data() + first + 1, buffer.size() - first - 1, sig);
                return second == qis::npos;
            } catch (...) {
                return false;
            }
        }
    }

    bool ApiSigmaker::CanHandle(const std::string& name) const {
        return name == "make_signature";
    }

    nlohmann::json ApiSigmaker::GetSchema() const {
        return nlohmann::json::array();
    }

    nlohmann::json ApiSigmaker::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "make_signature") return MakeSignature(id, args);

        return nlohmann::json({
            {"jsonrpc", "2.0"},
            {"id", id},
            {"error", {{"code", -32601}, {"message", "Method not found"}}}
        });
    }

    nlohmann::json ApiSigmaker::MakeSignature(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t eaStart = tools::utils::GetAddressArg(args, "start", tools::utils::GetAddressArg(args, "start_addr"));
        ea_t eaEnd = tools::utils::GetAddressArg(args, "end", tools::utils::GetAddressArg(args, "end_addr"));
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        size_t max_len = static_cast<size_t>(tools::utils::GetIntArg(args, "max_length", 250));
        bool wildcard_ops = tools::utils::GetBoolArg(args, "wildcard_operands", true);
        bool continue_outside = tools::utils::GetBoolArg(args, "continue_outside_function", false);

        std::string sig_str;
        bool unique = false;
        std::string err_code;
        std::string err_msg;

        sync::SyncRead([&]() {
            // Check if explicit range is specified
            if (eaStart != BADADDR && eaEnd != BADADDR) {
                if (eaStart >= eaEnd) {
                    err_code = "invalid_range";
                    err_msg = "start address must be less than end address";
                    return;
                }

                Signature sig;
                ea_t currentAddress = eaStart;
                while (currentAddress < eaEnd && sig.size() < max_len) {
                    insn_t instruction;
                    auto len = decode_insn(&instruction, currentAddress);
                    if (len <= 0) {
                        AddByteToSignature(sig, currentAddress, false);
                        currentAddress++;
                    } else {
                        uint32_t wildcardBits = 0;
                        if (wildcard_ops) GetOperandWildcardBits(instruction, &wildcardBits);
                        AddBytesToSignature(sig, currentAddress, len, wildcardBits);
                        currentAddress += len;
                    }
                }

                TrimSignature(sig);
                sig_str = BuildIDASignatureString(sig);
                auto buffer = ReadSegmentsToBuffer();
                unique = IsSignatureUnique(sig_str, buffer);
                return;
            }

            if (ea == BADADDR) {
                err_code = "invalid_addr";
                err_msg = "Parameter 'addr' or 'start'+'end' range is required";
                return;
            }

            auto buffer = ReadSegmentsToBuffer();
            Signature sig;
            auto currentFunction = get_func(ea);
            ea_t currentAddress = ea;

            while (sig.size() < max_len) {
                insn_t instruction;
                auto currentInstructionLength = decode_insn(&instruction, currentAddress);
                if (currentInstructionLength <= 0) break;

                uint32_t wildcardBits = 0;
                if (wildcard_ops && GetOperandWildcardBits(instruction, &wildcardBits)) {
                    AddBytesToSignature(sig, currentAddress, currentInstructionLength, wildcardBits);
                } else {
                    AddBytesToSignature(sig, currentAddress, currentInstructionLength, 0);
                }

                auto currentSig = BuildIDASignatureString(sig);
                if (IsSignatureUnique(currentSig, buffer)) {
                    TrimSignature(sig);
                    unique = true;
                    break;
                }

                currentAddress += currentInstructionLength;
                if (currentFunction && get_func(currentAddress) != currentFunction) {
                    if (!continue_outside) break;
                }
            }

            TrimSignature(sig);
            sig_str = BuildIDASignatureString(sig);
            if (!unique) {
                unique = IsSignatureUnique(sig_str, buffer);
            }
        });

        if (!err_code.empty()) {
            return tools::utils::MakeToolErrorJson(id, err_msg, err_code);
        }

        nlohmann::json res = {
            {"status", "success"},
            {"signature", sig_str},
            {"unique", unique}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }
}
