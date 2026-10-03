#include <string>
#include <vector>
#include <sstream>
#include <format>
#include <algorithm>
#include <cstring>

#pragma warning(push, 0)
#include "json.h"
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
#include <xref.hpp>

namespace tools::sigmaker {
    namespace {
        constexpr auto BIT(uint8_t index) {
            return 1LLU << index;
        }
        constexpr auto SET_BIT(auto x, uint8_t index) {
            return x | BIT(index);
        }
        constexpr bool GET_BIT(auto x, uint8_t index) {
            return x & BIT(index);
        }

        struct FastPattern {
            std::vector<uint8_t> bytes;
            std::vector<uint8_t> mask; // 0xFF for fixed byte, 0x00 for wildcard
            size_t fixed_count = 0;
            size_t first_fixed = 0;
            size_t last_fixed = 0;

            void add_byte(uint8_t b, bool is_wildcard) {
                bytes.push_back(b);
                if (is_wildcard) {
                    mask.push_back(0x00);
                } else {
                    mask.push_back(0xFF);
                    if (fixed_count == 0) first_fixed = bytes.size() - 1;
                    last_fixed = bytes.size() - 1;
                    fixed_count++;
                }
            }

            void add_bytes(ea_t addr, size_t count, uint32_t wildcard_bits) {
                bytes.reserve(bytes.size() + count);
                mask.reserve(mask.size() + count);
                for (size_t i = 0; i < count; ++i) {
                    bool is_wildcard = GET_BIT(wildcard_bits, i);
                    uint8_t b = get_byte(addr + i);
                    add_byte(b, is_wildcard);
                }
            }

            void trim() {
                while (!mask.empty() && mask.back() == 0x00) {
                    bytes.pop_back();
                    mask.pop_back();
                }
                last_fixed = 0;
                for (size_t i = mask.size(); i > 0; --i) {
                    if (mask[i - 1] == 0xFF) {
                        last_fixed = i - 1;
                        break;
                    }
                }
            }

            size_t size() const { return bytes.size(); }
            bool empty() const { return bytes.empty(); }
        };

        std::string BuildIDASignatureString(const FastPattern& pat, bool doubleQM = false) {
            std::string result;
            result.reserve(pat.size() * 3);
            char buf[8];
            for (size_t i = 0; i < pat.size(); ++i) {
                if (pat.mask[i] == 0x00) {
                    result += (doubleQM ? "?? " : "? ");
                } else {
                    qsnprintf(buf, sizeof(buf), "%02X ", pat.bytes[i]);
                    result += buf;
                }
            }
            if (!result.empty()) result.pop_back();
            return result;
        }

        bool GetOperandWildcardBits(const insn_t& instruction, uint32_t* wildcardBits) {
            if (!wildcardBits) return false;
            *wildcardBits = 0;
            for (int i = 0; i < UA_MAXOP; ++i) {
                const auto& op = instruction.ops[i];
                if (op.type == o_void) break;
                // Only wildcard relocatable addresses / branches / memory operands, NOT immediate constants (o_imm)
                if (op.type == o_imm) continue;
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

        struct ScanSegment {
            ea_t start_ea = BADADDR;
            ea_t end_ea = BADADDR;
            size_t size = 0;
            std::vector<uint8_t> data;
        };

        inline const uint8_t* GetSegmentPtr(const std::vector<ScanSegment>& segments, ea_t addr) {
            for (const auto& seg : segments) {
                if (addr >= seg.start_ea && addr < seg.end_ea) {
                    size_t off = static_cast<size_t>(addr - seg.start_ea);
                    if (off < seg.size) return seg.data.data() + off;
                }
            }
            return nullptr;
        }

        struct ScanResult {
            size_t count = 0;
            ea_t first_ea = BADADDR;
            ea_t second_ea = BADADDR;
            std::vector<ea_t> matches;
        };

        inline ScanResult ScanPattern(
            const std::vector<ScanSegment>& segments,
            const FastPattern& pat,
            size_t max_matches = 2,
            bool collect_matches = false
        ) {
            ScanResult res;
            if (pat.empty() || pat.fixed_count < 4) return res;

            const size_t pat_len = pat.size();
            const size_t first_off = pat.first_fixed;
            const uint8_t first_byte = pat.bytes[first_off];
            const size_t last_off = pat.last_fixed;
            const uint8_t last_byte = pat.bytes[last_off];

            for (const auto& seg : segments) {
                if (seg.size < pat_len) continue;

                const uint8_t* const base = seg.data.data();
                const uint8_t* ptr = base;
                const uint8_t* const max_start = base + seg.size - pat_len;

                while (ptr <= max_start) {
                    // Vectorized hardware search for the first non-wildcard byte
                    const uint8_t* cand = static_cast<const uint8_t*>(
                        std::memchr(ptr + first_off, first_byte, (max_start - ptr) + 1)
                    );
                    if (!cand) break;

                    const uint8_t* match_start = cand - first_off;

                    // Fast check on last fixed byte before comparing the rest
                    if (match_start[last_off] == last_byte) {
                        bool match = true;
                        for (size_t i = 0; i < pat_len; ++i) {
                            if (pat.mask[i] != 0 && match_start[i] != pat.bytes[i]) {
                                match = false;
                                break;
                            }
                        }

                        if (match) {
                            ea_t match_ea = seg.start_ea + static_cast<ea_t>(match_start - base);
                            res.count++;
                            if (res.first_ea == BADADDR) res.first_ea = match_ea;
                            else if (res.second_ea == BADADDR) res.second_ea = match_ea;

                            if (collect_matches) {
                                res.matches.push_back(match_ea);
                            }

                            if (!collect_matches && res.count >= max_matches) {
                                return res;
                            }
                        }
                    }

                    ptr = cand + 1 - first_off;
                    if (ptr <= match_start) ptr = match_start + 1;
                }

                if (!collect_matches && res.count >= max_matches) {
                    return res;
                }
            }

            return res;
        }

        inline bool IsPatternUniqueFast(
            const std::vector<ScanSegment>& segments,
            const FastPattern& pat
        ) {
            if (pat.empty() || pat.fixed_count < 5) return false;

            if (!segments.empty()) {
                ScanResult sr = ScanPattern(segments, pat, 2, false);
                return (sr.count == 1);
            }

            ea_t min_ea = inf_get_min_ea();
            ea_t max_ea = inf_get_max_ea();
            constexpr int flags = BIN_SEARCH_FORWARD | BIN_SEARCH_NOBREAK | BIN_SEARCH_NOSHOW;

            ea_t first = bin_search(min_ea, max_ea, pat.bytes.data(), pat.mask.data(), pat.size(), flags);
            if (first == BADADDR) return false;

            ea_t second = bin_search(first + 1, max_ea, pat.bytes.data(), pat.mask.data(), pat.size(), flags);
            return (second == BADADDR);
        }

        struct GrowResult {
            FastPattern pat;
            ea_t start_ea = BADADDR;
            size_t length = 0;
            bool unique = false;
        };

        GrowResult GrowSignature(
            const std::vector<ScanSegment>& segments,
            ea_t start_ea,
            size_t max_len,
            size_t prune_len,
            bool wildcard_ops,
            func_t* scope_func,
            bool continue_outside
        ) {
            GrowResult res;
            res.start_ea = start_ea;
            ea_t cur = start_ea;

            std::vector<ea_t> active_collisions;
            bool tracked_collisions = false;

            while (res.pat.size() < max_len && res.pat.size() < prune_len) {
                insn_t insn;
                int len = decode_insn(&insn, cur);
                if (len <= 0) break;

                size_t prev_size = res.pat.size();
                uint32_t wildcardBits = 0;
                if (wildcard_ops && GetOperandWildcardBits(insn, &wildcardBits)) {
                    res.pat.add_bytes(cur, len, wildcardBits);
                } else {
                    res.pat.add_bytes(cur, len, 0);
                }

                if (res.pat.size() >= prune_len) break;

                // Incremental collision filtering: if we have a small set of collisions from prefix,
                // verify only those collision addresses directly in memory without full rescanning!
                if (tracked_collisions) {
                    size_t added_len = res.pat.size() - prev_size;
                    auto it = std::remove_if(active_collisions.begin(), active_collisions.end(), [&](ea_t coll_ea) {
                        for (size_t i = 0; i < added_len; ++i) {
                            size_t pat_idx = prev_size + i;
                            if (res.pat.mask[pat_idx] == 0) continue;
                            const uint8_t* b = GetSegmentPtr(segments, coll_ea + pat_idx);
                            if (!b || *b != res.pat.bytes[pat_idx]) return true;
                        }
                        return false;
                    });
                    active_collisions.erase(it, active_collisions.end());

                    if (active_collisions.empty()) {
                        FastPattern trimmed = res.pat;
                        trimmed.trim();
                        if (trimmed.size() < prune_len) {
                            res.pat = std::move(trimmed);
                            res.length = res.pat.size();
                            res.unique = true;
                            return res;
                        }
                    }
                } else if (res.pat.fixed_count >= 5) {
                    FastPattern trimmed = res.pat;
                    trimmed.trim();
                    if (trimmed.size() < prune_len) {
                        ScanResult sr = ScanPattern(segments, trimmed, 2, true);
                        if (sr.count == 1) {
                            res.pat = std::move(trimmed);
                            res.length = res.pat.size();
                            res.unique = true;
                            return res;
                        } else if (sr.count > 1 && sr.matches.size() <= 64) {
                            active_collisions.clear();
                            for (ea_t m : sr.matches) {
                                if (m != start_ea) active_collisions.push_back(m);
                            }
                            tracked_collisions = true;
                        }
                    }
                }

                cur += len;
                if (scope_func && get_func(cur) != scope_func) {
                    if (!continue_outside) break;
                }
            }

            res.pat.trim();
            res.length = res.pat.size();
            if (!res.pat.empty() && res.length < prune_len && res.pat.fixed_count >= 5) {
                res.unique = IsPatternUniqueFast(segments, res.pat);
            }
            return res;
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
        if (max_len == 0) max_len = 250;
        bool wildcard_ops = tools::utils::GetBoolArg(args, "wildcard_operands", true);
        bool continue_outside = tools::utils::GetBoolArg(args, "continue_outside_function", false);

        bool shortest = tools::utils::GetBoolArg(args, "shortest", false);
        size_t candidate_limit = static_cast<size_t>(tools::utils::GetIntArg(args, "candidate_limit", 64));
        if (candidate_limit == 0) candidate_limit = 64;
        if (candidate_limit > 256) candidate_limit = 256;

        std::string sig_str;
        bool unique = false;
        size_t sig_len = 0;
        ea_t sig_ea = BADADDR;
        int64_t target_offset = 0;
        std::string sig_type = "direct";
        ea_t xref_site_ea = BADADDR;
        int disp_off_in_sig = -1;

        std::string err_code;
        std::string err_msg;

        sync::SyncRead([&]() {
            // Snapshot initialized non-empty program segments for zero-allocation high-speed scanning
            std::vector<ScanSegment> segments;
            segments.reserve(get_segm_qty());
            for (int i = 0; i < get_segm_qty(); ++i) {
                segment_t* seg = getnseg(i);
                if (!seg) continue;
                if (seg->type == SEG_XTRN || seg->type == SEG_NULL || seg->type == SEG_BSS) continue;
                if (seg->size() == 0) continue;

                ScanSegment ss;
                ss.start_ea = seg->start_ea;
                ss.end_ea = seg->end_ea;
                ss.size = static_cast<size_t>(seg->size());
                ss.data.resize(ss.size);

                ssize_t read_bytes = get_bytes(ss.data.data(), ss.size, ss.start_ea, GMB_READALL);
                if (read_bytes <= 0) continue;
                if (static_cast<size_t>(read_bytes) < ss.size) {
                    ss.size = static_cast<size_t>(read_bytes);
                    ss.data.resize(ss.size);
                }
                segments.push_back(std::move(ss));
            }

            // 1. Explicit range mode
            if (eaStart != BADADDR && eaEnd != BADADDR) {
                if (eaStart >= eaEnd) {
                    err_code = "invalid_range";
                    err_msg = "start address must be less than end address";
                    return;
                }

                FastPattern pat;
                ea_t currentAddress = eaStart;
                while (currentAddress < eaEnd && pat.size() < max_len) {
                    insn_t instruction;
                    auto len = decode_insn(&instruction, currentAddress);
                    if (len <= 0) {
                        pat.add_byte(get_byte(currentAddress), false);
                        currentAddress++;
                    } else {
                        uint32_t wildcardBits = 0;
                        if (wildcard_ops) GetOperandWildcardBits(instruction, &wildcardBits);
                        pat.add_bytes(currentAddress, len, wildcardBits);
                        currentAddress += len;
                    }
                }

                pat.trim();
                sig_str = BuildIDASignatureString(pat);
                sig_len = pat.size();
                sig_ea = eaStart;
                unique = IsPatternUniqueFast(segments, pat);
                if (sig_len == 0 || sig_str.empty()) {
                    err_code = "empty_signature";
                    err_msg = "No valid bytes or instructions found in range " + tools::utils::FormatAddress(eaStart) + " - " + tools::utils::FormatAddress(eaEnd);
                }
                return;
            }

            if (ea == BADADDR) {
                err_code = "invalid_addr";
                err_msg = "Parameter 'addr' or 'start'+'end' range is required";
                return;
            }

            func_t* currentFunction = get_func(ea);

            // 2. Standard mode (from start address)
            if (!shortest) {
                GrowResult r = GrowSignature(segments, ea, max_len, max_len + 1, wildcard_ops, currentFunction, continue_outside);
                sig_str = BuildIDASignatureString(r.pat);
                unique = r.unique;
                sig_len = r.length;
                sig_ea = ea;
                target_offset = 0;
                sig_type = currentFunction ? "function_entry" : "direct";
                if (sig_len == 0 || sig_str.empty()) {
                    err_code = "signature_not_found";
                    err_msg = "Could not decode any instructions starting at address " + tools::utils::FormatAddress(ea);
                }
                return;
            }

            // 3. Ultra-optimized Shortest Search Mode
            GrowResult best_res;
            size_t best_len = max_len + 1;
            GrowResult fallback_res;
            ea_t fallback_sig_ea = BADADDR;
            int64_t fallback_target_offset = 0;
            ea_t fallback_xref_site_ea = BADADDR;
            std::string fallback_sig_type = "variable_xref";

            auto evaluate_candidate = [&](ea_t cand_ea, int64_t offset, const std::string& type, ea_t xref_ea, func_t* fn) {
                GrowResult r = GrowSignature(segments, cand_ea, max_len, best_len, wildcard_ops, fn, continue_outside);
                if (r.unique && r.length < best_len) {
                    best_len = r.length;
                    best_res = std::move(r);
                    sig_ea = cand_ea;
                    target_offset = offset;
                    sig_type = type;
                    xref_site_ea = xref_ea;
                } else if (r.pat.size() > fallback_res.pat.size()) {
                    fallback_res = r;
                    fallback_sig_ea = cand_ea;
                    fallback_target_offset = offset;
                    fallback_sig_type = type;
                    fallback_xref_site_ea = xref_ea;
                }
            };

            if (currentFunction) {
                // A1. Scan candidate instructions inside function
                func_item_iterator_t fii;
                std::vector<ea_t> candidates;
                for (bool ok = fii.set(currentFunction, currentFunction->start_ea); ok; ok = fii.next_code()) {
                    candidates.push_back(fii.current());
                    if (candidates.size() >= candidate_limit) break;
                }

                for (ea_t cand : candidates) {
                    evaluate_candidate(cand, static_cast<int64_t>(cand - currentFunction->start_ea),
                        (cand == currentFunction->start_ea) ? "function_entry" : "function_internal",
                        BADADDR, currentFunction);
                }

                // A2. Check callers (code xrefs to function entry)
                xrefblk_t xb;
                size_t callers_checked = 0;
                for (bool ok = xb.first_to(currentFunction->start_ea, XREF_ALL); ok && callers_checked < 16; ok = xb.next_to()) {
                    if (!xb.iscode && !is_code(get_flags(xb.from))) continue;
                    callers_checked++;
                    ea_t call_site = xb.from;
                    func_t* caller_fn = get_func(call_site);

                    evaluate_candidate(call_site, 0, "caller_call_site", call_site, caller_fn);

                    segment_t* seg = getseg(call_site);
                    ea_t min_seg = seg ? seg->start_ea : inf_get_min_ea();
                    ea_t walk = call_site;
                    for (int step = 1; step <= 5; ++step) {
                        ea_t prev = prev_head(walk, min_seg);
                        if (prev == BADADDR || !is_code(get_flags(prev))) break;
                        if (caller_fn && get_func(prev) != caller_fn) break;

                        evaluate_candidate(prev, static_cast<int64_t>(call_site - prev), "caller_call_site", call_site, caller_fn);
                        walk = prev;
                    }
                }
            } else {
                // B. Global Variable / Data: search code xrefs
                xrefblk_t xb;
                size_t xrefs_checked = 0;
                for (bool ok = xb.first_to(ea, XREF_ALL); ok && xrefs_checked < 32; ok = xb.next_to()) {
                    if (!is_code(get_flags(xb.from))) continue;
                    xrefs_checked++;
                    ea_t call_site = xb.from;
                    func_t* caller_fn = get_func(call_site);

                    evaluate_candidate(call_site, 0, "variable_xref", call_site, caller_fn);

                    segment_t* seg = getseg(call_site);
                    ea_t min_seg = seg ? seg->start_ea : inf_get_min_ea();
                    ea_t walk = call_site;
                    for (int step = 1; step <= 5; ++step) {
                        ea_t prev = prev_head(walk, min_seg);
                        if (prev == BADADDR || !is_code(get_flags(prev))) break;
                        if (caller_fn && get_func(prev) != caller_fn) break;

                        evaluate_candidate(prev, static_cast<int64_t>(call_site - prev), "variable_xref", call_site, caller_fn);
                        walk = prev;
                    }
                }
            }

            if (best_res.unique) {
                sig_str = BuildIDASignatureString(best_res.pat);
                unique = true;
                sig_len = best_res.length;
            } else if (fallback_res.pat.size() > 0) {
                sig_str = BuildIDASignatureString(fallback_res.pat);
                unique = false;
                sig_len = fallback_res.pat.size();
                sig_ea = fallback_sig_ea;
                target_offset = fallback_target_offset;
                sig_type = fallback_sig_type;
                xref_site_ea = fallback_xref_site_ea;
            } else if (currentFunction) {
                GrowResult r = GrowSignature(segments, ea, max_len, max_len + 1, wildcard_ops, currentFunction, continue_outside);
                sig_str = BuildIDASignatureString(r.pat);
                unique = r.unique;
                sig_len = r.length;
                sig_ea = ea;
                target_offset = 0;
                sig_type = "function_entry";
            }

            if (xref_site_ea != BADADDR) {
                insn_t insn;
                if (decode_insn(&insn, xref_site_ea) > 0) {
                    for (int i = 0; i < UA_MAXOP; ++i) {
                        if (insn.ops[i].offb != 0) {
                            disp_off_in_sig = static_cast<int>(target_offset + insn.ops[i].offb);
                            break;
                        }
                    }
                }
            }

            if (sig_len == 0 || sig_str.empty()) {
                err_code = "signature_not_found";
                if (!currentFunction) {
                    err_msg = "Could not generate signature for " + tools::utils::FormatAddress(ea) + 
                              ": target is data and no code references (XREFs) could produce instructions.";
                } else {
                    err_msg = "Could not generate signature for " + tools::utils::FormatAddress(ea) + 
                              ": failed to decode valid instructions.";
                }
                return;
            }
        });

        if (!err_code.empty()) {
            return tools::utils::MakeToolErrorJson(id, err_msg, err_code);
        }

        nlohmann::json res = {
            {"status", "success"},
            {"signature", sig_str},
            {"unique", unique},
            {"length", sig_len},
            {"address", tools::utils::FormatAddress(sig_ea)},
            {"target", tools::utils::FormatAddress(ea)},
            {"type", sig_type}
        };

        if (shortest) {
            res["shortest"] = true;
            res["offset"] = target_offset;
            if (xref_site_ea != BADADDR) {
                res["xref_address"] = tools::utils::FormatAddress(xref_site_ea);
            }
            if (disp_off_in_sig >= 0) {
                res["disp_offset"] = disp_off_in_sig;
            }
        }

        return tools::utils::MakeToolSuccessJson(id, res);
    }
}
