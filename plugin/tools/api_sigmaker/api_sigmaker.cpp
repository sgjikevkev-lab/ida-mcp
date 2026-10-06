#include <string>
#include <vector>
#include <sstream>
#include <format>
#include <algorithm>
#include <cstring>
#include <mutex>
#include <memory>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "api_sigmaker.h"
#include "tools/utils/utils.h"
#include "sync/sync.h"
#include "sync/cache_manager.h"

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

            void add_raw_bytes(const uint8_t* raw_bytes, size_t count, uint32_t wildcard_bits) {
                bytes.reserve(bytes.size() + count);
                mask.reserve(mask.size() + count);
                for (size_t i = 0; i < count; ++i) {
                    bool is_wildcard = GET_BIT(wildcard_bits, i);
                    add_byte(raw_bytes ? raw_bytes[i] : 0, is_wildcard);
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

        class SegmentSnapshotCache {
        public:
            static SegmentSnapshotCache& Instance() {
                static SegmentSnapshotCache inst;
                return inst;
            }

            std::shared_ptr<const std::vector<ScanSegment>> GetSegments() const {
                std::lock_guard<std::mutex> lock(mutex_);
                return segments_;
            }

            void SetSegments(std::shared_ptr<const std::vector<ScanSegment>> segs) {
                std::lock_guard<std::mutex> lock(mutex_);
                segments_ = std::move(segs);
            }

            void Invalidate() {
                std::lock_guard<std::mutex> lock(mutex_);
                segments_.reset();
            }

        private:
            mutable std::mutex mutex_;
            std::shared_ptr<const std::vector<ScanSegment>> segments_;
        };

        struct DecodedInsn {
            ea_t ea = BADADDR;
            int len = 0;
            uint32_t wildcard_bits = 0;
        };

        struct CandidateMetadata {
            ea_t cand_ea = BADADDR;
            int64_t offset = 0;
            std::string type = "direct";
            ea_t xref_ea = BADADDR;
            int disp_off = -1;
            std::vector<DecodedInsn> insns;
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

        GrowResult GrowCandSignature(
            const std::vector<ScanSegment>& segments,
            const CandidateMetadata& cand,
            size_t max_len,
            size_t prune_len
        ) {
            GrowResult res;
            res.start_ea = cand.cand_ea;

            std::vector<ea_t> active_collisions;
            bool tracked_collisions = false;

            for (const auto& di : cand.insns) {
                if (res.pat.size() >= max_len || res.pat.size() >= prune_len) break;

                size_t prev_size = res.pat.size();
                const uint8_t* raw = GetSegmentPtr(segments, di.ea);
                res.pat.add_raw_bytes(raw, di.len, di.wildcard_bits);

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
                                if (m != cand.cand_ea) active_collisions.push_back(m);
                            }
                            tracked_collisions = true;
                        }
                    }
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

    void InvalidateSegmentCache() {
        SegmentSnapshotCache::Instance().Invalidate();
    }

    namespace {
        struct SigmakerCacheAutoReg {
            SigmakerCacheAutoReg() {
                cache::CacheManager::Instance().RegisterByteInvalidator(&InvalidateSegmentCache);
            }
        } s_sigmaker_cache_reg;
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
        bool refresh_cache = tools::utils::GetBoolArg(args, "refresh", false);

        bool shortest = tools::utils::GetBoolArg(args, "shortest", false);
        size_t candidate_limit = static_cast<size_t>(tools::utils::GetIntArg(args, "candidate_limit", 64));
        if (candidate_limit == 0) candidate_limit = 64;
        if (candidate_limit > 256) candidate_limit = 256;

        std::string err_code;
        std::string err_msg;

        bool is_range_mode = false;
        std::vector<DecodedInsn> range_insns;

        bool is_func = false;
        CandidateMetadata direct_candidate;
        std::vector<CandidateMetadata> candidates;

        std::shared_ptr<const std::vector<ScanSegment>> segments_ptr;

        // --- STEP 1: Main Thread Phase (Fast Snapshot & Candidate Metadata Gathering) ---
        sync::SyncRead([&]() {
            if (refresh_cache) {
                SegmentSnapshotCache::Instance().Invalidate();
            }

            segments_ptr = SegmentSnapshotCache::Instance().GetSegments();
            if (!segments_ptr) {
                auto segs = std::make_shared<std::vector<ScanSegment>>();
                segs->reserve(get_segm_qty());
                for (int i = 0; i < get_segm_qty(); ++i) {
                    segment_t* seg = getnseg(i);
                    if (!seg) continue;
                    if (seg->type == SEG_XTRN || seg->type == SEG_NULL || seg->type == SEG_BSS) continue;
                    if (seg->size() == 0) continue;

                    ScanSegment ss;
                    ss.start_ea = seg->start_ea;
                    ss.end_ea = seg->end_ea;
                    ss.size = static_cast<size_t>(seg->size());
                    ss.data.resize(ss.size, 0);

                    get_bytes(ss.data.data(), ss.size, ss.start_ea, GMB_READALL);
                    segs->push_back(std::move(ss));
                }
                SegmentSnapshotCache::Instance().SetSegments(segs);
                segments_ptr = segs;
            }

            // 1. Explicit range mode
            if (eaStart != BADADDR && eaEnd != BADADDR) {
                if (eaStart >= eaEnd) {
                    err_code = "invalid_range";
                    err_msg = "start address must be less than end address";
                    return;
                }
                is_range_mode = true;
                ea_t cur = eaStart;
                while (cur < eaEnd && range_insns.size() < max_len) {
                    insn_t instruction;
                    int len = decode_insn(&instruction, cur);
                    if (len <= 0) {
                        range_insns.push_back({cur, 1, 0});
                        cur++;
                    } else {
                        uint32_t wildcardBits = 0;
                        if (wildcard_ops) GetOperandWildcardBits(instruction, &wildcardBits);
                        range_insns.push_back({cur, len, wildcardBits});
                        cur += len;
                    }
                }
                return;
            }

            if (ea == BADADDR) {
                err_code = "invalid_addr";
                err_msg = "Parameter 'addr' or 'start'+'end' range is required";
                return;
            }

            func_t* currentFunction = get_func(ea);
            is_func = (currentFunction != nullptr);

            auto decode_candidate_insns = [&](ea_t start_addr, func_t* scope_fn) -> std::vector<DecodedInsn> {
                std::vector<DecodedInsn> res;
                ea_t cur = start_addr;
                size_t acc_len = 0;
                while (acc_len < max_len) {
                    insn_t insn;
                    int len = decode_insn(&insn, cur);
                    if (len <= 0) break;
                    uint32_t wildcardBits = 0;
                    if (wildcard_ops) GetOperandWildcardBits(insn, &wildcardBits);
                    res.push_back({cur, len, wildcardBits});
                    acc_len += len;
                    cur += len;
                    if (scope_fn && get_func(cur) != scope_fn && !continue_outside) break;
                }
                return res;
            };

            auto get_disp_offset = [&](ea_t xref_site, int64_t base_offset) -> int {
                if (xref_site == BADADDR) return -1;
                insn_t insn;
                if (decode_insn(&insn, xref_site) > 0) {
                    for (int i = 0; i < UA_MAXOP; ++i) {
                        if (insn.ops[i].offb != 0) {
                            return static_cast<int>(base_offset + insn.ops[i].offb);
                        }
                    }
                }
                return -1;
            };

            // 2. Standard mode (from start address)
            if (!shortest) {
                direct_candidate.cand_ea = ea;
                direct_candidate.offset = 0;
                direct_candidate.type = currentFunction ? "function_entry" : "direct";
                direct_candidate.xref_ea = BADADDR;
                direct_candidate.disp_off = -1;
                direct_candidate.insns = decode_candidate_insns(ea, currentFunction);
                return;
            }

            // 3. Shortest search candidates collection
            if (currentFunction) {
                func_item_iterator_t fii;
                std::vector<ea_t> func_cands;
                for (bool ok = fii.set(currentFunction, currentFunction->start_ea); ok; ok = fii.next_code()) {
                    func_cands.push_back(fii.current());
                    if (func_cands.size() >= candidate_limit) break;
                }

                for (ea_t cand : func_cands) {
                    CandidateMetadata cm;
                    cm.cand_ea = cand;
                    cm.offset = static_cast<int64_t>(cand - currentFunction->start_ea);
                    cm.type = (cand == currentFunction->start_ea) ? "function_entry" : "function_internal";
                    cm.xref_ea = BADADDR;
                    cm.disp_off = -1;
                    cm.insns = decode_candidate_insns(cand, currentFunction);
                    candidates.push_back(std::move(cm));
                }

                xrefblk_t xb;
                size_t callers_checked = 0;
                for (bool ok = xb.first_to(currentFunction->start_ea, XREF_ALL); ok && callers_checked < 16; ok = xb.next_to()) {
                    if (!xb.iscode && !is_code(get_flags(xb.from))) continue;
                    callers_checked++;
                    ea_t call_site = xb.from;
                    func_t* caller_fn = get_func(call_site);

                    CandidateMetadata cm;
                    cm.cand_ea = call_site;
                    cm.offset = 0;
                    cm.type = "caller_call_site";
                    cm.xref_ea = call_site;
                    cm.disp_off = get_disp_offset(call_site, 0);
                    cm.insns = decode_candidate_insns(call_site, caller_fn);
                    candidates.push_back(std::move(cm));

                    segment_t* seg = getseg(call_site);
                    ea_t min_seg = seg ? seg->start_ea : inf_get_min_ea();
                    ea_t walk = call_site;
                    for (int step = 1; step <= 5; ++step) {
                        ea_t prev = prev_head(walk, min_seg);
                        if (prev == BADADDR || !is_code(get_flags(prev))) break;
                        if (caller_fn && get_func(prev) != caller_fn) break;

                        CandidateMetadata pcm;
                        pcm.cand_ea = prev;
                        pcm.offset = static_cast<int64_t>(call_site - prev);
                        pcm.type = "caller_call_site";
                        pcm.xref_ea = call_site;
                        pcm.disp_off = get_disp_offset(call_site, pcm.offset);
                        pcm.insns = decode_candidate_insns(prev, caller_fn);
                        candidates.push_back(std::move(pcm));
                        walk = prev;
                    }
                }
            } else {
                xrefblk_t xb;
                size_t xrefs_checked = 0;
                for (bool ok = xb.first_to(ea, XREF_ALL); ok && xrefs_checked < 32; ok = xb.next_to()) {
                    if (!is_code(get_flags(xb.from))) continue;
                    xrefs_checked++;
                    ea_t call_site = xb.from;
                    func_t* caller_fn = get_func(call_site);

                    CandidateMetadata cm;
                    cm.cand_ea = call_site;
                    cm.offset = 0;
                    cm.type = "variable_xref";
                    cm.xref_ea = call_site;
                    cm.disp_off = get_disp_offset(call_site, 0);
                    cm.insns = decode_candidate_insns(call_site, caller_fn);
                    candidates.push_back(std::move(cm));

                    segment_t* seg = getseg(call_site);
                    ea_t min_seg = seg ? seg->start_ea : inf_get_min_ea();
                    ea_t walk = call_site;
                    for (int step = 1; step <= 5; ++step) {
                        ea_t prev = prev_head(walk, min_seg);
                        if (prev == BADADDR || !is_code(get_flags(prev))) break;
                        if (caller_fn && get_func(prev) != caller_fn) break;

                        CandidateMetadata pcm;
                        pcm.cand_ea = prev;
                        pcm.offset = static_cast<int64_t>(call_site - prev);
                        pcm.type = "variable_xref";
                        pcm.xref_ea = call_site;
                        pcm.disp_off = get_disp_offset(call_site, pcm.offset);
                        pcm.insns = decode_candidate_insns(prev, caller_fn);
                        candidates.push_back(std::move(pcm));
                        walk = prev;
                    }
                }
            }
        });
        // --- END OF MAIN THREAD PHASE ---

        if (!err_code.empty()) {
            return tools::utils::MakeToolErrorJson(id, err_msg, err_code);
        }
        if (!segments_ptr || segments_ptr->empty()) {
            return tools::utils::MakeToolErrorJson(id, "Failed to read binary segments", "internal_error");
        }

        const auto& segments = *segments_ptr;

        std::string sig_str;
        bool unique = false;
        size_t sig_len = 0;
        ea_t sig_ea = BADADDR;
        int64_t target_offset = 0;
        std::string sig_type = "direct";
        ea_t xref_site_ea = BADADDR;
        int disp_off_in_sig = -1;

        // --- STEP 2: Worker Thread Phase (CPU-Intensive Scanning Outside Main Thread) ---
        FastPattern final_pat;

        // 1. Explicit range mode
        if (is_range_mode) {
            for (const auto& di : range_insns) {
                if (final_pat.size() >= max_len) break;
                const uint8_t* raw = GetSegmentPtr(segments, di.ea);
                final_pat.add_raw_bytes(raw, di.len, di.wildcard_bits);
            }
            final_pat.trim();
            sig_str = BuildIDASignatureString(final_pat);
            sig_len = final_pat.size();
            sig_ea = eaStart;
            unique = IsPatternUniqueFast(segments, final_pat);
            if (sig_len == 0 || sig_str.empty()) {
                return tools::utils::MakeToolErrorJson(id, "No valid bytes or instructions found in range", "empty_signature");
            }
        }
        // 2. Standard mode (from start address)
        else if (!shortest) {
            GrowResult r = GrowCandSignature(segments, direct_candidate, max_len, max_len + 1);
            final_pat = std::move(r.pat);
            sig_str = BuildIDASignatureString(final_pat);
            unique = r.unique;
            sig_len = r.length;
            sig_ea = ea;
            target_offset = 0;
            sig_type = direct_candidate.type;
            if (sig_len == 0 || sig_str.empty()) {
                return tools::utils::MakeToolErrorJson(id, "Could not decode any instructions starting at address " + tools::utils::FormatAddress(ea), "signature_not_found");
            }
        }
        // 3. Ultra-optimized Shortest Search Mode
        else {
            GrowResult best_res;
            size_t best_len = max_len + 1;
            const CandidateMetadata* best_cand = nullptr;

            GrowResult fallback_res;
            const CandidateMetadata* fallback_cand = nullptr;

            for (const auto& cand : candidates) {
                GrowResult r = GrowCandSignature(segments, cand, max_len, best_len);
                if (r.unique && r.length < best_len) {
                    best_len = r.length;
                    best_res = std::move(r);
                    best_cand = &cand;
                } else if (r.pat.size() > fallback_res.pat.size()) {
                    fallback_res = std::move(r);
                    fallback_cand = &cand;
                }
            }

            if (best_cand && best_res.unique) {
                final_pat = std::move(best_res.pat);
                sig_str = BuildIDASignatureString(final_pat);
                unique = true;
                sig_len = best_res.length;
                sig_ea = best_cand->cand_ea;
                target_offset = best_cand->offset;
                sig_type = best_cand->type;
                xref_site_ea = best_cand->xref_ea;
                disp_off_in_sig = best_cand->disp_off;
            } else if (fallback_cand && fallback_res.pat.size() > 0) {
                final_pat = std::move(fallback_res.pat);
                sig_str = BuildIDASignatureString(final_pat);
                unique = false;
                sig_len = final_pat.size();
                sig_ea = fallback_cand->cand_ea;
                target_offset = fallback_cand->offset;
                sig_type = fallback_cand->type;
                xref_site_ea = fallback_cand->xref_ea;
                disp_off_in_sig = fallback_cand->disp_off;
            } else if (is_func) {
                CandidateMetadata entry_cm;
                entry_cm.cand_ea = ea;
                GrowResult r = GrowCandSignature(segments, entry_cm, max_len, max_len + 1);
                final_pat = std::move(r.pat);
                sig_str = BuildIDASignatureString(final_pat);
                unique = r.unique;
                sig_len = r.length;
                sig_ea = ea;
                target_offset = 0;
                sig_type = "function_entry";
            }

            if (sig_len == 0 || sig_str.empty()) {
                std::string msg = is_func ?
                    "Could not generate signature for " + tools::utils::FormatAddress(ea) + ": failed to decode valid instructions." :
                    "Could not generate signature for " + tools::utils::FormatAddress(ea) + ": target is data and no code references (XREFs) could produce instructions.";
                return tools::utils::MakeToolErrorJson(id, msg, "signature_not_found");
            }
        }

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["signature"] = sig_str;
        res["unique"] = unique;
        res["length"] = sig_len;
        res["address"] = tools::utils::FormatAddress(sig_ea);
        res["target"] = tools::utils::FormatAddress(ea != BADADDR ? ea : eaStart);
        res["type"] = sig_type;

        if (!unique) {
            ScanResult sr = ScanPattern(segments, final_pat, 10, true);
            res["matches_count"] = sr.count;
            nlohmann::json matches_arr = nlohmann::json::array();
            for (ea_t m : sr.matches) {
                matches_arr.push_back(tools::utils::FormatAddress(m));
            }
            res["matches"] = std::move(matches_arr);
            res["hint"] = "Signature has duplicate occurrences in binary. Try setting 'shortest': true or 'candidate_limit': 128.";
        }

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
