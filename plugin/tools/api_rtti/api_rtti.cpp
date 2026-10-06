#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include <ida.hpp>
#include <idp.hpp>
#include <lines.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <demangle.hpp>
#include <strlist.hpp>
#include <typeinf.hpp>
#include <auto.hpp>
#include <algorithm>
#include <regex>
#include <unordered_set>
#include <unordered_map>

#include "api_rtti.h"
#include "../../sync/sync.h"
#include "../../sync/cache_manager.h"
#include "../utils/utils.h"

namespace tools::rtti {

    namespace {
        struct RttiBaseClassInfo {
            std::string clean_name;
            std::string raw_name;
            int32_t offset = 0;              // mdisp (offset of this base inside derived class)
            int32_t pdisp = -1;              // vbtable displacement (-1 if not virtual base)
            int32_t vdisp = 0;               // displacement within vftable
            uint32_t num_contained_bases = 0;
            uint32_t attributes = 0;         // BCD attributes (0x40 = non-virtual, etc.)
            bool is_virtual = false;
            ea_t type_desc_ea = BADADDR;
            ea_t bcd_ea = BADADDR;
        };

        struct RttiClassEntry {
            ea_t type_desc_ea = BADADDR;
            std::string raw_name;
            std::string clean_name;
            ea_t vtable_ea = BADADDR;
            ea_t col_ea = BADADDR;
            ea_t chd_ea = BADADDR;
            uint32_t chd_attributes = 0;
            uint32_t offset = 0;
            size_t methods_count = 0;
            std::vector<std::string> hierarchy;
            std::vector<RttiBaseClassInfo> base_classes;
            std::vector<ea_t> constructors;
        };

        std::string SanitizeCIdentifier(const std::string& name) {
            if (name.empty()) return "AnonymousClass";
            std::string out;
            for (char c : name) {
                if (isalnum(static_cast<unsigned char>(c)) || c == '_') {
                    out.push_back(c);
                } else if (c == ':' || c == '<' || c == '>' || c == ' ' || c == '*' || c == '&' || c == '-' || c == '.') {
                    if (out.empty() || out.back() != '_') {
                        out.push_back('_');
                    }
                }
            }
            while (!out.empty() && out.back() == '_') out.pop_back();
            if (out.empty() || isdigit(static_cast<unsigned char>(out[0]))) {
                out = "Class_" + out;
            }
            return out;
        }

        std::string CleanTypeName(const std::string& raw) {
            if (raw.empty()) return "";

            if (raw.rfind(".?A", 0) == 0) {
                std::string mangled = "??_R0" + raw.substr(1) + "@8";
                try {
                    qstring demangled = demangle_name(mangled.c_str(), 0, DQT_FULL);
                    if (!demangled.empty()) {
                        std::string res = demangled.c_str();
                        if (res.rfind("class ", 0) == 0) res = res.substr(6);
                        else if (res.rfind("struct ", 0) == 0) res = res.substr(7);
                        else if (res.rfind("union ", 0) == 0) res = res.substr(6);
                        else if (res.rfind("enum ", 0) == 0) res = res.substr(5);

                        static const std::string kSuffix = " `RTTI Type Descriptor'";
                        if (res.size() >= kSuffix.size() &&
                            res.compare(res.size() - kSuffix.size(), kSuffix.size(), kSuffix) == 0) {
                            res.erase(res.size() - kSuffix.size());
                        }
                        return res;
                    }
                } catch (...) {
                }
            }

            std::string s = raw;
            if (s.rfind(".?AV", 0) == 0 || s.rfind(".?AU", 0) == 0) {
                s = s.substr(4);
            }
            while (!s.empty() && s.back() == '@') {
                s.pop_back();
            }

            std::vector<std::string> parts;
            size_t start = 0;
            for (size_t i = 0; i <= s.size(); ++i) {
                if (i == s.size() || s[i] == '@') {
                    if (i > start) {
                        parts.push_back(s.substr(start, i - start));
                    }
                    start = i + 1;
                }
            }

            if (!parts.empty()) {
                std::reverse(parts.begin(), parts.end());
                std::string result;
                for (size_t i = 0; i < parts.size(); ++i) {
                    if (i > 0) result += "::";
                    result += parts[i];
                }
                return result;
            }

            return s;
        }

        std::string ReadNullTermString(ea_t ea, size_t max_len = 512) {
            std::string s;
            if (ea == BADADDR || !is_mapped(ea)) return s;

            for (size_t i = 0; i < max_len; ++i) {
                ea_t cur = ea + i;
                if (!is_mapped(cur) || !is_loaded(cur)) break;
                char c = static_cast<char>(get_byte(cur));
                if (c == 0) break;
                s.push_back(c);
            }
            return s;
        }

        static std::string GetRegisterName(int reg, size_t width) {
            qstring buf;
            if (get_reg_name(&buf, reg, width) > 0) {
                return buf.c_str();
            }
            return "";
        }

        static thread_local std::string g_rtti_decl_errors;
        static int ida_export RttiDeclPrinter(const char *format, ...) {
            char buf[1024];
            va_list va;
            va_start(va, format);
            qvsnprintf(buf, sizeof(buf), format, va);
            va_end(va);
            g_rtti_decl_errors += buf;
            return 0;
        }

        static std::string ExtractCleanMethodName(const std::string& raw_name, const std::string& demangled, size_t index) {
            if (!demangled.empty()) {
                std::string d = demangled;
                if (d.find("scalar deleting destructor") != std::string::npos ||
                    d.find("`scalar deleting destructor'") != std::string::npos) {
                    return "scalar_deleting_destructor";
                }
                if (d.find("vector deleting destructor") != std::string::npos ||
                    d.find("`vector deleting destructor'") != std::string::npos) {
                    return "vector_deleting_destructor";
                }
                if (d.find("::~") != std::string::npos) {
                    return "destructor";
                }
                if (d.find("purecall") != std::string::npos) {
                    return "purecall";
                }
                size_t paren = d.find('(');
                std::string before_paren = (paren != std::string::npos) ? d.substr(0, paren) : d;
                size_t scope = before_paren.rfind("::");
                std::string mname = (scope != std::string::npos) ? before_paren.substr(scope + 2) : before_paren;
                while (!mname.empty() && mname.front() == ' ') mname.erase(mname.begin());
                while (!mname.empty() && mname.back() == ' ') mname.pop_back();

                std::string clean;
                for (char c : mname) {
                    if (isalnum(static_cast<unsigned char>(c)) || c == '_') {
                        clean += c;
                    }
                }
                if (!clean.empty() && (isalpha(static_cast<unsigned char>(clean[0])) || clean[0] == '_')) {
                    return clean;
                }
            }

            if (!raw_name.empty()) {
                if (raw_name.rfind("??_G", 0) == 0) return "scalar_deleting_destructor";
                if (raw_name.rfind("??_E", 0) == 0) return "vector_deleting_destructor";
                if (raw_name == "_purecall" || raw_name == "__cxa_pure_virtual") return "purecall";
                std::string clean;
                for (char c : raw_name) {
                    if (isalnum(static_cast<unsigned char>(c)) || c == '_') {
                        clean += c;
                    }
                }
                if (!clean.empty() && (isalpha(static_cast<unsigned char>(clean[0])) || clean[0] == '_')) {
                    return clean;
                }
            }

            return "vfunc_" + std::to_string(index);
        }

        size_t CountVtableMethods(ea_t vtable_ea, bool is64, size_t max_methods = 1024) {
            if (vtable_ea == BADADDR || !is_mapped(vtable_ea)) return 0;
            size_t ptr_size = is64 ? 8 : 4;
            size_t count = 0;

            for (size_t i = 0; i < max_methods; ++i) {
                ea_t entry_ea = vtable_ea + i * ptr_size;
                if (!is_mapped(entry_ea) || !is_loaded(entry_ea)) break;

                // Stop if another xref points here (start of another vftable/symbol)
                if (i > 0 && has_xref(get_flags(entry_ea))) {
                    break;
                }

                ea_t fn_ea = is64 ? get_qword(entry_ea) : get_dword(entry_ea);
                if (fn_ea == 0 || fn_ea == BADADDR || !is_mapped(fn_ea) || !is_loaded(fn_ea)) {
                    break;
                }

                flags_t F = get_flags(fn_ea);
                if (!is_code(F) && get_func(fn_ea) == nullptr) {
                    segment_t* s = getseg(fn_ea);
                    if (!s || s->type != SEG_CODE) {
                        break;
                    }
                }

                count++;
            }

            return count;
        }

        bool ParseColAndClass(ea_t col_ea, ea_t vtable_ea, bool is64, ea_t img_base, RttiClassEntry& entry) {
            if (col_ea == BADADDR || !is_mapped(col_ea) || !is_loaded(col_ea)) return false;
            segment_t* s = getseg(col_ea);
            if (!s || s->type == SEG_CODE) return false;

            try {
                // Validate MSVC RTTI CompleteObjectLocator signature: 1 on x64, 0 on x86
                uint32_t sig = get_dword(col_ea);
                if (is64 && sig != 1) return false;
                if (!is64 && sig != 0) return false;

                entry.col_ea = col_ea;
                entry.offset = get_dword(col_ea + 4);

                // Read TypeDescriptor
                ea_t td_ea = BADADDR;
                ea_t col_base = img_base;

                if (!is64) {
                    td_ea = get_dword(col_ea + 12);
                } else {
                    uint32_t td_rva = get_dword(col_ea + 12);
                    uint32_t self_rva = get_dword(col_ea + 20);
                    if (self_rva == 0) return false;
                    col_base = col_ea - self_rva;
                    // Validate base sanity
                    if (col_base != img_base && col_base > col_ea) return false;
                    td_ea = col_base + td_rva;
                }

                if (td_ea == BADADDR || !is_mapped(td_ea) || !is_loaded(td_ea)) return false;
                entry.type_desc_ea = td_ea;

                // Read raw name from TypeDescriptor
                ea_t raw_str_ea = td_ea + (is64 ? 16 : 8);
                if (!is_mapped(raw_str_ea)) return false;
                entry.raw_name = ReadNullTermString(raw_str_ea);
                if (entry.raw_name.empty() || entry.raw_name.rfind(".?A", 0) != 0) return false;
                entry.clean_name = tools::utils::SanitizeUtf8(CleanTypeName(entry.raw_name));

                // Read ClassHierarchyDescriptor (CHD)
                ea_t chd_ea = BADADDR;
                if (!is64) {
                    chd_ea = get_dword(col_ea + 16);
                } else {
                    uint32_t chd_rva = get_dword(col_ea + 16);
                    chd_ea = col_base + chd_rva;
                }

                if (chd_ea != BADADDR && is_mapped(chd_ea) && is_loaded(chd_ea)) {
                    entry.chd_ea = chd_ea;
                    entry.chd_attributes = get_dword(chd_ea + 4);
                    uint32_t num_bases = get_dword(chd_ea + 8);
                    ea_t bca_ea = is64 ? (col_base + get_dword(chd_ea + 12)) : get_dword(chd_ea + 12);

                    if (is_mapped(bca_ea) && is_loaded(bca_ea)) {
                        for (uint32_t bi = 0; bi < std::min(num_bases, 128u); ++bi) {
                            ea_t bcd_ptr = bca_ea + bi * 4;
                            if (!is_mapped(bcd_ptr) || !is_loaded(bcd_ptr)) break;

                            ea_t bcd_ea = is64 ? (col_base + get_dword(bcd_ptr)) : get_dword(bcd_ptr);
                            if (is_mapped(bcd_ea) && is_loaded(bcd_ea)) {
                                ea_t b_td = is64 ? (col_base + get_dword(bcd_ea)) : get_dword(bcd_ea);
                                if (is_mapped(b_td) && is_loaded(b_td)) {
                                    RttiBaseClassInfo base_info;
                                    base_info.bcd_ea = bcd_ea;
                                    base_info.type_desc_ea = b_td;
                                    base_info.num_contained_bases = get_dword(bcd_ea + 4);
                                    base_info.offset = static_cast<int32_t>(get_dword(bcd_ea + 8));
                                    base_info.pdisp = static_cast<int32_t>(get_dword(bcd_ea + 12));
                                    base_info.vdisp = static_cast<int32_t>(get_dword(bcd_ea + 16));
                                    base_info.attributes = get_dword(bcd_ea + 20);
                                    base_info.is_virtual = (base_info.pdisp != -1) || ((base_info.attributes & 1) == 0 && (base_info.attributes & 4) != 0);

                                    std::string b_raw = ReadNullTermString(b_td + (is64 ? 16 : 8));
                                    base_info.raw_name = b_raw;
                                    base_info.clean_name = tools::utils::SanitizeUtf8(CleanTypeName(b_raw));

                                    if (!base_info.clean_name.empty()) {
                                        entry.hierarchy.push_back(base_info.clean_name);
                                    }
                                    entry.base_classes.push_back(std::move(base_info));
                                }
                            }
                        }
                    }
                }

                // Vtable info
                entry.vtable_ea = vtable_ea;
                if (vtable_ea != BADADDR && is_mapped(vtable_ea)) {
                    entry.methods_count = CountVtableMethods(vtable_ea, is64);

                    // Collect constructors from xrefs to vtable
                    std::unordered_set<ea_t> ctor_set;
                    xrefblk_t vtxb;
                    for (bool vok = vtxb.first_to(vtable_ea, XREF_ALL); vok; vok = vtxb.next_to()) {
                        if (vtxb.from == BADADDR) continue;
                        func_t* pfn = get_func(vtxb.from);
                        if (pfn && ctor_set.insert(pfn->start_ea).second) {
                            entry.constructors.push_back(pfn->start_ea);
                        }
                    }
                }

                return true;
            } catch (...) {
                return false;
            }
        }

        class RttiIndex {
        private:
            std::vector<RttiClassEntry> classes_;
            std::unordered_map<std::string, size_t> by_clean_name_;
            std::unordered_map<std::string, size_t> by_raw_name_;
            std::unordered_map<ea_t, size_t> by_vtable_;
            std::unordered_map<ea_t, size_t> by_col_;
            std::unordered_map<ea_t, size_t> by_type_desc_;
            bool initialized_ = false;

            std::vector<RttiClassEntry> CollectRttiClassesInternal() {
                std::vector<RttiClassEntry> classes;
                std::unordered_set<ea_t> seen_vtables;
                std::unordered_set<ea_t> seen_cols;

                bool is64 = inf_is_64bit();
                ea_t img_base = get_imagebase();

                // Strategy 1: Scan IDA's Name List (instantaneous & accurate for symbols defined/analyzed by IDA)
                size_t name_count = get_nlist_size();
                for (size_t i = 0; i < name_count; ++i) {
                    const char* sym_name = get_nlist_name(i);
                    if (!sym_name) continue;

                    // Match vftable symbol: ??_7...
                    if (strncmp(sym_name, "??_7", 4) == 0) {
                        ea_t vt_ea = get_nlist_ea(i);
                        if (vt_ea != BADADDR && is_mapped(vt_ea) && seen_vtables.insert(vt_ea).second) {
                            ea_t col_ea = is64 ? get_qword(vt_ea - 8) : get_dword(vt_ea - 4);
                            if (col_ea != BADADDR && is_mapped(col_ea) && seen_cols.insert(col_ea).second) {
                                RttiClassEntry entry;
                                if (ParseColAndClass(col_ea, vt_ea, is64, img_base, entry)) {
                                    classes.push_back(entry);
                                }
                            }
                        }
                    }
                    // Match COL symbol: ??_R4...
                    else if (strncmp(sym_name, "??_R4", 5) == 0) {
                        ea_t col_ea = get_nlist_ea(i);
                        if (col_ea != BADADDR && is_mapped(col_ea) && seen_cols.insert(col_ea).second) {
                            // Find vtable via xrefs to COL
                            ea_t vt_ea = BADADDR;
                            xrefblk_t cxb;
                            for (bool cok = cxb.first_to(col_ea, XREF_DATA); cok; cok = cxb.next_to()) {
                                ea_t cand = is64 ? (cxb.from + 8) : (cxb.from + 4);
                                if (is_mapped(cand) && is_loaded(cand)) {
                                    ea_t m0 = is64 ? get_qword(cand) : get_dword(cand);
                                    if (m0 != 0 && m0 != BADADDR && is_mapped(m0)) {
                                        vt_ea = cand;
                                        seen_vtables.insert(vt_ea);
                                        break;
                                    }
                                }
                            }

                            RttiClassEntry entry;
                            if (ParseColAndClass(col_ea, vt_ea, is64, img_base, entry)) {
                                classes.push_back(entry);
                            }
                        }
                    }
                }

                // Strategy 2: If few classes found via nlist, scan String List for .?AV / .?AU
                if (classes.size() < 5) {
                    size_t str_qty = get_strlist_qty();
                    for (size_t si_idx = 0; si_idx < str_qty; ++si_idx) {
                        string_info_t si;
                        if (!get_strlist_item(&si, si_idx)) continue;
                        if (si.ea == BADADDR || !is_mapped(si.ea)) continue;

                        std::string s_text = ReadNullTermString(si.ea, 128);
                        if (s_text.rfind(".?AV", 0) == 0 || s_text.rfind(".?AU", 0) == 0) {
                            ea_t td_ea = is64 ? (si.ea - 16) : (si.ea - 8);
                            if (!is_mapped(td_ea)) continue;

                            // Find COL referencing this TD
                            xrefblk_t tdxb;
                            for (bool tok = tdxb.first_to(td_ea, XREF_DATA); tok; tok = tdxb.next_to()) {
                                if (tdxb.from == BADADDR) continue;
                                ea_t col_cand = tdxb.from - 12;
                                if (is_mapped(col_cand) && seen_cols.insert(col_cand).second) {
                                    ea_t vt_ea = BADADDR;
                                    xrefblk_t cxb;
                                    for (bool cok = cxb.first_to(col_cand, XREF_DATA); cok; cok = cxb.next_to()) {
                                        ea_t cand = is64 ? (cxb.from + 8) : (cxb.from + 4);
                                        if (is_mapped(cand) && is_loaded(cand)) {
                                            ea_t m0 = is64 ? get_qword(cand) : get_dword(cand);
                                            if (m0 != 0 && m0 != BADADDR && is_mapped(m0)) {
                                                vt_ea = cand;
                                                seen_vtables.insert(vt_ea);
                                                break;
                                            }
                                        }
                                    }

                                    RttiClassEntry entry;
                                    if (ParseColAndClass(col_cand, vt_ea, is64, img_base, entry)) {
                                        classes.push_back(entry);
                                    }
                                }
                            }
                        }
                    }
                }

                return classes;
            }

        public:
            static RttiIndex& Instance() {
                static RttiIndex inst;
                return inst;
            }

            void Invalidate() {
                classes_.clear();
                by_clean_name_.clear();
                by_raw_name_.clear();
                by_vtable_.clear();
                by_col_.clear();
                by_type_desc_.clear();
                initialized_ = false;
            }

            const std::vector<RttiClassEntry>& GetClasses() {
                if (!initialized_ || !auto_is_ok()) {
                    classes_ = CollectRttiClassesInternal();
                    by_clean_name_.clear();
                    by_raw_name_.clear();
                    by_vtable_.clear();
                    by_col_.clear();
                    by_type_desc_.clear();
                    for (size_t i = 0; i < classes_.size(); ++i) {
                        const auto& e = classes_[i];
                        if (!e.clean_name.empty()) {
                            auto it = by_clean_name_.find(e.clean_name);
                            if (it == by_clean_name_.end() || (classes_[it->second].offset != 0 && e.offset == 0)) {
                                by_clean_name_[e.clean_name] = i;
                            }
                        }
                        if (!e.raw_name.empty()) {
                            auto it = by_raw_name_.find(e.raw_name);
                            if (it == by_raw_name_.end() || (classes_[it->second].offset != 0 && e.offset == 0)) {
                                by_raw_name_[e.raw_name] = i;
                            }
                        }
                        if (e.vtable_ea != BADADDR) by_vtable_[e.vtable_ea] = i;
                        if (e.col_ea != BADADDR) by_col_[e.col_ea] = i;
                        if (e.type_desc_ea != BADADDR) by_type_desc_[e.type_desc_ea] = i;
                    }
                    if (auto_is_ok()) {
                        initialized_ = true;
                    }
                }
                return classes_;
            }

            const RttiClassEntry* FindClass(const std::string& query, ea_t query_ea = BADADDR) {
                const auto& clist = GetClasses();
                if (query_ea != BADADDR) {
                    auto it_vt = by_vtable_.find(query_ea);
                    if (it_vt != by_vtable_.end()) return &clist[it_vt->second];
                    auto it_col = by_col_.find(query_ea);
                    if (it_col != by_col_.end()) return &clist[it_col->second];
                    auto it_td = by_type_desc_.find(query_ea);
                    if (it_td != by_type_desc_.end()) return &clist[it_td->second];

                    // Check if query_ea is within any vtable slot range
                    bool is64 = inf_is_64bit();
                    size_t ptr_sz = is64 ? 8 : 4;
                    for (const auto& c : clist) {
                        if (c.vtable_ea != BADADDR && query_ea >= c.vtable_ea && query_ea < c.vtable_ea + c.methods_count * ptr_sz) {
                            return &c;
                        }
                    }

                    // Check if query_ea is a virtual method function (referenced by data XREF from a vtable slot)
                    xrefblk_t xb;
                    for (bool ok = xb.first_to(query_ea, XREF_DATA); ok; ok = xb.next_to()) {
                        if (xb.from == BADADDR) continue;
                        for (const auto& c : clist) {
                            if (c.vtable_ea != BADADDR && xb.from >= c.vtable_ea && xb.from < c.vtable_ea + c.methods_count * ptr_sz) {
                                return &c;
                            }
                        }
                    }

                    // Check if query_ea is a constructor
                    for (const auto& c : clist) {
                        for (ea_t ctor_ea : c.constructors) {
                            if (ctor_ea == query_ea) return &c;
                        }
                    }
                }
                if (!query.empty()) {
                    auto it_c = by_clean_name_.find(query);
                    if (it_c != by_clean_name_.end()) return &clist[it_c->second];
                    auto it_r = by_raw_name_.find(query);
                    if (it_r != by_raw_name_.end()) return &clist[it_r->second];
                    for (const auto& c : clist) {
                        if (c.clean_name == query || c.raw_name == query) return &c;
                    }
                    for (const auto& c : clist) {
                        if (tools::utils::PatternMatch(c.clean_name, query) ||
                            tools::utils::PatternMatch(c.raw_name, query)) {
                            return &c;
                        }
                    }
                    for (const auto& c : clist) {
                        if (c.clean_name.find(query) != std::string::npos ||
                            c.raw_name.find(query) != std::string::npos) {
                            return &c;
                        }
                    }
                }
                return nullptr;
            }
        };

        inline const std::vector<RttiClassEntry>& CollectRttiClasses() {
            return RttiIndex::Instance().GetClasses();
        }

        struct RttiCacheAutoReg {
            RttiCacheAutoReg() {
                cache::CacheManager::Instance().RegisterAnalysisInvalidator([]() {
                    RttiIndex::Instance().Invalidate();
                });
            }
        } s_rtti_cache_reg;
    }

    ApiRtti::ApiRtti() = default;

    bool ApiRtti::CanHandle(const std::string& name) const {
        return name == "rtti" ||
               name == "resolve_vcall";
    }

    nlohmann::json ApiRtti::GetSchema() const {
        return nlohmann::json::array();
    }

    nlohmann::json ApiRtti::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "rtti") return UnifiedRtti(id, args);
        if (name == "resolve_vcall") return ResolveVcall(id, args);

        return tools::utils::MakeToolErrorJson(id, "Method not found: " + name, "method_not_found");
    }

    nlohmann::json ApiRtti::UnifiedRtti(const nlohmann::json& id, const nlohmann::json& args) {
        // 1. Explicit refresh RTTI cache
        if (args.contains("refresh") && args["refresh"].is_boolean() && args["refresh"].get<bool>() && !args.contains("name") && !args.contains("pattern") && !args.contains("class") && !args.contains("addr")) {
            return RttiRefresh(id, args);
        }

        // 2. Create struct / TIL type for class
        if (args.contains("create_struct") || args.contains("struct_name") || args.contains("apply_to_vtable")) {
            nlohmann::json create_args = args;
            if (!create_args.contains("name")) {
                if (create_args.contains("class")) create_args["name"] = create_args["class"];
                else if (create_args.contains("addr")) create_args["name"] = create_args["addr"];
            }
            return RttiCreateStruct(id, create_args);
        }

        // 3. Inspect specific class (by name, class, addr, vtable)
        if (args.contains("name") || args.contains("class") || args.contains("addr") || args.contains("vtable")) {
            nlohmann::json class_args = args;
            if (!class_args.contains("name")) {
                if (class_args.contains("class")) class_args["name"] = class_args["class"];
                else if (class_args.contains("addr")) class_args["name"] = class_args["addr"];
                else if (class_args.contains("vtable")) class_args["name"] = class_args["vtable"];
            }
            return RttiGetClass(id, class_args);
        }

        // 4. Default: list classes (with optional pattern, base_class, etc.)
        return RttiListClasses(id, args);
    }

    nlohmann::json ApiRtti::RttiListClasses(const nlohmann::json& id, const nlohmann::json& args) {
        std::string pattern = tools::utils::GetStringArg(args, "pattern");
        std::string base_class = tools::utils::GetStringArg(args, "base_class");
        int min_methods = static_cast<int>(tools::utils::GetIntArg(args, "min_methods", -1));
        int max_methods = static_cast<int>(tools::utils::GetIntArg(args, "max_methods", -1));
        bool has_vtable_only = tools::utils::GetBoolArg(args, "has_vtable", false);
        std::string sort_by = tools::utils::GetStringArg(args, "sort", "name");
        std::string sort_order = tools::utils::GetStringArg(args, "sort_order", (sort_by == "methods" ? "desc" : "asc"));

        size_t offset = static_cast<size_t>(tools::utils::GetIntArg(args, "offset", 0));
        std::string cursor_str = tools::utils::GetStringArg(args, "cursor");
        if (!cursor_str.empty()) {
            try { offset = static_cast<size_t>(std::stoul(cursor_str)); } catch (...) {}
        }
        size_t count = static_cast<size_t>(tools::utils::GetIntArg(args, "count", 50));
        if (count <= 0) count = 50;
        if (count > 500) count = 500;

        bool refresh = tools::utils::GetBoolArg(args, "refresh", false);
        std::vector<RttiClassEntry> all_classes;
        sync::SyncRead([&]() {
            try {
                if (refresh) {
                    RttiIndex::Instance().Invalidate();
                }
                all_classes = CollectRttiClasses();
            } catch (...) {
            }
        });

        std::vector<const RttiClassEntry*> filtered;
        filtered.reserve(all_classes.size());

        for (const auto& c : all_classes) {
            if (!pattern.empty()) {
                if (!tools::utils::PatternMatch(c.clean_name, pattern) &&
                    !tools::utils::PatternMatch(c.raw_name, pattern)) {
                    continue;
                }
            }

            if (!base_class.empty()) {
                bool base_matched = false;
                for (const auto& b : c.hierarchy) {
                    if (tools::utils::PatternMatch(b, base_class)) {
                        base_matched = true;
                        break;
                    }
                }
                if (!base_matched) continue;
            }

            if (min_methods >= 0 && static_cast<int>(c.methods_count) < min_methods) {
                continue;
            }
            if (max_methods >= 0 && static_cast<int>(c.methods_count) > max_methods) {
                continue;
            }
            if (has_vtable_only && (c.vtable_ea == BADADDR || c.vtable_ea == 0)) {
                continue;
            }

            filtered.push_back(&c);
        }

        bool is_desc = (sort_order == "desc");
        if (sort_by == "methods") {
            std::stable_sort(filtered.begin(), filtered.end(), [is_desc](const RttiClassEntry* a, const RttiClassEntry* b) {
                return is_desc ? (a->methods_count > b->methods_count) : (a->methods_count < b->methods_count);
            });
        } else if (sort_by == "vtable") {
            std::stable_sort(filtered.begin(), filtered.end(), [is_desc](const RttiClassEntry* a, const RttiClassEntry* b) {
                return is_desc ? (a->vtable_ea > b->vtable_ea) : (a->vtable_ea < b->vtable_ea);
            });
        } else if (sort_by == "offset") {
            std::stable_sort(filtered.begin(), filtered.end(), [is_desc](const RttiClassEntry* a, const RttiClassEntry* b) {
                return is_desc ? (a->offset > b->offset) : (a->offset < b->offset);
            });
        } else {
            std::stable_sort(filtered.begin(), filtered.end(), [is_desc](const RttiClassEntry* a, const RttiClassEntry* b) {
                return is_desc ? (a->clean_name > b->clean_name) : (a->clean_name < b->clean_name);
            });
        }

        nlohmann::json classes_arr = nlohmann::json::array();
        size_t total_matched = filtered.size();
        size_t end_idx = std::min(offset + count, total_matched);

        for (size_t i = offset; i < end_idx; ++i) {
            const auto* c = filtered[i];
            nlohmann::ordered_json item;
            item["class"] = c->clean_name;
            if (c->vtable_ea != BADADDR && c->vtable_ea != 0) {
                item["vtable"] = tools::utils::FormatAddress(c->vtable_ea);
            }
            item["methods"] = c->methods_count;
            if (c->offset != 0) {
                item["offset"] = c->offset;
            }
            if (!c->hierarchy.empty()) {
                item["hierarchy"] = c->hierarchy;
            }
            classes_arr.push_back(std::move(item));
        }

        int next_offset = -1;
        if (end_idx < total_matched) {
            next_offset = static_cast<int>(end_idx);
        }

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["total"] = total_matched;
        res["returned"] = classes_arr.size();
        res["offset"] = offset;
        res["classes"] = classes_arr;
        if (next_offset != -1) {
            res["next_offset"] = next_offset;
            res["next_cursor"] = std::to_string(next_offset);
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    namespace {
        nlohmann::json ExtractVtableMethods(ea_t vtable_ea, size_t methods_count, bool is64, ea_t query_ea) {
            nlohmann::json methods_arr = nlohmann::json::array();
            if (vtable_ea == BADADDR || !is_mapped(vtable_ea)) return methods_arr;
            size_t ptr_size = is64 ? 8 : 4;

            for (size_t i = 0; i < methods_count; ++i) {
                ea_t entry_ea = vtable_ea + i * ptr_size;
                if (!is_mapped(entry_ea) || !is_loaded(entry_ea)) break;

                ea_t fn_ea = is64 ? get_qword(entry_ea) : get_dword(entry_ea);
                nlohmann::ordered_json m;
                m["index"] = i;
                m["address"] = tools::utils::FormatAddress(fn_ea);

                qstring fname;
                if (is_mapped(fn_ea)) {
                    get_func_name(&fname, fn_ea);
                    if (fname.empty()) get_name(&fname, fn_ea);
                }
                std::string name_str = fname.c_str();
                m["name"] = name_str;

                // Demangle C++ signature
                qstring demangled = demangle_name(name_str.c_str(), 0, DQT_FULL);
                if (!demangled.empty()) {
                    m["demangled_name"] = demangled.c_str();
                }

                // Prototype from Type Library
                tinfo_t tif;
                if (get_tinfo(&tif, fn_ea)) {
                    qstring proto;
                    if (tif.print(&proto, nullptr, PRTYPE_1LINE | PRTYPE_SEMI)) {
                        m["prototype"] = proto.c_str();
                    }
                }

                // Function metadata
                func_t* pfn = get_func(fn_ea);
                if (pfn) {
                    m["size"] = pfn->end_ea - pfn->start_ea;
                    if (pfn->flags & FUNC_THUNK) {
                        m["is_thunk"] = true;
                    }
                }

                // Pure virtual detection
                if (name_str == "_purecall" || name_str == "__cxa_pure_virtual" ||
                    name_str.find("purecall") != std::string::npos) {
                    m["is_pure_virtual"] = true;
                }

                // Destructor detection
                std::string d_str = demangled.empty() ? "" : demangled.c_str();
                if (name_str.rfind("??_G", 0) == 0 || name_str.rfind("??_E", 0) == 0 ||
                    d_str.find("deleting destructor") != std::string::npos ||
                    d_str.find("::~") != std::string::npos) {
                    m["is_destructor"] = true;
                }

                if (query_ea != BADADDR && (fn_ea == query_ea || entry_ea == query_ea)) {
                    m["is_queried"] = true;
                }

                methods_arr.push_back(std::move(m));
            }
            return methods_arr;
        }
    }

    nlohmann::json ApiRtti::RttiGetClass(const nlohmann::json& id, const nlohmann::json& args) {
        std::string query = tools::utils::GetStringArg(args, "name", tools::utils::GetStringArg(args, "addr", tools::utils::GetStringArg(args, "query")));
        ea_t query_ea = tools::utils::ParseAddress(query);
        bool refresh = tools::utils::GetBoolArg(args, "refresh", false);

        if (query.empty() && query_ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'name' is required", "missing_argument");
        }

        RttiClassEntry target_copy;
        std::vector<RttiClassEntry> all_matching_entries;
        std::vector<std::string> candidate_classes;
        bool found = false;
        bool is64 = false;

        sync::SyncRead([&]() {
            try {
                if (refresh) {
                    RttiIndex::Instance().Invalidate();
                }
                is64 = inf_is_64bit();
                const auto* target = RttiIndex::Instance().FindClass(query, query_ea);
                if (target) {
                    found = true;
                    target_copy = *target;

                    const auto& clist = RttiIndex::Instance().GetClasses();
                    for (const auto& c : clist) {
                        if (c.type_desc_ea != BADADDR && c.type_desc_ea == target->type_desc_ea) {
                            all_matching_entries.push_back(c);
                        } else if (!query.empty() && c.clean_name.find(query) != std::string::npos) {
                            if (candidate_classes.size() < 10 && c.clean_name != target_copy.clean_name) {
                                candidate_classes.push_back(c.clean_name);
                            }
                        }
                    }

                    std::sort(all_matching_entries.begin(), all_matching_entries.end(), [](const RttiClassEntry& a, const RttiClassEntry& b) {
                        return a.offset < b.offset;
                    });
                }
            } catch (...) {
            }
        });

        if (!found) {
            return tools::utils::MakeToolErrorJson(id, "No RTTI class matching query '" + query + "' was found in binary", "class_not_found");
        }

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["class"] = target_copy.clean_name;
        res["raw_name"] = target_copy.raw_name;
        if (target_copy.vtable_ea != BADADDR) {
            res["vtable"] = tools::utils::FormatAddress(target_copy.vtable_ea);
        }
        if (target_copy.offset != 0) {
            res["offset"] = target_copy.offset;
        }

        // Inheritance flags
        if (target_copy.chd_attributes & 1) {
            res["multiple_inheritance"] = true;
        }
        if (target_copy.chd_attributes & 2) {
            res["virtual_inheritance"] = true;
        }

        // Base classes with member offsets
        if (!target_copy.base_classes.empty()) {
            nlohmann::json base_classes_arr = nlohmann::json::array();
            for (const auto& b : target_copy.base_classes) {
                nlohmann::ordered_json b_obj;
                b_obj["name"] = b.clean_name;
                b_obj["offset"] = b.offset;
                if (b.is_virtual) {
                    b_obj["is_virtual"] = true;
                }
                base_classes_arr.push_back(std::move(b_obj));
            }
            res["base_classes"] = base_classes_arr;
        }

        // Primary methods
        res["methods_count"] = target_copy.methods_count;
        res["methods"] = ExtractVtableMethods(target_copy.vtable_ea, target_copy.methods_count, is64, query_ea);

        // Constructors & initializers (if detected)
        if (!target_copy.constructors.empty()) {
            nlohmann::json ctors_arr = nlohmann::json::array();
            for (ea_t c_ea : target_copy.constructors) {
                nlohmann::ordered_json c_obj;
                c_obj["address"] = tools::utils::FormatAddress(c_ea);
                qstring cname;
                get_func_name(&cname, c_ea);
                if (cname.empty()) get_name(&cname, c_ea);
                c_obj["name"] = cname.c_str();
                qstring cdemangled = demangle_name(cname.c_str(), 0, DQT_FULL);
                if (!cdemangled.empty()) {
                    c_obj["demangled_name"] = cdemangled.c_str();
                }
                func_t* cpfn = get_func(c_ea);
                if (cpfn) {
                    c_obj["size"] = cpfn->end_ea - cpfn->start_ea;
                }
                tinfo_t ctif;
                if (get_tinfo(&ctif, c_ea)) {
                    qstring cproto;
                    if (ctif.print(&cproto, nullptr, PRTYPE_1LINE | PRTYPE_SEMI)) {
                        c_obj["prototype"] = cproto.c_str();
                    }
                }
                ctors_arr.push_back(std::move(c_obj));
            }
            res["constructors"] = ctors_arr;
        }

        // Multiple vtables list (only if more than one vtable exists for this class)
        if (all_matching_entries.size() > 1) {
            nlohmann::json vtables_arr = nlohmann::json::array();
            for (const auto& e : all_matching_entries) {
                nlohmann::ordered_json vt_obj;
                vt_obj["offset"] = e.offset;
                vt_obj["vtable"] = tools::utils::FormatAddress(e.vtable_ea);
                vt_obj["methods_count"] = e.methods_count;
                vt_obj["methods"] = ExtractVtableMethods(e.vtable_ea, e.methods_count, is64, query_ea);
                vtables_arr.push_back(std::move(vt_obj));
            }
            res["vtables"] = vtables_arr;
        }

        if (!candidate_classes.empty()) {
            res["candidate_classes"] = candidate_classes;
        }

        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiRtti::RttiRefresh(const nlohmann::json& id, const nlohmann::json& args) {
        size_t count = 0;
        bool ok = false;
        std::string err_msg;

        sync::SyncRead([&]() {
            try {
                RttiIndex::Instance().Invalidate();
                cache::InvalidateIDBAnalysis();
                cache::CacheManager::Instance().InvalidateAnalysis();
                count = CollectRttiClasses().size();
                ok = true;
            } catch (const std::exception& e) {
                err_msg = e.what();
            } catch (...) {
                err_msg = "Unknown error during RTTI refresh";
            }
        });

        if (!ok) {
            return tools::utils::MakeToolErrorJson(id, "Failed to refresh RTTI index: " + err_msg, "rtti_refresh_failed");
        }

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["refreshed"] = true;
        res["classes_count"] = count;

        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiRtti::RttiCreateStruct(const nlohmann::json& id, const nlohmann::json& args) {
        std::string query = tools::utils::GetStringArg(args, "name", tools::utils::GetStringArg(args, "query", tools::utils::GetStringArg(args, "addr")));
        std::string custom_name = tools::utils::GetStringArg(args, "struct_name", tools::utils::GetStringArg(args, "struct_prefix"));
        bool apply_to_vtable = tools::utils::GetBoolArg(args, "apply_to_vtable", false);
        ea_t query_ea = tools::utils::ParseAddress(query);

        RttiClassEntry target_copy;
        std::vector<RttiClassEntry> all_matching_entries;
        bool found = false;
        bool is64 = false;

        sync::SyncRead([&]() {
            try {
                is64 = inf_is_64bit();
                const auto* target = RttiIndex::Instance().FindClass(query, query_ea);
                if (target) {
                    found = true;
                    target_copy = *target;

                    const auto& clist = RttiIndex::Instance().GetClasses();
                    for (const auto& c : clist) {
                        if (c.type_desc_ea != BADADDR && c.type_desc_ea == target->type_desc_ea) {
                            all_matching_entries.push_back(c);
                        }
                    }

                    std::sort(all_matching_entries.begin(), all_matching_entries.end(), [](const RttiClassEntry& a, const RttiClassEntry& b) {
                        return a.offset < b.offset;
                    });
                }
            } catch (...) {
            }
        });

        if (!found) {
            return tools::utils::MakeToolErrorJson(id, "No RTTI class matching query '" + query + "' was found in binary", "class_not_found");
        }

        std::string base_struct_name = custom_name.empty() ? SanitizeCIdentifier(target_copy.clean_name) : SanitizeCIdentifier(custom_name);
        std::string vtable_struct_name = base_struct_name + "_vftable";
        std::string class_struct_name = base_struct_name;
        size_t ptr_size = is64 ? 8 : 4;

        std::ostringstream ss;
        ss << "// Forward declarations\n";
        ss << "struct " << vtable_struct_name << ";\n";
        for (size_t ei = 1; ei < all_matching_entries.size(); ++ei) {
            ss << "struct " << vtable_struct_name << "_" << all_matching_entries[ei].offset << ";\n";
        }
        ss << "struct " << class_struct_name << ";\n\n";

        // Primary vtable struct
        nlohmann::json methods_arr = nlohmann::json::array();
        std::unordered_set<std::string> seen_names;

        ss << "struct " << vtable_struct_name << " {\n";
        sync::SyncRead([&]() {
            if (target_copy.vtable_ea != BADADDR && is_mapped(target_copy.vtable_ea)) {
                for (size_t i = 0; i < target_copy.methods_count; ++i) {
                    ea_t entry_ea = target_copy.vtable_ea + i * ptr_size;
                    if (!is_mapped(entry_ea) || !is_loaded(entry_ea)) break;

                    ea_t fn_ea = is64 ? get_qword(entry_ea) : get_dword(entry_ea);
                    qstring fname;
                    if (is_mapped(fn_ea)) {
                        get_func_name(&fname, fn_ea);
                        if (fname.empty()) get_name(&fname, fn_ea);
                    }
                    std::string fn_str = fname.c_str();
                    qstring demangled = demangle_name(fn_str.c_str(), 0, DQT_FULL);
                    std::string dem_str = demangled.empty() ? "" : demangled.c_str();

                    std::string m_name = ExtractCleanMethodName(fn_str, dem_str, i);
                    if (!seen_names.insert(m_name).second) {
                        m_name += "_" + std::to_string(i);
                        seen_names.insert(m_name);
                    }

                    ss << "    void* " << m_name << ";\n";

                    nlohmann::ordered_json mj;
                    mj["index"] = i;
                    mj["name"] = m_name;
                    mj["address"] = tools::utils::FormatAddress(fn_ea);
                    if (!dem_str.empty()) mj["demangled"] = dem_str;
                    methods_arr.push_back(std::move(mj));
                }
            } else {
                for (size_t i = 0; i < target_copy.methods_count; ++i) {
                    ss << "    void* vfunc_" << i << ";\n";
                }
            }
        });
        ss << "};\n\n";

        // Secondary vtable structs if multiple inheritance exists
        for (size_t ei = 1; ei < all_matching_entries.size(); ++ei) {
            const auto& sec_entry = all_matching_entries[ei];
            std::string sec_vtable_name = vtable_struct_name + "_" + std::to_string(sec_entry.offset);
            std::unordered_set<std::string> sec_seen;

            ss << "struct " << sec_vtable_name << " {\n";
            sync::SyncRead([&]() {
                if (sec_entry.vtable_ea != BADADDR && is_mapped(sec_entry.vtable_ea)) {
                    for (size_t i = 0; i < sec_entry.methods_count; ++i) {
                        ea_t entry_ea = sec_entry.vtable_ea + i * ptr_size;
                        if (!is_mapped(entry_ea) || !is_loaded(entry_ea)) break;

                        ea_t fn_ea = is64 ? get_qword(entry_ea) : get_dword(entry_ea);
                        qstring fname;
                        if (is_mapped(fn_ea)) {
                            get_func_name(&fname, fn_ea);
                            if (fname.empty()) get_name(&fname, fn_ea);
                        }
                        std::string fn_str = fname.c_str();
                        qstring demangled = demangle_name(fn_str.c_str(), 0, DQT_FULL);
                        std::string dem_str = demangled.empty() ? "" : demangled.c_str();

                        std::string m_name = ExtractCleanMethodName(fn_str, dem_str, i);
                        if (!sec_seen.insert(m_name).second) {
                            m_name += "_" + std::to_string(i);
                            sec_seen.insert(m_name);
                        }
                        ss << "    void* " << m_name << ";\n";
                    }
                }
            });
            ss << "};\n\n";
        }

        // Class struct definition
        ss << "struct " << class_struct_name << " {\n";
        ss << "    struct " << vtable_struct_name << "* __vftable;\n";
        for (size_t ei = 1; ei < all_matching_entries.size(); ++ei) {
            const auto& sec_entry = all_matching_entries[ei];
            std::string sec_vtable_name = vtable_struct_name + "_" + std::to_string(sec_entry.offset);
            ss << "    struct " << sec_vtable_name << "* __vftable_" << sec_entry.offset << ";\n";
        }
        ss << "};\n";

        std::string c_header = ss.str();
        int parse_errs = 0;
        g_rtti_decl_errors.clear();

        sync::SyncWrite([&]() {
            try {
                parse_errs = parse_decls(get_idati(), c_header.c_str(), RttiDeclPrinter, HTI_DCL | HTI_PAKDEF | HTI_NWR | HTI_SEMICOLON);
            } catch (...) {
                parse_errs = -1;
            }
        });

        if (parse_errs != 0) {
            std::string msg = g_rtti_decl_errors.empty() ? "C header parser failed to declare struct in IDA type library" : g_rtti_decl_errors;
            return tools::utils::MakeToolErrorJson(id, msg, "create_struct_failed", parse_errs);
        }

        // Read registered struct sizes
        size_t cls_size = 0;
        size_t vt_size = 0;
        sync::SyncRead([&]() {
            tinfo_t cls_tif;
            if (cls_tif.get_named_type(get_idati(), class_struct_name.c_str())) {
                cls_size = cls_tif.get_size();
            }
            tinfo_t vt_tif;
            if (vt_tif.get_named_type(get_idati(), vtable_struct_name.c_str())) {
                vt_size = vt_tif.get_size();
            }
        });

        // Optionally apply vtable struct type to IDB vtable address
        if (apply_to_vtable && target_copy.vtable_ea != BADADDR) {
            sync::SyncWrite([&]() {
                tinfo_t vt_tif;
                if (vt_tif.get_named_type(get_idati(), vtable_struct_name.c_str())) {
                    apply_tinfo(target_copy.vtable_ea, vt_tif, TINFO_DEFINITE);
                }
            });
        }

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["struct_name"] = class_struct_name;
        res["vtable_struct"] = vtable_struct_name;
        res["size"] = cls_size;
        res["vtable_size"] = vt_size;
        res["methods_count"] = methods_arr.size();
        res["c_declaration"] = c_header;
        res["methods"] = methods_arr;
        if (apply_to_vtable && target_copy.vtable_ea != BADADDR) {
            res["applied_to_vtable"] = tools::utils::FormatAddress(target_copy.vtable_ea);
        }

        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiRtti::ResolveVcall(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t query_ea = tools::utils::GetAddressArg(args, "addr");
        if (query_ea == BADADDR) query_ea = tools::utils::GetAddressArg(args, "call_addr");
        if (query_ea == BADADDR) query_ea = tools::utils::GetAddressArg(args, "vtable_addr");
        if (query_ea == BADADDR) query_ea = tools::utils::GetAddressArg(args, "vtable");
        if (query_ea == BADADDR) query_ea = tools::utils::GetAddressArg(args, "method_addr");

        std::string class_query = tools::utils::GetStringArg(args, "class", tools::utils::GetStringArg(args, "class_name"));
        int target_index = static_cast<int>(tools::utils::GetIntArg(args, "index", -1));
        bool all_methods = tools::utils::GetBoolArg(args, "all_methods", false);
        bool demangle = tools::utils::GetBoolArg(args, "demangle", true);
        size_t max_methods = static_cast<size_t>(tools::utils::GetIntArg(args, "max_methods", 128));
        if (max_methods == 0 || max_methods > 512) max_methods = 128;

        if (query_ea == BADADDR && class_query.empty()) {
            return tools::utils::MakeToolErrorJson(id, "Either 'addr' (call site / vtable / method address) or 'class' name must be provided", "addr_or_class_required");
        }

        bool is64 = false;
        std::string mode = "unknown";
        ea_t resolved_vtable_ea = BADADDR;
        std::string resolved_class_name;
        std::vector<std::string> class_hierarchy;
        nlohmann::json methods_arr = nlohmann::json::array();
        nlohmann::json resolved_method_json = nullptr;
        std::string insn_str;
        std::string base_reg;
        std::string pfn_name;
        std::string inferred_from;
        int call_disp = -1;
        bool is_code_seg = false;

        sync::SyncRead([&]() {
            is64 = inf_is_64bit();
            size_t ptr_size = is64 ? 8 : 4;

            if (target_index == -1) {
                int64_t off_arg = tools::utils::GetIntArg(args, "offset", -1);
                if (off_arg >= 0) {
                    target_index = static_cast<int>(off_arg / ptr_size);
                } else {
                    std::string offset_str = tools::utils::GetStringArg(args, "offset");
                    if (!offset_str.empty()) {
                        ea_t off_val = tools::utils::ParseAddress(offset_str);
                        if (off_val != BADADDR) {
                            target_index = static_cast<int>(off_val / ptr_size);
                        }
                    }
                }
            }

            if (!class_query.empty() && query_ea == BADADDR) {
                mode = "class";
                const auto* c = RttiIndex::Instance().FindClass(class_query);
                if (c) {
                    resolved_vtable_ea = c->vtable_ea;
                    resolved_class_name = c->clean_name;
                    class_hierarchy = c->hierarchy;
                }
            }

            if (query_ea != BADADDR && is_mapped(query_ea)) {
                segment_t* seg = getseg(query_ea);
                is_code_seg = (seg && (seg->perm & SEGPERM_EXEC) != 0);

                if (is_code_seg) {
                    qstring dline;
                    if (generate_disasm_line(&dline, query_ea, GENDSM_REMOVE_TAGS)) {
                        insn_str = dline.c_str();
                    }
                    func_t* pfn = get_func(query_ea);
                    if (pfn) {
                        qstring qpfn;
                        get_func_name(&qpfn, pfn->start_ea);
                        pfn_name = qpfn.c_str();
                    }

                    insn_t insn;
                    if (decode_insn(&insn, query_ea) > 0) {
                        for (int op_i = 0; op_i < 6; ++op_i) {
                            if (insn.ops[op_i].type == o_displ) {
                                call_disp = static_cast<int>(insn.ops[op_i].addr);
                                base_reg = GetRegisterName(insn.ops[op_i].reg, ptr_size);
                                mode = "call_site";
                                break;
                            } else if (insn.ops[op_i].type == o_phrase) {
                                call_disp = 0;
                                base_reg = GetRegisterName(insn.ops[op_i].reg, ptr_size);
                                mode = "call_site";
                                break;
                            } else if (insn.ops[op_i].type == o_reg && (is_call_insn(insn) || is_indirect_jump_insn(insn))) {
                                base_reg = GetRegisterName(insn.ops[op_i].reg, ptr_size);
                                mode = "call_site";

                                // Backward search up to 5 steps to find where register was loaded: `mov reg, [vtable_reg + disp]`
                                if (pfn) {
                                    ea_t b_ea = query_ea;
                                    for (int step = 0; step < 5; ++step) {
                                        ea_t prev_b = prev_head(b_ea, pfn->start_ea);
                                        if (prev_b == BADADDR || prev_b == b_ea) break;
                                        b_ea = prev_b;
                                        insn_t prev_b_insn;
                                        if (decode_insn(&prev_b_insn, b_ea) > 0) {
                                            if (prev_b_insn.ops[0].type == o_reg && prev_b_insn.ops[0].reg == insn.ops[op_i].reg) {
                                                if (prev_b_insn.ops[1].type == o_displ) {
                                                    call_disp = static_cast<int>(prev_b_insn.ops[1].addr);
                                                    base_reg = GetRegisterName(prev_b_insn.ops[1].reg, ptr_size);
                                                    break;
                                                } else if (prev_b_insn.ops[1].type == o_phrase) {
                                                    call_disp = 0;
                                                    base_reg = GetRegisterName(prev_b_insn.ops[1].reg, ptr_size);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                                break;
                            }
                        }

                        if (call_disp >= 0 && target_index == -1) {
                            target_index = call_disp / static_cast<int>(ptr_size);
                        }
                    }

                    if (!class_query.empty()) {
                        const auto* c = RttiIndex::Instance().FindClass(class_query);
                        if (c) {
                            resolved_vtable_ea = c->vtable_ea;
                            resolved_class_name = c->clean_name;
                            class_hierarchy = c->hierarchy;
                        }
                    }

                    // If call_disp is still -1, check if query_ea itself is a virtual method implementation
                    if (call_disp == -1) {
                        ea_t target_fn_ea = pfn ? pfn->start_ea : query_ea;
                        xrefblk_t xb;
                        for (bool ok = xb.first_to(target_fn_ea, XREF_DATA); ok; ok = xb.next_to()) {
                            if (xb.from == BADADDR) continue;
                            segment_t* from_seg = getseg(xb.from);
                            if (from_seg && (from_seg->perm & SEGPERM_EXEC) == 0) {
                                const auto* c = RttiIndex::Instance().FindClass("", xb.from);
                                if (c) {
                                    resolved_vtable_ea = c->vtable_ea;
                                    resolved_class_name = c->clean_name;
                                    class_hierarchy = c->hierarchy;
                                    target_index = static_cast<int>((xb.from - c->vtable_ea) / ptr_size);
                                    mode = "method_lookup";
                                    break;
                                }
                            }
                        }
                    }

                    // Backward search in basic block to see if register loaded a known vtable
                    if (mode == "call_site" && resolved_vtable_ea == BADADDR && pfn) {
                        ea_t cur_ea = query_ea;
                        for (int step = 0; step < 15; ++step) {
                            ea_t prev_ea = prev_head(cur_ea, pfn->start_ea);
                            if (prev_ea == BADADDR || prev_ea == cur_ea) break;
                            cur_ea = prev_ea;
                            insn_t prev_insn;
                            if (decode_insn(&prev_insn, cur_ea) > 0) {
                                for (int op_i = 0; op_i < 6; ++op_i) {
                                    if (prev_insn.ops[op_i].type == o_mem || prev_insn.ops[op_i].type == o_imm) {
                                        ea_t cand_ea = prev_insn.ops[op_i].addr;
                                        const auto* c = RttiIndex::Instance().FindClass("", cand_ea);
                                        if (c) {
                                            resolved_vtable_ea = c->vtable_ea;
                                            resolved_class_name = c->clean_name;
                                            class_hierarchy = c->hierarchy;
                                            break;
                                        }
                                        if (is_mapped(cand_ea)) {
                                            segment_t* cs = getseg(cand_ea);
                                            if (cs && (cs->perm & SEGPERM_EXEC) == 0) {
                                                ea_t first_fn = is64 ? get_qword(cand_ea) : get_dword(cand_ea);
                                                if (is_mapped(first_fn)) {
                                                    segment_t* fns = getseg(first_fn);
                                                    if (fns && (fns->perm & SEGPERM_EXEC) != 0) {
                                                        resolved_vtable_ea = cand_ea;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                if (resolved_vtable_ea != BADADDR) break;
                            }
                        }

                        // If still not resolved, check if call is on 'this' pointer (member function)
                        if (resolved_vtable_ea == BADADDR && !pfn_name.empty()) {
                            qstring dem_pfn;
                            if (demangle_name(&dem_pfn, pfn_name.c_str(), 0, DQT_FULL) > 0) {
                                std::string d = dem_pfn.c_str();
                                size_t scope_pos = d.find("::");
                                if (scope_pos != std::string::npos) {
                                    // Extract class name
                                    size_t c_start = d.rfind(' ', scope_pos);
                                    c_start = (c_start == std::string::npos) ? 0 : c_start + 1;
                                    std::string caller_class = d.substr(c_start, scope_pos - c_start);
                                    const auto* c = RttiIndex::Instance().FindClass(caller_class);
                                    if (c) {
                                        resolved_vtable_ea = c->vtable_ea;
                                        resolved_class_name = c->clean_name;
                                        class_hierarchy = c->hierarchy;
                                        inferred_from = "caller_this (" + caller_class + ")";
                                    }
                                }
                            }
                        }
                    }
                } else {
                    mode = "vtable";
                    resolved_vtable_ea = query_ea;

                    // Check if query_ea is an object pointing to vtable
                    ea_t deref1 = is64 ? get_qword(query_ea) : get_dword(query_ea);
                    if (is_mapped(deref1)) {
                        segment_t* deref_seg = getseg(deref1);
                        if (deref_seg && (deref_seg->perm & SEGPERM_EXEC) == 0) {
                            ea_t deref2 = is64 ? get_qword(deref1) : get_dword(deref1);
                            if (is_mapped(deref2)) {
                                segment_t* deref2_seg = getseg(deref2);
                                if (deref2_seg && (deref2_seg->perm & SEGPERM_EXEC) != 0) {
                                    resolved_vtable_ea = deref1;
                                    mode = "object_instance";
                                }
                            }
                        }
                    }
                }
            }

            if (resolved_vtable_ea != BADADDR && is_mapped(resolved_vtable_ea)) {
                if (resolved_class_name.empty()) {
                    const auto* c = RttiIndex::Instance().FindClass("", resolved_vtable_ea);
                    if (c) {
                        resolved_class_name = c->clean_name;
                        class_hierarchy = c->hierarchy;
                    }
                }

                if (resolved_class_name.empty()) {
                    ea_t col_ptr = resolved_vtable_ea - ptr_size;
                    if (is_mapped(col_ptr)) {
                        ea_t col_ea = is64 ? get_qword(col_ptr) : get_dword(col_ptr);
                        if (is_mapped(col_ea)) {
                            RttiClassEntry c;
                            if (ParseColAndClass(col_ea, resolved_vtable_ea, is64, get_imagebase(), c)) {
                                resolved_class_name = c.clean_name;
                                class_hierarchy = c.hierarchy;
                            }
                        }
                    }
                }

                if (resolved_class_name.empty()) {
                    qstring vt_name;
                    get_name(&vt_name, resolved_vtable_ea);
                    if (!vt_name.empty()) {
                        qstring vt_dem;
                        if (demangle_name(&vt_dem, vt_name.c_str(), 0, DQT_FULL) > 0) {
                            std::string d = vt_dem.c_str();
                            size_t vpos = d.find("::`vftable'");
                            if (vpos != std::string::npos) {
                                size_t start = (d.rfind("const ", 0) == 0) ? 6 : 0;
                                resolved_class_name = d.substr(start, vpos - start);
                            }
                        }
                    }
                }

                for (size_t i = 0; i < max_methods; ++i) {
                    ea_t slot_ea = resolved_vtable_ea + i * ptr_size;
                    if (!is_mapped(slot_ea) || !is_loaded(slot_ea)) break;

                    ea_t fn_ea = is64 ? get_qword(slot_ea) : get_dword(slot_ea);
                    if (fn_ea == 0 || fn_ea == BADADDR || !is_mapped(fn_ea)) break;

                    segment_t* fn_seg = getseg(fn_ea);
                    if (!fn_seg || (fn_seg->perm & SEGPERM_EXEC) == 0) {
                        break;
                    }

                    qstring fname;
                    get_func_name(&fname, fn_ea);
                    if (fname.empty()) get_name(&fname, fn_ea);
                    std::string fname_str = fname.c_str();

                    qstring dem;
                    std::string demangled_sig;
                    if (demangle && demangle_name(&dem, fname.c_str(), 0, DQT_FULL) > 0) {
                        demangled_sig = dem.c_str();
                    }

                    nlohmann::ordered_json method_info;
                    method_info["index"] = i;
                    method_info["offset"] = i * ptr_size;
                    method_info["offset_hex"] = tools::utils::FormatAddress(i * ptr_size);
                    method_info["address"] = tools::utils::FormatAddress(fn_ea);
                    method_info["name"] = fname_str;
                    if (!demangled_sig.empty()) {
                        method_info["demangled"] = demangled_sig;
                    }

                    tinfo_t tif;
                    if (get_tinfo(&tif, fn_ea)) {
                        qstring proto;
                        if (tif.print(&proto, nullptr, PRTYPE_1LINE | PRTYPE_SEMI)) {
                            method_info["prototype"] = proto.c_str();
                        }
                    }

                    func_t* pfn = get_func(fn_ea);
                    if (pfn) {
                        method_info["size"] = pfn->end_ea - pfn->start_ea;
                        if (pfn->flags & FUNC_THUNK) {
                            method_info["is_thunk"] = true;
                        }
                    }

                    if (fname_str == "_purecall" || fname_str == "__cxa_pure_virtual" ||
                        fname_str.find("purecall") != std::string::npos) {
                        method_info["is_pure_virtual"] = true;
                    }

                    std::string d_str = demangled_sig;
                    if (fname_str.rfind("??_G", 0) == 0 || fname_str.rfind("??_E", 0) == 0 ||
                        d_str.find("deleting destructor") != std::string::npos ||
                        d_str.find("::~") != std::string::npos) {
                        method_info["is_destructor"] = true;
                    }

                    if (static_cast<int>(i) == target_index) {
                        resolved_method_json = method_info;
                    }

                    methods_arr.push_back(std::move(method_info));
                }
            }
        });

        nlohmann::ordered_json res;
        res["status"] = "success";
        res["mode"] = mode;

        if (mode == "call_site") {
            res["call_address"] = tools::utils::FormatAddress(query_ea);
            if (!insn_str.empty()) res["instruction"] = insn_str;
            if (!base_reg.empty()) res["register"] = base_reg;
            if (call_disp >= 0) {
                res["displacement"] = call_disp;
                res["displacement_hex"] = tools::utils::FormatAddress(call_disp);
            }
            if (!pfn_name.empty()) res["caller_function"] = pfn_name;
            if (!inferred_from.empty()) res["inferred_from"] = inferred_from;
        } else if (mode == "method_lookup") {
            res["method_address"] = tools::utils::FormatAddress(query_ea);
            if (!pfn_name.empty()) res["method_name"] = pfn_name;
        }

        if (resolved_vtable_ea != BADADDR) {
            res["vtable"] = tools::utils::FormatAddress(resolved_vtable_ea);
        }
        if (!resolved_class_name.empty()) {
            res["class"] = resolved_class_name;
        }
        if (!class_hierarchy.empty()) {
            res["hierarchy"] = class_hierarchy;
        }

        if (target_index >= 0) {
            res["target_index"] = target_index;
            if (!resolved_method_json.is_null()) {
                res["resolved_method"] = resolved_method_json;
            } else if (resolved_vtable_ea != BADADDR) {
                res["message"] = "Slot index " + std::to_string(target_index) + " exceeds vtable bounds";
            }
        }

        if (target_index < 0 || all_methods) {
            res["methods_count"] = methods_arr.size();
            res["methods"] = methods_arr;
        }

        if (resolved_vtable_ea == BADADDR && resolved_method_json.is_null()) {
            if (target_index >= 0) {
                res["resolved"] = false;
                res["message"] = "Virtual call decoded at slot " + std::to_string(target_index) + " (displacement " + tools::utils::FormatAddress(call_disp) + "). Specify 'class' or 'vtable' to resolve the target function.";
            } else {
                return tools::utils::MakeToolErrorJson(id, "Could not resolve virtual table or target method", "resolve_failed");
            }
        }

        return tools::utils::MakeToolSuccessJson(id, res);
    }
}
