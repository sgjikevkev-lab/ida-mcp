#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include <ida.hpp>
#include <idp.hpp>
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
#include "../utils/utils.h"

namespace tools::rtti {

    namespace {
        struct RttiClassEntry {
            ea_t type_desc_ea = BADADDR;
            std::string raw_name;
            std::string clean_name;
            ea_t vtable_ea = BADADDR;
            ea_t col_ea = BADADDR;
            uint32_t offset = 0;
            size_t methods_count = 0;
            std::vector<std::string> hierarchy;
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

            std::string to_demangle = raw;
            if (to_demangle.rfind(".?A", 0) == 0) {
                to_demangle = "?" + to_demangle.substr(4);
            }

            try {
                qstring demangled = demangle_name(to_demangle.c_str(), 0, DQT_FULL);
                if (!demangled.empty()) {
                    std::string res = demangled.c_str();
                    if (res.rfind("class ", 0) == 0) res = res.substr(6);
                    else if (res.rfind("struct ", 0) == 0) res = res.substr(7);
                    else if (res.rfind("union ", 0) == 0) res = res.substr(6);
                    return res;
                }
            } catch (...) {
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
                    uint32_t num_bases = get_dword(chd_ea + 8);
                    ea_t bca_ea = is64 ? (col_base + get_dword(chd_ea + 12)) : get_dword(chd_ea + 12);

                    if (is_mapped(bca_ea) && is_loaded(bca_ea)) {
                        for (uint32_t bi = 0; bi < std::min(num_bases, 64u); ++bi) {
                            ea_t bcd_ptr = bca_ea + bi * 4;
                            if (!is_mapped(bcd_ptr) || !is_loaded(bcd_ptr)) break;

                            ea_t bcd_ea = is64 ? (col_base + get_dword(bcd_ptr)) : get_dword(bcd_ptr);
                            if (is_mapped(bcd_ea) && is_loaded(bcd_ea)) {
                                ea_t b_td = is64 ? (col_base + get_dword(bcd_ea)) : get_dword(bcd_ea);
                                if (is_mapped(b_td) && is_loaded(b_td)) {
                                    std::string b_raw = ReadNullTermString(b_td + (is64 ? 16 : 8));
                                    std::string b_clean = tools::utils::SanitizeUtf8(CleanTypeName(b_raw));
                                    if (!b_clean.empty()) {
                                        entry.hierarchy.push_back(b_clean);
                                    }
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
                        if (!e.clean_name.empty()) by_clean_name_[e.clean_name] = i;
                        if (!e.raw_name.empty()) by_raw_name_[e.raw_name] = i;
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
                }
                if (!query.empty()) {
                    auto it_c = by_clean_name_.find(query);
                    if (it_c != by_clean_name_.end()) return &clist[it_c->second];
                    auto it_r = by_raw_name_.find(query);
                    if (it_r != by_raw_name_.end()) return &clist[it_r->second];
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
    }

    ApiRtti::ApiRtti() = default;

    bool ApiRtti::CanHandle(const std::string& name) const {
        return name == "rtti_list_classes" ||
               name == "rtti_get_class" ||
               name == "rtti_refresh" ||
               name == "rtti_create_struct" ||
               name == "resolve_vcall";
    }

    nlohmann::json ApiRtti::GetSchema() const {
        return nlohmann::json::array();
    }

    nlohmann::json ApiRtti::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "rtti_list_classes") return RttiListClasses(id, args);
        if (name == "rtti_get_class") return RttiGetClass(id, args);
        if (name == "rtti_refresh") return RttiRefresh(id, args);
        if (name == "rtti_create_struct") return RttiCreateStruct(id, args);
        if (name == "resolve_vcall") return ResolveVcall(id, args);

        return nlohmann::json({
            {"jsonrpc", "2.0"},
            {"id", id},
            {"error", {{"code", -32601}, {"message", "Method not found"}}}
        });
    }

    nlohmann::json ApiRtti::RttiListClasses(const nlohmann::json& id, const nlohmann::json& args) {
        std::string pattern = tools::utils::GetStringArg(args, "pattern");
        size_t offset = static_cast<size_t>(tools::utils::GetIntArg(args, "offset", 0));
        std::string cursor_str = tools::utils::GetStringArg(args, "cursor");
        if (!cursor_str.empty()) {
            try { offset = static_cast<size_t>(std::stoul(cursor_str)); } catch (...) {}
        }
        size_t count = static_cast<size_t>(tools::utils::GetIntArg(args, "count", 50));
        if (count <= 0) count = 50;

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

        nlohmann::json classes_arr = nlohmann::json::array();
        size_t matched_total = 0;
        int next_offset = -1;

        for (size_t i = 0; i < all_classes.size(); ++i) {
            const auto& c = all_classes[i];
            if (!pattern.empty()) {
                if (!tools::utils::PatternMatch(c.clean_name, pattern) &&
                    !tools::utils::PatternMatch(c.raw_name, pattern)) {
                    continue;
                }
            }

            if (matched_total >= offset && classes_arr.size() < count) {
                classes_arr.push_back({
                    {"class", c.clean_name},
                    {"raw_name", c.raw_name},
                    {"vtable", tools::utils::FormatAddress(c.vtable_ea)},
                    {"methods", c.methods_count}
                });
                next_offset = static_cast<int>(matched_total + 1);
            }
            matched_total++;
        }

        if (next_offset >= static_cast<int>(matched_total)) {
            next_offset = -1;
        }

        nlohmann::json res = {
            {"status", "success"},
            {"total", matched_total},
            {"returned", classes_arr.size()},
            {"classes", classes_arr}
        };
        if (next_offset != -1) {
            res["next_offset"] = next_offset;
            res["next_cursor"] = std::to_string(next_offset);
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiRtti::RttiGetClass(const nlohmann::json& id, const nlohmann::json& args) {
        std::string query = tools::utils::GetStringArg(args, "name", tools::utils::GetStringArg(args, "addr", tools::utils::GetStringArg(args, "query")));
        ea_t query_ea = tools::utils::ParseAddress(query);
        bool refresh = tools::utils::GetBoolArg(args, "refresh", false);

        RttiClassEntry target_copy;
        bool found = false;
        nlohmann::json methods_arr = nlohmann::json::array();

        sync::SyncRead([&]() {
            try {
                if (refresh) {
                    RttiIndex::Instance().Invalidate();
                }
                bool is64 = inf_is_64bit();
                size_t ptr_size = is64 ? 8 : 4;
                const auto* target = RttiIndex::Instance().FindClass(query, query_ea);
                if (target) {
                    found = true;
                    target_copy = *target;

                    if (target->vtable_ea != BADADDR && is_mapped(target->vtable_ea)) {
                        for (size_t i = 0; i < target->methods_count; ++i) {
                            ea_t entry_ea = target->vtable_ea + i * ptr_size;
                            if (!is_mapped(entry_ea) || !is_loaded(entry_ea)) break;

                            ea_t fn_ea = is64 ? get_qword(entry_ea) : get_dword(entry_ea);
                            qstring fname;
                            if (is_mapped(fn_ea)) {
                                get_func_name(&fname, fn_ea);
                                if (fname.empty()) get_name(&fname, fn_ea);
                            }
                            methods_arr.push_back({
                                {"index", i},
                                {"address", tools::utils::FormatAddress(fn_ea)},
                                {"name", fname.c_str()}
                            });
                        }
                    }
                }
            } catch (...) {
            }
        });

        if (!found) {
            return tools::utils::MakeToolErrorJson(id, "No RTTI class matching query '" + query + "' was found in binary", "class_not_found");
        }

        nlohmann::json res = {
            {"status", "success"},
            {"class", target_copy.clean_name},
            {"raw_name", target_copy.raw_name},
            {"vtable", tools::utils::FormatAddress(target_copy.vtable_ea)},
            {"methods_count", target_copy.methods_count},
            {"hierarchy", target_copy.hierarchy},
            {"methods", methods_arr}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiRtti::RttiRefresh(const nlohmann::json& id, const nlohmann::json& args) {
        size_t count = 0;
        sync::SyncRead([&]() {
            try {
                RttiIndex::Instance().Invalidate();
                count = CollectRttiClasses().size();
            } catch (...) {
            }
        });
        return tools::utils::MakeToolSuccessJson(id, {
            {"status", "success"},
            {"refreshed", true},
            {"classes_count", count}
        });
    }

    nlohmann::json ApiRtti::RttiCreateStruct(const nlohmann::json& id, const nlohmann::json& args) {
        std::string query = tools::utils::GetStringArg(args, "name", tools::utils::GetStringArg(args, "query"));
        std::string struct_prefix = tools::utils::GetStringArg(args, "struct_prefix");
        ea_t query_ea = tools::utils::ParseAddress(query);

        RttiClassEntry target_copy;
        bool found = false;

        sync::SyncRead([&]() {
            try {
                const auto* target = RttiIndex::Instance().FindClass(query, query_ea);
                if (target) {
                    found = true;
                    target_copy = *target;
                }
            } catch (...) {
            }
        });

        if (!found) {
            return tools::utils::MakeToolErrorJson(id, "No RTTI class matching query '" + query + "' was found in binary", "class_not_found");
        }

        std::string base_struct_name = struct_prefix.empty() ? SanitizeCIdentifier(target_copy.clean_name) : struct_prefix;
        std::string vtable_struct_name = base_struct_name + "_vftable";
        std::string class_struct_name = base_struct_name;

        std::ostringstream ss;
        ss << "struct " << vtable_struct_name << ";\n";
        ss << "struct " << class_struct_name << ";\n\n";

        ss << "struct " << vtable_struct_name << " {\n";
        for (size_t i = 0; i < target_copy.methods_count; ++i) {
            ss << "    void* vfunc_" << i << ";\n";
        }
        ss << "};\n\n";

        ss << "struct " << class_struct_name << " {\n";
        ss << "    struct " << vtable_struct_name << "* __vftable;\n";
        ss << "};\n";

        std::string c_header = ss.str();
        int parse_errs = 0;

        sync::SyncWrite([&]() {
            try {
                parse_errs = parse_decls(get_idati(), c_header.c_str(), nullptr, HTI_DCL | HTI_PAKDEF | HTI_NWR);
            } catch (...) {
                parse_errs = -1;
            }
        });

        if (parse_errs != 0) {
            return tools::utils::MakeToolErrorJson(id, "C header parser failed to declare struct in IDA type library", "create_struct_failed", parse_errs);
        }

        nlohmann::json res = {
            {"status", "success"},
            {"struct_name", class_struct_name},
            {"vtable_struct", vtable_struct_name}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiRtti::ResolveVcall(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t query_ea = tools::utils::GetAddressArg(args, "addr");
        if (query_ea == BADADDR) query_ea = tools::utils::GetAddressArg(args, "call_addr");
        if (query_ea == BADADDR) query_ea = tools::utils::GetAddressArg(args, "vtable_addr");

        std::string class_query = tools::utils::GetStringArg(args, "class", tools::utils::GetStringArg(args, "class_name"));
        int target_index = static_cast<int>(tools::utils::GetIntArg(args, "index", -1));
        size_t max_methods = static_cast<size_t>(tools::utils::GetIntArg(args, "max_methods", 128));
        if (max_methods == 0 || max_methods > 512) max_methods = 128;
        bool demangle = tools::utils::GetBoolArg(args, "demangle", true);

        if (query_ea == BADADDR && class_query.empty()) {
            return tools::utils::MakeToolErrorJson(id, "Either 'addr' (call site / vtable address) or 'class' name must be provided", "addr_or_class_required");
        }

        bool is64 = false;
        std::string mode = "unknown";
        ea_t resolved_vtable_ea = BADADDR;
        std::string resolved_class_name;
        std::vector<std::string> class_hierarchy;
        nlohmann::json methods_arr = nlohmann::json::array();
        nlohmann::json resolved_method_json = nullptr;

        sync::SyncRead([&]() {
            is64 = inf_is_64bit();
            size_t ptr_size = is64 ? 8 : 4;

            if (!class_query.empty() && query_ea == BADADDR) {
                const auto* c = RttiIndex::Instance().FindClass(class_query);
                if (c) {
                    resolved_vtable_ea = c->vtable_ea;
                    resolved_class_name = c->clean_name;
                    class_hierarchy = c->hierarchy;
                }
            }

            if (query_ea != BADADDR && is_mapped(query_ea)) {
                segment_t* seg = getseg(query_ea);
                bool is_code_seg = (seg && (seg->perm & SEGPERM_EXEC) != 0);

                if (is_code_seg) {
                    mode = "call_site";
                    insn_t insn;
                    if (decode_insn(&insn, query_ea) > 0) {
                        int disp = -1;
                        for (int op_i = 0; op_i < 6; ++op_i) {
                            if (insn.ops[op_i].type == o_displ) {
                                disp = static_cast<int>(insn.ops[op_i].addr);
                                break;
                            } else if (insn.ops[op_i].type == o_phrase) {
                                disp = 0;
                                break;
                            }
                        }

                        if (disp >= 0 && target_index == -1) {
                            target_index = disp / static_cast<int>(ptr_size);
                        }
                    }

                    if (resolved_vtable_ea == BADADDR && !class_query.empty()) {
                        const auto* c = RttiIndex::Instance().FindClass(class_query);
                        if (c) {
                            resolved_vtable_ea = c->vtable_ea;
                            resolved_class_name = c->clean_name;
                            class_hierarchy = c->hierarchy;
                        }
                    }
                } else {
                    mode = "vtable";
                    resolved_vtable_ea = query_ea;
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

                    std::string demangled_sig;
                    if (demangle && !fname.empty()) {
                        qstring dem;
                        if (demangle_name(&dem, fname.c_str(), 0, DQT_FULL) > 0) {
                            demangled_sig = dem.c_str();
                        }
                    }

                    nlohmann::json method_info = {
                        {"index", i},
                        {"offset", i * ptr_size},
                        {"offset_hex", tools::utils::FormatAddress(i * ptr_size)},
                        {"address", tools::utils::FormatAddress(fn_ea)},
                        {"name", fname.c_str()}
                    };
                    if (!demangled_sig.empty()) {
                        method_info["demangled"] = demangled_sig;
                    }

                    if (static_cast<int>(i) == target_index) {
                        resolved_method_json = method_info;
                    }

                    methods_arr.push_back(method_info);
                }
            }
        });

        if (resolved_vtable_ea == BADADDR && resolved_method_json.is_null()) {
            return tools::utils::MakeToolErrorJson(id, "Could not resolve virtual table or target method", "resolve_failed");
        }

        nlohmann::json res = {
            {"status", "success"},
            {"mode", mode},
            {"vtable", tools::utils::FormatAddress(resolved_vtable_ea)},
            {"methods_count", methods_arr.size()}
        };
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
            }
        }
        res["methods"] = methods_arr;

        return tools::utils::MakeToolSuccessJson(id, res);
    }
}
