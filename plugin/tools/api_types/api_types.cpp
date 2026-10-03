#include <string>
#include <vector>
#include <functional>
#include <sstream>
#include <iomanip>
#include <unordered_set>
#include <map>
#include <set>

#pragma warning(push, 0)
#include "json.h"
#pragma warning(pop)

#include "api_types.h"
#include "tools/utils/utils.h"
#include "sync/sync.h"

#include <ida.hpp>
#include <typeinf.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <frame.hpp>
#include <hexrays.hpp>

namespace tools::types {
    namespace {
        tinfo_t GetTypeByName(const std::string& name) {
            std::string clean = name;
            if (clean.rfind("struct ", 0) == 0) clean = clean.substr(7);
            else if (clean.rfind("union ", 0) == 0) clean = clean.substr(6);
            else if (clean.rfind("enum ", 0) == 0) clean = clean.substr(5);

            tinfo_t tif;
            // 1. Try resolving in idati (Local Types) with default decl_type=BTF_TYPEDEF
            if (tif.get_named_type(get_idati(), clean.c_str())) {
                return tif;
            }
            // 2. Try resolving across all loaded base tils
            if (tif.get_named_type(nullptr, clean.c_str())) {
                return tif;
            }
            // 3. Try IDB structures/enums by TID
            tid_t tid = get_named_type_tid(clean.c_str());
            if (tid != BADADDR) {
                uint32 ord = get_tid_ordinal(tid);
                if (ord != 0 && tif.get_numbered_type(get_idati(), ord)) {
                    return tif;
                }
            }
            return tinfo_t();
        }
    }

    bool ApiTypes::CanHandle(const std::string& name) const {
        return name == "declare_type" ||
               name == "type_query" ||
               name == "type_inspect" ||
               name == "read_struct" ||
               name == "stack_frame" ||
               name == "reconstruct_struct";
    }

    nlohmann::json ApiTypes::Dispatch(const nlohmann::json& id, const std::string& name, const nlohmann::json& args) {
        if (name == "declare_type") return DeclareType(id, args);
        if (name == "type_query") return TypeQuery(id, args);
        if (name == "type_inspect") return TypeInspect(id, args);
        if (name == "read_struct") return ReadStruct(id, args);
        if (name == "stack_frame") return StackFrame(id, args);
        if (name == "reconstruct_struct") return ReconstructStruct(id, args);

        return tools::utils::MakeToolErrorJson(id, "Method not found: " + name, "method_not_found");
    }

    nlohmann::json ApiTypes::DeclareType(const nlohmann::json& id, const nlohmann::json& args) {
        std::string decls = tools::utils::GetStringArg(args, "c_code", tools::utils::GetStringArg(args, "declarations"));
        if (decls.empty()) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'c_code' or 'declarations' is required", "c_code_required");
        }

        int errs = 0;
        sync::SyncWrite([&]() {
            // parse_decls takes HTI_* flags
            errs = parse_decls(get_idati(), decls.c_str(), nullptr, HTI_DCL | HTI_PAKDEF | HTI_NWR);
        });

        if (errs != 0) {
            return tools::utils::MakeToolErrorJson(
                id,
                "C parser encountered " + std::to_string(errs) + " syntax or semantic errors",
                "declare_type_failed",
                errs
            );
        }

        return tools::utils::MakeToolSuccessJson(id);
    }

    nlohmann::json ApiTypes::TypeQuery(const nlohmann::json& id, const nlohmann::json& args) {
        std::string pattern = tools::utils::GetStringArg(args, "pattern", tools::utils::GetStringArg(args, "filter"));
        size_t offset = static_cast<size_t>(tools::utils::GetIntArg(args, "offset", 0));
        size_t count = static_cast<size_t>(tools::utils::GetIntArg(args, "count", 50));
        if (count <= 0) count = 50;
        if (count > 2000) count = 2000;

        nlohmann::json types_arr = nlohmann::json::array();
        size_t total = 0;
        int next_offset = -1;
        std::unordered_set<std::string> seen;

        sync::SyncRead([&]() {
            const char* named = first_named_type(get_idati(), NTF_TYPE);
            while (named != nullptr) {
                std::string t_name = named;
                named = next_named_type(get_idati(), named, NTF_TYPE);

                if (!seen.insert(t_name).second) continue;
                if (!pattern.empty() && !tools::utils::PatternMatch(t_name, pattern)) continue;

                if (total >= offset && types_arr.size() < count) {
                    types_arr.push_back(t_name);
                    next_offset = static_cast<int>(total + 1);
                }
                total++;
            }

            if (next_offset >= static_cast<int>(total)) {
                next_offset = -1;
            }
        });

        nlohmann::json res = {
            {"status", "success"},
            {"total", total},
            {"count", types_arr.size()},
            {"types", types_arr}
        };
        if (next_offset != -1) {
            res["next_offset"] = next_offset;
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiTypes::TypeInspect(const nlohmann::json& id, const nlohmann::json& args) {
        std::string name = tools::utils::GetStringArg(args, "name");
        if (name.empty()) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'name' is required", "name_required");
        }

        std::string decl_str;
        size_t type_size = 0;
        nlohmann::json fields = nlohmann::json::array();
        bool found = false;

        sync::SyncRead([&]() {
            tinfo_t tif = GetTypeByName(name);
            if (!tif.empty() && tif.present()) {
                found = true;
                type_size = tif.get_size();

                qstring decl;
                bool ok = tif.print(&decl, nullptr, PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_DEF | PRTYPE_SEMI);
                if (!ok || decl.empty()) {
                    tif.print(&decl, name.c_str(), PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_DEF | PRTYPE_SEMI);
                }
                decl_str = decl.c_str();

                // If struct or union, enumerate fields
                if (tif.is_udt()) {
                    int nmembers = tif.get_udt_nmembers();
                    for (int i = 0; i < nmembers; ++i) {
                        udm_t udm;
                        if (tif.get_udm(&udm, static_cast<size_t>(i)) >= 0) {
                            qstring m_decl;
                            udm.type.print(&m_decl, udm.name.c_str(), PRTYPE_1LINE | PRTYPE_SEMI);
                            fields.push_back({
                                {"name", udm.name.c_str()},
                                {"offset", udm.offset / 8},
                                {"size", udm.size / 8},
                                {"type", m_decl.c_str()}
                            });
                        }
                    }
                }
            }
        });

        if (!found || decl_str.empty()) {
            return tools::utils::MakeToolErrorJson(
                id,
                "Type '" + name + "' does not exist in local type library",
                "type_not_found"
            );
        }

        nlohmann::json res = {
            {"status", "success"},
            {"name", name},
            {"size", type_size},
            {"declaration", decl_str}
        };
        if (!fields.empty()) {
            res["fields"] = fields;
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiTypes::ReadStruct(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        std::string struct_name = tools::utils::GetStringArg(args, "name", tools::utils::GetStringArg(args, "struct"));
        int max_depth = static_cast<int>(tools::utils::GetIntArg(args, "max_depth", 2));
        if (max_depth <= 0) max_depth = 2;
        if (max_depth > 5) max_depth = 5;
        int array_limit = static_cast<int>(tools::utils::GetIntArg(args, "array_limit", 16));
        if (array_limit <= 0) array_limit = 16;
        if (array_limit > 128) array_limit = 128;

        if (struct_name.empty()) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'name' or 'struct' is required", "struct_name_required");
        }

        nlohmann::json fields_arr = nlohmann::json::array();
        size_t struct_size = 0;
        bool found = false;

        // Recursive field reader (lambda defined inside SyncRead)
        sync::SyncRead([&]() {
            tinfo_t tif = GetTypeByName(struct_name);
            if (tif.empty()) return;

            found = true;
            struct_size = tif.get_size();

            std::vector<uint8_t> bulk_buf;
            bool has_bulk = false;
            if (ea != BADADDR && struct_size > 0 && struct_size <= 0x100000) {
                bulk_buf.resize(struct_size, 0);
                ssize_t rb = get_bytes(bulk_buf.data(), struct_size, ea, GMB_READALL);
                if (rb > 0) {
                    has_bulk = true;
                    if (static_cast<size_t>(rb) < struct_size) {
                        bulk_buf.resize(rb);
                    }
                }
            }

            // Forward-declare the recursive lambda via std::function
            std::function<nlohmann::json(ea_t, const tinfo_t&, const qstring&, size_t, size_t, int, int, int)> ReadFieldRecursive;

            ReadFieldRecursive = [&](
                ea_t base_ea,           // base address in memory
                const tinfo_t& ftype,   // field type
                const qstring& fname,   // field name
                size_t f_offset_bits,   // offset from parent (in bits)
                size_t f_size,          // field size in bytes
                int depth,
                int max_d,
                int arr_lim
            ) -> nlohmann::json {
                size_t offset_bytes = f_offset_bits / 8;
                ea_t field_ea = (base_ea != BADADDR) ? (base_ea + offset_bytes) : BADADDR;

                qstring type_str;
                ftype.print(&type_str);

                nlohmann::json field_obj = {
                    {"name", fname.c_str()},
                    {"offset", offset_bytes},
                    {"offset_hex", tools::utils::FormatAddress(offset_bytes)},
                    {"size", f_size},
                    {"type", type_str.c_str()}
                };

                auto read_val = [&](size_t sz, uint64_t& out_val) -> bool {
                    size_t root_off = (field_ea != BADADDR && ea != BADADDR && field_ea >= ea) ? static_cast<size_t>(field_ea - ea) : 0;
                    if (has_bulk && root_off + sz <= bulk_buf.size()) {
                        out_val = 0;
                        memcpy(&out_val, bulk_buf.data() + root_off, sz);
                        return true;
                    }
                    if (field_ea != BADADDR && is_mapped(field_ea)) {
                        if (sz == 1) { out_val = get_byte(field_ea); return true; }
                        if (sz == 2) { out_val = get_word(field_ea); return true; }
                        if (sz == 4) { out_val = get_dword(field_ea); return true; }
                        if (sz == 8) { out_val = get_qword(field_ea); return true; }
                    }
                    return false;
                };

                // 1. Nested struct/union: recurse
                if (ftype.is_udt() && depth < max_d) {
                    udt_type_data_t nested;
                    if (ftype.get_udt_details(&nested)) {
                        nlohmann::json nested_fields = nlohmann::json::array();
                        for (const auto& nm : nested) {
                            size_t nm_size = nm.type.get_size();
                            nested_fields.push_back(
                                ReadFieldRecursive(field_ea, nm.type, nm.name, nm.offset, nm_size, depth + 1, max_d, arr_lim)
                            );
                        }
                        field_obj["fields"] = nested_fields;
                    }
                }
                // 2. Array: read elements
                else if (ftype.is_array() && depth < max_d) {
                    tinfo_t elem_type;
                    int nelems_total = -1;
                    array_type_data_t ai;
                    if (ftype.get_array_details(&ai)) {
                        elem_type = ai.elem_type;
                        nelems_total = static_cast<int>(ai.nelems);
                    }

                    if (!elem_type.empty() && nelems_total > 0) {
                        size_t elem_size = elem_type.get_size();
                        int show_count = std::min(nelems_total, arr_lim);
                        field_obj["array_total"] = nelems_total;
                        field_obj["array_shown"] = show_count;

                        nlohmann::json elems = nlohmann::json::array();
                        for (int i = 0; i < show_count; ++i) {
                            qstring idx_name;
                            idx_name.sprnt("[%d]", i);
                            size_t elem_offset_bits = f_offset_bits + static_cast<size_t>(i) * elem_size * 8;
                            elems.push_back(
                                ReadFieldRecursive(base_ea, elem_type, idx_name, elem_offset_bits, elem_size, depth + 1, max_d, arr_lim)
                            );
                        }
                        field_obj["elements"] = elems;
                    }
                }
                // 3. Pointer: dereference if mapped
                else if (ftype.is_ptr() && field_ea != BADADDR) {
                    size_t ptr_sz = inf_is_64bit() ? 8 : 4;
                    uint64_t raw_ptr = 0;
                    if (read_val(ptr_sz, raw_ptr)) {
                        ea_t pointed = static_cast<ea_t>(raw_ptr);
                        field_obj["value"] = tools::utils::FormatAddress(pointed);
                        if (pointed != 0 && pointed != BADADDR && is_mapped(pointed)) {
                            qstring pointed_name;
                            get_ea_name(&pointed_name, pointed);
                            if (!pointed_name.empty()) {
                                field_obj["pointed_name"] = pointed_name.c_str();
                            }
                        }
                    }
                }
                // 4. Enum: resolve constant name
                else if (ftype.is_enum() && field_ea != BADADDR) {
                    uint64_t raw_val = 0;
                    if (read_val(f_size, raw_val)) {
                        field_obj["value"] = tools::utils::FormatAddress(raw_val);
                        enum_type_data_t ei;
                        if (ftype.get_enum_details(&ei)) {
                            for (const auto& em : ei) {
                                if (static_cast<uint64_t>(em.value) == raw_val) {
                                    field_obj["enum_name"] = em.name.c_str();
                                    break;
                                }
                            }
                        }
                    }
                }
                // 5. Scalar: read value for standard sizes
                else if (field_ea != BADADDR) {
                    uint64_t raw_val = 0;
                    if (read_val(f_size, raw_val)) {
                        field_obj["value"] = tools::utils::FormatAddress(raw_val);
                    }
                }

                return field_obj;
            };

            udt_type_data_t udt;
            if (tif.get_udt_details(&udt)) {
                for (const auto& m : udt) {
                    size_t m_size = m.type.get_size();
                    fields_arr.push_back(
                        ReadFieldRecursive(ea, m.type, m.name, m.offset, m_size, 0, max_depth, array_limit)
                    );
                }
            }
        });

        if (!found || fields_arr.empty()) {
            return tools::utils::MakeToolErrorJson(
                id,
                "Struct '" + struct_name + "' was not found or contains no fields",
                "struct_not_found"
            );
        }

        nlohmann::json res = {
            {"status", "success"},
            {"struct", struct_name},
            {"size", struct_size},
            {"max_depth", max_depth},
            {"fields", fields_arr}
        };
        if (ea != BADADDR) {
            res["address"] = tools::utils::FormatAddress(ea);
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiTypes::StackFrame(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        if (ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }

        nlohmann::json members_arr = nlohmann::json::array();
        ea_t fn_start = BADADDR;
        bool found_fn = false;

        sync::SyncRead([&]() {
            func_t* fn = get_func(ea);
            if (!fn) return;
            found_fn = true;
            fn_start = fn->start_ea;

            tinfo_t frame_tif;
            if (get_func_frame(&frame_tif, fn)) {
                udt_type_data_t udt;
                if (frame_tif.get_udt_details(&udt)) {
                    for (const auto& m : udt) {
                        qstring type_name;
                        m.type.print(&type_name);
                        size_t offset_bytes = m.offset / 8;
                        members_arr.push_back({
                            {"name", m.name.c_str()},
                            {"offset", offset_bytes},
                            {"offset_hex", tools::utils::FormatAddress(offset_bytes)},
                            {"size", m.type.get_size()},
                            {"type", type_name.c_str()}
                        });
                    }
                }
            }
        });

        if (!found_fn) {
            return tools::utils::MakeToolErrorJson(
                id,
                "No function found containing address " + tools::utils::FormatAddress(ea),
                "function_not_found"
            );
        }

        nlohmann::json res = {
            {"status", "success"},
            {"function", tools::utils::FormatAddress(fn_start)},
            {"members", members_arr}
        };
        return tools::utils::MakeToolSuccessJson(id, res);
    }

    nlohmann::json ApiTypes::ReconstructStruct(const nlohmann::json& id, const nlohmann::json& args) {
        ea_t ea = tools::utils::GetAddressArg(args, "addr");
        if (ea == BADADDR) {
            return tools::utils::MakeToolErrorJson(id, "Parameter 'addr' could not be resolved", "invalid_addr");
        }

        std::string target_var_name = tools::utils::GetStringArg(args, "var");
        std::string struct_name = tools::utils::GetStringArg(args, "struct_name");
        int max_depth = static_cast<int>(tools::utils::GetIntArg(args, "scan_depth", 1));
        if (max_depth < 0) max_depth = 0;
        if (max_depth > 3) max_depth = 3;

        bool apply = tools::utils::GetBoolArg(args, "apply", false);

        struct InferredField {
            uint64_t offset = 0;
            size_t size = 4;
            std::string type_name = "uint32_t";
            bool is_float = false;
            bool is_pointer = false;
            bool is_vftable = false;
        };

        std::map<uint64_t, InferredField> observed_fields;
        std::string fn_name;
        ea_t fn_start = BADADDR;
        bool found_fn = false;
        bool decompiled_ok = false;
        bool applied_ok = false;
        std::string apply_error;
        uint64_t inferred_total_size = 0;

        sync::SyncRead([&]() {
            if (!init_hexrays_plugin()) return;

            func_t* pfn = get_func(ea);
            if (!pfn) return;
            found_fn = true;
            fn_start = pfn->start_ea;

            qstring q_fname;
            get_func_name(&q_fname, fn_start);
            fn_name = q_fname.c_str();

            hexrays_failure_t hf;
            cfuncptr_t cf = decompile(pfn, &hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
            if (!cf) return;
            decompiled_ok = true;

            const lvars_t* lvars = cf->get_lvars();
            if (!lvars || lvars->empty()) return;

            // Resolve target variable index
            int target_idx = -1;
            if (!target_var_name.empty()) {
                for (size_t i = 0; i < lvars->size(); ++i) {
                    if ((*lvars)[i].name == target_var_name.c_str()) {
                        target_idx = static_cast<int>(i);
                        break;
                    }
                }
            } else {
                // Auto-detect first pointer argument or first argument
                for (size_t i = 0; i < lvars->size(); ++i) {
                    if ((*lvars)[i].is_arg_var() && (*lvars)[i].type().is_ptr()) {
                        target_idx = static_cast<int>(i);
                        target_var_name = (*lvars)[i].name.c_str();
                        break;
                    }
                }
                if (target_idx == -1) {
                    for (size_t i = 0; i < lvars->size(); ++i) {
                        if ((*lvars)[i].is_arg_var()) {
                            target_idx = static_cast<int>(i);
                            target_var_name = (*lvars)[i].name.c_str();
                            break;
                        }
                    }
                }
                if (target_idx == -1 && !lvars->empty()) {
                    target_idx = 0;
                    target_var_name = (*lvars)[0].name.c_str();
                }
            }

            if (target_idx == -1) return;

            if (struct_name.empty()) {
                std::string clean_fn = fn_name;
                while (!clean_fn.empty() && (clean_fn.front() == '.' || clean_fn.front() == '?' || clean_fn.front() == '@')) clean_fn.erase(clean_fn.begin());
                struct_name = "Struct_" + clean_fn + "_" + target_var_name;
            }

            // Recursive function scanner with context tuple (func_ea, lvar_idx, base_offset)
            std::set<std::tuple<ea_t, int, uint64_t>> visited_contexts;
            std::function<void(func_t*, int, int, uint64_t)> scan_fn;

            scan_fn = [&](func_t* cur_fn, int lvar_idx, int current_depth, uint64_t base_offset) {
                if (!cur_fn || current_depth > max_depth) return;
                auto ctx_key = std::make_tuple(cur_fn->start_ea, lvar_idx, base_offset);
                if (visited_contexts.count(ctx_key)) return;
                visited_contexts.insert(ctx_key);

                hexrays_failure_t local_hf;
                cfuncptr_t local_cf = decompile(cur_fn, &local_hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                if (!local_cf) return;

                struct StructVisitor : public ctree_visitor_t {
                    const cfunc_t* cf;
                    int target_idx;
                    std::map<uint64_t, InferredField>& fields;
                    int depth;
                    int max_d;
                    uint64_t base_off;
                    uint64_t& total_sz;
                    std::function<void(func_t*, int, int, uint64_t)> recurse_fn;

                    StructVisitor(const cfunc_t* f, int tidx, std::map<uint64_t, InferredField>& flds,
                                  int d, int md, uint64_t bo, uint64_t& tsz,
                                  std::function<void(func_t*, int, int, uint64_t)> rf)
                        : ctree_visitor_t(CV_FAST), cf(f), target_idx(tidx), fields(flds),
                          depth(d), max_d(md), base_off(bo), total_sz(tsz), recurse_fn(rf) {}

                    bool IsTargetBase(const cexpr_t* e, int64_t& out_off) {
                        if (!e) return false;
                        if (e->op == cot_var) {
                            if (e->v.idx == target_idx) {
                                out_off = 0;
                                return true;
                            }
                            return false;
                        }
                        if (e->op == cot_cast && e->x) {
                            return IsTargetBase(e->x, out_off);
                        }
                        if (e->op == cot_add && e->x && e->y) {
                            int64_t sub_off = 0;
                            if (IsTargetBase(e->x, sub_off) && e->y->op == cot_num) {
                                out_off = sub_off + static_cast<int64_t>(e->y->numval());
                                return true;
                            }
                            if (IsTargetBase(e->y, sub_off) && e->x->op == cot_num) {
                                out_off = sub_off + static_cast<int64_t>(e->x->numval());
                                return true;
                            }
                        }
                        if (e->op == cot_sub && e->x && e->y) {
                            int64_t sub_off = 0;
                            if (IsTargetBase(e->x, sub_off) && e->y->op == cot_num) {
                                out_off = sub_off - static_cast<int64_t>(e->y->numval());
                                return true;
                            }
                        }
                        return false;
                    }

                    int idaapi visit_expr(cexpr_t* e) override {
                        // 1. Pointer dereference: *(type*)(var + offset)
                        if (e->op == cot_ptr && e->x) {
                            int64_t off = 0;
                            if (IsTargetBase(e->x, off)) {
                                int64_t signed_final = static_cast<int64_t>(base_off) + off;
                                if (signed_final >= 0) {
                                    uint64_t final_off = static_cast<uint64_t>(signed_final);
                                    size_t sz = e->type.get_size();
                                    if (sz <= 0 || sz > 16) sz = inf_is_64bit() ? 8 : 4;

                                    bool is_flt = e->type.is_floating();
                                    bool is_p = e->type.is_ptr();
                                    bool is_vf = (final_off == 0 && sz == (inf_is_64bit() ? 8 : 4));

                                    auto it = fields.find(final_off);
                                    if (it == fields.end()) {
                                        InferredField f;
                                        f.offset = final_off;
                                        f.size = sz;
                                        f.is_float = is_flt;
                                        f.is_pointer = is_p;
                                        f.is_vftable = is_vf;
                                        fields[final_off] = f;
                                    } else {
                                        if (sz > it->second.size) it->second.size = sz;
                                        if (is_flt) it->second.is_float = true;
                                        if (is_p) it->second.is_pointer = true;
                                        if (is_vf) it->second.is_vftable = true;
                                    }
                                }
                            }
                        }

                        // 2. Member pointer or reference: var->member or var.member
                        if ((e->op == cot_memptr || e->op == cot_memref) && e->x) {
                            int64_t off = 0;
                            if (IsTargetBase(e->x, off)) {
                                int64_t signed_final = static_cast<int64_t>(base_off) + off + static_cast<int64_t>(e->m);
                                if (signed_final >= 0) {
                                    uint64_t final_off = static_cast<uint64_t>(signed_final);
                                    size_t sz = e->type.get_size();
                                    if (sz <= 0 || sz > 16) sz = 4;

                                    auto it = fields.find(final_off);
                                    if (it == fields.end()) {
                                        InferredField f;
                                        f.offset = final_off;
                                        f.size = sz;
                                        f.is_float = e->type.is_floating();
                                        f.is_pointer = e->type.is_ptr();
                                        fields[final_off] = f;
                                    } else if (sz > it->second.size) {
                                        it->second.size = sz;
                                    }
                                }
                            }
                        }

                        // 3. Array indexing: var[i]
                        if (e->op == cot_idx && e->x && e->y && e->y->op == cot_num) {
                            int64_t off = 0;
                            if (IsTargetBase(e->x, off)) {
                                size_t elem_sz = e->type.get_size();
                                if (elem_sz <= 0) elem_sz = 4;
                                int64_t signed_final = static_cast<int64_t>(base_off) + off + static_cast<int64_t>(e->y->numval() * elem_sz);
                                if (signed_final >= 0) {
                                    uint64_t final_off = static_cast<uint64_t>(signed_final);
                                    if (fields.find(final_off) == fields.end()) {
                                        InferredField f;
                                        f.offset = final_off;
                                        f.size = elem_sz;
                                        f.is_float = e->type.is_floating();
                                        f.is_pointer = e->type.is_ptr();
                                        fields[final_off] = f;
                                    }
                                }
                            }
                        }

                        // 4. Sniff allocation size: var = operator new(N) or malloc(N)
                        if (e->op == cot_asg) {
                            int64_t off = 0;
                            if (IsTargetBase(e->x, off) && off == 0) {
                                const cexpr_t* rhs = e->y;
                                while (rhs && rhs->op == cot_cast) rhs = rhs->x;
                                if (rhs && rhs->op == cot_call && rhs->a && !rhs->a->empty()) {
                                    if ((*rhs->a)[0].op == cot_num) {
                                        uint64_t alloc_sz = (*rhs->a)[0].numval();
                                        if (alloc_sz > 0 && alloc_sz < 0x200000) {
                                            total_sz = std::max(total_sz, base_off + alloc_sz);
                                        }
                                    }
                                }
                            }
                        }

                        // 5. Sniff memset(var, 0, N)
                        if (e->op == cot_call && e->a && e->a->size() >= 3) {
                            int64_t off = 0;
                            if (IsTargetBase(&(*e->a)[0], off)) {
                                if ((*e->a)[2].op == cot_num) {
                                    uint64_t set_sz = (*e->a)[2].numval();
                                    int64_t signed_final = static_cast<int64_t>(base_off) + off + static_cast<int64_t>(set_sz);
                                    if (signed_final > 0 && set_sz < 0x200000) {
                                        total_sz = std::max(total_sz, static_cast<uint64_t>(signed_final));
                                    }
                                }
                            }
                        }

                        // 6. Inter-procedural call passing with base offset propagation
                        if (e->op == cot_call && e->a && depth < max_d) {
                            ea_t callee_ea = (e->x && e->x->op == cot_obj) ? e->x->obj_ea : BADADDR;
                            if (callee_ea != BADADDR) {
                                func_t* callee_fn = get_func(callee_ea);
                                if (callee_fn) {
                                    for (size_t a_idx = 0; a_idx < e->a->size(); ++a_idx) {
                                        int64_t off = 0;
                                        if (IsTargetBase(&(*e->a)[a_idx], off)) {
                                            int64_t next_base = static_cast<int64_t>(base_off) + off;
                                            if (next_base >= 0) {
                                                hexrays_failure_t c_hf;
                                                cfuncptr_t callee_cf = decompile(callee_fn, &c_hf, DECOMP_WARNINGS | DECOMP_NO_WAIT);
                                                if (callee_cf) {
                                                    const lvars_t* callee_lvars = callee_cf->get_lvars();
                                                    if (callee_lvars) {
                                                        size_t arg_counter = 0;
                                                        for (size_t k = 0; k < callee_lvars->size(); ++k) {
                                                            if ((*callee_lvars)[k].is_arg_var()) {
                                                                if (arg_counter == a_idx) {
                                                                    recurse_fn(callee_fn, static_cast<int>(k), depth + 1, static_cast<uint64_t>(next_base));
                                                                    break;
                                                                }
                                                                arg_counter++;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        return 0;
                    }
                };

                StructVisitor visitor(local_cf, lvar_idx, observed_fields, current_depth, max_depth, base_offset, inferred_total_size, scan_fn);
                visitor.apply_to(&local_cf->body, nullptr);
            };

            scan_fn(pfn, target_idx, 0, 0);
        });

        // If apply requested and fields found: compile to TIL and update lvar under SyncWrite
        if (apply && !observed_fields.empty()) {
            std::ostringstream hss;
            hss << "#pragma pack(push, 1)\n";
            hss << "struct " << struct_name << " {\n";

            uint64_t cur_offset = 0;
            for (const auto& [off, field] : observed_fields) {
                if (off > cur_offset) {
                    uint64_t gap = off - cur_offset;
                    std::ostringstream pss;
                    pss << "0x" << std::hex << cur_offset;
                    hss << "    /* " << pss.str() << " */ uint8_t _pad_" << pss.str() << "[" << std::dec << gap << "];\n";
                    cur_offset = off;
                }

                std::ostringstream oss;
                oss << "0x" << std::hex << off;
                std::string f_type;
                std::string f_name;

                if (off == 0 && field.is_vftable) {
                    f_type = "void**";
                    f_name = "__vftable";
                } else if (field.is_pointer) {
                    f_type = "void*";
                    f_name = "ptr_" + oss.str();
                } else if (field.is_float) {
                    f_type = (field.size == 8 ? "double" : "float");
                    f_name = "flt_" + oss.str();
                } else {
                    switch (field.size) {
                        case 1: f_type = "uint8_t"; break;
                        case 2: f_type = "uint16_t"; break;
                        case 8: f_type = "uint64_t"; break;
                        default: f_type = "uint32_t"; break;
                    }
                    f_name = "field_" + oss.str();
                }

                hss << "    /* " << oss.str() << " */ " << f_type << " " << f_name << ";\n";
                cur_offset = off + field.size;
            }

            if (inferred_total_size > cur_offset) {
                uint64_t gap = inferred_total_size - cur_offset;
                std::ostringstream pss;
                pss << "0x" << std::hex << cur_offset;
                hss << "    /* " << pss.str() << " */ uint8_t _pad_tail[" << std::dec << gap << "];\n";
                cur_offset = inferred_total_size;
            }

            hss << "};\n";
            hss << "#pragma pack(pop)\n";

            sync::SyncWrite([&]() {
                int parse_err = parse_decls(get_idati(), hss.str().c_str(), nullptr, HTI_DCL | HTI_PAKDEF | HTI_NWR);
                if (parse_err == 0) {
                    lvar_saved_info_t info;
                    if (locate_lvar(&info.ll, fn_start, target_var_name.c_str())) {
                        tinfo_t tif;
                        qstring nbuf;
                        std::string decl_str = "struct " + struct_name + "*;";
                        if (parse_decl(&tif, &nbuf, get_idati(), decl_str.c_str(), PT_SIL | PT_TYP)) {
                            info.type = tif;
                            applied_ok = modify_user_lvar_info(fn_start, MLI_TYPE, info);
                        }
                    }
                } else {
                    apply_error = "TIL parse_decls failed with code " + std::to_string(parse_err);
                }
            });
        }

        if (!found_fn) {
            return tools::utils::MakeToolErrorJson(id, "No function found containing address " + tools::utils::FormatAddress(ea), "function_not_found");
        }
        if (!decompiled_ok) {
            return tools::utils::MakeToolErrorJson(id, "Decompilation failed for function", "decompile_failed");
        }

        // Build output JSON and formatted C code
        nlohmann::json fields_arr = nlohmann::json::array();
        std::ostringstream css;
        css << "#pragma pack(push, 1)\n";
        css << "struct " << struct_name << " {\n";

        uint64_t cur_offset = 0;
        for (const auto& [off, field] : observed_fields) {
            if (off > cur_offset) {
                uint64_t gap = off - cur_offset;
                std::ostringstream pss;
                pss << "0x" << std::hex << cur_offset;
                css << "    /* " << pss.str() << " */ uint8_t _pad_" << pss.str() << "[" << std::dec << gap << "];\n";
                fields_arr.push_back({
                    {"offset", cur_offset},
                    {"offset_hex", pss.str()},
                    {"size", gap},
                    {"type", "uint8_t[]"},
                    {"name", "_pad_" + pss.str()},
                    {"is_padding", true}
                });
                cur_offset = off;
            }

            std::ostringstream oss;
            oss << "0x" << std::hex << off;
            std::string f_type;
            std::string f_name;

            if (off == 0 && field.is_vftable) {
                f_type = "void**";
                f_name = "__vftable";
            } else if (field.is_pointer) {
                f_type = "void*";
                f_name = "ptr_" + oss.str();
            } else if (field.is_float) {
                f_type = (field.size == 8 ? "double" : "float");
                f_name = "flt_" + oss.str();
            } else {
                switch (field.size) {
                    case 1: f_type = "uint8_t"; break;
                    case 2: f_type = "uint16_t"; break;
                    case 8: f_type = "uint64_t"; break;
                    default: f_type = "uint32_t"; break;
                }
                f_name = "field_" + oss.str();
            }

            css << "    /* " << oss.str() << " */ " << f_type << " " << f_name << ";\n";
            fields_arr.push_back({
                {"offset", off},
                {"offset_hex", oss.str()},
                {"size", field.size},
                {"type", f_type},
                {"name", f_name},
                {"is_padding", false}
            });

            cur_offset = off + field.size;
        }

        if (inferred_total_size > cur_offset) {
            uint64_t gap = inferred_total_size - cur_offset;
            std::ostringstream pss;
            pss << "0x" << std::hex << cur_offset;
            css << "    /* " << pss.str() << " */ uint8_t _pad_tail[" << std::dec << gap << "];\n";
            fields_arr.push_back({
                {"offset", cur_offset},
                {"offset_hex", pss.str()},
                {"size", gap},
                {"type", "uint8_t[]"},
                {"name", "_pad_tail"},
                {"is_padding", true}
            });
            cur_offset = inferred_total_size;
        }

        css << "};\n";
        css << "#pragma pack(pop)\n";

        nlohmann::json res = {
            {"status", "success"},
            {"function", fn_name},
            {"function_addr", tools::utils::FormatAddress(fn_start)},
            {"var", target_var_name},
            {"struct_name", struct_name},
            {"fields_count", observed_fields.size()},
            {"total_size", cur_offset},
            {"total_size_hex", tools::utils::FormatAddress(cur_offset)},
            {"applied", applied_ok},
            {"fields", fields_arr},
            {"c_code", css.str()}
        };
        if (!apply_error.empty()) {
            res["apply_error"] = apply_error;
        }
        return tools::utils::MakeToolSuccessJson(id, res);
    }
}
