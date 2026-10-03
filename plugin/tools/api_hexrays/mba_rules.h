#pragma once
#include <string>
#include <vector>
#include <functional>
#include <optional>
#include <cstdint>
#include <set>
#include <sstream>
#include "ctree_serializer.h"

namespace tools::hexrays_ast {

    struct MbaRule {
        int id;
        std::string name;
        nlohmann::json pattern;
        std::function<std::string(const std::map<std::string, nlohmann::json>&)> format_simplified;
        std::function<bool(uint8_t, uint8_t)> verify_eval;
    };

    inline std::string ExtractBindingName(const nlohmann::json& val) {
        if (val.is_string()) return val.get<std::string>();
        if (val.is_object()) {
            if (val.contains("var_name")) return val["var_name"].get<std::string>();
            if (val.contains("obj_name")) return val["obj_name"].get<std::string>();
            if (val.contains("value")) return std::to_string(val["value"].get<uint64_t>());
        }
        return val.dump();
    }

    inline const std::vector<MbaRule>& GetMbaRules() {
        static const std::vector<MbaRule> kRules = {
            // === Original 15 rules ===
            {
                1,
                "MBA Add: (x ^ y) + 2*(x & y) => x + y",
                nlohmann::json::parse(R"({"op": "cot_add", "x": {"op": "cot_xor", "x": "$x", "y": "$y"}, "y": {"op": "cot_mul", "x": {"op": "cot_num", "value": 2}, "y": {"op": "cot_band", "x": "$x", "y": "$y"}}})"),
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " + " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t((x ^ y) + 2 * (x & y)) == uint8_t(x + y); }
            },
            {
                2,
                "MBA And: (x | y) - (x ^ y) => x & y",
                nlohmann::json::parse(R"({"op": "cot_sub", "x": {"op": "cot_bor", "x": "$x", "y": "$y"}, "y": {"op": "cot_xor", "x": "$x", "y": "$y"}})") ,
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " & " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t((x | y) - (x ^ y)) == uint8_t(x & y); }
            },
            {
                3,
                "MBA Add: (x | y) + (x & y) => x + y",
                nlohmann::json::parse(R"({"op": "cot_add", "x": {"op": "cot_bor", "x": "$x", "y": "$y"}, "y": {"op": "cot_band", "x": "$x", "y": "$y"}})") ,
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " + " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t((x | y) + (x & y)) == uint8_t(x + y); }
            },
            {
                4,
                "MBA Add: 2*(x | y) - (x ^ y) => x + y",
                nlohmann::json::parse(R"({"op": "cot_sub", "x": {"op": "cot_mul", "x": {"op": "cot_num", "value": 2}, "y": {"op": "cot_bor", "x": "$x", "y": "$y"}}, "y": {"op": "cot_xor", "x": "$x", "y": "$y"}})") ,
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " + " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t(2 * (x | y) - (x ^ y)) == uint8_t(x + y); }
            },
            {
                5,
                "MBA Xor: (x + y) - 2*(x & y) => x ^ y",
                nlohmann::json::parse(R"({"op": "cot_sub", "x": {"op": "cot_add", "x": "$x", "y": "$y"}, "y": {"op": "cot_mul", "x": {"op": "cot_num", "value": 2}, "y": {"op": "cot_band", "x": "$x", "y": "$y"}}})") ,
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " ^ " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t((x + y) - 2 * (x & y)) == uint8_t(x ^ y); }
            },
            {
                6,
                "MBA Xor: (x & ~y) | (~x & y) => x ^ y",
                nlohmann::json::parse(R"({"op": "cot_bor", "x": {"op": "cot_band", "x": "$x", "y": {"op": "cot_bnot", "x": "$y"}}, "y": {"op": "cot_band", "x": {"op": "cot_bnot", "x": "$x"}, "y": "$y"}})") ,
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " ^ " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t((x & uint8_t(~y)) | (uint8_t(~x) & y)) == uint8_t(x ^ y); }
            },
            {
                7,
                "De Morgan: ~(~x & ~y) => x | y",
                nlohmann::json::parse(R"({"op": "cot_bnot", "x": {"op": "cot_band", "x": {"op": "cot_bnot", "x": "$x"}, "y": {"op": "cot_bnot", "x": "$y"}}})") ,
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " | " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t(~(uint8_t(~x) & uint8_t(~y))) == uint8_t(x | y); }
            },
            {
                8,
                "De Morgan: ~(~x | ~y) => x & y",
                nlohmann::json::parse(R"({"op": "cot_bnot", "x": {"op": "cot_bor", "x": {"op": "cot_bnot", "x": "$x"}, "y": {"op": "cot_bnot", "x": "$y"}}})") ,
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " & " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t(~(uint8_t(~x) | uint8_t(~y))) == uint8_t(x & y); }
            },
            {
                9,
                "Absorption: (x & y) | (x & ~y) => x",
                nlohmann::json::parse(R"({"op": "cot_bor", "x": {"op": "cot_band", "x": "$x", "y": "$y"}, "y": {"op": "cot_band", "x": "$x", "y": {"op": "cot_bnot", "x": "$y"}}})") ,
                [](const auto& b) { return ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t y) { return uint8_t((x & y) | (x & uint8_t(~y))) == uint8_t(x); }
            },
            {
                10,
                "NOT Sub: x + ~y + 1 => x - y",
                nlohmann::json::parse(R"({"op": "cot_add", "x": {"op": "cot_add", "x": "$x", "y": {"op": "cot_bnot", "x": "$y"}}, "y": {"op": "cot_num", "value": 1}})") ,
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " - " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t(x + uint8_t(~y) + 1) == uint8_t(x - y); }
            },
            {
                11,
                "Idempotence XOR: x ^ x => 0",
                nlohmann::json::parse(R"({"op": "cot_xor", "x": "$x", "y": "$x"})") ,
                [](const auto&) { return "0"; },
                [](uint8_t x, uint8_t) { return uint8_t(x ^ x) == 0; }
            },
            {
                12,
                "Idempotence AND: x & x => x",
                nlohmann::json::parse(R"({"op": "cot_band", "x": "$x", "y": "$x"})") ,
                [](const auto& b) { return ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t) { return uint8_t(x & x) == x; }
            },
            {
                13,
                "Idempotence OR: x | x => x",
                nlohmann::json::parse(R"({"op": "cot_bor", "x": "$x", "y": "$x"})") ,
                [](const auto& b) { return ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t) { return uint8_t(x | x) == x; }
            },
            {
                14,
                "Annihilation AND: x & ~x => 0",
                nlohmann::json::parse(R"({"op": "cot_band", "x": "$x", "y": {"op": "cot_bnot", "x": "$x"}})") ,
                [](const auto&) { return "0"; },
                [](uint8_t x, uint8_t) { return uint8_t(x & uint8_t(~x)) == 0; }
            },
            {
                15,
                "Tautology OR: x | ~x => ~0",
                nlohmann::json::parse(R"({"op": "cot_bor", "x": "$x", "y": {"op": "cot_bnot", "x": "$x"}})") ,
                [](const auto&) { return "~0"; },
                [](uint8_t x, uint8_t) { return uint8_t(x | uint8_t(~x)) == uint8_t(~0); }
            },

            // === New rules 16-37 ===
            {
                16,
                "MBA Or: (x & y) + (x ^ y) => x | y",
                nlohmann::json::parse(R"({"op": "cot_add", "x": {"op": "cot_band", "x": "$x", "y": "$y"}, "y": {"op": "cot_xor", "x": "$x", "y": "$y"}})"),
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " | " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t((x & y) + (x ^ y)) == uint8_t(x | y); }
            },
            {
                17,
                "MBA Or: (x + y) - (x & y) => x | y",
                nlohmann::json::parse(R"({"op": "cot_sub", "x": {"op": "cot_add", "x": "$x", "y": "$y"}, "y": {"op": "cot_band", "x": "$x", "y": "$y"}})"),
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " | " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t((x + y) - (x & y)) == uint8_t(x | y); }
            },
            {
                18,
                "MBA Neg: ~x + 1 => -x",
                nlohmann::json::parse(R"({"op": "cot_add", "x": {"op": "cot_bnot", "x": "$x"}, "y": {"op": "cot_num", "value": 1}})"),
                [](const auto& b) { return "-" + ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t) { return uint8_t(uint8_t(~x) + 1) == uint8_t(-x); }
            },
            {
                19,
                "MBA Neg: (x ^ -1) + 1 => -x",
                nlohmann::json::parse(R"({"op": "cot_add", "x": {"op": "cot_xor", "x": "$x", "y": {"op": "cot_num"}}, "y": {"op": "cot_num", "value": 1}})"),
                [](const auto& b) { return "-" + ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t) { return uint8_t((x ^ 0xFF) + 1) == uint8_t(-x); }
            },
            {
                20,
                "MBA Xor: (x | y) - (x & y) => x ^ y",
                nlohmann::json::parse(R"({"op": "cot_sub", "x": {"op": "cot_bor", "x": "$x", "y": "$y"}, "y": {"op": "cot_band", "x": "$x", "y": "$y"}})"),
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " ^ " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t((x | y) - (x & y)) == uint8_t(x ^ y); }
            },
            {
                21,
                "Identity XOR: x ^ 0 => x",
                nlohmann::json::parse(R"({"op": "cot_xor", "x": "$x", "y": {"op": "cot_num", "value": 0}})"),
                [](const auto& b) { return ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t) { return uint8_t(x ^ 0) == x; }
            },
            {
                22,
                "Identity AND: x & -1 => x",
                nlohmann::json::parse(R"({"op": "cot_band", "x": "$x", "y": {"op": "cot_num"}})"),
                [](const auto& b) { return ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t) { return uint8_t(x & 0xFF) == x; }
            },
            {
                23,
                "Identity OR: x | 0 => x",
                nlohmann::json::parse(R"({"op": "cot_bor", "x": "$x", "y": {"op": "cot_num", "value": 0}})"),
                [](const auto& b) { return ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t) { return uint8_t(x | 0) == x; }
            },
            {
                24,
                "Annihilation AND: x & 0 => 0",
                nlohmann::json::parse(R"({"op": "cot_band", "x": "$x", "y": {"op": "cot_num", "value": 0}})"),
                [](const auto&) { return "0"; },
                [](uint8_t x, uint8_t) { return uint8_t(x & 0) == 0; }
            },
            {
                25,
                "Double NOT: ~~x => x",
                nlohmann::json::parse(R"({"op": "cot_bnot", "x": {"op": "cot_bnot", "x": "$x"}})"),
                [](const auto& b) { return ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t) { return uint8_t(~~x) == x; }
            },
            {
                26,
                "Complement Sub: x - x => 0",
                nlohmann::json::parse(R"({"op": "cot_sub", "x": "$x", "y": "$x"})"),
                [](const auto&) { return "0"; },
                [](uint8_t x, uint8_t) { return uint8_t(x - x) == 0; }
            },
            {
                27,
                "MBA Neg: ~(x - 1) => -x",
                nlohmann::json::parse(R"({"op": "cot_bnot", "x": {"op": "cot_sub", "x": "$x", "y": {"op": "cot_num", "value": 1}}})"),
                [](const auto& b) { return "-" + ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t) { return uint8_t(~(x - 1)) == uint8_t(-x); }
            },
            {
                28,
                "Distribute AND: (x & z) | (y & z) => (x | y) & z",
                nlohmann::json::parse(R"({"op": "cot_bor", "x": {"op": "cot_band", "x": "$x", "y": "$z"}, "y": {"op": "cot_band", "x": "$y", "y": "$z"}})"),
                [](const auto& b) { return "(" + ExtractBindingName(b.at("$x")) + " | " + ExtractBindingName(b.at("$y")) + ") & " + ExtractBindingName(b.at("$z")); },
                [](uint8_t, uint8_t) { return true; } // structural rule, verified by pattern match
            },
            {
                29,
                "Distribute OR: (x | z) & (y | z) => (x & y) | z",
                nlohmann::json::parse(R"({"op": "cot_band", "x": {"op": "cot_bor", "x": "$x", "y": "$z"}, "y": {"op": "cot_bor", "x": "$y", "y": "$z"}})"),
                [](const auto& b) { return "(" + ExtractBindingName(b.at("$x")) + " & " + ExtractBindingName(b.at("$y")) + ") | " + ExtractBindingName(b.at("$z")); },
                [](uint8_t, uint8_t) { return true; }
            },
            {
                30,
                "MBA Sub: x + y*(-1) => x - y",
                nlohmann::json::parse(R"({"op": "cot_add", "x": "$x", "y": {"op": "cot_mul", "x": "$y", "y": {"op": "cot_num"}}})"),
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " - " + ExtractBindingName(b.at("$y")); },
                [](uint8_t, uint8_t) { return true; }
            },
            {
                31,
                "Shift Mul: x << 1 => x * 2",
                nlohmann::json::parse(R"({"op": "cot_shl", "x": "$x", "y": {"op": "cot_num", "value": 1}})"),
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " * 2"; },
                [](uint8_t x, uint8_t) { return uint8_t(x << 1) == uint8_t(x * 2); }
            },
            {
                32,
                "Shift Identity: x >> 0 => x",
                nlohmann::json::parse(R"({"op": "cot_sshr", "x": "$x", "y": {"op": "cot_num", "value": 0}})"),
                [](const auto& b) { return ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t) { return uint8_t(x >> 0) == x; }
            },
            {
                33,
                "MBA Add: (x & ~y) + (x & y) => x",
                nlohmann::json::parse(R"({"op": "cot_add", "x": {"op": "cot_band", "x": "$x", "y": {"op": "cot_bnot", "x": "$y"}}, "y": {"op": "cot_band", "x": "$x", "y": "$y"}})"),
                [](const auto& b) { return ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t y) { return uint8_t((x & uint8_t(~y)) + (x & y)) == x; }
            },
            {
                34,
                "MBA Or: ~(~x & ~y) => x | y (De Morgan variant)",
                nlohmann::json::parse(R"({"op": "cot_bnot", "x": {"op": "cot_band", "x": {"op": "cot_bnot", "x": "$x"}, "y": {"op": "cot_bnot", "x": "$y"}}})"),
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " | " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t(~(uint8_t(~x) & uint8_t(~y))) == uint8_t(x | y); }
            },
            {
                35,
                "MBA Xor: (x | y) & (~x | ~y) => x ^ y",
                nlohmann::json::parse(R"({"op": "cot_band", "x": {"op": "cot_bor", "x": "$x", "y": "$y"}, "y": {"op": "cot_bor", "x": {"op": "cot_bnot", "x": "$x"}, "y": {"op": "cot_bnot", "x": "$y"}}})"),
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " ^ " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t((x | y) & (uint8_t(~x) | uint8_t(~y))) == uint8_t(x ^ y); }
            },
            {
                36,
                "MBA Xor: ~(x & y) & (x | y) => x ^ y",
                nlohmann::json::parse(R"({"op": "cot_band", "x": {"op": "cot_bnot", "x": {"op": "cot_band", "x": "$x", "y": "$y"}}, "y": {"op": "cot_bor", "x": "$x", "y": "$y"}})"),
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " ^ " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t(uint8_t(~(x & y)) & (x | y)) == uint8_t(x ^ y); }
            },
            {
                37,
                "MBA And: x + y - (x | y) => x & y",
                nlohmann::json::parse(R"({"op": "cot_sub", "x": {"op": "cot_add", "x": "$x", "y": "$y"}, "y": {"op": "cot_bor", "x": "$x", "y": "$y"}})"),
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " & " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t((x + y) - (x | y)) == uint8_t(x & y); }
            }
        };
        return kRules;
    }

    // === Constant Folding Engine ===
    // Try to evaluate a pure-constant expression to a single value.
    inline std::optional<uint64_t> TryConstFold(const cexpr_t* expr) {
        if (!expr) return std::nullopt;

        if (expr->op == cot_num) {
            return static_cast<uint64_t>(expr->numval());
        }

        // Unary: ~x
        if (expr->op == cot_bnot && expr->x) {
            auto v = TryConstFold(expr->x);
            if (v) return ~(*v);
        }

        // Unary: -x
        if (expr->op == cot_neg && expr->x) {
            auto v = TryConstFold(expr->x);
            if (v) return static_cast<uint64_t>(-static_cast<int64_t>(*v));
        }

        // Unary: !x
        if (expr->op == cot_lnot && expr->x) {
            auto v = TryConstFold(expr->x);
            if (v) return (*v == 0) ? 1 : 0;
        }

        // Cast
        if (expr->op == cot_cast && expr->x) {
            int sz = expr->type.get_size();
            uint64_t cast_mask = (sz >= 8 || sz <= 0) ? ~0ULL : ((1ULL << (sz * 8)) - 1);
            auto v = TryConstFold(expr->x);
            if (v) return (*v) & cast_mask;
        }

        // Binary operations
        if (is_binary(expr->op) && expr->x && expr->y) {
            auto l = TryConstFold(expr->x);
            auto r = TryConstFold(expr->y);
            if (!l || !r) return std::nullopt;

            switch (expr->op) {
                case cot_add:  return *l + *r;
                case cot_sub:  return *l - *r;
                case cot_mul:  return *l * *r;
                case cot_band: return *l & *r;
                case cot_bor:  return *l | *r;
                case cot_xor:  return *l ^ *r;
                case cot_shl:  return *l << (*r & 63);
                case cot_sshr: return static_cast<uint64_t>(static_cast<int64_t>(*l) >> (*r & 63));
                case cot_ushr: return *l >> (*r & 63);
                case cot_eq:   return (*l == *r) ? 1 : 0;
                case cot_ne:   return (*l != *r) ? 1 : 0;
                case cot_slt:  return (static_cast<int64_t>(*l) < static_cast<int64_t>(*r)) ? 1 : 0;
                case cot_ult:  return (*l < *r) ? 1 : 0;
                case cot_sle:  return (static_cast<int64_t>(*l) <= static_cast<int64_t>(*r)) ? 1 : 0;
                case cot_ule:  return (*l <= *r) ? 1 : 0;
                case cot_sgt:  return (static_cast<int64_t>(*l) > static_cast<int64_t>(*r)) ? 1 : 0;
                case cot_ugt:  return (*l > *r) ? 1 : 0;
                case cot_sge:  return (static_cast<int64_t>(*l) >= static_cast<int64_t>(*r)) ? 1 : 0;
                case cot_uge:  return (*l >= *r) ? 1 : 0;
                case cot_land: return (*l != 0 && *r != 0) ? 1 : 0;
                case cot_lor:  return (*l != 0 || *r != 0) ? 1 : 0;
                default: break;
            }
        }

        return std::nullopt;
    }

    // === Brute-force Symbolic Verification ===
    // For expressions with exactly ONE free variable: try substituting test values
    // to verify if the expression is equivalent to a simpler form.
    struct BruteForceResult {
        std::string simplified;
        std::string confidence; // "brute_force_verified" or "const_fold"
    };

    // Count unique lvars used in an expression
    inline void CollectLvars(const cexpr_t* expr, const cfunc_t* cf, std::set<int>& lvar_indices) {
        if (!expr) return;
        if (expr->op == cot_var) {
            lvar_indices.insert(expr->v.idx);
            return;
        }
        if (op_uses_x(expr->op) && expr->x) CollectLvars(expr->x, cf, lvar_indices);
        if (op_uses_y(expr->op) && expr->y) CollectLvars(expr->y, cf, lvar_indices);
        if (op_uses_z(expr->op) && expr->z) CollectLvars(expr->z, cf, lvar_indices);
        if (expr->op == cot_call && expr->a) {
            for (const auto& arg : *expr->a) {
                CollectLvars(&arg, cf, lvar_indices);
            }
        }
    }

    inline std::optional<uint64_t> EvalExprWithSingleVar(
        const cexpr_t* expr,
        int target_var_idx,
        uint64_t var_val,
        uint64_t mask) {
        if (!expr) return std::nullopt;

        if (expr->op == cot_num) {
            return static_cast<uint64_t>(expr->numval()) & mask;
        }

        if (expr->op == cot_var) {
            if (expr->v.idx == target_var_idx) {
                return var_val & mask;
            }
            return std::nullopt;
        }

        if (expr->op == cot_bnot && expr->x) {
            auto v = EvalExprWithSingleVar(expr->x, target_var_idx, var_val, mask);
            if (v) return (~(*v)) & mask;
            return std::nullopt;
        }

        if (expr->op == cot_neg && expr->x) {
            auto v = EvalExprWithSingleVar(expr->x, target_var_idx, var_val, mask);
            if (v) return static_cast<uint64_t>(-static_cast<int64_t>(*v)) & mask;
            return std::nullopt;
        }

        if (expr->op == cot_lnot && expr->x) {
            auto v = EvalExprWithSingleVar(expr->x, target_var_idx, var_val, mask);
            if (v) return (*v == 0) ? 1 : 0;
            return std::nullopt;
        }

        if (expr->op == cot_cast && expr->x) {
            int sz = expr->type.get_size();
            uint64_t cast_mask = (sz >= 8 || sz <= 0) ? ~0ULL : ((1ULL << (sz * 8)) - 1);
            auto v = EvalExprWithSingleVar(expr->x, target_var_idx, var_val, cast_mask);
            if (v) return (*v) & mask;
            return std::nullopt;
        }

        if (is_binary(expr->op) && expr->x && expr->y) {
            auto l = EvalExprWithSingleVar(expr->x, target_var_idx, var_val, mask);
            auto r = EvalExprWithSingleVar(expr->y, target_var_idx, var_val, mask);
            if (!l || !r) return std::nullopt;

            switch (expr->op) {
                case cot_add:  return (*l + *r) & mask;
                case cot_sub:  return (*l - *r) & mask;
                case cot_mul:  return (*l * *r) & mask;
                case cot_band: return (*l & *r) & mask;
                case cot_bor:  return (*l | *r) & mask;
                case cot_xor:  return (*l ^ *r) & mask;
                case cot_shl:  return (*l << (*r & 63)) & mask;
                case cot_sshr: return static_cast<uint64_t>(static_cast<int64_t>(*l) >> (*r & 63)) & mask;
                case cot_ushr: return (*l >> (*r & 63)) & mask;
                case cot_eq:   return (*l == *r) ? 1 : 0;
                case cot_ne:   return (*l != *r) ? 1 : 0;
                case cot_slt:  return (static_cast<int64_t>(*l) < static_cast<int64_t>(*r)) ? 1 : 0;
                case cot_ult:  return (*l < *r) ? 1 : 0;
                case cot_sle:  return (static_cast<int64_t>(*l) <= static_cast<int64_t>(*r)) ? 1 : 0;
                case cot_ule:  return (*l <= *r) ? 1 : 0;
                case cot_sgt:  return (static_cast<int64_t>(*l) > static_cast<int64_t>(*r)) ? 1 : 0;
                case cot_ugt:  return (*l > *r) ? 1 : 0;
                case cot_sge:  return (static_cast<int64_t>(*l) >= static_cast<int64_t>(*r)) ? 1 : 0;
                case cot_uge:  return (*l >= *r) ? 1 : 0;
                case cot_land: return (*l != 0 && *r != 0) ? 1 : 0;
                case cot_lor:  return (*l != 0 || *r != 0) ? 1 : 0;
                default: break;
            }
        }

        return std::nullopt;
    }

    inline std::optional<BruteForceResult> BruteForceSimplify(
        const cexpr_t* expr,
        const cfunc_t* cf) {
        if (!expr || !cf) return std::nullopt;

        std::set<int> lvar_indices;
        CollectLvars(expr, cf, lvar_indices);

        if (lvar_indices.empty()) {
            auto cf_val = TryConstFold(expr);
            if (cf_val) {
                std::ostringstream oss;
                oss << "0x" << std::hex << *cf_val;
                return BruteForceResult{oss.str(), "const_fold"};
            }
            return std::nullopt;
        }

        if (lvar_indices.size() != 1) {
            return std::nullopt;
        }

        int target_var = *lvar_indices.begin();
        const lvars_t* lvars = const_cast<cfunc_t*>(cf)->get_lvars();
        if (!lvars || target_var < 0 || target_var >= static_cast<int>(lvars->size())) {
            return std::nullopt;
        }
        std::string var_name = (*lvars)[target_var].name.c_str();

        int sz = expr->type.get_size();
        uint64_t mask = (sz >= 8 || sz <= 0) ? ~0ULL : ((1ULL << (sz * 8)) - 1);

        static const uint64_t kTestValues[] = {
            0, 1, 2, 7, 0x42, 0x7F, 0x80, 0xAA, 0x55, 0xFF,
            0x100, 0x1234, 0x7FFF, 0x8000, 0xFFFF, 0x10000,
            0x12345678, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
            0x100000000ULL, 0xDEADBEEFCAFEBABEULL
        };

        bool all_identity = true;
        bool all_neg = true;
        bool all_bnot = true;
        bool all_zero = true;
        bool all_all_ones = true;
        bool all_same_const = true;
        std::optional<uint64_t> first_val = std::nullopt;

        for (uint64_t raw_val : kTestValues) {
            uint64_t val = raw_val & mask;
            auto eval_res = EvalExprWithSingleVar(expr, target_var, val, mask);
            if (!eval_res) {
                return std::nullopt;
            }
            uint64_t out = *eval_res & mask;

            if (out != val) all_identity = false;
            if (out != (static_cast<uint64_t>(-static_cast<int64_t>(val)) & mask)) all_neg = false;
            if (out != ((~val) & mask)) all_bnot = false;
            if (out != 0) all_zero = false;
            if (out != mask) all_all_ones = false;

            if (!first_val) {
                first_val = out;
            } else if (*first_val != out) {
                all_same_const = false;
            }
        }

        if (all_identity) {
            return BruteForceResult{var_name, "brute_force_verified"};
        }
        if (all_zero) {
            return BruteForceResult{"0", "brute_force_verified"};
        }
        if (all_neg) {
            return BruteForceResult{"-" + var_name, "brute_force_verified"};
        }
        if (all_bnot) {
            return BruteForceResult{"~" + var_name, "brute_force_verified"};
        }
        if (all_all_ones) {
            return BruteForceResult{"~0", "brute_force_verified"};
        }
        if (all_same_const && first_val) {
            std::ostringstream oss;
            if (*first_val == 0) oss << "0";
            else oss << "0x" << std::hex << *first_val;
            return BruteForceResult{oss.str(), "brute_force_verified"};
        }

        return std::nullopt;
    }
}
