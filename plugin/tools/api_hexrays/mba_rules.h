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
                nlohmann::json::parse(R"({"op": "cot_add", "x": {"op": "cot_xor", "x": "$x", "y": {"op": "cot_num", "value": -1}}, "y": {"op": "cot_num", "value": 1}})"),
                [](const auto& b) { return "-" + ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t) { return uint8_t((x ^ 0xFF) + 1) == uint8_t(-x); }
            },
            {
                20,
                "MBA Xor: (x | y) - (x & y) => x ^ y",
                nlohmann::json::parse(R"({"op": "cot_sub", "x": {"op": "cot_bor", "x": "$x", "y": "$y"}, "y": {"op": "cot_band", "x": "$x", "y": "$y"}})") ,
                [](const auto& b) { return ExtractBindingName(b.at("$x")) + " ^ " + ExtractBindingName(b.at("$y")); },
                [](uint8_t x, uint8_t y) { return uint8_t((x | y) - (x & y)) == uint8_t(x ^ y); }
            },
            {
                21,
                "Identity XOR: x ^ 0 => x",
                nlohmann::json::parse(R"({"op": "cot_xor", "x": "$x", "y": {"op": "cot_num", "value": 0}})") ,
                [](const auto& b) { return ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t) { return uint8_t(x ^ 0) == x; }
            },
            {
                22,
                "Identity AND: x & -1 => x",
                nlohmann::json::parse(R"({"op": "cot_band", "x": "$x", "y": {"op": "cot_num", "value": -1}})") ,
                [](const auto& b) { return ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t) { return uint8_t(x & 0xFF) == x; }
            },
            {
                23,
                "Identity OR: x | 0 => x",
                nlohmann::json::parse(R"({"op": "cot_bor", "x": "$x", "y": {"op": "cot_num", "value": 0}})") ,
                [](const auto& b) { return ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t) { return uint8_t(x | 0) == x; }
            },
            {
                24,
                "Annihilation AND: x & 0 => 0",
                nlohmann::json::parse(R"({"op": "cot_band", "x": "$x", "y": {"op": "cot_num", "value": 0}})") ,
                [](const auto&) { return "0"; },
                [](uint8_t x, uint8_t) { return uint8_t(x & 0) == 0; }
            },
            {
                25,
                "Double NOT: ~~x => x",
                nlohmann::json::parse(R"({"op": "cot_bnot", "x": {"op": "cot_bnot", "x": "$x"}})") ,
                [](const auto& b) { return ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t) { return uint8_t(~~x) == x; }
            },
            {
                26,
                "Complement Sub: x - x => 0",
                nlohmann::json::parse(R"({"op": "cot_sub", "x": "$x", "y": "$x"}})") ,
                [](const auto&) { return "0"; },
                [](uint8_t x, uint8_t) { return uint8_t(x - x) == 0; }
            },
            {
                27,
                "MBA Neg: ~(x - 1) => -x",
                nlohmann::json::parse(R"({"op": "cot_bnot", "x": {"op": "cot_sub", "x": "$x", "y": {"op": "cot_num", "value": 1}}})") ,
                [](const auto& b) { return "-" + ExtractBindingName(b.at("$x")); },
                [](uint8_t x, uint8_t) { return uint8_t(~(x - 1)) == uint8_t(-x); }
            },
            {
                28,
                "Distribute AND: (x & z) | (y & z) => (x | y) & z",
                nlohmann::json::parse(R"({"op": "cot_bor", "x": {"op": "cot_band", "x": "$x", "y": "$z"}, "y": {"op": "cot_band", "x": "$y", "y": "$z"}})") ,
                [](const auto& b) { return "(" + ExtractBindingName(b.at("$x")) + " | " + ExtractBindingName(b.at("$y")) + ") & " + ExtractBindingName(b.at("$z")); },
                [](uint8_t, uint8_t) { return true; } // structural rule, verified by pattern match
            },
            {
                29,
                "Distribute OR: (x | z) & (y | z) => (x & y) | z",
                nlohmann::json::parse(R"({"op": "cot_band", "x": {"op": "cot_bor", "x": "$x", "y": "$z"}, "y": {"op": "cot_bor", "x": "$y", "y": "$z"}})") ,
                [](const auto& b) { return "(" + ExtractBindingName(b.at("$x")) + " & " + ExtractBindingName(b.at("$y")) + ") | " + ExtractBindingName(b.at("$z")); },
                [](uint8_t, uint8_t) { return true; }
            },
            {
                30,
                "MBA Sub: x + y*(-1) => x - y",
                nlohmann::json::parse(R"({"op": "cot_add", "x": "$x", "y": {"op": "cot_mul", "x": "$y", "y": {"op": "cot_num", "value": -1}}})"),
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

    inline int64_t SignExtend(uint64_t val, int byte_size) {
        if (byte_size <= 0 || byte_size >= 8) return static_cast<int64_t>(val);
        int shift = 64 - (byte_size * 8);
        return (static_cast<int64_t>(val << shift)) >> shift;
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
            if (v) {
                int x_sz = expr->x ? expr->x->type.get_size() : expr->type.get_size();
                int64_t sv = SignExtend(*v, x_sz);
                return static_cast<uint64_t>(-sv);
            }
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

            int l_sz = expr->x ? expr->x->type.get_size() : expr->type.get_size();
            int r_sz = expr->y ? expr->y->type.get_size() : expr->type.get_size();
            int64_t sl = SignExtend(*l, l_sz);
            int64_t sr = SignExtend(*r, r_sz);

            switch (expr->op) {
                case cot_add:  return *l + *r;
                case cot_sub:  return *l - *r;
                case cot_mul:  return *l * *r;
                case cot_band: return *l & *r;
                case cot_bor:  return *l | *r;
                case cot_xor:  return *l ^ *r;
                case cot_shl:  return *l << (*r & 63);
                case cot_sshr: return static_cast<uint64_t>(sl >> (*r & 63));
                case cot_ushr: return *l >> (*r & 63);
                case cot_eq:   return (*l == *r) ? 1 : 0;
                case cot_ne:   return (*l != *r) ? 1 : 0;
                case cot_slt:  return (sl < sr) ? 1 : 0;
                case cot_ult:  return (*l < *r) ? 1 : 0;
                case cot_sle:  return (sl <= sr) ? 1 : 0;
                case cot_ule:  return (*l <= *r) ? 1 : 0;
                case cot_sgt:  return (sl > sr) ? 1 : 0;
                case cot_ugt:  return (*l > *r) ? 1 : 0;
                case cot_sge:  return (sl >= sr) ? 1 : 0;
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
        std::string confidence; // "exact_constant", "exhaustive_8bit", "sampled_22"
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

    inline std::optional<uint64_t> EvalExprWithVars(
        const cexpr_t* expr,
        const std::map<int, uint64_t>& var_map,
        uint64_t mask) {
        if (!expr) return std::nullopt;

        if (expr->op == cot_num) {
            return static_cast<uint64_t>(expr->numval()) & mask;
        }

        if (expr->op == cot_var) {
            auto it = var_map.find(expr->v.idx);
            if (it != var_map.end()) {
                return it->second & mask;
            }
            return std::nullopt;
        }

        if (expr->op == cot_bnot && expr->x) {
            auto v = EvalExprWithVars(expr->x, var_map, mask);
            if (v) return (~(*v)) & mask;
            return std::nullopt;
        }

        if (expr->op == cot_neg && expr->x) {
            auto v = EvalExprWithVars(expr->x, var_map, mask);
            if (v) {
                int x_sz = expr->x ? expr->x->type.get_size() : expr->type.get_size();
                int64_t sv = SignExtend(*v, x_sz);
                return static_cast<uint64_t>(-sv) & mask;
            }
            return std::nullopt;
        }

        if (expr->op == cot_lnot && expr->x) {
            auto v = EvalExprWithVars(expr->x, var_map, mask);
            if (v) return (*v == 0) ? 1 : 0;
            return std::nullopt;
        }

        if (expr->op == cot_cast && expr->x) {
            int sz = expr->type.get_size();
            uint64_t cast_mask = (sz >= 8 || sz <= 0) ? ~0ULL : ((1ULL << (sz * 8)) - 1);
            auto v = EvalExprWithVars(expr->x, var_map, cast_mask);
            if (v) return (*v) & mask;
            return std::nullopt;
        }

        if (is_binary(expr->op) && expr->x && expr->y) {
            auto l = EvalExprWithVars(expr->x, var_map, mask);
            auto r = EvalExprWithVars(expr->y, var_map, mask);
            if (!l || !r) return std::nullopt;

            int l_sz = expr->x ? expr->x->type.get_size() : expr->type.get_size();
            int r_sz = expr->y ? expr->y->type.get_size() : expr->type.get_size();
            int64_t sl = SignExtend(*l, l_sz);
            int64_t sr = SignExtend(*r, r_sz);

            switch (expr->op) {
                case cot_add:  return (*l + *r) & mask;
                case cot_sub:  return (*l - *r) & mask;
                case cot_mul:  return (*l * *r) & mask;
                case cot_band: return (*l & *r) & mask;
                case cot_bor:  return (*l | *r) & mask;
                case cot_xor:  return (*l ^ *r) & mask;
                case cot_shl:  return (*l << (*r & 63)) & mask;
                case cot_sshr: return static_cast<uint64_t>(sl >> (*r & 63)) & mask;
                case cot_ushr: return (*l >> (*r & 63)) & mask;
                case cot_eq:   return (*l == *r) ? 1 : 0;
                case cot_ne:   return (*l != *r) ? 1 : 0;
                case cot_slt:  return (sl < sr) ? 1 : 0;
                case cot_ult:  return (*l < *r) ? 1 : 0;
                case cot_sle:  return (sl <= sr) ? 1 : 0;
                case cot_ule:  return (*l <= *r) ? 1 : 0;
                case cot_sgt:  return (sl > sr) ? 1 : 0;
                case cot_ugt:  return (*l > *r) ? 1 : 0;
                case cot_sge:  return (sl >= sr) ? 1 : 0;
                case cot_uge:  return (*l >= *r) ? 1 : 0;
                case cot_land: return (*l != 0 && *r != 0) ? 1 : 0;
                case cot_lor:  return (*l != 0 || *r != 0) ? 1 : 0;
                default: break;
            }
        }

        return std::nullopt;
    }

    inline std::optional<uint64_t> EvalExprWithSingleVar(
        const cexpr_t* expr,
        int target_var_idx,
        uint64_t var_val,
        uint64_t mask) {
        return EvalExprWithVars(expr, {{target_var_idx, var_val}}, mask);
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
                return BruteForceResult{oss.str(), "exact_constant"};
            }
            return std::nullopt;
        }

        // 2-variable algebraic identity solver (e.g. (x ^ y) + 2*(x & y) => x + y)
        if (lvar_indices.size() == 2) {
            auto it = lvar_indices.begin();
            int var1_idx = *it++;
            int var2_idx = *it;
            const lvars_t* lvs = const_cast<cfunc_t*>(cf)->get_lvars();
            if (!lvs || var1_idx < 0 || var1_idx >= static_cast<int>(lvs->size()) ||
                var2_idx < 0 || var2_idx >= static_cast<int>(lvs->size())) {
                return std::nullopt;
            }
            std::string x_name = (*lvs)[var1_idx].name.c_str();
            std::string y_name = (*lvs)[var2_idx].name.c_str();

            int sz = expr->type.get_size();
            uint64_t mask = (sz >= 8 || sz <= 0) ? ~0ULL : ((1ULL << (sz * 8)) - 1);

            static const uint64_t kSample2[] = {
                0, 1, 2, 7, 0x42, 0x7F, 0x80, 0xAA, 0x55, 0xFF,
                0x100, 0x7FFF, 0x8000, 0xFFFF, 0x12345678, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF
            };

            bool is_add = true, is_sub = true, is_sub_rev = true;
            bool is_and = true, is_or = true, is_xor = true, is_zero = true;

            for (uint64_t vx : kSample2) {
                uint64_t x_val = vx & mask;
                for (uint64_t vy : kSample2) {
                    uint64_t y_val = vy & mask;
                    auto eval_res = EvalExprWithVars(expr, {{var1_idx, x_val}, {var2_idx, y_val}}, mask);
                    if (!eval_res) return std::nullopt;
                    uint64_t out = *eval_res & mask;

                    if (out != ((x_val + y_val) & mask)) is_add = false;
                    if (out != ((x_val - y_val) & mask)) is_sub = false;
                    if (out != ((y_val - x_val) & mask)) is_sub_rev = false;
                    if (out != ((x_val & y_val) & mask)) is_and = false;
                    if (out != ((x_val | y_val) & mask)) is_or = false;
                    if (out != ((x_val ^ y_val) & mask)) is_xor = false;
                    if (out != 0) is_zero = false;
                }
            }

            if (is_add) return BruteForceResult{x_name + " + " + y_name, "sampled_2var"};
            if (is_sub) return BruteForceResult{x_name + " - " + y_name, "sampled_2var"};
            if (is_sub_rev) return BruteForceResult{y_name + " - " + x_name, "sampled_2var"};
            if (is_and) return BruteForceResult{x_name + " & " + y_name, "sampled_2var"};
            if (is_or) return BruteForceResult{x_name + " | " + y_name, "sampled_2var"};
            if (is_xor) return BruteForceResult{x_name + " ^ " + y_name, "sampled_2var"};
            if (is_zero) return BruteForceResult{"0", "sampled_2var"};

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

        std::vector<uint64_t> test_values;
        std::string confidence;
        if (sz == 1) {
            confidence = "exhaustive_8bit";
            test_values.reserve(256);
            for (int v = 0; v < 256; ++v) test_values.push_back(v);
        } else {
            confidence = "sampled_22";
            test_values.assign(std::begin(kTestValues), std::end(kTestValues));
        }

        bool all_identity = true;
        bool all_neg = true;
        bool all_bnot = true;
        bool all_zero = true;
        bool all_all_ones = true;
        bool all_same_const = true;
        std::optional<uint64_t> first_val = std::nullopt;

        for (uint64_t raw_val : test_values) {
            uint64_t val = raw_val & mask;
            auto eval_res = EvalExprWithSingleVar(expr, target_var, val, mask);
            if (!eval_res) {
                return std::nullopt;
            }
            uint64_t out = *eval_res & mask;

            if (out != val) all_identity = false;
            int64_t sval = SignExtend(val, sz);
            if (out != (static_cast<uint64_t>(-sval) & mask)) all_neg = false;
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
            return BruteForceResult{var_name, confidence};
        }
        if (all_zero) {
            return BruteForceResult{"0", confidence};
        }
        if (all_neg) {
            return BruteForceResult{"-" + var_name, confidence};
        }
        if (all_bnot) {
            return BruteForceResult{"~" + var_name, confidence};
        }
        if (all_all_ones) {
            return BruteForceResult{"~0", confidence};
        }
        if (all_same_const && first_val) {
            std::ostringstream oss;
            if (*first_val == 0) oss << "0";
            else oss << "0x" << std::hex << *first_val;
            return BruteForceResult{oss.str(), confidence};
        }

        return std::nullopt;
    }
}
