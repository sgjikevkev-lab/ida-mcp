#pragma once
#include <cstdint>
using ea_t = uint64_t;
inline constexpr ea_t BADADDR = ~ea_t(0);
#define idaapi
