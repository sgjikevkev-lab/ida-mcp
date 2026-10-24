#pragma once
#include <cstddef>
#include <cstdint>

namespace mcp::limits {
    inline constexpr uint32_t operation_ms = 30 * 60 * 1000;
    inline constexpr size_t frame_bytes = 32 * 1024 * 1024;
    inline constexpr size_t result_bytes = 2 * 1024 * 1024;
}
