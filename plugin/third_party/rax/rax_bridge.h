#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "../../../shared/json.h"

namespace tools::rax {
    bool Available(std::string& error);
    nlohmann::ordered_json AnalyzeX64(uint64_t address, const uint8_t* bytes, size_t size);
}
