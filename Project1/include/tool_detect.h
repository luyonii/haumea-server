#pragma once
#include <cstdint>

namespace tool_detect {

enum class detection : uint32_t {
    none       = 0,
    debugger   = 1u << 0,
    disasm     = 1u << 1,
    inspector  = 1u << 2,
    memhack    = 1u << 3,
    hypervisor = 1u << 4,
};

// Bitmask of categories where at least one process matched. 0 == clean.
uint32_t enumerate();

} // namespace tool_detect
