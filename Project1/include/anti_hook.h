#pragma once
#include <cstdint>

namespace anti_hook {

// Returns bitmask (slot index per watched API, up to 16). 0 == clean.
uint32_t check_critical_apis();

} // namespace anti_hook
