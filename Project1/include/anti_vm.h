#pragma once
#include <cstdint>

namespace anti_vm {

enum class detection : uint32_t {
    none            = 0,
    hypervisor_bit  = 1u << 0,
    hv_vendor       = 1u << 1,
    rdtsc_timing    = 1u << 2,
    vm_mac_prefix   = 1u << 3,
    vm_registry     = 1u << 4,
};

// Returns bitmask. 0 == bare metal (probably).
uint32_t check_all();

} // namespace anti_vm
