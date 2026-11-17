#pragma once
#include <cstdint>

namespace anti_debug {

enum class detection : uint32_t {
    none                  = 0,
    peb_being_debugged    = 1u << 0,
    peb_nt_global_flag    = 1u << 1,
    peb_heap_flags        = 1u << 2,
    debug_port            = 1u << 3,
    debug_object          = 1u << 4,
    debug_flags           = 1u << 5,
    kernel_debugger       = 1u << 6,
    hw_breakpoint         = 1u << 7,
    remote_debugger       = 1u << 8,
    output_debug_trick    = 1u << 9,
};

// Returns bitmask of tripped detections. 0 == clean.
uint32_t check_all();

// NtSetInformationThread(ThreadHideFromDebugger) on the current thread.
void hide_current_thread();

} // namespace anti_debug
