#pragma once
#include <cstdint>

namespace sentinel {

enum class action { continue_, abort_ };

struct report {
    uint32_t anti_debug      = 0;
    uint32_t anti_vm         = 0;
    uint32_t anti_hook       = 0;
    uint32_t tool_mask       = 0;
    bool     tamper_detected = false;
};

// Severity policy:
//   CRITICAL (abort): any anti_debug bit, any tool_mask bit, tamper, any hook.
//   WARN (continue):  anti_vm alone.
action scan(report& out);

bool start_monitor(uint32_t text_crc_baseline, uint32_t code_canary_baseline);
void stop_monitor();

using scrub_cb = void (*)();
// Optional: called before terminate_silent() when the monitor trips.
void set_scrub_callback(scrub_cb cb);

} // namespace sentinel
