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

// Reserved high bits of the sentinel_mask sent on the heartbeat telemetry
// channel. Low bits (< 0x10000000) stay free for anti_debug / anti_hook
// native bitmasks.
namespace bits {
constexpr uint32_t TAMPER      = 0x80000000u;
constexpr uint32_t CANARY_DATA = 0x40000000u;
constexpr uint32_t CANARY_CODE = 0x20000000u;
constexpr uint32_t SEH_FAULT   = 0x10000000u;
} // namespace bits

namespace detail {
// Pure composition of the sentinel_mask from the raw check results. Exposed
// so tests can pin the mapping without having to drive the full monitor.
uint32_t compose_sentinel_mask(uint32_t anti_debug_bits,
                               uint32_t anti_hook_bits,
                               bool tamper_fail,
                               bool canary_data_fail,
                               bool canary_code_fail,
                               bool seh_fault) noexcept;
} // namespace detail

} // namespace sentinel
