#pragma once
// Periodic heartbeat thread. Sends timestamps authenticated with a keyed
// message integrity tag to the licensing server. Detects remote
// license-suspension flags, entitlement revocation, or connectivity loss.

#include <cstdint>

namespace heartbeat {

enum class stop_reason {
    requested,   // normal stop() call
    killed,      // server sent kill flag
    revoked,     // session revoked
    failed       // 3 consecutive heartbeat failures
};

bool start(const char* session_token, const uint8_t* session_key,
           int interval_seconds, const char* initial_nonce_b64);
void stop();
bool is_running();
stop_reason get_stop_reason();

// Fold a sentinel/tool-detect trip bitmask into every subsequent heartbeat.
// Thread-safe and idempotent (bits are OR-ed in). Never cleared client-side:
// the server is the source of truth for whether a trip was received.
void report_trip(uint32_t sentinel_mask, uint32_t tool_mask) noexcept;

// Send exactly one heartbeat right now (not waiting for the next tick),
// carrying the current trip masks. Returns true only on HTTP 200. Returns
// within timeout_ms even if the network wedges: the send is dispatched on
// std::async and abandoned on timeout. Used by the sentinel abort path to get
// one last telemetry heartbeat out before local terminate.
bool flush_once(uint32_t timeout_ms) noexcept;

} // namespace heartbeat
