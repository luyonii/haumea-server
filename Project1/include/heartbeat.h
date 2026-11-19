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

} // namespace heartbeat
