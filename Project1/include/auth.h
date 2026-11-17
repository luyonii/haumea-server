#pragma once
// Authentication: challenge-response flow, HMAC-SHA256, HKDF via Windows CNG.

#include <string>
#include <vector>
#include <cstdint>

namespace auth {

struct session_info {
    std::string session_token;
    // Per-use sub-keys derived from the session_key PRK via HKDF-Expand.
    // The raw PRK is scrubbed after expansion (never stored).
    std::vector<uint8_t> k_payload_aes;  // AES-256-GCM of the payload
    std::vector<uint8_t> k_heartbeat;    // HMAC of the heartbeat
    std::vector<uint8_t> k_watermark;    // HMAC of the watermark
    std::vector<uint8_t> k_rpc;          // HMAC of the RPC
    int ttl = 0;
    int heartbeat_interval = 0;
    std::string next_nonce;              // base64-encoded
};

struct auth_result {
    bool success = false;
    std::string error_message;
    session_info session;
};

auth_result authenticate(const std::string& license_key, const std::string& hwid);

// Zeros session_key and clears all fields.
void clear_session(session_info& info);

// HMAC-SHA256 via CNG. Exposed for heartbeat module.
bool hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t out[32]);

} // namespace auth
