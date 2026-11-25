#pragma once
// Client authentication: nonce-based auth flow against the licensing server,
// keyed message integrity tag (HMAC-SHA256) and key derivation (RFC 5869)
// via Windows CNG.

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

// text_crc32 / code_fingerprint bind the client's own .text CRC and code
// fingerprint into the HKDF salt of derived_key. If the shipped binary diverges
// from the server's known baseline, derived_key diverges, the challenge HMAC
// fails to verify, and login is rejected — no isolated boolean gate to patch.
//
// anti_debug_mask / anti_hook_mask / tool_detect_mask / anti_vm_mask are the raw
// detection bitmasks captured by sentinel::scan BEFORE the local abort gate
// (audit #1). They are folded into the same salt so a runtime bypass of the
// local gate (NOP the jne / zero the registers) is no longer sufficient: unless
// the attacker also forces every mask back to the server's expected baseline
// (normally all-zero), derived_key diverges and login is rejected. The local
// gate stays as defense-in-depth but is no longer the security boundary.
auth_result authenticate(const std::string& license_key, const std::string& hwid,
                         uint32_t text_crc32, uint32_t code_fingerprint,
                         uint32_t anti_debug_mask, uint32_t anti_hook_mask,
                         uint32_t tool_detect_mask, uint32_t anti_vm_mask);

// Zeros session_key and clears all fields.
void clear_session(session_info& info);

// HMAC-SHA256 via CNG. Exposed for heartbeat module.
bool hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t out[32]);

} // namespace auth
