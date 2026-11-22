#pragma once
// Fetches the encrypted entitled module from the licensing server, decrypts
// it, verifies the per-session integrity tag, launches the target host
// process, and injects the module into it.

#include <cstdint>

namespace payload {

enum class result {
    ok,
    fetch_failed,
    envelope_invalid,
    decrypt_failed,
    watermark_hwid,
    watermark_license,
    watermark_expired,
    watermark_signature,
    launch_failed,
    inject_failed,
};

// local_hwid: 64-char hex SHA-256 string (from hwid::generate()).
// license_hash: 32-byte SHA-256 of the raw license key (watermark::sha256).
// k_payload_aes decrypts the envelope; k_watermark verifies the session binding.
// target_exe_fallback: used only when the server's fetch response omits
// `target_exe_path` (empty string). May be nullptr; the call then returns
// `launch_failed` if the server also returned no path.
result load_and_execute(const char* session_token,
                        const uint8_t* k_payload_aes,   // 32 bytes
                        const uint8_t* k_watermark,     // 32 bytes
                        const char*    local_hwid,
                        const uint8_t* license_hash,    // 32 bytes
                        const wchar_t* target_exe_fallback);

} // namespace payload
