#pragma once
// Per-user watermark binding a decrypted payload to this HWID + license.
// The server prepends a 128-byte watermark to the plaintext PE before AES-GCM
// encryption. The client verifies it before mapping the PE.

#include <cstddef>
#include <cstdint>

namespace watermark {

constexpr size_t SIZE = 128;

enum class result {
    ok,
    bad_size,
    hwid_mismatch,
    license_mismatch,
    expired,
    bad_signature,
};

// In-place verify. On ok, *out_pe_ptr points to plaintext + SIZE and
// *out_pe_size is plaintext_len - SIZE. On failure, buffer unchanged.
// local_hwid: 64-char hex SHA-256 from hwid::generate().
// license_hash: 32-byte SHA-256 of the raw license key.
result verify(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* session_key,
    const char*    local_hwid,
    const uint8_t* license_hash,
    const uint8_t** out_pe_ptr,
    size_t*        out_pe_size);

// SHA-256 via BCrypt. Caller provides a 32-byte output buffer.
bool sha256(const uint8_t* data, size_t data_len, uint8_t out[32]);

} // namespace watermark
