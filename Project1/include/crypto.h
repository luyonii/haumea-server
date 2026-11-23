#pragma once
// HKDF-Expand (RFC 5869) utilities shared across the auth / key-derivation
// path. AES-GCM decryption lived here until Phase B.4 — the target-side
// stub_worker now owns that step and the loader no longer needs it.

#include <cstdint>
#include <cstddef>

namespace crypto {

// HKDF-Expand with SHA-256. `prk` is the pseudo-random key from a prior
// HKDF-Extract (or any 32-byte secret). `info` is the context string.
// Writes `out_len` bytes into `out`. Shortcut: out_len <= 32 (single
// block); extend with a T(n) loop when a derived key wider than one HMAC
// block is needed.
bool hkdf_expand(const uint8_t* prk, size_t prk_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* out, size_t out_len);

} // namespace crypto
