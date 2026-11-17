#pragma once
// AES-256-GCM via Windows CNG (bcrypt.dll). All APIs resolved via dynapi.

#include <cstdint>
#include <cstddef>
#include <vector>

namespace crypto {

// Decrypts src (ciphertext) with AES-256-GCM. Returns true on success.
// key must be 32 bytes. iv must be 12 bytes. tag must be 16 bytes.
// out is resized to ciphertext length on success, cleared on failure.
bool aes256_gcm_decrypt(
    const uint8_t* key,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* tag, size_t tag_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    std::vector<uint8_t>& out);

} // namespace crypto
