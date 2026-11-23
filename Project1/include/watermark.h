#pragma once
// SHA-256 wrapper kept after Phase B.4 for the license-id hash that
// payload_worker forwards into the target process. Watermark VERIFICATION
// lived here until the target-side stub_worker took that step over.

#include <cstddef>
#include <cstdint>

namespace watermark {

// SHA-256 via BCrypt. Caller provides a 32-byte output buffer.
bool sha256(const uint8_t* data, size_t data_len, uint8_t out[32]);

} // namespace watermark
