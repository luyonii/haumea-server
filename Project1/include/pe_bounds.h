// pe_bounds.h - shared bounded helpers for PE parsing paths.
// Header-only: pe_loader (and later dynapi) include this to avoid duplicating
// bound-checked string walks over attacker-controlled PE data.
#pragma once

#include <cstddef>
#include <cstdint>

namespace pe_bounds {

// Walk `p` as a NUL-terminated string, refusing to read past the mapped image
// [image_base, image_base + image_size) or past `max_len` bytes.
// Returns the string length (not counting NUL) on success, SIZE_MAX if `p`
// lies outside the image or no NUL is found within the allowed window.
inline size_t safe_strnlen(const char* p,
                           const uint8_t* image_base,
                           size_t image_size,
                           size_t max_len) {
    if (!p || !image_base) return SIZE_MAX;
    auto up = reinterpret_cast<const uint8_t*>(p);
    if (up < image_base) return SIZE_MAX;
    size_t offset = static_cast<size_t>(up - image_base);
    if (offset >= image_size) return SIZE_MAX;
    size_t avail = image_size - offset;
    size_t limit = avail < max_len ? avail : max_len;
    for (size_t i = 0; i < limit; ++i) {
        if (p[i] == '\0') return i;
    }
    return SIZE_MAX;
}

} // namespace pe_bounds
