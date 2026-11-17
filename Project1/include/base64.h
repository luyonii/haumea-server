#pragma once
// Minimal base64 encode/decode. Header-only.

#include <cstdint>
#include <string>
#include <vector>

namespace base64 {

inline std::string encode(const uint8_t* data, size_t len) {
    static constexpr char t[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string r;
    r.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
        r += t[(n >> 18) & 63];
        r += t[(n >> 12) & 63];
        r += (i + 1 < len) ? t[(n >> 6) & 63] : '=';
        r += (i + 2 < len) ? t[n & 63] : '=';
    }
    return r;
}

inline std::vector<uint8_t> decode(const char* s, size_t len) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::vector<uint8_t> r;
    r.reserve(len * 3 / 4);
    uint32_t buf = 0;
    int bits = 0;
    for (size_t i = 0; i < len; ++i) {
        int v = val(s[i]);
        if (v < 0) continue;
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            r.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
        }
    }
    return r;
}

inline std::vector<uint8_t> decode(const std::string& s) {
    return decode(s.data(), s.size());
}

} // namespace base64
