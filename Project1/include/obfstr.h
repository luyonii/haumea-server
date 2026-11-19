#pragma once
// Compile-time string protection. XOR per-byte key derived from a per-string seed.
// Decrypts on stack, zeros on destruction.

#include <cstddef>
#include <cstdint>

namespace obf {

template<size_t N>
struct decrypted_string {
    char buf[N]{};

    ~decrypted_string() {
        volatile char* p = buf;
        for (size_t i = 0; i < N; ++i) p[i] = 0;
    }

    operator const char*() const { return buf; }
    const char* c_str() const { return buf; }
    constexpr size_t size() const { return N - 1; }
};

template<size_t N, uint8_t Seed>
struct encrypted_string {
    char data[N]{};

    constexpr encrypted_string(const char (&str)[N]) : data{} {
        for (size_t i = 0; i < N; ++i) {
            auto key = static_cast<uint8_t>(Seed ^ (i * 0xAD + 0x37));
            data[i] = static_cast<char>(static_cast<uint8_t>(str[i]) ^ key);
        }
    }

    decrypted_string<N> decrypt() const {
        decrypted_string<N> out;
        for (size_t i = 0; i < N; ++i) {
            auto key = static_cast<uint8_t>(Seed ^ (i * 0xAD + 0x37));
            out.buf[i] = static_cast<char>(static_cast<uint8_t>(data[i]) ^ key);
        }
        return out;
    }
};

} // namespace obf

// Each invocation gets a unique seed via __COUNTER__.
// The encrypted payload lives in .rdata; decryption happens at the call site.
#define OBF(str) \
    ([]() -> ::obf::decrypted_string<sizeof(str)> { \
        constexpr static auto _e = ::obf::encrypted_string<sizeof(str), \
            static_cast<uint8_t>((__COUNTER__ * 131 + 97) & 0xFF)>(str); \
        return _e.decrypt(); \
    }())
