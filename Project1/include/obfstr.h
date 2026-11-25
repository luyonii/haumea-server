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
        // Read the ciphertext through a volatile pointer: with /O2 + LTCG the
        // optimizer would otherwise constant-fold this constexpr decrypt() and
        // re-materialize the PLAINTEXT in .rdata, eliding the XOR entirely
        // (defeating the obfuscation — the root cause behind audit #4). A
        // volatile load is an observable access the compiler must emit at
        // runtime, so only the encrypted bytes live in the image.
        const volatile char* src = data;
        for (size_t i = 0; i < N; ++i) {
            auto key = static_cast<uint8_t>(Seed ^ (i * 0xAD + 0x37));
            out.buf[i] = static_cast<char>(static_cast<uint8_t>(src[i]) ^ key);
        }
        return out;
    }
};

// Wide-char analogue. Keys are 16-bit so they cover the full wchar_t (UTF-16 LE)
// width; for ASCII-only literals the obfuscated bytes still differ from the
// originals once the high byte (nonzero after XOR) stops being 0x00.
template<size_t N>
struct decrypted_wstring {
    wchar_t buf[N]{};

    ~decrypted_wstring() {
        volatile wchar_t* p = buf;
        for (size_t i = 0; i < N; ++i) p[i] = 0;
    }

    operator const wchar_t*() const { return buf; }
    const wchar_t* c_str() const { return buf; }
    constexpr size_t size() const { return N - 1; }
};

template<size_t N, uint16_t Seed>
struct encrypted_wstring {
    wchar_t data[N]{};

    constexpr encrypted_wstring(const wchar_t (&str)[N]) : data{} {
        for (size_t i = 0; i < N; ++i) {
            auto key = static_cast<uint16_t>(Seed ^ (i * 0xAD37u + 0x3719u));
            data[i] = static_cast<wchar_t>(static_cast<uint16_t>(str[i]) ^ key);
        }
    }

    decrypted_wstring<N> decrypt() const {
        decrypted_wstring<N> out;
        // volatile load: keep the optimizer from folding decrypt() to plaintext
        // in .rdata (see the narrow decrypt() above; audit #4).
        const volatile wchar_t* src = data;
        for (size_t i = 0; i < N; ++i) {
            auto key = static_cast<uint16_t>(Seed ^ (i * 0xAD37u + 0x3719u));
            out.buf[i] = static_cast<wchar_t>(static_cast<uint16_t>(src[i]) ^ key);
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

// Wide-string variant. `str` must be a wide literal (L"..."). The size in
// chars is sizeof(str)/sizeof(wchar_t); on MSVC wchar_t is 16-bit.
#define OBF_W(str) \
    ([]() -> ::obf::decrypted_wstring<sizeof(str)/sizeof(wchar_t)> { \
        constexpr static auto _e = ::obf::encrypted_wstring<sizeof(str)/sizeof(wchar_t), \
            static_cast<uint16_t>((__COUNTER__ * 131 + 97) & 0xFFFF)>(str); \
        return _e.decrypt(); \
    }())
