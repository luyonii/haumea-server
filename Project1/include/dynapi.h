#pragma once
// Runtime symbol resolver: enumerates loaded modules and walks PE export
// tables to bind Windows API addresses at runtime. Resolved symbols do not
// appear in the executable's import table (lazy-symbol-binder build policy).

#include <cstddef>
#include <cstdint>

namespace dynapi {

// FNV-1a hash for API names (case-sensitive, narrow strings)
constexpr uint32_t hash_api(const char* str) {
    uint32_t h = 2166136261u;
    while (*str) {
        h ^= static_cast<uint8_t>(*str++);
        h *= 16777619u;
    }
    return h;
}

// C++20 NTTP wrapper: carries a string literal as a template argument so the
// `api_hash_v<"Name">()` instantiation lives entirely at compile time. MSVC
// otherwise emits the literal to `.rdata` whenever API_HASH expands inside a
// non-constexpr context (argument to a runtime call), defeating the whole
// point of hashing the name.
template <std::size_t N>
struct api_name_lit {
    char data[N];
    constexpr api_name_lit(const char (&s)[N]) {
        for (std::size_t i = 0; i < N; ++i) data[i] = s[i];
    }
};

template <api_name_lit L>
consteval uint32_t api_hash_v() {
    return hash_api(L.data);
}

// FNV-1a hash for module names. Simulates case-insensitive wide-char hashing
// by lower-casing A-Z and injecting the high byte of wchar_t (0 for ASCII).
// Convergence: hash_module(compile-time) and hash_module_runtime(runtime)
// always hash the same byte sequence regardless of input case.
constexpr uint32_t hash_module(const char* str) {
    uint32_t h = 2166136261u;
    while (*str) {
        uint8_t c = static_cast<uint8_t>(*str++);
        if (c >= 'A' && c <= 'Z') c |= 0x20;  // force lowercase ASCII
        h ^= c;
        h *= 16777619u;
        h ^= 0u;               // high byte of wchar_t is 0 for ASCII
        h *= 16777619u;
    }
    return h;
}

#define API_HASH(name)  (::dynapi::api_hash_v<name>())
#define MOD_HASH(name)  (::dynapi::hash_module(name))

namespace modules {
    constexpr uint32_t KERNEL32   = hash_module("kernel32.dll");
    constexpr uint32_t NTDLL      = hash_module("ntdll.dll");
    constexpr uint32_t KERNELBASE = hash_module("kernelbase.dll");
    constexpr uint32_t USER32     = hash_module("user32.dll");
    constexpr uint32_t ADVAPI32   = hash_module("advapi32.dll");
    constexpr uint32_t BCRYPT     = hash_module("bcrypt.dll");
}

// Find an already-loaded module by hash (PEB InMemoryOrderModuleList walk).
void* get_module(uint32_t module_hash);

// Load a module by name via dynamically resolved LoadLibraryA.
// Pass the name through OBF() to avoid plaintext in the binary.
void* load_module(const char* name);

// FNV-1a module hash from an ASCII narrow string at runtime. Lower-cases
// A-Z and uses the same wide-char simulation as compile-time hash_module().
uint32_t hash_module_runtime(const char* str);

// Resolve an export from a module base address by function name hash.
void* resolve(void* module_base, uint32_t func_hash);

// Convenience: resolve by module hash + function hash (PEB-loaded modules only).
void* resolve(uint32_t module_hash, uint32_t func_hash);

} // namespace dynapi
