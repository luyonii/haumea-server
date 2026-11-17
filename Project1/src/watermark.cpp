#include "watermark.h"
#include "auth.h"
#include "dynapi.h"
#include "obfstr.h"

#include <Windows.h>
#include <cstring>

namespace watermark {

// ---- BCrypt plain-hash function types (bcrypt.dll) ----
using fn_BCOpen    = long(WINAPI*)(void**, const wchar_t*, const wchar_t*, ULONG);
using fn_BCCreate  = long(WINAPI*)(void*, void**, uint8_t*, ULONG, uint8_t*, ULONG, ULONG);
using fn_BCHash    = long(WINAPI*)(void*, uint8_t*, ULONG, ULONG);
using fn_BCFinish  = long(WINAPI*)(void*, uint8_t*, ULONG, ULONG);
using fn_BCDestroy = long(WINAPI*)(void*);
using fn_BCClose   = long(WINAPI*)(void*, ULONG);

static fn_BCOpen    s_pOpen    = nullptr;
static fn_BCCreate  s_pCreate  = nullptr;
static fn_BCHash    s_pHash    = nullptr;
static fn_BCFinish  s_pFinish  = nullptr;
static fn_BCDestroy s_pDestroy = nullptr;
static fn_BCClose   s_pClose   = nullptr;

static bool ensure_cng() {
    if (s_pOpen) return true;
    auto bcrypt = dynapi::load_module(OBF("bcrypt.dll"));
    if (!bcrypt) return false;
    s_pOpen    = reinterpret_cast<fn_BCOpen>   (dynapi::resolve(bcrypt, API_HASH("BCryptOpenAlgorithmProvider")));
    s_pCreate  = reinterpret_cast<fn_BCCreate> (dynapi::resolve(bcrypt, API_HASH("BCryptCreateHash")));
    s_pHash    = reinterpret_cast<fn_BCHash>   (dynapi::resolve(bcrypt, API_HASH("BCryptHashData")));
    s_pFinish  = reinterpret_cast<fn_BCFinish> (dynapi::resolve(bcrypt, API_HASH("BCryptFinishHash")));
    s_pDestroy = reinterpret_cast<fn_BCDestroy>(dynapi::resolve(bcrypt, API_HASH("BCryptDestroyHash")));
    s_pClose   = reinterpret_cast<fn_BCClose>  (dynapi::resolve(bcrypt, API_HASH("BCryptCloseAlgorithmProvider")));
    return s_pOpen && s_pCreate && s_pHash && s_pFinish && s_pDestroy && s_pClose;
}

bool sha256(const uint8_t* data, size_t data_len, uint8_t out[32]) {
    if (!ensure_cng()) return false;

    auto alg_n = OBF("SHA256");
    wchar_t alg_w[7]{};
    for (int i = 0; i < 7; ++i)
        alg_w[i] = static_cast<wchar_t>(static_cast<uint8_t>(alg_n.c_str()[i]));

    void* alg = nullptr;
    if (s_pOpen(&alg, alg_w, nullptr, 0) != 0) return false;

    void* hash = nullptr;
    if (s_pCreate(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
        s_pClose(alg, 0);
        return false;
    }

    long st = s_pHash(hash, const_cast<uint8_t*>(data), static_cast<ULONG>(data_len), 0);
    if (st == 0) st = s_pFinish(hash, out, 32, 0);
    s_pDestroy(hash);
    s_pClose(alg, 0);

    volatile wchar_t* wp = alg_w;
    for (int i = 0; i < 7; ++i) wp[i] = 0;

    return st == 0;
}

// Constant-time compare.
static bool ct_eq(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; ++i) acc |= static_cast<uint8_t>(a[i] ^ b[i]);
    return acc == 0;
}

// Parse 64-char lowercase hex -> 32 bytes. Rejects anything non-hex.
static bool hex_to_bytes_32(const char* hex, uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) {
        int hi = -1, lo = -1;
        char ch = hex[i * 2];
        char cl = hex[i * 2 + 1];
        if (ch >= '0' && ch <= '9') hi = ch - '0';
        else if (ch >= 'a' && ch <= 'f') hi = 10 + (ch - 'a');
        else if (ch >= 'A' && ch <= 'F') hi = 10 + (ch - 'A');
        if (cl >= '0' && cl <= '9') lo = cl - '0';
        else if (cl >= 'a' && cl <= 'f') lo = 10 + (cl - 'a');
        else if (cl >= 'A' && cl <= 'F') lo = 10 + (cl - 'A');
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

static uint64_t read_u64_le(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (i * 8);
    return v;
}

// Current unix seconds via kernel32!GetSystemTimeAsFileTime (dynapi).
static uint64_t now_unix() {
    using fn_GSTAFT = void(WINAPI*)(LPFILETIME);
    auto pGS = reinterpret_cast<fn_GSTAFT>(
        dynapi::resolve(dynapi::modules::KERNEL32, API_HASH("GetSystemTimeAsFileTime")));
    if (!pGS) return 0;
    FILETIME ft{};
    pGS(&ft);
    uint64_t ft100 = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    // FILETIME is 100-ns since 1601-01-01; unix epoch offset = 116444736000000000.
    if (ft100 < 116444736000000000ULL) return 0;
    return (ft100 - 116444736000000000ULL) / 10000000ULL;
}

result verify(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* session_key,
    const char*    local_hwid,
    const uint8_t* license_hash,
    const uint8_t** out_pe_ptr,
    size_t*        out_pe_size)
{
    if (!plaintext || plaintext_len < SIZE) return result::bad_size;
    if (!session_key || !local_hwid || !license_hash) return result::bad_size;

    // 1) HWID: hex -> 32 bytes, constant-time compare with wm[0..32].
    uint8_t local_hwid_bytes[32]{};
    auto scrub_hwid = [&]() {
        volatile uint8_t* p = local_hwid_bytes;
        for (size_t i = 0; i < 32; ++i) p[i] = 0;
    };
    if (!hex_to_bytes_32(local_hwid, local_hwid_bytes)) {
        scrub_hwid();
        return result::hwid_mismatch;
    }
    if (!ct_eq(local_hwid_bytes, plaintext + 0, 32)) {
        scrub_hwid();
        return result::hwid_mismatch;
    }

    // 2) License hash: constant-time compare with wm[32..64].
    if (!ct_eq(license_hash, plaintext + 32, 32)) {
        scrub_hwid();
        return result::license_mismatch;
    }

    // 3) Expiry: now > issued_at + ttl? (ttl==0 expires immediately; overflow treated as expired)
    uint64_t issued_at = read_u64_le(plaintext + 64);
    uint64_t ttl       = read_u64_le(plaintext + 72);
    uint64_t now       = now_unix();
    if (now == 0) { scrub_hwid(); return result::expired; }
    uint64_t deadline = issued_at + ttl;
    if (deadline < issued_at) { scrub_hwid(); return result::expired; } // u64 overflow
    if (now > deadline)       { scrub_hwid(); return result::expired; }

    // 4) Signature: HMAC-SHA256(session_key, wm[0..96]) == wm[96..128].
    uint8_t sig[32]{};
    if (!auth::hmac_sha256(session_key, 32, plaintext, 96, sig)) {
        scrub_hwid();
        return result::bad_signature;
    }
    bool sig_ok = ct_eq(sig, plaintext + 96, 32);
    volatile uint8_t* sp = sig;
    for (int i = 0; i < 32; ++i) sp[i] = 0;
    if (!sig_ok) { scrub_hwid(); return result::bad_signature; }

    if (out_pe_ptr)  *out_pe_ptr  = plaintext + SIZE;
    if (out_pe_size) *out_pe_size = plaintext_len - SIZE;
    scrub_hwid();
    return result::ok;
}

} // namespace watermark
