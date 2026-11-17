#include "crypto.h"
#include "auth.h"
#include "dynapi.h"
#include "obfstr.h"

#include <Windows.h>
#include <cstring>

namespace crypto {

// ---- BCrypt structures (defined manually to avoid linking bcrypt.lib) ----

typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    ULONG     cbSize;
    ULONG     dwInfoVersion;
    PUCHAR    pbNonce;
    ULONG     cbNonce;
    PUCHAR    pbAuthData;
    ULONG     cbAuthData;
    PUCHAR    pbTag;
    ULONG     cbTag;
    PUCHAR    pbMacContext;
    ULONG     cbMacContext;
    ULONG     cbAAD;
    ULONGLONG cbData;
    ULONG     dwFlags;
} BCRYPT_AUTH_INFO;

// ---- BCrypt function types ----

using fn_BCOpen      = long(WINAPI*)(void**, const wchar_t*, const wchar_t*, ULONG);
using fn_BCSetProp   = long(WINAPI*)(void*, const wchar_t*, uint8_t*, ULONG, ULONG);
using fn_BCGenKey    = long(WINAPI*)(void*, void**, uint8_t*, ULONG, uint8_t*, ULONG, ULONG);
using fn_BCDecrypt   = long(WINAPI*)(void*, uint8_t*, ULONG, void*, uint8_t*, ULONG, uint8_t*, ULONG, ULONG*, ULONG);
using fn_BCDestKey   = long(WINAPI*)(void*);
using fn_BCClose     = long(WINAPI*)(void*, ULONG);

static fn_BCOpen    s_pOpen    = nullptr;
static fn_BCSetProp s_pSetProp = nullptr;
static fn_BCGenKey  s_pGenKey  = nullptr;
static fn_BCDecrypt s_pDecrypt = nullptr;
static fn_BCDestKey s_pDestKey = nullptr;
static fn_BCClose   s_pClose   = nullptr;

static bool ensure_cng() {
    if (s_pOpen) return true;
    auto bcrypt = dynapi::load_module(OBF("bcrypt.dll"));
    if (!bcrypt) return false;

    s_pOpen    = reinterpret_cast<fn_BCOpen>   (dynapi::resolve(bcrypt, API_HASH("BCryptOpenAlgorithmProvider")));
    s_pSetProp = reinterpret_cast<fn_BCSetProp>(dynapi::resolve(bcrypt, API_HASH("BCryptSetProperty")));
    s_pGenKey  = reinterpret_cast<fn_BCGenKey> (dynapi::resolve(bcrypt, API_HASH("BCryptGenerateSymmetricKey")));
    s_pDecrypt = reinterpret_cast<fn_BCDecrypt>(dynapi::resolve(bcrypt, API_HASH("BCryptDecrypt")));
    s_pDestKey = reinterpret_cast<fn_BCDestKey>(dynapi::resolve(bcrypt, API_HASH("BCryptDestroyKey")));
    s_pClose   = reinterpret_cast<fn_BCClose>  (dynapi::resolve(bcrypt, API_HASH("BCryptCloseAlgorithmProvider")));

    return s_pOpen && s_pSetProp && s_pGenKey && s_pDecrypt && s_pDestKey && s_pClose;
}

// Promotes an OBF narrow string to a stack-local wide buffer (null-terminated).
// Same trick auth.cpp uses for "SHA256"; keeps the plaintext constant off .rdata.
template<size_t N>
static void narrow_to_wide(const char* src, wchar_t (&dst)[N]) {
    for (size_t i = 0; i < N; ++i)
        dst[i] = static_cast<wchar_t>(static_cast<uint8_t>(src[i]));
}

bool aes256_gcm_decrypt(
    const uint8_t* key,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* tag, size_t tag_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    std::vector<uint8_t>& out)
{
    out.clear();

    if (!key || !iv || !tag || !ciphertext) return false;
    if (iv_len != 12 || tag_len != 16) return false;
    if (!ensure_cng()) return false;

    // Wide algorithm names decoded from OBF into stack buffers.
    auto alg_n  = OBF("AES");              // 4 bytes w/ null
    auto mode_n = OBF("ChainingMode");     // 13 bytes w/ null
    auto gcm_n  = OBF("ChainingModeGCM");  // 16 bytes w/ null

    wchar_t alg_w[4]{};
    wchar_t mode_w[13]{};
    wchar_t gcm_w[16]{};
    narrow_to_wide(alg_n.c_str(),  alg_w);
    narrow_to_wide(mode_n.c_str(), mode_w);
    narrow_to_wide(gcm_n.c_str(),  gcm_w);

    void* alg = nullptr;
    if (s_pOpen(&alg, alg_w, nullptr, 0) != 0) return false;

    // Set GCM chaining mode. Length must include the trailing null (bytes).
    if (s_pSetProp(alg, mode_w,
                   reinterpret_cast<uint8_t*>(gcm_w),
                   static_cast<ULONG>(sizeof(gcm_w)), 0) != 0)
    {
        s_pClose(alg, 0);
        return false;
    }

    void* key_handle = nullptr;
    if (s_pGenKey(alg, &key_handle, nullptr, 0,
                  const_cast<uint8_t*>(key), 32, 0) != 0)
    {
        s_pClose(alg, 0);
        return false;
    }

    BCRYPT_AUTH_INFO info{};
    info.cbSize        = sizeof(info);
    info.dwInfoVersion = 1;
    info.pbNonce       = const_cast<uint8_t*>(iv);
    info.cbNonce       = static_cast<ULONG>(iv_len);
    info.pbTag         = const_cast<uint8_t*>(tag);
    info.cbTag         = static_cast<ULONG>(tag_len);

    out.resize(ciphertext_len);
    ULONG produced = 0;
    long st = s_pDecrypt(
        key_handle,
        const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertext_len),
        &info,
        nullptr, 0,
        out.data(), static_cast<ULONG>(out.size()),
        &produced, 0);

    bool ok = (st == 0);

    s_pDestKey(key_handle);
    s_pClose(alg, 0);

    // Scrub wide-char algorithm names.
    volatile wchar_t* p1 = alg_w;  for (size_t i = 0; i < sizeof(alg_w)/sizeof(wchar_t);  ++i) p1[i] = 0;
    volatile wchar_t* p2 = mode_w; for (size_t i = 0; i < sizeof(mode_w)/sizeof(wchar_t); ++i) p2[i] = 0;
    volatile wchar_t* p3 = gcm_w;  for (size_t i = 0; i < sizeof(gcm_w)/sizeof(wchar_t);  ++i) p3[i] = 0;

    if (!ok) {
        // Scrub partial plaintext on auth failure.
        volatile uint8_t* op = out.data();
        for (size_t i = 0; i < out.size(); ++i) op[i] = 0;
        out.clear();
        return false;
    }

    if (produced < ciphertext_len) {
        // Scrub any untouched tail bytes from the pre-sized buffer.
        volatile uint8_t* vp = out.data();
        for (size_t i = produced; i < ciphertext_len; ++i) vp[i] = 0;
    }

    out.resize(produced);
    return true;
}

// HKDF-Expand, single block. Reuses auth::hmac_sha256 (BCryptCreateHash +
// BCRYPT_ALG_HANDLE_HMAC_FLAG) so both sides share one HMAC path.
// shortcut: out_len <= 32 (one HMAC block); upgrade with a T(n) loop if a
// future sub-key needs > 32 bytes.
bool hkdf_expand(const uint8_t* prk, size_t prk_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* out, size_t out_len)
{
    if (!prk || !out) return false;
    if (out_len == 0 || out_len > 32) return false;
    if (info_len > 254) return false;

    // T(1) = HMAC-SHA256(prk, info || 0x01)
    uint8_t t[256]{};
    if (info && info_len) memcpy(t, info, info_len);
    t[info_len] = 0x01;

    uint8_t block[32]{};
    bool ok = auth::hmac_sha256(prk, prk_len, t, info_len + 1, block);
    if (ok) memcpy(out, block, out_len);

    volatile uint8_t* bp = block;
    for (int i = 0; i < 32; ++i) bp[i] = 0;
    volatile uint8_t* tp = t;
    for (size_t i = 0; i < info_len + 1; ++i) tp[i] = 0;
    return ok;
}

} // namespace crypto
