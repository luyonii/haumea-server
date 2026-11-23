#include "watermark.h"
#include "dynapi.h"
#include "obfstr.h"

#include <Windows.h>

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
    auto bcrypt = dynapi::load_module(OBF("bcrypt.dll").c_str());
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

} // namespace watermark
