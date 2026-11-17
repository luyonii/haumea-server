#include "auth.h"
#include "net.h"
#include "dynapi.h"
#include "obfstr.h"
#include "base64.h"
#include "json_lite.h"

#include <Windows.h>
#include <cstring>
#include <string>

namespace auth {

// ---- CNG function types (bcrypt.dll, resolved once) ----

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

// ---- Crypto helpers ----

bool hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t out[32])
{
    if (!ensure_cng()) return false;

    auto alg_n = OBF("SHA256");
    wchar_t alg_w[7]{};
    for (int i = 0; i < 7; ++i)
        alg_w[i] = static_cast<wchar_t>(static_cast<uint8_t>(alg_n.c_str()[i]));

    void* alg = nullptr;
    constexpr ULONG HMAC_FLAG = 0x00000008; // BCRYPT_ALG_HANDLE_HMAC_FLAG
    if (s_pOpen(&alg, alg_w, nullptr, HMAC_FLAG) != 0) return false;

    void* hash = nullptr;
    if (s_pCreate(alg, &hash, nullptr, 0,
                  const_cast<uint8_t*>(key), static_cast<ULONG>(key_len), 0) != 0) {
        s_pClose(alg, 0);
        return false;
    }

    s_pHash(hash, const_cast<uint8_t*>(data), static_cast<ULONG>(data_len), 0);
    long st = s_pFinish(hash, out, 32, 0);
    s_pDestroy(hash);
    s_pClose(alg, 0);

    volatile wchar_t* wp = alg_w;
    for (int i = 0; i < 7; ++i) wp[i] = 0;

    return st == 0;
}

// HKDF-SHA256 (RFC 5869). Output is always 32 bytes (one HMAC block).
static bool hkdf_sha256(const uint8_t* ikm,  size_t ikm_len,
                        const uint8_t* salt, size_t salt_len,
                        const uint8_t* info, size_t info_len,
                        uint8_t out[32])
{
    // Extract: PRK = HMAC-SHA256(salt, IKM)
    uint8_t prk[32]{};
    if (!hmac_sha256(salt, salt_len, ikm, ikm_len, prk))
        return false;

    // Expand: T(1) = HMAC-SHA256(PRK, info || 0x01)
    uint8_t expand[256]{};
    if (info_len > 254) return false;
    if (info && info_len > 0)
        memcpy(expand, info, info_len);
    expand[info_len] = 0x01;

    bool ok = hmac_sha256(prk, 32, expand, info_len + 1, out);

    volatile uint8_t* p = prk;
    for (int i = 0; i < 32; ++i) p[i] = 0;
    volatile uint8_t* ep = expand;
    for (size_t i = 0; i < info_len + 1; ++i) ep[i] = 0;

    return ok;
}

// ---- Public API ----

auth_result authenticate(const std::string& license_key, const std::string& hwid) {
    auth_result result{};

    // --- Step 1: request challenge ---
    auto challenge_body = json::object({{"hwid", hwid}});
    auto resp = net::post(OBF("/api/v1/auth/challenge"), challenge_body);

    if (resp.status_code == 0) {
        result.error_message = "Connection failed (network or certificate pin mismatch)";
        return result;
    }
    if (resp.status_code == 429) {
        result.error_message = "Rate limited. Try again later.";
        return result;
    }
    if (resp.status_code != 200) {
        result.error_message = "Challenge request failed (HTTP "
            + std::to_string(resp.status_code) + ")";
        return result;
    }

    auto challenge_b64 = json::get_string(resp.body, "challenge");
    if (challenge_b64.empty()) {
        result.error_message = "Invalid challenge response from server";
        return result;
    }

    // --- Step 2: derive key + compute challenge response ---
    auto nonce = base64::decode(challenge_b64);

    // salt = hwid_bytes || fixed session salt
    auto salt_fixed = OBF("SecBlind_HKDF_v1");
    std::vector<uint8_t> salt;
    salt.insert(salt.end(), hwid.begin(), hwid.end());
    salt.insert(salt.end(), salt_fixed.c_str(),
                salt_fixed.c_str() + salt_fixed.size());

    // derived_key = HKDF-SHA256(IKM=license_key, salt=hwid||fixed_salt)
    uint8_t derived_key[32]{};
    if (!hkdf_sha256(
            reinterpret_cast<const uint8_t*>(license_key.data()), license_key.size(),
            salt.data(), salt.size(),
            nullptr, 0,
            derived_key))
    {
        result.error_message = "Key derivation failed";
        return result;
    }

    // Scrub salt vector
    volatile uint8_t* sp = salt.data();
    for (size_t i = 0; i < salt.size(); ++i) sp[i] = 0;

    // challenge_response = HMAC-SHA256(key=derived_key, data=nonce)
    uint8_t hmac_out[32]{};
    bool hmac_ok = hmac_sha256(derived_key, 32, nonce.data(),
                               static_cast<size_t>(nonce.size()), hmac_out);

    // Scrub derived key immediately
    volatile uint8_t* dk = derived_key;
    for (int i = 0; i < 32; ++i) dk[i] = 0;

    if (!hmac_ok) {
        result.error_message = "HMAC computation failed";
        return result;
    }

    auto response_b64 = base64::encode(hmac_out, 32);

    volatile uint8_t* hp = hmac_out;
    for (int i = 0; i < 32; ++i) hp[i] = 0;

    // --- Step 3: login ---
    auto login_body = json::object({
        {"license_key",       license_key},
        {"hwid",              hwid},
        {"challenge",         challenge_b64},
        {"challenge_response", response_b64}
    });

    resp = net::post(OBF("/api/v1/auth/login"), login_body);

    if (resp.status_code == 0) {
        result.error_message = "Connection failed (network or certificate pin mismatch)";
        return result;
    }
    if (resp.status_code == 401) {
        auto err = json::get_string(resp.body, "error");
        auto msg = json::get_string(resp.body, "message");
        result.error_message = msg.empty() ? ("Auth failed: " + err) : msg;
        return result;
    }
    if (resp.status_code == 429) {
        result.error_message = "Rate limited. Try again later.";
        return result;
    }
    if (resp.status_code != 200) {
        result.error_message = "Login failed (HTTP "
            + std::to_string(resp.status_code) + ")";
        return result;
    }

    // --- Parse session info ---
    result.session.session_token = json::get_string(resp.body, "session_token");
    auto sk_b64 = json::get_string(resp.body, "session_key");
    result.session.session_key   = base64::decode(sk_b64);
    result.session.ttl           = static_cast<int>(json::get_int(resp.body, "ttl", 900));
    result.session.heartbeat_interval =
        static_cast<int>(json::get_int(resp.body, "heartbeat_interval", 60));
    result.session.next_nonce    = json::get_string(resp.body, "next_nonce");

    if (result.session.session_token.empty() ||
        result.session.session_key.size() != 32)
    {
        result.error_message = "Invalid session data from server";
        return result;
    }

    result.success = true;
    return result;
}

void clear_session(session_info& info) {
    if (!info.session_key.empty()) {
        volatile uint8_t* p = info.session_key.data();
        for (size_t i = 0; i < info.session_key.size(); ++i) p[i] = 0;
        info.session_key.clear();
    }
    info.session_token.clear();
    info.next_nonce.clear();
    info.ttl = 0;
    info.heartbeat_interval = 0;
}

} // namespace auth
