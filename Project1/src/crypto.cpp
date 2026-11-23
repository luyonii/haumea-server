#include "crypto.h"
#include "auth.h"

#include <cstring>

namespace crypto {

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
