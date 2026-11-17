#include "payload.h"
#include "net.h"
#include "crypto.h"
#include "pe_loader.h"
#include "watermark.h"
#include "obfstr.h"
#include "base64.h"
#include "json_lite.h"

#include <string>
#include <vector>
#include <cstdint>

namespace payload {

static void scrub(std::vector<uint8_t>& v) {
    if (v.empty()) return;
    volatile uint8_t* p = v.data();
    for (size_t i = 0; i < v.size(); ++i) p[i] = 0;
    v.clear();
}

result load_and_execute(const char* session_token,
                        const uint8_t* k_payload_aes,
                        const uint8_t* k_watermark,
                        const char*    local_hwid,
                        const uint8_t* license_hash,
                        bool is_dll)
{
    if (!session_token || !k_payload_aes || !k_watermark || !local_hwid || !license_hash)
        return result::fetch_failed;

    auto body = json::object({{OBF("session_token").c_str(), session_token}});
    auto resp = net::post(OBF("/api/v1/payload/fetch"), body);

    // Scrub the serialized request body — holds the session_token.
    if (!body.empty()) {
        volatile char* bp = &body[0];
        for (size_t i = 0; i < body.size(); ++i) bp[i] = 0;
    }
    body.clear();

    if (resp.status_code != 200) {
        if (!resp.body.empty()) {
            volatile char* rb0 = &resp.body[0];
            for (size_t i = 0; i < resp.body.size(); ++i) rb0[i] = 0;
        }
        resp.body.clear();
        return result::fetch_failed;
    }

    auto iv_b64  = json::get_string(resp.body, OBF("iv").c_str());
    auto tag_b64 = json::get_string(resp.body, OBF("tag").c_str());
    auto ct_b64  = json::get_string(resp.body, OBF("ciphertext").c_str());
    if (iv_b64.empty() || tag_b64.empty() || ct_b64.empty()) {
        if (!resp.body.empty()) {
            volatile char* rb0 = &resp.body[0];
            for (size_t i = 0; i < resp.body.size(); ++i) rb0[i] = 0;
        }
        resp.body.clear();
        return result::envelope_invalid;
    }

    auto iv  = base64::decode(iv_b64);
    auto tag = base64::decode(tag_b64);
    auto ct  = base64::decode(ct_b64);

    // Scrub the response body as soon as we've extracted the ciphertext.
    volatile char* rb = resp.body.empty() ? nullptr : &resp.body[0];
    if (rb) for (size_t i = 0; i < resp.body.size(); ++i) rb[i] = 0;
    resp.body.clear();

    if (iv.size() != 12 || tag.size() != 16 || ct.empty()) {
        scrub(iv); scrub(tag); scrub(ct);
        return result::envelope_invalid;
    }

    std::vector<uint8_t> pe_bytes;
    bool dec_ok = crypto::aes256_gcm_decrypt(
        k_payload_aes,
        iv.data(),  iv.size(),
        tag.data(), tag.size(),
        ct.data(),  ct.size(),
        pe_bytes);

    scrub(iv); scrub(tag); scrub(ct);

    if (!dec_ok) {
        scrub(pe_bytes);
        return result::decrypt_failed;
    }

    // --- Watermark verification (binds plaintext to this HWID + license) ---
    const uint8_t* body_ptr = nullptr;
    size_t body_size = 0;
    auto wm = watermark::verify(pe_bytes.data(), pe_bytes.size(),
                                k_watermark, local_hwid, license_hash,
                                &body_ptr, &body_size);
    if (wm != watermark::result::ok) {
        scrub(pe_bytes);
        switch (wm) {
        case watermark::result::bad_size:         return result::envelope_invalid;
        case watermark::result::hwid_mismatch:    return result::watermark_hwid;
        case watermark::result::license_mismatch: return result::watermark_license;
        case watermark::result::expired:          return result::watermark_expired;
        case watermark::result::bad_signature:    return result::watermark_signature;
        default:                                  return result::envelope_invalid;
        }
    }

    pe_loader::mapped_image img{};
    auto map_err = pe_loader::map(body_ptr, body_size, img);

    // Plaintext PE no longer needed after mapping — scrub either way.
    scrub(pe_bytes);

    if (map_err != pe_loader::map_error::ok)
        return result::map_failed;

    if (!pe_loader::execute(img, is_dll)) {
        pe_loader::unmap(img);
        return result::exec_failed;
    }

    // Intentional leak: the mapped image owns the process from here on.
    return result::ok;
}

} // namespace payload
