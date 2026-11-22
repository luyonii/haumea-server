#include "payload.h"
#include "net.h"
#include "crypto.h"
#include "watermark.h"
#include "obfstr.h"
#include "base64.h"
#include "json_lite.h"
#include "game_launcher.h"
#include "injector.h"
#include "dynapi.h"

#include <Windows.h>
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

using fn_TerminateProcess = BOOL(WINAPI*)(HANDLE, UINT);
using fn_CloseHandle      = BOOL(WINAPI*)(HANDLE);
using fn_ResumeThread     = DWORD(WINAPI*)(HANDLE);

static void close_handles(const game_launcher::process& p) {
    auto k32 = dynapi::get_module(dynapi::modules::KERNEL32);
    auto pCH = reinterpret_cast<fn_CloseHandle>(dynapi::resolve(k32, API_HASH("CloseHandle")));
    if (!pCH) return;
    if (p.hThread)  pCH(p.hThread);
    if (p.hProcess) pCH(p.hProcess);
}

static void kill_target(const game_launcher::process& p) {
    auto k32 = dynapi::get_module(dynapi::modules::KERNEL32);
    auto pTP = reinterpret_cast<fn_TerminateProcess>(dynapi::resolve(k32, API_HASH("TerminateProcess")));
    if (pTP && p.hProcess) pTP(p.hProcess, 1);
    close_handles(p);
}

result load_and_execute(const char* session_token,
                        const uint8_t* k_payload_aes,
                        const uint8_t* k_watermark,
                        const char*    local_hwid,
                        const uint8_t* license_hash,
                        const wchar_t* target_exe_fallback)
{
    if (!session_token || !k_payload_aes || !k_watermark || !local_hwid ||
        !license_hash)
        return result::fetch_failed;
    // target_exe_fallback may be null; the launch path checks again once the
    // server response has been inspected.

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

    auto iv_b64      = json::get_string(resp.body, OBF("iv").c_str());
    auto tag_b64     = json::get_string(resp.body, OBF("tag").c_str());
    auto ct_b64      = json::get_string(resp.body, OBF("ciphertext").c_str());
    // Server-sent host path for the target process. Empty when the server
    // has no per-license override; the caller's fallback is then consulted.
    auto target_utf8 = json::get_string(resp.body, OBF("target_exe_path").c_str());
    if (iv_b64.empty() || tag_b64.empty() || ct_b64.empty()) {
        if (!resp.body.empty()) {
            volatile char* rb0 = &resp.body[0];
            for (size_t i = 0; i < resp.body.size(); ++i) rb0[i] = 0;
        }
        resp.body.clear();
        if (!target_utf8.empty()) {
            volatile char* tp = &target_utf8[0];
            for (size_t i = 0; i < target_utf8.size(); ++i) tp[i] = 0;
        }
        target_utf8.clear();
        return result::envelope_invalid;
    }

    auto iv  = base64::decode(iv_b64);
    auto tag = base64::decode(tag_b64);
    auto ct  = base64::decode(ct_b64);

    // Scrub the response body as soon as we've extracted the ciphertext.
    volatile char* rb = resp.body.empty() ? nullptr : &resp.body[0];
    if (rb) for (size_t i = 0; i < resp.body.size(); ++i) rb[i] = 0;
    resp.body.clear();

    // Promote the (ASCII-only) server path into a wide string before the
    // UTF-8 buffer is scrubbed. Non-ASCII bytes get widened byte-for-byte,
    // which is fine for the Latin-1 subset the vendor ships paths in; the
    // path is validated again by CreateProcessW at launch.
    std::wstring effective_target;
    if (!target_utf8.empty()) {
        effective_target.reserve(target_utf8.size());
        for (char c : target_utf8)
            effective_target.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    } else if (target_exe_fallback && target_exe_fallback[0]) {
        effective_target = target_exe_fallback;
    }
    if (!target_utf8.empty()) {
        volatile char* tp = &target_utf8[0];
        for (size_t i = 0; i < target_utf8.size(); ++i) tp[i] = 0;
    }
    target_utf8.clear();

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

    // Watermark verification binds the plaintext to this HWID + license.
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

    // No target path at all — server shipped none and no fallback was given.
    if (effective_target.empty()) {
        scrub(pe_bytes);
        return result::launch_failed;
    }

    // Derive the basename for the kill step. The loader no longer hardcodes
    // the host executable's name; we kill whatever matches whatever path we
    // were told to launch.
    const wchar_t* path     = effective_target.c_str();
    const size_t   path_len = effective_target.size();
    size_t last_sep = 0;
    bool   has_sep  = false;
    for (size_t j = 0; j < path_len; ++j) {
        if (path[j] == L'\\' || path[j] == L'/') { last_sep = j + 1; has_sep = true; }
    }
    const wchar_t* basename = has_sep ? path + last_sep : path;

    game_launcher::stop_by_name(basename);

    game_launcher::process proc{};
#if defined(SB_SKIP_INJECT)
    // Dev mode: just launch, no inject.
    (void)body_ptr; (void)body_size;
    auto sr = game_launcher::start(effective_target.c_str(), /*suspended=*/false, &proc);
    scrub(pe_bytes);
    if (sr != game_launcher::start_result::ok) return result::launch_failed;
    close_handles(proc);
    return result::ok;
#else
    // Launch non-suspended; game finishes init (vtables, Data folder, D3D)
    // before we inject so map.dll's hooks have real targets.
    auto sr = game_launcher::start(effective_target.c_str(), /*suspended=*/false, &proc);
    if (sr != game_launcher::start_result::ok) {
        scrub(pe_bytes);
        return result::launch_failed;
    }

    // Wait for the renderer DLL to show up in the target — proxy for "menu
    // loaded, hooks have real targets". 60 s is enough for a cold start on
    // typical hardware; a target that never loads d3d9.dll is the wrong host
    // executable and is surfaced as inject_failed.
    if (!game_launcher::wait_for_module(proc.hProcess, OBF_W(L"d3d9.dll"), 60000)) {
        scrub(pe_bytes);
        close_handles(proc);
        return result::inject_failed;
    }

    auto ir = injector::inject(proc.hProcess, body_ptr, body_size);
    scrub(pe_bytes);
    if (ir != injector::result::ok) {
        // Game already running — do not terminate it; user can retry.
        close_handles(proc);
        return result::inject_failed;
    }
    close_handles(proc);
    return result::ok;
#endif
}

} // namespace payload
