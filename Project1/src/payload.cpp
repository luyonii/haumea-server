#include "payload.h"
#include "net.h"
#include "obfstr.h"
#include "base64.h"
#include "json_lite.h"
#include "game_launcher.h"
#include "payload_worker.h"
#include "stub_worker.h"
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

static void close_handles(const game_launcher::process& p) {
    auto k32 = dynapi::get_module(dynapi::modules::KERNEL32);
    auto pCH = reinterpret_cast<fn_CloseHandle>(dynapi::resolve(k32, API_HASH("CloseHandle")));
    if (!pCH) return;
    if (p.hThread)  pCH(p.hThread);
    if (p.hProcess) pCH(p.hProcess);
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

    auto body = json::object({{OBF("session_token").c_str(), session_token}});
    auto resp = net::post(OBF("/api/v1/payload/fetch"), body);

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

    volatile char* rb = resp.body.empty() ? nullptr : &resp.body[0];
    if (rb) for (size_t i = 0; i < resp.body.size(); ++i) rb[i] = 0;
    resp.body.clear();

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

    if (effective_target.empty()) {
        scrub(iv); scrub(tag); scrub(ct);
        return result::launch_failed;
    }

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
    auto sr = game_launcher::start(effective_target.c_str(), /*suspended=*/false, &proc);
    scrub(iv); scrub(tag); scrub(ct);
    if (sr != game_launcher::start_result::ok) return result::launch_failed;
    close_handles(proc);
    return result::ok;
#else
    auto sr = game_launcher::start(effective_target.c_str(), /*suspended=*/false, &proc);
    if (sr != game_launcher::start_result::ok) {
        scrub(iv); scrub(tag); scrub(ct);
        return result::launch_failed;
    }

    if (!game_launcher::wait_for_module(proc.hProcess, OBF_W(L"d3d9.dll").c_str(), 60000)) {
        scrub(iv); scrub(tag); scrub(ct);
        close_handles(proc);
        return result::inject_failed;
    }

    // Phase B.3: hand the ciphertext (NOT the plaintext DLL) to the
    // in-target worker. Decrypt, watermark verify, PE map, and
    // DllMain all run inside the target process.
    auto wr = payload_worker::schedule(
        proc.hProcess,
        ct.data(), static_cast<uint32_t>(ct.size()),
        iv.data(), tag.data(),
        k_payload_aes, k_watermark,
        local_hwid, license_hash,
        30000);

    scrub(iv); scrub(tag); scrub(ct);

    if (wr.res != payload_worker::result::ok) {
        close_handles(proc);
        // Map worker-side result codes back to payload::result as best we
        // can. Watermark failures bubble through worker_rc; cryptographic
        // decrypt failures too. Everything else is an inject-path problem.
        if (wr.res == payload_worker::result::worker_failed) {
            switch (wr.worker_rc) {
            case SB_RC_DECRYPT_FAILED:         return result::decrypt_failed;
            case SB_RC_WM_HWID_MISMATCH:       return result::watermark_hwid;
            case SB_RC_WM_LICENSE_MISMATCH:    return result::watermark_license;
            case SB_RC_WM_EXPIRED:             return result::watermark_expired;
            case SB_RC_WM_SIG_FAIL:            return result::watermark_signature;
            default:                           return result::inject_failed;
            }
        }
        return result::inject_failed;
    }
    close_handles(proc);
    return result::ok;
#endif
}

} // namespace payload
