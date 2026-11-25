#include "obfstr.h"
#include "dynapi.h"
#include "hwid.h"
#include "net.h"
#include "auth.h"
#include "heartbeat.h"
#include "payload.h"
#include "watermark.h"
#include "canary.h"
#include "anti_debug.h"
#include "anti_tamper.h"
#include "sentinel.h"
#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>

// File-scope snapshot of the payload sub-keys. Kept off the stack so the
// sentinel monitor thread can scrub them via a registered callback on trip.
static volatile uint8_t g_payload_aes_key[32] = {};  // k_payload_aes (AES-GCM)
static volatile uint8_t g_watermark_key[32]  = {};   // k_watermark (binding HMAC)
// SHA-256 of the license key — needed by payload to verify watermark after
// the raw license string is already scrubbed.
static volatile uint8_t g_license_hash[32] = {};

void scrub_payload_key() {
    volatile uint8_t* a = g_payload_aes_key;
    for (int i = 0; i < 32; ++i) a[i] = 0;
    volatile uint8_t* w = g_watermark_key;
    for (int i = 0; i < 32; ++i) w[i] = 0;
    volatile uint8_t* h = g_license_hash;
    for (int i = 0; i < 32; ++i) h[i] = 0;
}

[[noreturn]] static void sentinel_abort_silent() {
    // Flush stdio + OS buffers so any diagnostic printed before the abort is
    // not lost when stdout/stderr is a pipe or redirect (audit item #9).
    fflush(stdout);
    fflush(stderr);
    using fn_GSH = HANDLE(WINAPI*)(DWORD);
    using fn_FFB = BOOL(WINAPI*)(HANDLE);
    using fn_TP = BOOL(WINAPI*)(HANDLE, UINT);
    using fn_EP = void(WINAPI*)(UINT);
    auto k32 = dynapi::get_module(dynapi::modules::KERNEL32);
    auto pGSH = reinterpret_cast<fn_GSH>(dynapi::resolve(k32, API_HASH("GetStdHandle")));
    auto pFFB = reinterpret_cast<fn_FFB>(dynapi::resolve(k32, API_HASH("FlushFileBuffers")));
    if (pGSH && pFFB) {
        pFFB(pGSH(static_cast<DWORD>(-11))); // STD_OUTPUT_HANDLE
        pFFB(pGSH(static_cast<DWORD>(-12))); // STD_ERROR_HANDLE
    }
    auto pTP = reinterpret_cast<fn_TP>(dynapi::resolve(k32, API_HASH("TerminateProcess")));
    if (pTP) pTP(reinterpret_cast<HANDLE>(-1), 0);
    auto pEP = reinterpret_cast<fn_EP>(dynapi::resolve(k32, API_HASH("ExitProcess")));
    if (pEP) pEP(0);
    for (;;) {}
}

// wmain is used so the fallback target path from argv is already wide and
// matches payload::load_and_execute's signature without a narrow->wide
// conversion at the call site.
// Interleaved multi-sample code-integrity running digest (audit #1 "Fix B").
// Each use folds a live read of the .text CRC32 + code fingerprint, tagged with
// the sample index k, into a 32-byte SHA-256 running digest. The digest later
// keys the /auth/login HKDF salt, so a runtime patch of .text must stay intact
// across EVERY sample point, not just the one early snapshot the old design took
// — closing the "sample early, use late" window. k is distinct per point, which
// both defeats accidental commutativity and keeps the compiler from folding the
// expansions (identical-COMDAT folding). This is a macro, not a helper function,
// on purpose: there must be no single `call sample_mix` an attacker can NOP to
// disarm every point at once. SHA-256 is the only shared primitive; patching it
// just corrupts the digest -> wrong key -> login rejected (fail-closed).
#define SB_MIX_SAMPLE(digest, k) do {                                          \
        uint8_t sb_buf[44];                                                    \
        for (int sb_i = 0; sb_i < 32; ++sb_i) sb_buf[sb_i] = (digest)[sb_i];   \
        uint32_t sb_crc = anti_tamper::text_section_crc32();                   \
        uint32_t sb_fp  = canary::code_fingerprint();                          \
        sb_buf[32] = (uint8_t)sb_crc;        sb_buf[33] = (uint8_t)(sb_crc>>8); \
        sb_buf[34] = (uint8_t)(sb_crc>>16);  sb_buf[35] = (uint8_t)(sb_crc>>24);\
        sb_buf[36] = (uint8_t)sb_fp;         sb_buf[37] = (uint8_t)(sb_fp>>8);  \
        sb_buf[38] = (uint8_t)(sb_fp>>16);   sb_buf[39] = (uint8_t)(sb_fp>>24); \
        sb_buf[40] = (uint8_t)((k));         sb_buf[41] = (uint8_t)((k)>>8);    \
        sb_buf[42] = (uint8_t)((k)>>16);     sb_buf[43] = (uint8_t)((k)>>24);   \
        watermark::sha256(sb_buf, sizeof(sb_buf), (digest));                   \
    } while (0)

int wmain(int argc, wchar_t* argv[]) {
    // --- Anti-analysis boot ---
    anti_debug::hide_current_thread();
    canary::install();

    // running_digest accumulates the code-integrity samples (see SB_MIX_SAMPLE).
    uint8_t running_digest[32]{};

    // Baseline helper: run ONLY the sampling sequence (no gates, no auth, no
    // heartbeat) and print the expected running digest, then exit. The operator
    // runs `Project1.exe --print-baseline` once on a clean reference machine and
    // copies the value into SECBLIND_EXPECTED_RUNNING_DIGEST on the server. The
    // digest depends only on the (crc, fp, k) sequence — constant for a clean
    // binary — so computing the samples back-to-back here yields the same value
    // the interleaved production path below does.
    if (argc >= 2 && argv && argv[1] && wcscmp(argv[1], L"--print-baseline") == 0) {
        SB_MIX_SAMPLE(running_digest, 1);
        SB_MIX_SAMPLE(running_digest, 2);
        SB_MIX_SAMPLE(running_digest, 3);
        SB_MIX_SAMPLE(running_digest, 4);
        printf("SECBLIND_EXPECTED_RUNNING_DIGEST=");
        for (int i = 0; i < 32; ++i) printf("%02x", running_digest[i]);
        printf("\n");
        return 0;
    }

    uint32_t crc_baseline  = anti_tamper::text_section_crc32();
    uint32_t code_baseline = canary::code_fingerprint();

    // k=1: earliest point — APIs resolved, canaries installed, pre abort gate.
    SB_MIX_SAMPLE(running_digest, 1);

    // rpt is kept alive past the abort gate on purpose: its raw detection masks
    // are folded into the /auth/login HKDF salt below (audit #1). A runtime patch
    // that NOPs the abort gate no longer yields clean masks for the salt — the
    // attacker would also have to zero rpt before authenticate() runs.
    sentinel::report rpt{};
    if (sentinel::scan(rpt) == sentinel::action::abort_)
        sentinel_abort_silent();

    // k=2: after the detection gate — a runtime NOP of the gate still has to
    // keep .text intact here to reproduce this sample.
    SB_MIX_SAMPLE(running_digest, 2);

    // --- HWID ---
    printf("Generating HWID...\n");
    auto id = hwid::generate();
    if (id.empty()) {
        printf("HWID generation failed\n");
        return 1;
    }
    printf("HWID: %s\n", id.c_str());

    // k=3: after HWID generation.
    SB_MIX_SAMPLE(running_digest, 3);

    // --- License key ---
    printf("License key: ");
    char key_buf[256]{};
    if (!fgets(key_buf, sizeof(key_buf), stdin)) {
        printf("Failed to read license key\n");
        return 1;
    }
    size_t klen = strlen(key_buf);
    // Detect silent truncation: a complete line always ends with '\n'
    // (or EOF right after the key); without one, the buffer was full.
    if (klen == sizeof(key_buf) - 1 && key_buf[klen - 1] != '\n') {
        printf("License key too long (max %zu chars)\n", sizeof(key_buf) - 2);
        volatile char* kb0 = key_buf;
        for (size_t i = 0; i < sizeof(key_buf); ++i) kb0[i] = 0;
        return 1;
    }
    auto is_ws = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (klen > 0 && is_ws(key_buf[klen - 1]))
        key_buf[--klen] = 0;
    size_t kstart = 0;
    if (klen >= 3 && (unsigned char)key_buf[0] == 0xEF &&
        (unsigned char)key_buf[1] == 0xBB && (unsigned char)key_buf[2] == 0xBF)
        kstart = 3;
    while (kstart < klen && is_ws(key_buf[kstart])) ++kstart;
    if (kstart) {
        memmove(key_buf, key_buf + kstart, klen - kstart);
        klen -= kstart;
        key_buf[klen] = 0;
    }

    std::string license_key(key_buf, klen);

    volatile char* kb = key_buf;
    for (size_t i = 0; i < sizeof(key_buf); ++i) kb[i] = 0;

    // Compute SHA-256(license_key) BEFORE we scrub the key below. Stored at
    // file scope so the sentinel scrub callback can zero it on trip.
    {
        uint8_t tmp[32]{};
        if (!watermark::sha256(
                reinterpret_cast<const uint8_t*>(license_key.data()),
                license_key.size(), tmp))
        {
            printf("License hash failed\n");
            volatile char* lk0 = license_key.empty() ? nullptr : &license_key[0];
            if (lk0) for (size_t i = 0; i < license_key.size(); ++i) lk0[i] = 0;
            return 1;
        }
        volatile uint8_t* gh = g_license_hash;
        for (int i = 0; i < 32; ++i) gh[i] = tmp[i];
        volatile uint8_t* tp = tmp;
        for (int i = 0; i < 32; ++i) tp[i] = 0;
    }

    // --- Network init ---
    printf("Connecting...\n");
    if (!net::init(OBF("secblind.local"), 443)) {
        printf("Network initialization failed\n");
        return 1;
    }

    // --- Auth ---
    printf("Authenticating...\n");
    // k=4: last sample, immediately before authenticate — no patch window
    // remains between the integrity proof and its use in the key derivation.
    SB_MIX_SAMPLE(running_digest, 4);
    auto result = auth::authenticate(license_key, id, running_digest,
                                     rpt.anti_debug, rpt.anti_hook,
                                     rpt.tool_mask, rpt.anti_vm);
#undef SB_MIX_SAMPLE

    // Scrub license key
    volatile char* lk = &license_key[0];
    for (size_t i = 0; i < license_key.size(); ++i) lk[i] = 0;
    license_key.clear();

    if (!result.success) {
        printf("Auth failed: %s\n", result.error_message.c_str());
        net::shutdown();
        return 1;
    }

    printf("Authenticated. TTL=%ds, heartbeat=%ds\n",
           result.session.ttl, result.session.heartbeat_interval);

    // --- Heartbeat ---
    if (!heartbeat::start(
            result.session.session_token.c_str(),
            result.session.k_heartbeat.data(),
            result.session.heartbeat_interval,
            result.session.next_nonce.c_str()))
    {
        printf("Failed to start heartbeat\n");
        auth::clear_session(result.session);
        net::shutdown();
        return 1;
    }

    // Snapshot the payload sub-keys needed after clear_session for the fetch.
    // They live at file scope so the sentinel monitor can scrub them from
    // another thread on trip.
    {
        volatile uint8_t* ga = g_payload_aes_key;
        const uint8_t* sa = result.session.k_payload_aes.data();
        for (int i = 0; i < 32; ++i) ga[i] = sa[i];
        volatile uint8_t* gw = g_watermark_key;
        const uint8_t* sw = result.session.k_watermark.data();
        for (int i = 0; i < 32; ++i) gw[i] = sw[i];
    }
    sentinel::set_scrub_callback(&scrub_payload_key);
    sentinel::start_monitor(crc_baseline, code_baseline);

    std::string payload_token = result.session.session_token;

    // Heartbeat has its own copy of the key — scrub the auth result
    auth::clear_session(result.session);

    // --- Payload ---
    printf("Fetching payload...\n");
    // Target host for the injected module. The server is the primary source
    // (envelope field `target_exe_path`); argv[1] is the fallback, kept so a
    // dev can point a test build at an arbitrary executable without changing
    // the licensing records. If neither supplies a path, load_and_execute
    // surfaces `launch_failed`.
    const wchar_t* target_fallback = (argc > 1 && argv && argv[1] && argv[1][0])
                                         ? argv[1]
                                         : nullptr;
    auto pr = payload::load_and_execute(
        payload_token.c_str(),
        const_cast<const uint8_t*>(g_payload_aes_key),
        const_cast<const uint8_t*>(g_watermark_key),
        id.c_str(),
        const_cast<const uint8_t*>(g_license_hash),
        target_fallback);

    // Scrub key + token immediately — payload module no longer needs them.
    scrub_payload_key();
    volatile char* pt = payload_token.empty() ? nullptr : &payload_token[0];
    if (pt) for (size_t i = 0; i < payload_token.size(); ++i) pt[i] = 0;
    payload_token.clear();

    if (pr != payload::result::ok) {
        printf("Payload load failed: %d\n", static_cast<int>(pr));
        sentinel::stop_monitor();
        heartbeat::stop();
        net::shutdown();
        return 1;
    }

    printf("Payload running. Waiting for heartbeat termination...\n");

    // Resolve Sleep lazily via dynapi — no IAT entry.
    using fn_Sleep = void(WINAPI*)(DWORD);
    fn_Sleep pSleep = reinterpret_cast<fn_Sleep>(
        dynapi::resolve(dynapi::modules::KERNEL32, API_HASH("Sleep")));
    if (!pSleep) {
        printf("Failed to resolve Sleep\n");
        sentinel::stop_monitor();
        heartbeat::stop();
        net::shutdown();
        return 1;
    }

    while (heartbeat::is_running()) {
        pSleep(1000);
    }

    // --- Shutdown ---
    sentinel::stop_monitor();
    heartbeat::stop();

    auto reason = heartbeat::get_stop_reason();
    switch (reason) {
    case heartbeat::stop_reason::killed:
        printf("Session killed by server\n"); break;
    case heartbeat::stop_reason::revoked:
        printf("Session revoked\n"); break;
    case heartbeat::stop_reason::failed:
        printf("Heartbeat lost (3 consecutive failures)\n"); break;
    default:
        break;
    }

    system("pause");
    net::shutdown();
    return 0;
}
