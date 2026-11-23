#include "heartbeat.h"
#include "auth.h"
#include "net.h"
#include "dynapi.h"
#include "obfstr.h"
#include "base64.h"
#include "json_lite.h"

#include <Windows.h>
#include <atomic>
#include <string>
#include <cstring>
#include <future>
#include <chrono>

namespace heartbeat {

// ---- Kernel32 function types ----

using fn_CreateEventA  = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
using fn_SetEvent      = BOOL(WINAPI*)(HANDLE);
using fn_WaitForSingle = DWORD(WINAPI*)(HANDLE, DWORD);
using fn_CreateThread  = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
using fn_CloseHandle   = BOOL(WINAPI*)(HANDLE);

// ---- State ----

static HANDLE      s_thread     = nullptr;
static HANDLE      s_stop_event = nullptr;
static uint8_t     s_key[32]{};
static std::string s_token;
static std::string s_nonce;
static int         s_interval   = 60;
static std::atomic<bool>        s_running{false};
static std::atomic<stop_reason> s_reason{stop_reason::requested};

// Sentinel/tool trip masks folded into each heartbeat. OR-set by report_trip,
// never cleared here (server owns trip state). relaxed: no ordering needed, the
// value is only observed, not used to gate other memory.
static std::atomic<uint32_t> g_sentinel_mask{0};
static std::atomic<uint32_t> g_tool_mask{0};

static fn_CreateEventA  pCreateEvent;
static fn_SetEvent      pSetEvent;
static fn_WaitForSingle pWaitFor;
static fn_CreateThread  pCreateThread;
static fn_CloseHandle   pCloseHandle;

// Current unix seconds via kernel32!GetSystemTimeAsFileTime (dynapi, zero-IAT).
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

// Build, sign and POST one heartbeat from the current session state and trip
// masks. Returns the raw server response (status_code 0 on HMAC failure, which
// callers treat as a failed beat). Does not mutate s_nonce; the tick loop owns
// nonce rotation from the response.
static net::response send_once() {
    auto ts = std::to_string(static_cast<int64_t>(now_unix()));
    uint32_t sMask = g_sentinel_mask.load(std::memory_order_relaxed);
    uint32_t tMask = g_tool_mask.load(std::memory_order_relaxed);

    // HMAC canonical: "<timestamp>|<sentinel_mask>|<tool_mask>", decimal ASCII,
    // no leading zeros, no sign, no quotes. Must match the Go server verbatim.
    std::string canon = ts + "|" + std::to_string(sMask) + "|" + std::to_string(tMask);

    uint8_t hmac[32]{};
    if (!auth::hmac_sha256(s_key, 32,
            reinterpret_cast<const uint8_t*>(canon.data()), canon.size(),
            hmac))
    {
        return net::response{}; // status_code == 0
    }

    auto hmac_b64 = base64::encode(hmac, 32);
    volatile uint8_t* hp = hmac;
    for (int i = 0; i < 32; ++i) hp[i] = 0;

    auto body = json::object({
        {"session_token", s_token},
        {"hmac",          hmac_b64},
        {"timestamp",     ts},
        {"next_nonce",    s_nonce}
    });
    // json::object quotes every value; sentinel_mask/tool_mask must be bare JSON
    // integers, so splice them in by hand before the closing brace.
    body.pop_back(); // drop '}'
    body += ",\"sentinel_mask\":" + std::to_string(sMask)
          + ",\"tool_mask\":"     + std::to_string(tMask) + "}";

    return net::post(OBF("/api/v1/session/heartbeat"), body);
}

// ---- Thread ----

static DWORD WINAPI thread_proc(LPVOID) {
    int fails = 0;

    while (true) {
        DWORD w = pWaitFor(s_stop_event, static_cast<DWORD>(s_interval) * 1000);
        if (w != WAIT_TIMEOUT) break; // stop signaled

        auto resp = send_once();

        if (resp.status_code == 200) {
            fails = 0;
            auto next = json::get_string(resp.body, "next_nonce");
            if (!next.empty()) s_nonce = next;

            if (json::get_bool(resp.body, "kill")) {
                s_reason.store(stop_reason::killed, std::memory_order_release);
                break;
            }
            if (json::get_bool(resp.body, "revoked")) {
                s_reason.store(stop_reason::revoked, std::memory_order_release);
                break;
            }
        } else {
            if (++fails >= 3) {
                s_reason.store(stop_reason::failed, std::memory_order_release);
                break;
            }
        }
    }

    // Scrub session key
    volatile uint8_t* p = s_key;
    for (int i = 0; i < 32; ++i) p[i] = 0;

    s_running.store(false, std::memory_order_release);
    return 0;
}

// ---- Public API ----

bool start(const char* session_token, const uint8_t* session_key,
           int interval_seconds, const char* initial_nonce_b64)
{
    if (s_running.load(std::memory_order_acquire)) return false;

    auto k32 = dynapi::get_module(dynapi::modules::KERNEL32);
    if (!k32) return false;

    pCreateEvent  = reinterpret_cast<fn_CreateEventA> (dynapi::resolve(k32, API_HASH("CreateEventA")));
    pSetEvent     = reinterpret_cast<fn_SetEvent>     (dynapi::resolve(k32, API_HASH("SetEvent")));
    pWaitFor      = reinterpret_cast<fn_WaitForSingle>(dynapi::resolve(k32, API_HASH("WaitForSingleObject")));
    pCreateThread = reinterpret_cast<fn_CreateThread> (dynapi::resolve(k32, API_HASH("CreateThread")));
    pCloseHandle  = reinterpret_cast<fn_CloseHandle>  (dynapi::resolve(k32, API_HASH("CloseHandle")));

    if (!pCreateEvent || !pSetEvent || !pWaitFor || !pCreateThread || !pCloseHandle)
        return false;

    s_token    = session_token;
    memcpy(s_key, session_key, 32);
    // clamp defensivo em Release (pareia com auth.cpp)
    if (interval_seconds < 10 || interval_seconds > 3600) interval_seconds = 60;
    s_interval = interval_seconds;
    s_nonce    = initial_nonce_b64;
    s_reason.store(stop_reason::requested, std::memory_order_release);

    s_stop_event = pCreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!s_stop_event) return false;

    s_running.store(true, std::memory_order_release);
    s_thread  = pCreateThread(nullptr, 0, thread_proc, nullptr, 0, nullptr);
    if (!s_thread) {
        s_running.store(false, std::memory_order_release);
        pCloseHandle(s_stop_event);
        s_stop_event = nullptr;
        return false;
    }

    return true;
}

void stop() {
    if (!s_stop_event) return;

    pSetEvent(s_stop_event);
    if (s_thread) {
        // Worker may be blocked inside WinHttpSendRequest/ReceiveResponse and
        // will not observe s_stop_event until the HTTP call returns. If the
        // first wait times out, cancel the in-flight request to unblock it;
        // otherwise it would touch net handles after net::shutdown() -> UAF.
        if (pWaitFor(s_thread, 2000) == WAIT_TIMEOUT) {
            net::cancel_in_flight();
            pWaitFor(s_thread, 8000);
        }
        pCloseHandle(s_thread);
        s_thread = nullptr;
    }
    pCloseHandle(s_stop_event);
    s_stop_event = nullptr;
    s_running.store(false, std::memory_order_release);

    // Scrub session data
    s_token.clear();
    s_nonce.clear();
    volatile uint8_t* p = s_key;
    for (int i = 0; i < 32; ++i) p[i] = 0;
}

bool is_running()         { return s_running.load(std::memory_order_acquire); }
stop_reason get_stop_reason() { return s_reason.load(std::memory_order_acquire); }

void report_trip(uint32_t sentinel_mask, uint32_t tool_mask) noexcept {
    g_sentinel_mask.fetch_or(sentinel_mask, std::memory_order_relaxed);
    g_tool_mask.fetch_or(tool_mask, std::memory_order_relaxed);
}

bool flush_once(uint32_t timeout_ms) noexcept {
    try {
        // Heap-allocated on purpose: std::future's destructor from std::async
        // blocks (joins) until the task finishes, which would defeat the
        // deadline on a wedged network. On timeout we abandon (leak) the future
        // so its destructor never runs on this thread; the async task keeps
        // running detached. The real caller (sentinel abort) terminates the
        // process immediately after, so the leak is irrelevant.
        auto* fut = new std::future<net::response>(
            std::async(std::launch::async, [] { return send_once(); }));
        if (fut->wait_for(std::chrono::milliseconds(timeout_ms)) == std::future_status::ready) {
            net::response r = fut->get();
            delete fut;
            return r.status_code == 200;
        }
        return false; // timed out: fut intentionally leaked
    } catch (...) {
        return false;
    }
}

} // namespace heartbeat
