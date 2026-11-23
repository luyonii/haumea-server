#include "sentinel.h"
#include "anti_debug.h"
#include "anti_vm.h"
#include "anti_hook.h"
#include "anti_tamper.h"
#include "tool_detect.h"
#include "canary.h"
#include "heartbeat.h"
#include "dynapi.h"

#include <Windows.h>
#include <atomic>

namespace sentinel {

using fn_CreateEventA  = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
using fn_SetEvent      = BOOL(WINAPI*)(HANDLE);
using fn_WaitForSingle = DWORD(WINAPI*)(HANDLE, DWORD);
using fn_CreateThread  = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
using fn_CloseHandle   = BOOL(WINAPI*)(HANDLE);
using fn_TerminateProcess  = BOOL(WINAPI*)(HANDLE, UINT);
using fn_ExitProcess       = VOID(WINAPI*)(UINT);

static HANDLE   s_thread         = nullptr;
static HANDLE   s_stop_event     = nullptr;
static uint32_t s_baseline       = 0;
static uint32_t s_code_baseline  = 0;
static std::atomic<bool> s_running{false};
static scrub_cb s_scrub_cb = nullptr;

void set_scrub_callback(scrub_cb cb) { s_scrub_cb = cb; }

namespace detail {
uint32_t compose_sentinel_mask(uint32_t anti_debug_bits,
                               uint32_t anti_hook_bits,
                               bool tamper_fail,
                               bool canary_data_fail,
                               bool canary_code_fail,
                               bool seh_fault) noexcept {
    uint32_t m = anti_debug_bits | anti_hook_bits;
    if (tamper_fail)      m |= bits::TAMPER;
    if (canary_data_fail) m |= bits::CANARY_DATA;
    if (canary_code_fail) m |= bits::CANARY_CODE;
    if (seh_fault)        m |= bits::SEH_FAULT;
    return m;
}
} // namespace detail

static void terminate_silent() {
    using fn_TP = BOOL (WINAPI*)(HANDLE, UINT);
    using fn_EP = VOID (WINAPI*)(UINT);
    auto pTP = reinterpret_cast<fn_TP>(dynapi::resolve(dynapi::modules::KERNEL32, API_HASH("TerminateProcess")));
    if (pTP) pTP(reinterpret_cast<HANDLE>(-1), 0);
    auto pEP = reinterpret_cast<fn_EP>(dynapi::resolve(dynapi::modules::KERNEL32, API_HASH("ExitProcess")));
    if (pEP) pEP(0);
    for (;;) {}
}

action scan(report& out) {
    out.anti_debug      = anti_debug::check_all();
    out.anti_vm         = anti_vm::check_all();
    out.anti_hook       = anti_hook::check_critical_apis();
    out.tool_mask       = tool_detect::enumerate();
    // tamper_detected is filled by the monitor, not by initial scan.

    if (out.anti_debug || out.anti_hook || out.tool_mask)
        return action::abort_;
    if (!canary::verify_data())
        return action::abort_;
    return action::continue_;
}

static void trip_and_die(uint32_t sMask, uint32_t tMask) {
    // Server-primary enforcement: push the trip bits to the licensing server
    // BEFORE the local kill, so a persistent trip bans the license even if a
    // later client build patches out this local terminate. Fire-and-forget,
    // hard 2s deadline — local kill runs regardless of the HTTP result.
    if (sMask || tMask) {
        heartbeat::report_trip(sMask, tMask);
        heartbeat::flush_once(2000);
    }
    if (s_scrub_cb) s_scrub_cb();
    heartbeat::stop();
    terminate_silent();
}

// No C++ unwindable locals here — required for __try/__except coexistence.
static DWORD WINAPI monitor_proc(LPVOID) {
    __try {
        auto k32 = dynapi::get_module(dynapi::modules::KERNEL32);
        auto pWait = reinterpret_cast<fn_WaitForSingle>(
            dynapi::resolve(k32, API_HASH("WaitForSingleObject")));
        if (!pWait) { s_running.store(false, std::memory_order_release); return 0; }

        while (true) {
            DWORD w = pWait(s_stop_event, 30000);
            if (w != WAIT_TIMEOUT) break;

            // No short-circuit: every check runs so the server receives the
            // full trip fingerprint, not just the first bit that fired.
            uint32_t ad_bits = anti_debug::check_all();
            uint32_t ah_bits = anti_hook::check_critical_apis();
            bool tamper_fail = !anti_tamper::verify(s_baseline);
            bool cdata_fail  = !canary::verify_data();
            bool ccode_fail  = !canary::verify_code(s_code_baseline);
            uint32_t tm      = tool_detect::enumerate();

            uint32_t sMask = detail::compose_sentinel_mask(
                ad_bits, ah_bits, tamper_fail, cdata_fail, ccode_fail,
                /*seh_fault=*/false);
            uint32_t tMask = tm;

            if (sMask || tMask) {
                trip_and_die(sMask, tMask);
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Any SEH inside the monitor loop (AV from corrupted headers, illegal
        // insn, etc.) is treated as tamper — never die silently. Reports the
        // SEH_FAULT bit so the server can distinguish image corruption from
        // ordinary anti_debug/anti_hook trips.
        trip_and_die(bits::SEH_FAULT, 0);
    }
    s_running.store(false, std::memory_order_release);
    return 0;
}

bool start_monitor(uint32_t text_crc_baseline, uint32_t code_canary_baseline) {
    if (s_running.load(std::memory_order_acquire)) return false;

    auto k32 = dynapi::get_module(dynapi::modules::KERNEL32);
    auto pCE = reinterpret_cast<fn_CreateEventA>(
        dynapi::resolve(k32, API_HASH("CreateEventA")));
    auto pCT = reinterpret_cast<fn_CreateThread>(
        dynapi::resolve(k32, API_HASH("CreateThread")));
    if (!pCE || !pCT) return false;

    s_baseline      = text_crc_baseline;
    s_code_baseline = code_canary_baseline;

    // Pre-flight: validate baselines against the current image before we spawn
    // the monitor. Catches tamper that happened between baseline capture and
    // start_monitor (e.g. headers smashed, .text patched). Fail closed.
    if (!anti_tamper::verify(s_baseline))        return false;
    if (!canary::verify_code(s_code_baseline))   return false;
    if (!canary::verify_data())                  return false;

    s_stop_event = pCE(nullptr, TRUE, FALSE, nullptr);
    if (!s_stop_event) return false;

    s_running.store(true, std::memory_order_release);
    s_thread  = pCT(nullptr, 0, monitor_proc, nullptr, 0, nullptr);
    if (!s_thread) { s_running.store(false, std::memory_order_release); return false; }
    return true;
}

void stop_monitor() {
    if (!s_stop_event) return;

    auto k32 = dynapi::get_module(dynapi::modules::KERNEL32);
    auto pSE = reinterpret_cast<fn_SetEvent>(
        dynapi::resolve(k32, API_HASH("SetEvent")));
    auto pWait = reinterpret_cast<fn_WaitForSingle>(
        dynapi::resolve(k32, API_HASH("WaitForSingleObject")));
    auto pCH = reinterpret_cast<fn_CloseHandle>(
        dynapi::resolve(k32, API_HASH("CloseHandle")));

    if (pSE) pSE(s_stop_event);
    if (s_thread) {
        if (pWait) pWait(s_thread, 5000);
        if (pCH)   pCH(s_thread);
        s_thread = nullptr;
    }
    if (pCH) pCH(s_stop_event);
    s_stop_event = nullptr;
    s_running.store(false, std::memory_order_release);
}

} // namespace sentinel
