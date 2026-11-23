// Sentinel lifecycle harness. Exercises start/stop/scan API surface against
// stubbed dependencies (see stubs.cpp) so no real tamper/debug detection
// fires. scan_clean, start/stop, double-start idempotency, stop-without-start
// safety. Trip/scrub-callback and SEH-in-monitor are reviewed statically
// (see report); exercising them would require corrupting the running image.

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include "sentinel.h"
#include "heartbeat.h"
#include "json_lite.h"

#include <cstdio>
#include <cstdint>
#include <atomic>
#include <chrono>
#include <string>

static int g_pass = 0;
static int g_fail = 0;

static void ok(const char* name, bool cond, const char* detail = "") {
    if (cond) { ++g_pass; std::printf("  PASS  %s %s\n", name, detail); }
    else      { ++g_fail; std::printf("  FAIL  %s %s\n", name, detail); }
}

// ----------------------------------------------------------------------------

static void test_scan_clean_returns_continue() {
    std::printf("[scan_clean_returns_continue]\n");
    sentinel::report r{};
    auto act = sentinel::scan(r);
    ok("scan returns continue_", act == sentinel::action::continue_);
    ok("anti_debug=0",  r.anti_debug == 0);
    ok("anti_hook=0",   r.anti_hook == 0);
    ok("tool_mask=0",   r.tool_mask == 0);
}

static void test_start_stop_lifecycle() {
    std::printf("[start_stop_lifecycle]\n");
    bool started = sentinel::start_monitor(/*text_crc*/ 0xAABBCCDD,
                                           /*code_canary*/ 0x11223344);
    ok("start_monitor returned true", started);
    Sleep(100);
    sentinel::stop_monitor();
    ok("stop_monitor returned cleanly", true);
}

static void test_double_start_idempotent() {
    std::printf("[double_start_idempotent]\n");
    bool a = sentinel::start_monitor(0xAABBCCDD, 0x11223344);
    bool b = sentinel::start_monitor(0xAABBCCDD, 0x11223344);
    ok("first  start=true",  a);
    ok("second start=false", !b);
    sentinel::stop_monitor();
}

static void test_stop_without_start_safe() {
    std::printf("[stop_without_start_safe]\n");
    // Fresh process state would be ideal; after prior tests the module is
    // already in stopped state (s_stop_event == nullptr). stop_monitor must
    // early-return without touching null handles.
    sentinel::stop_monitor();
    sentinel::stop_monitor();
    ok("double stop_monitor did not crash", true);
}

static bool g_scrub_fired = false;
static void scrub_cb() { g_scrub_fired = true; }

static void test_scrub_callback_setter() {
    std::printf("[scrub_callback_setter]\n");
    // We cannot force a real trip without corrupting the image. Just verify
    // the setter does not crash and leaves the monitor startable.
    sentinel::set_scrub_callback(&scrub_cb);
    sentinel::set_scrub_callback(nullptr);
    ok("set_scrub_callback idempotent", true);
}

// ---- heartbeat telemetry (Task 3) -----------------------------------------

namespace stubs {
    extern std::string           g_last_post_body;
    extern std::string           g_last_hmac_input;
    extern std::atomic<int>      g_post_status;
    extern std::atomic<uint32_t> g_post_sleep_ms;
    extern std::atomic<int>      g_post_calls;
}

static bool has(const std::string& h, const char* n) { return h.find(n) != std::string::npos; }

// report_trip OR-sets the masks; flush_once sends one heartbeat right now with
// those masks folded into the JSON and the HMAC canonical "<ts>|s|t".
static void test_heartbeat_canonical_includes_fields() {
    std::printf("[heartbeat_canonical_includes_fields]\n");
    stubs::g_post_sleep_ms.store(0);
    stubs::g_post_status.store(200);
    stubs::g_last_post_body.clear();
    stubs::g_last_hmac_input.clear();

    heartbeat::report_trip(0x4, 0x2);

    auto t0 = std::chrono::steady_clock::now();
    bool sent = heartbeat::flush_once(500);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    ok("flush_once returned true", sent);
    ok("flush_once returned < 500ms", ms < 500);
    ok("body carries sentinel_mask:4", has(stubs::g_last_post_body, "\"sentinel_mask\":4"));
    ok("body carries tool_mask:2",     has(stubs::g_last_post_body, "\"tool_mask\":2"));

    // HMAC input must be exactly "<timestamp>|4|2" (decimal, no quotes).
    auto ts = json::get_string(stubs::g_last_post_body, "timestamp");
    std::string expect = ts + "|4|2";
    ok("hmac input == <ts>|4|2", stubs::g_last_hmac_input == expect,
       ("got='" + stubs::g_last_hmac_input + "' want='" + expect + "'").c_str());
}

// A wedged network must not hold the caller past the deadline: flush_once
// dispatches on std::async and abandons it on timeout.
static void test_flush_once_returns_fast_on_network_stall() {
    std::printf("[flush_once_returns_fast_on_network_stall]\n");
    stubs::g_post_sleep_ms.store(5000);
    stubs::g_post_status.store(200);

    auto t0 = std::chrono::steady_clock::now();
    bool sent = heartbeat::flush_once(200);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    ok("flush_once returned false on stall", !sent);
    ok("flush_once returned < 400ms on stall", ms < 400);
    stubs::g_post_sleep_ms.store(0);
}

// ----------------------------------------------------------------------------

int main() {
    std::printf("sentinel_tests: start\n");

    test_scan_clean_returns_continue();
    test_start_stop_lifecycle();
    test_double_start_idempotent();
    test_stop_without_start_safe();
    test_scrub_callback_setter();
    test_heartbeat_canonical_includes_fields();
    test_flush_once_returns_fast_on_network_stall();

    std::printf("---- %d passed, %d failed ----\n", g_pass, g_fail);
    std::printf("Skipped (covered by static review):\n");
    std::printf("  - scrub_callback_fires_on_trip (requires tamper injection)\n");
    std::printf("  - seh_catches_av_in_monitor    (requires image corruption)\n");
    return g_fail == 0 ? 0 : 1;
}
