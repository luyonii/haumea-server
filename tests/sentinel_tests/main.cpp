// Sentinel lifecycle harness. Exercises start/stop/scan API surface against
// stubbed dependencies (see stubs.cpp) so no real tamper/debug detection
// fires. scan_clean, start/stop, double-start idempotency, stop-without-start
// safety. Trip/scrub-callback and SEH-in-monitor are reviewed statically
// (see report); exercising them would require corrupting the running image.

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include "sentinel.h"

#include <cstdio>
#include <cstdint>

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

// ----------------------------------------------------------------------------

int main() {
    std::printf("sentinel_tests: start\n");

    test_scan_clean_returns_continue();
    test_start_stop_lifecycle();
    test_double_start_idempotent();
    test_stop_without_start_safe();
    test_scrub_callback_setter();

    std::printf("---- %d passed, %d failed ----\n", g_pass, g_fail);
    std::printf("Skipped (covered by static review):\n");
    std::printf("  - scrub_callback_fires_on_trip (requires tamper injection)\n");
    std::printf("  - seh_catches_av_in_monitor    (requires image corruption)\n");
    return g_fail == 0 ? 0 : 1;
}
