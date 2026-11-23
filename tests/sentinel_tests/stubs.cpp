// Test shims: isolate sentinel.cpp from its runtime dependencies so the
// harness can exercise lifecycle paths without spinning up real anti-debug,
// crypto, net, heartbeat, etc. All stubs report a clean environment so the
// monitor never trips. Flip g_force_* to force trip paths (not used today;
// scrub_callback / SEH coverage is tracked in review notes).
//
// heartbeat.cpp is now compiled into this harness for real (report_trip /
// flush_once / tick canonical coverage), so its two external collaborators are
// stubbed here with capturing implementations: net::post records the outbound
// body + optionally stalls, auth::hmac_sha256 records the exact canonical bytes
// it is asked to sign. heartbeat::stop is NOT stubbed anymore -- the real one
// (from heartbeat.cpp) links in; it early-returns when never started.

#include <cstdint>
#include <atomic>
#include <string>
#include <chrono>
#include <thread>

#include "net.h"
#include "auth.h"

namespace stubs {
    std::atomic<uint32_t> g_anti_debug_val{0};
    std::atomic<uint32_t> g_anti_vm_val{0};
    std::atomic<uint32_t> g_anti_hook_val{0};
    std::atomic<uint32_t> g_tool_mask_val{0};
    std::atomic<bool>     g_tamper_ok{true};
    std::atomic<bool>     g_canary_data_ok{true};
    std::atomic<bool>     g_canary_code_ok{true};
    std::atomic<int>      g_heartbeat_stop_calls{0};

    // ---- heartbeat capture ----
    std::string           g_last_post_path;
    std::string           g_last_post_body;
    std::string           g_last_hmac_input;
    std::atomic<int>      g_post_status{200};
    std::atomic<uint32_t> g_post_sleep_ms{0};
    std::atomic<int>      g_post_calls{0};
}

namespace anti_debug  { uint32_t check_all()           { return stubs::g_anti_debug_val.load(); } }
namespace anti_vm     { uint32_t check_all()           { return stubs::g_anti_vm_val.load(); } }
namespace anti_hook   { uint32_t check_critical_apis() { return stubs::g_anti_hook_val.load(); } }
namespace tool_detect { uint32_t enumerate()           { return stubs::g_tool_mask_val.load(); } }

namespace anti_tamper {
    constexpr uint32_t SENTINEL_NOT_FOUND = 0xFFFFFFFFu;
    uint32_t text_section_crc32() { return 0x12345678u; }
    bool verify(uint32_t /*baseline*/) { return stubs::g_tamper_ok.load(); }
}

namespace canary {
    bool verify_data()                  { return stubs::g_canary_data_ok.load(); }
    bool verify_code(uint32_t /*b*/)    { return stubs::g_canary_code_ok.load(); }
}

// ---- heartbeat collaborators ----

namespace net {
    response post(const char* path, const std::string& json_body) {
        stubs::g_post_calls.fetch_add(1, std::memory_order_relaxed);
        uint32_t sleep_ms = stubs::g_post_sleep_ms.load(std::memory_order_relaxed);
        if (sleep_ms) std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
        stubs::g_last_post_path = path ? path : "";
        stubs::g_last_post_body = json_body;
        response r;
        r.status_code = stubs::g_post_status.load(std::memory_order_relaxed);
        r.body = "{}";
        return r;
    }
    void cancel_in_flight() {}
    void shutdown() {}
    bool init(const char*, uint16_t) { return true; }
}

namespace auth {
    bool hmac_sha256(const uint8_t* /*key*/, size_t /*key_len*/,
                     const uint8_t* data, size_t data_len,
                     uint8_t out[32]) {
        stubs::g_last_hmac_input.assign(reinterpret_cast<const char*>(data), data_len);
        for (int i = 0; i < 32; ++i) out[i] = static_cast<uint8_t>(i);
        return true;
    }
}
