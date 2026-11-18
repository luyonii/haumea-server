// Test shims: isolate sentinel.cpp from its runtime dependencies so the
// harness can exercise lifecycle paths without spinning up real anti-debug,
// crypto, net, heartbeat, etc. All stubs report a clean environment so the
// monitor never trips. Flip g_force_* to force trip paths (not used today;
// scrub_callback / SEH coverage is tracked in review notes).

#include <cstdint>
#include <atomic>

namespace stubs {
    std::atomic<uint32_t> g_anti_debug_val{0};
    std::atomic<uint32_t> g_anti_vm_val{0};
    std::atomic<uint32_t> g_anti_hook_val{0};
    std::atomic<uint32_t> g_tool_mask_val{0};
    std::atomic<bool>     g_tamper_ok{true};
    std::atomic<bool>     g_canary_data_ok{true};
    std::atomic<bool>     g_canary_code_ok{true};
    std::atomic<int>      g_heartbeat_stop_calls{0};
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

namespace heartbeat {
    void stop() { stubs::g_heartbeat_stop_calls.fetch_add(1); }
}
