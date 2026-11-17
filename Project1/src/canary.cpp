#include "canary.h"

#include <cstdint>
#include <cstddef>

namespace canary {

// ---- Data canaries ----
static volatile uint64_t g_canary[4] = {};
static volatile uint64_t g_sink = 0;

void install() {
    g_canary[0] = MAGIC_A;
    g_canary[1] = MAGIC_B;
    g_canary[2] = MAGIC_C;
    g_canary[3] = MAGIC_D;
}

bool verify_data() {
    uint64_t acc = 0;
    acc |= g_canary[0] ^ MAGIC_A;
    acc |= g_canary[1] ^ MAGIC_B;
    acc |= g_canary[2] ^ MAGIC_C;
    acc |= g_canary[3] ^ MAGIC_D;
    return acc == 0;
}

// ---- Code canaries ----
// Each trap writes a magic to the sink and returns it. noinline prevents the
// compiler from folding the body at the call site and dropping the magic
// literal from .text.
__declspec(noinline) uint64_t trap_a() { g_sink ^= MAGIC_A; return MAGIC_A; }
__declspec(noinline) uint64_t trap_b() { g_sink ^= MAGIC_B; return MAGIC_B; }
__declspec(noinline) uint64_t trap_c() { g_sink ^= MAGIC_C; return MAGIC_C; }
__declspec(noinline) uint64_t trap_d() { g_sink ^= MAGIC_D; return MAGIC_D; }

static uint32_t crc32_buf(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b)
            crc = (crc >> 1) ^ (0xEDB88320u & -static_cast<int32_t>(crc & 1));
    }
    return crc ^ 0xFFFFFFFFu;
}

// Fingerprint = sum of CRC32 of first 64 bytes of each trap_*.
// shortcut: 64 bytes per trap, raise if traps grow past that.
uint32_t code_fingerprint() {
    using fn_t = uint64_t(*)();
    fn_t fns[4] = { &trap_a, &trap_b, &trap_c, &trap_d };
    uint32_t sum = 0;
    for (int i = 0; i < 4; ++i) {
        auto p = reinterpret_cast<const uint8_t*>(fns[i]);
        sum += crc32_buf(p, 64);
    }
    return sum;
}

bool verify_code(uint32_t baseline) {
    return code_fingerprint() == baseline;
}

} // namespace canary
