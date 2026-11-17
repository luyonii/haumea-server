#pragma once
// Two-layer tripwire: data canaries (volatile guards) + code canaries
// (magic constants embedded in trap functions, CRC32 fingerprint).

#include <cstdint>

namespace canary {

constexpr uint64_t MAGIC_A = 0xA17E2B3C4D5E6F70ULL;
constexpr uint64_t MAGIC_B = 0xBADC0FFEE0DDF00DULL;
constexpr uint64_t MAGIC_C = 0x00C0DEDBADC0FFEEULL;
constexpr uint64_t MAGIC_D = 0xDEADBEEFCAFEBABEULL;

void install();
bool verify_data();

uint32_t code_fingerprint();
bool     verify_code(uint32_t baseline);

uint64_t trap_a();
uint64_t trap_b();
uint64_t trap_c();
uint64_t trap_d();

} // namespace canary
