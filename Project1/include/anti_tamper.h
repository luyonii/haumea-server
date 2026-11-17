#pragma once
#include <cstdint>

namespace anti_tamper {

// Sentinel returned when no code section can be located (malformed PE, stripped
// headers). verify() treats a sentinel baseline as tamper-detected.
constexpr uint32_t SENTINEL_NOT_FOUND = 0xFFFFFFFFu;

// CRC32 of this process's .text section. Baseline must be captured AFTER
// relocations/anti-dump settle — call at the top of main (after
// anti_debug::hide_current_thread). Returns SENTINEL_NOT_FOUND if no code
// section can be identified (pass 1: name ".text"; pass 2: first section with
// CNT_CODE|MEM_EXECUTE).
uint32_t text_section_crc32();

// Returns false if the current CRC differs from baseline, or if baseline is
// SENTINEL_NOT_FOUND (initial snapshot failed — treated as tamper).
bool verify(uint32_t baseline);

} // namespace anti_tamper
