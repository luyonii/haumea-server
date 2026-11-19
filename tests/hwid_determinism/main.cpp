// Standalone self-check for the HWID determinism fix (no Windows/CNG deps).
//
// Root cause it guards: CPUID leaf 1 EBX[31:24] is the Initial APIC ID, which
// reports the logical CPU the thread ran on. Two runs on different cores fed
// different bytes into the SHA-256 input, so the HWID changed run to run.
//
// SHA-256 is deterministic by definition, so proving the HASH is stable reduces
// to proving its INPUT buffer is identical across runs. These asserts prove
// that: after the mask, two cpuid blocks that differ only in the APIC-ID byte
// serialize to byte-identical hash input, and the other collectors already feed
// only their zero-initialized, exact-length bytes.
//
// Build: cl /EHsc /std:c++17 tests\hwid_determinism\main.cpp
//    or: g++ -std=c++17 tests/hwid_determinism/main.cpp -o hwid_check

#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

struct cpuid_block { int regs[12]; };

// Mirrors the masking added to hwid::collect_cpuid (Project1/src/hwid.cpp).
void mask_apic_id(cpuid_block& out) { out.regs[5] &= 0x00FFFFFF; }

// Mirrors the serialization in hwid::generate:
// [disk_serial_len:4][disk_serial][smbios_uuid:16][cpuid:48]
std::vector<uint8_t> serialize(const uint8_t* ds_data, uint32_t ds_len,
                               const uint8_t uuid[16], const cpuid_block& cpu) {
    std::vector<uint8_t> buf;
    buf.resize(4 + ds_len + 16 + sizeof(cpu.regs));
    size_t off = 0;
    memcpy(buf.data() + off, &ds_len, 4); off += 4;
    if (ds_len > 0) { memcpy(buf.data() + off, ds_data, ds_len); off += ds_len; }
    memcpy(buf.data() + off, uuid, 16); off += 16;
    memcpy(buf.data() + off, cpu.regs, sizeof(cpu.regs)); off += sizeof(cpu.regs);
    assert(off == buf.size()); // every hashed byte is written, no uninitialized tail
    return buf;
}

} // namespace

int main() {
    // 1) Mask zeroes the APIC-ID byte and preserves the low 24 bits.
    cpuid_block a{};
    a.regs[5] = static_cast<int>(0xAB123456u);
    mask_apic_id(a);
    assert((static_cast<uint32_t>(a.regs[5]) & 0xFF000000u) == 0);
    assert((static_cast<uint32_t>(a.regs[5]) & 0x00FFFFFFu) == 0x00123456u);

    // 2) Two blocks that differ ONLY in the APIC-ID byte become byte-identical.
    cpuid_block run1{}, run2{};
    for (int i = 0; i < 12; ++i) run1.regs[i] = run2.regs[i] = 0x11111111;
    run1.regs[5] = static_cast<int>(0x01ABCDEFu); // core 0x01
    run2.regs[5] = static_cast<int>(0x9AABCDEFu); // core 0x9A, same machine
    mask_apic_id(run1);
    mask_apic_id(run2);
    assert(memcmp(run1.regs, run2.regs, sizeof(run1.regs)) == 0);

    // 3) Full HWID hash input is identical across the two runs => identical
    //    SHA-256 => identical HWID. (disk serial and smbios uuid are the same
    //    deterministic inputs here, as they are on one machine with a fixed set
    //    of succeeding sources.)
    const uint8_t uuid[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const uint8_t serial[] = "WD-WX11A2B3C4D5";
    auto in1 = serialize(serial, sizeof(serial) - 1, uuid, run1);
    auto in2 = serialize(serial, sizeof(serial) - 1, uuid, run2);
    assert(in1 == in2);

    // 4) A failed disk collector (len 0) must not shift later fields or leak
    //    bytes: input stays fully determined by the remaining sources.
    auto in_nodisk = serialize(nullptr, 0, uuid, run1);
    assert(in_nodisk.size() == 4u + 16u + sizeof(cpuid_block::regs));

    return 0; // all asserts held
}
