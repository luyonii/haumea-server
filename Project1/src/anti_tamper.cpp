#include "anti_tamper.h"
#include "dynapi.h"
#include "obfstr.h"

#include <Windows.h>

extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace anti_tamper {

static uint32_t crc32_buf(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b)
            crc = (crc >> 1) ^ (0xEDB88320u & -static_cast<int32_t>(crc & 1));
    }
    return crc ^ 0xFFFFFFFFu;
}

uint32_t text_section_crc32() {
    auto mod = reinterpret_cast<uint8_t*>(&__ImageBase);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return SENTINEL_NOT_FOUND;

    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return SENTINEL_NOT_FOUND;

    // Guard NumberOfSections and section-table bounds. Two tampered bytes in
    // FileHeader could otherwise force OOB section-header reads and crash scan.
    const WORD num_sections = nt->FileHeader.NumberOfSections;
    if (num_sections == 0 || num_sections > 96) return SENTINEL_NOT_FOUND;
    const DWORD sec_tbl_off = dos->e_lfanew
        + static_cast<DWORD>(FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader))
        + nt->FileHeader.SizeOfOptionalHeader;
    const DWORD sec_tbl_end = sec_tbl_off + num_sections * sizeof(IMAGE_SECTION_HEADER);
    if (sec_tbl_end < sec_tbl_off) return SENTINEL_NOT_FOUND; // overflow
    if (sec_tbl_end > nt->OptionalHeader.SizeOfHeaders) return SENTINEL_NOT_FOUND;

    // Pass 1: match section name ".text".
    auto sec = IMAGE_FIRST_SECTION(nt);
    auto tag = OBF(".text");
    for (WORD i = 0; i < num_sections; ++i, ++sec) {
        bool eq = true;
        for (int k = 0; k < 5; ++k)
            if (sec->Name[k] != static_cast<BYTE>(tag.c_str()[k])) { eq = false; break; }
        if (!eq || sec->Name[5] != 0) continue;

        auto base = mod + sec->VirtualAddress;
        auto len  = sec->Misc.VirtualSize;
        return crc32_buf(base, len);
    }

    // Pass 2: fall back to first executable code section (renamed-section case).
    const DWORD exec_mask = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
    sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < num_sections; ++i, ++sec) {
        if ((sec->Characteristics & exec_mask) == exec_mask) {
            auto base = mod + sec->VirtualAddress;
            auto len  = sec->Misc.VirtualSize;
            return crc32_buf(base, len);
        }
    }
    return SENTINEL_NOT_FOUND;
}

bool verify(uint32_t baseline) {
    // Sentinel baseline means the initial snapshot failed — treat as tamper.
    if (baseline == SENTINEL_NOT_FOUND) return false;
    return text_section_crc32() == baseline;
}

} // namespace anti_tamper
