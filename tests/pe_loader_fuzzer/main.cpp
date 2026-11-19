// Minimal fuzz harness for pe_loader::map.
// Builds malformed PEs in std::vector<uint8_t> and verifies the expected enum.
// Standalone console app; owns its own main(); not linked into the main loader.

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include "pe_loader.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

using std::vector;

// ---- Skeleton geometry -----------------------------------------------------
// File layout (1024 bytes total):
//   [0..64)     DOS header
//   [64..328)   NT headers (sig 4 + file 20 + opt 240 = 264)
//   [328..368)  1 section header
//   [368..512)  zero pad (SizeOfHeaders = 512)
//   [512..1024) section raw data (SizeOfRawData = 512 == VirtualSize)
//
// Memory image: SizeOfImage = 0x2000. Headers page + section page.
// ImageBase = 0x400000 (standard EXE base). On x64 user-mode,
// VirtualAlloc(nullptr, ...) returns a high address (0x7FF...), so
// actual_base - ImageBase = delta != 0 is near-certain and reloc tests run.

static constexpr uint32_t FILE_SIZE       = 1024;
static constexpr uint32_t SECT_RAW_OFFSET = 512;
static constexpr uint32_t SECT_RAW_SIZE   = 512;
static constexpr uint32_t SECT_VA         = 0x1000;
static constexpr uint32_t SECT_VIRT_SIZE  = 0x200;
static constexpr uint32_t SIZE_OF_IMAGE   = 0x2000;
static constexpr uint32_t SIZE_OF_HEADERS = 512;
static constexpr uint64_t IMAGE_BASE_LOW  = 0x400000ULL;
static constexpr uint32_t NT_OFFSET       = 64;

static vector<uint8_t> build_valid_skeleton() {
    vector<uint8_t> buf(FILE_SIZE, 0);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    dos->e_magic  = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = static_cast<LONG>(NT_OFFSET);

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + NT_OFFSET);
    nt->Signature                     = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine            = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections   = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.Characteristics    = IMAGE_FILE_EXECUTABLE_IMAGE;

    auto& oh = nt->OptionalHeader;
    oh.Magic                         = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    oh.AddressOfEntryPoint           = SECT_VA;
    oh.ImageBase                     = IMAGE_BASE_LOW;
    oh.SectionAlignment              = 0x1000;
    oh.FileAlignment                 = 0x200;
    oh.MajorOperatingSystemVersion   = 6;
    oh.MajorSubsystemVersion         = 6;
    oh.SizeOfImage                   = SIZE_OF_IMAGE;
    oh.SizeOfHeaders                 = SIZE_OF_HEADERS;
    oh.Subsystem                     = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    oh.NumberOfRvaAndSizes           = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    // all DataDirectory entries left zero -> no imports, no relocs

    auto* sec = IMAGE_FIRST_SECTION(nt);
    memcpy(sec->Name, ".text\0\0\0", 8);
    sec->Misc.VirtualSize = SECT_VIRT_SIZE;
    sec->VirtualAddress   = SECT_VA;
    sec->SizeOfRawData    = SECT_RAW_SIZE;
    sec->PointerToRawData = SECT_RAW_OFFSET;
    sec->Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

    return buf;
}

static IMAGE_DOS_HEADER*     dos_at(vector<uint8_t>& b) { return reinterpret_cast<IMAGE_DOS_HEADER*>(b.data()); }
static IMAGE_NT_HEADERS64*   nt_at (vector<uint8_t>& b) { return reinterpret_cast<IMAGE_NT_HEADERS64*>(b.data() + dos_at(b)->e_lfanew); }
static IMAGE_SECTION_HEADER* sec0  (vector<uint8_t>& b) { return IMAGE_FIRST_SECTION(nt_at(b)); }

// ---- Mutations -------------------------------------------------------------

static vector<uint8_t> build_null()  { return {}; } // size==0, harness passes nullptr
static vector<uint8_t> build_empty() { return {}; } // size==0 also triggers bad_dos_header

static vector<uint8_t> build_bad_mz() {
    auto b = build_valid_skeleton();
    b[0] = 'X'; b[1] = 'X';
    return b;
}

static vector<uint8_t> build_bad_lfanew() {
    auto b = build_valid_skeleton();
    dos_at(b)->e_lfanew = 0xFFFF; // beyond pe_size
    return b;
}

static vector<uint8_t> build_bad_pe_sig() {
    auto b = build_valid_skeleton();
    nt_at(b)->Signature = 0xDEADBEEFu;
    return b;
}

static vector<uint8_t> build_bad_machine() {
    auto b = build_valid_skeleton();
    nt_at(b)->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    return b;
}

static vector<uint8_t> build_big_size_of_headers() {
    auto b = build_valid_skeleton();
    nt_at(b)->OptionalHeader.SizeOfHeaders = FILE_SIZE + 1;
    return b;
}

static vector<uint8_t> build_bad_opt_header_size() {
    auto b = build_valid_skeleton();
    nt_at(b)->FileHeader.SizeOfOptionalHeader = 100; // != sizeof(IMAGE_OPTIONAL_HEADER64)
    return b;
}

// Reloc tests assume the mapped base differs from ImageBase (0x400000).
// On x64 user-mode VirtualAlloc(nullptr,...) returns a high address, so delta
// is effectively always nonzero and the reloc walker actually runs.
// Place a relocation block at the start of the section's raw data.
// Section VA 0x1000 maps to file offset 512.
static vector<uint8_t> build_small_reloc_block() {
    auto b = build_valid_skeleton();
    auto& dd = nt_at(b)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    dd.VirtualAddress = SECT_VA;
    dd.Size           = 8;
    auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(b.data() + SECT_RAW_OFFSET);
    block->VirtualAddress = SECT_VA;
    block->SizeOfBlock    = 4; // < sizeof(IMAGE_BASE_RELOCATION) == 8
    return b;
}

static vector<uint8_t> build_reloc_va_overflow() {
    auto b = build_valid_skeleton();
    auto& dd = nt_at(b)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    dd.VirtualAddress = SECT_VA;
    dd.Size           = 12;
    auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(b.data() + SECT_RAW_OFFSET);
    block->VirtualAddress = SIZE_OF_IMAGE; // block VA at image end -> VA+offset+8 > image_size
    block->SizeOfBlock    = 12;
    auto* entries = reinterpret_cast<uint16_t*>(block + 1);
    entries[0] = static_cast<uint16_t>((IMAGE_REL_BASED_DIR64 << 12) | 0);
    entries[1] = 0; // padding
    return b;
}

static vector<uint8_t> build_section_va_overflow() {
    auto b = build_valid_skeleton();
    auto* s = sec0(b);
    s->Misc.VirtualSize = 0x2000;
    s->SizeOfRawData    = 0x2000; // VA(0x1000) + SRD(0x2000) > SizeOfImage(0x2000)
    return b;
}

static vector<uint8_t> build_section_ptr_overflow() {
    auto b = build_valid_skeleton();
    auto* s = sec0(b);
    s->PointerToRawData = FILE_SIZE - 100; // PRD + SRD(0x200) > pe_size(1024)
    return b;
}

// Positive import test: ordinal import must be rejected.
// Layout inside section raw data (VA 0x1000, file offset 512):
//   [ 0.. 40) 2 IMAGE_IMPORT_DESCRIPTORs (second is null terminator)
//   [40.. 56) OriginalFirstThunk: [IMAGE_ORDINAL_FLAG64|1, 0]
//   [56.. 72) FirstThunk: same two qwords
//   [72.. 85) "kernel32.dll\0"
static vector<uint8_t> build_ordinal_import() {
    auto b = build_valid_skeleton();
    auto& dd = nt_at(b)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    dd.VirtualAddress = SECT_VA;
    dd.Size           = sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;

    uint8_t* base = b.data() + SECT_RAW_OFFSET;
    auto*    desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base);
    desc[0].OriginalFirstThunk = SECT_VA + 40;
    desc[0].Name               = SECT_VA + 72;
    desc[0].FirstThunk         = SECT_VA + 56;
    // desc[1] left all-zero as terminator.

    auto* oft = reinterpret_cast<ULONGLONG*>(base + 40);
    oft[0] = IMAGE_ORDINAL_FLAG64 | 1ULL;
    oft[1] = 0;

    auto* ft = reinterpret_cast<ULONGLONG*>(base + 56);
    ft[0] = IMAGE_ORDINAL_FLAG64 | 1ULL;
    ft[1] = 0;

    memcpy(base + 72, "kernel32.dll\0", 13);
    return b;
}

// Oversized image: 0x7FFFFFFF > any sensible user-mode allocation.
// Chosen over UINT32_MAX to avoid u32 arithmetic surprises in the loader.
static vector<uint8_t> build_oversized_image() {
    auto b = build_valid_skeleton();
    nt_at(b)->OptionalHeader.SizeOfImage = 0x7FFFFFFF;
    return b;
}

// ---- Audit fix cases (12) --------------------------------------------------

// 1) e_lfanew is a signed LONG; a negative value would wrap to a huge size_t
// when cast. Fix: reject dos->e_lfanew < 0 before any arithmetic.
static vector<uint8_t> build_e_lfanew_negative() {
    auto b = build_valid_skeleton();
    dos_at(b)->e_lfanew = static_cast<LONG>(0x80000000); // sign bit set -> negative
    return b;
}

// 2) NumberOfSections == 0 is rejected (PE must have at least one section
// for the loader to do useful work; was previously unbounded on the low end).
static vector<uint8_t> build_sections_zero() {
    auto b = build_valid_skeleton();
    nt_at(b)->FileHeader.NumberOfSections = 0;
    return b;
}

// 3) NumberOfSections > 96 is rejected (PE spec maximum).
static vector<uint8_t> build_sections_above_cap() {
    auto b = build_valid_skeleton();
    nt_at(b)->FileHeader.NumberOfSections = 100;
    return b;
}

// 4) SizeOfHeaders must cover the section table (e_lfanew + sizeof(NT64) + N*sec hdr).
// Setting it below that bound is rejected so the section-header walk cannot
// read past the headers region.
static vector<uint8_t> build_size_of_headers_small_for_sections() {
    auto b = build_valid_skeleton();
    // Required: 64 + 264 + 1*40 = 368. Picking 200 is clearly below it
    // while still > sizeof(DOS)+sizeof(NT64) so earlier checks don't fire.
    nt_at(b)->OptionalHeader.SizeOfHeaders = 200;
    return b;
}

// 12) e_lfanew + sizeof(NT64) must not overrun pe_size. Picking a value just
// below FILE_SIZE exercises the arithmetic bound (not the "way out of range"
// path already covered by lfanew_out_of_bounds).
static vector<uint8_t> build_e_lfanew_plus_nt_overflow() {
    auto b = build_valid_skeleton();
    // 1020 + 264 = 1284 > 1024
    dos_at(b)->e_lfanew = static_cast<LONG>(FILE_SIZE - 4);
    return b;
}

// 9) Section whose VirtualAddress + Misc.VirtualSize > image_size must not
// let VirtualProtect flip pages past the allocation. SRD=0 skips the section
// copy so we land specifically in the protect-step bounds check.
static vector<uint8_t> build_virtual_protect_section_overflow() {
    auto b = build_valid_skeleton();
    auto* s = sec0(b);
    s->SizeOfRawData    = 0;       // skip memcpy / section_copy checks
    s->VirtualAddress   = 0x1000;
    s->Misc.VirtualSize = 0x2000;  // VA + VS = 0x3000 > SizeOfImage 0x2000
    return b;
}

// 10) VirtualSize alone > image_size is rejected in the protect step.
static vector<uint8_t> build_virtual_size_overflow() {
    auto b = build_valid_skeleton();
    auto* s = sec0(b);
    s->SizeOfRawData    = 0;
    s->VirtualAddress   = 0x1000;
    s->Misc.VirtualSize = 0x3000;  // > SizeOfImage 0x2000 on its own
    return b;
}

// 11) VirtualAddress > image_size is rejected in the section copy loop
// (SRD > 0 so the copy path, not the protect path, triggers).
static vector<uint8_t> build_section_va_above_image() {
    auto b = build_valid_skeleton();
    auto* s = sec0(b);
    s->VirtualAddress   = 0x3000;      // > SizeOfImage 0x2000
    s->Misc.VirtualSize = SECT_VIRT_SIZE;
    s->SizeOfRawData    = SECT_RAW_SIZE;
    s->PointerToRawData = SECT_RAW_OFFSET;
    return b;
}

// 5) IMPORT data directory VirtualAddress + Size overruns the image.
static vector<uint8_t> build_import_desc_overflow_dir() {
    auto b = build_valid_skeleton();
    auto& dd = nt_at(b)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    dd.VirtualAddress = SECT_VA;      // valid start
    dd.Size           = SIZE_OF_IMAGE; // VA + Size = 0x3000 > SizeOfImage
    return b;
}

// 6) Import descriptor's thunk RVA lies at/past image_size.
// Needs a valid desc->Name so the thunk bound check is what fails.
static vector<uint8_t> build_import_thunk_overflow_image() {
    auto b = build_valid_skeleton();
    auto& dd = nt_at(b)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    dd.VirtualAddress = SECT_VA;
    dd.Size           = sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;

    uint8_t* base = b.data() + SECT_RAW_OFFSET;
    auto*    desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base);
    desc[0].OriginalFirstThunk = SIZE_OF_IMAGE; // >= image_size -> rejected
    desc[0].FirstThunk         = SECT_VA + 56;  // valid, but check fires on OFT
    desc[0].Name               = SECT_VA + 40;  // valid "kernel32.dll\0" below
    // desc[1] zero terminator.
    // load_module() must succeed so we reach the thunk bound check; using a
    // real DLL ensures load_module("kernel32.dll") returns non-null.
    memcpy(base + 40, "kernel32.dll\0", 13);
    return b;
}

// ---- Extra coverage cases (FileHeader / OptionalHeader gaps) --------------

// NumberOfSections = 97 (one past the PE spec cap of 96).
static vector<uint8_t> build_sections_97() {
    auto b = build_valid_skeleton();
    nt_at(b)->FileHeader.NumberOfSections = 97;
    return b;
}

// NumberOfSections = 0xFFFF (worst case).
static vector<uint8_t> build_sections_ffff() {
    auto b = build_valid_skeleton();
    nt_at(b)->FileHeader.NumberOfSections = 0xFFFF;
    return b;
}

// SizeOfOptionalHeader = 0 -> != sizeof(IMAGE_OPTIONAL_HEADER64).
static vector<uint8_t> build_opt_header_size_zero() {
    auto b = build_valid_skeleton();
    nt_at(b)->FileHeader.SizeOfOptionalHeader = 0;
    return b;
}

// SizeOfOptionalHeader = 0xFFFF (way too large).
static vector<uint8_t> build_opt_header_size_huge() {
    auto b = build_valid_skeleton();
    nt_at(b)->FileHeader.SizeOfOptionalHeader = 0xFFFF;
    return b;
}

// Machine = 0 (another non-AMD64 path, distinct from the i386 case).
static vector<uint8_t> build_machine_zero() {
    auto b = build_valid_skeleton();
    nt_at(b)->FileHeader.Machine = 0;
    return b;
}

// SizeOfImage < SizeOfHeaders -> rejected post-alloc by the
// "SizeOfHeaders > image_size" bound check.
static vector<uint8_t> build_image_smaller_than_headers() {
    auto b = build_valid_skeleton();
    nt_at(b)->OptionalHeader.SizeOfImage = 0x100; // < SizeOfHeaders(512)
    return b;
}

// AddressOfEntryPoint >= SizeOfImage -> explicit late check.
static vector<uint8_t> build_entry_point_above_image() {
    auto b = build_valid_skeleton();
    nt_at(b)->OptionalHeader.AddressOfEntryPoint = SIZE_OF_IMAGE; // == image_size
    return b;
}

// SectionAlignment < 0x1000 -> rejected.
static vector<uint8_t> build_section_alignment_too_small() {
    auto b = build_valid_skeleton();
    nt_at(b)->OptionalHeader.SectionAlignment = 0x200;
    return b;
}

// ---- Documentation cases: fields the loader does NOT inspect --------------
// Each of these produces a maldito PE that the loader currently accepts.
// They map cleanly rather than crash (no UB), which is what this harness
// exists to confirm. Treat the "ok" expectation as a documented gap.

// AddressOfEntryPoint = 0 -> loader only rejects AOEP >= image_size.
static vector<uint8_t> build_entry_point_zero() {
    auto b = build_valid_skeleton();
    nt_at(b)->OptionalHeader.AddressOfEntryPoint = 0;
    return b;
}

// OptionalHeader.Magic = PE32 (0x10B). Loader validates via
// SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64) only; Magic
// itself is never read.
static vector<uint8_t> build_opt_magic_pe32() {
    auto b = build_valid_skeleton();
    nt_at(b)->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    return b;
}

// Characteristics without IMAGE_FILE_EXECUTABLE_IMAGE. Loader never
// inspects Characteristics.
static vector<uint8_t> build_characteristics_no_exe() {
    auto b = build_valid_skeleton();
    nt_at(b)->FileHeader.Characteristics = 0;
    return b;
}

// NumberOfRvaAndSizes = 0. Loader indexes DataDirectory by fixed indices
// regardless of this field, so the value has no effect.
static vector<uint8_t> build_rva_count_zero() {
    auto b = build_valid_skeleton();
    nt_at(b)->OptionalHeader.NumberOfRvaAndSizes = 0;
    return b;
}

// ---- Larger-section skeleton (for the string-NUL cases) --------------------
// The 1 KiB skeleton can't stage 512 non-NUL bytes in mapped memory (section
// raw data is only 512 bytes and VirtualAlloc pages are zero-filled). Grow
// the file so safe_strnlen actually scans 512 non-NUL bytes.

static constexpr uint32_t BIG_FILE_SIZE       = 4096;
static constexpr uint32_t BIG_SECT_RAW_OFFSET = 512;
static constexpr uint32_t BIG_SECT_RAW_SIZE   = 3584; // 4096 - 512
static constexpr uint32_t BIG_SECT_VIRT_SIZE  = 0x1000;

static vector<uint8_t> build_big_section_skeleton() {
    vector<uint8_t> buf(BIG_FILE_SIZE, 0);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    dos->e_magic  = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = static_cast<LONG>(NT_OFFSET);

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + NT_OFFSET);
    nt->Signature                       = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine              = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections     = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.Characteristics      = IMAGE_FILE_EXECUTABLE_IMAGE;

    auto& oh = nt->OptionalHeader;
    oh.Magic                       = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    oh.AddressOfEntryPoint         = SECT_VA;
    oh.ImageBase                   = IMAGE_BASE_LOW;
    oh.SectionAlignment            = 0x1000;
    oh.FileAlignment               = 0x200;
    oh.MajorOperatingSystemVersion = 6;
    oh.MajorSubsystemVersion       = 6;
    oh.SizeOfImage                 = SIZE_OF_IMAGE;
    oh.SizeOfHeaders               = SIZE_OF_HEADERS;
    oh.Subsystem                   = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    oh.NumberOfRvaAndSizes         = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    memcpy(sec->Name, ".text\0\0\0", 8);
    sec->Misc.VirtualSize = BIG_SECT_VIRT_SIZE;
    sec->VirtualAddress   = SECT_VA;
    sec->SizeOfRawData    = BIG_SECT_RAW_SIZE;
    sec->PointerToRawData = BIG_SECT_RAW_OFFSET;
    sec->Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

    return buf;
}

// 7) desc->Name points at >=512 non-NUL bytes with no terminator -> safe_strnlen
// returns SIZE_MAX and resolve_imports bails out.
static vector<uint8_t> build_import_name_no_null() {
    auto b = build_big_section_skeleton();
    auto& dd = nt_at(b)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    dd.VirtualAddress = SECT_VA;
    dd.Size           = sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;

    uint8_t* base = b.data() + BIG_SECT_RAW_OFFSET;
    auto*    desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base);
    desc[0].OriginalFirstThunk = SECT_VA + 40; // valid thunks (never reached)
    desc[0].FirstThunk         = SECT_VA + 56;
    desc[0].Name               = SECT_VA + 100; // 512-byte non-NUL run below

    // Fill [100 .. 100+512) with non-NUL bytes.
    memset(base + 100, 'A', 512);
    return b;
}

// 8) IMAGE_IMPORT_BY_NAME.Name is a >=512 non-NUL run with no terminator.
static vector<uint8_t> build_import_by_name_no_null() {
    auto b = build_big_section_skeleton();
    auto& dd = nt_at(b)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    dd.VirtualAddress = SECT_VA;
    dd.Size           = sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;

    uint8_t* base = b.data() + BIG_SECT_RAW_OFFSET;
    auto*    desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base);
    desc[0].OriginalFirstThunk = SECT_VA + 40;
    desc[0].FirstThunk         = SECT_VA + 56;
    desc[0].Name               = SECT_VA + 72; // valid "kernel32.dll\0"

    memcpy(base + 72, "kernel32.dll\0", 13);

    // Thunks point to an IMAGE_IMPORT_BY_NAME at offset 200. Hint is 2 bytes,
    // then the Name buffer: fill the Name run with 512 non-NUL bytes.
    const uint32_t by_name_offset = 200;
    auto* oft = reinterpret_cast<ULONGLONG*>(base + 40);
    oft[0] = SECT_VA + by_name_offset; // non-ordinal -> treated as name RVA
    oft[1] = 0;
    auto* ft = reinterpret_cast<ULONGLONG*>(base + 56);
    ft[0] = SECT_VA + by_name_offset;
    ft[1] = 0;

    // IMAGE_IMPORT_BY_NAME: WORD Hint; CHAR Name[1];
    // Zero Hint (2 bytes), then non-NUL Name from offset 202 for 512 bytes.
    base[by_name_offset + 0] = 0;
    base[by_name_offset + 1] = 0;
    memset(base + by_name_offset + 2, 'A', 512);
    return b;
}

// ---- Harness ---------------------------------------------------------------

struct test_case {
    const char*            name;
    pe_loader::map_error   expected;
    vector<uint8_t>      (*build)();
};

int main() {
    test_case cases[] = {
        // Case 0 is the sanity baseline: if this fails, build_valid_skeleton is
        // broken and every other test is unreliable.
        {"clean_ok",              pe_loader::map_error::ok,                  &build_valid_skeleton},
        {"null_ptr",              pe_loader::map_error::bad_dos_header,      &build_null},
        {"size_zero",             pe_loader::map_error::bad_dos_header,      &build_empty},
        {"bad_mz_magic",          pe_loader::map_error::bad_dos_header,      &build_bad_mz},
        {"lfanew_out_of_bounds",  pe_loader::map_error::bad_nt_header,       &build_bad_lfanew},
        {"bad_pe_signature",      pe_loader::map_error::bad_nt_header,       &build_bad_pe_sig},
        {"bad_machine",           pe_loader::map_error::bad_machine,         &build_bad_machine},
        {"size_of_headers_big",   pe_loader::map_error::bad_nt_header,       &build_big_size_of_headers},
        {"bad_opt_header_size",   pe_loader::map_error::bad_nt_header,       &build_bad_opt_header_size},
        {"reloc_block_too_small", pe_loader::map_error::reloc_failed,        &build_small_reloc_block},
        {"reloc_va_overflow",     pe_loader::map_error::reloc_failed,        &build_reloc_va_overflow},
        {"section_va_overflow",   pe_loader::map_error::section_copy_failed, &build_section_va_overflow},
        {"section_ptr_overflow",  pe_loader::map_error::section_copy_failed, &build_section_ptr_overflow},
        {"ordinal_import",        pe_loader::map_error::import_failed,       &build_ordinal_import},
        {"oversized_image",       pe_loader::map_error::alloc_failed,        &build_oversized_image},

        // Cases exercising today's audit fixes (one per fix).
        {"e_lfanew_negative",                   pe_loader::map_error::bad_nt_header,       &build_e_lfanew_negative},
        {"number_of_sections_zero",             pe_loader::map_error::bad_nt_header,       &build_sections_zero},
        {"number_of_sections_above_cap",        pe_loader::map_error::bad_nt_header,       &build_sections_above_cap},
        {"size_of_headers_too_small_for_sections", pe_loader::map_error::bad_nt_header,    &build_size_of_headers_small_for_sections},
        {"e_lfanew_plus_nt_overflow",           pe_loader::map_error::bad_nt_header,       &build_e_lfanew_plus_nt_overflow},
        {"import_desc_overflow_dir",            pe_loader::map_error::import_failed,       &build_import_desc_overflow_dir},
        {"import_thunk_overflow_image",         pe_loader::map_error::import_failed,       &build_import_thunk_overflow_image},
        {"import_name_no_null_terminator",      pe_loader::map_error::import_failed,       &build_import_name_no_null},
        {"import_by_name_no_null_terminator",   pe_loader::map_error::import_failed,       &build_import_by_name_no_null},
        {"virtual_protect_section_overflow",    pe_loader::map_error::protect_failed,      &build_virtual_protect_section_overflow},
        {"virtual_size_overflow",               pe_loader::map_error::protect_failed,      &build_virtual_size_overflow},
        {"section_va_above_image",              pe_loader::map_error::section_copy_failed, &build_section_va_above_image},

        // Extra FileHeader / OptionalHeader coverage.
        {"number_of_sections_97",               pe_loader::map_error::bad_nt_header,       &build_sections_97},
        {"number_of_sections_ffff",             pe_loader::map_error::bad_nt_header,       &build_sections_ffff},
        {"opt_header_size_zero",                pe_loader::map_error::bad_nt_header,       &build_opt_header_size_zero},
        {"opt_header_size_huge",                pe_loader::map_error::bad_nt_header,       &build_opt_header_size_huge},
        {"machine_zero",                        pe_loader::map_error::bad_machine,         &build_machine_zero},
        {"image_smaller_than_headers",          pe_loader::map_error::bad_nt_header,       &build_image_smaller_than_headers},
        {"entry_point_above_image",             pe_loader::map_error::bad_nt_header,       &build_entry_point_above_image},
        {"section_alignment_too_small",         pe_loader::map_error::bad_nt_header,       &build_section_alignment_too_small},

        // Documented gaps: loader does not inspect these fields -> maps ok.
        {"entry_point_zero",                    pe_loader::map_error::ok,                  &build_entry_point_zero},
        {"opt_magic_pe32",                      pe_loader::map_error::ok,                  &build_opt_magic_pe32},
        {"characteristics_no_exe",              pe_loader::map_error::ok,                  &build_characteristics_no_exe},
        {"number_of_rva_and_sizes_zero",        pe_loader::map_error::ok,                  &build_rva_count_zero},
    };

    const int total = static_cast<int>(sizeof(cases) / sizeof(*cases));
    int failures = 0;
    bool skeleton_ok = true;

    for (int idx = 0; idx < total; ++idx) {
        auto& tc = cases[idx];
        auto bytes = tc.build();
        pe_loader::mapped_image img{};
        const uint8_t* p = bytes.empty() ? nullptr : bytes.data();
        auto got = pe_loader::map(p, bytes.size(), img);
        bool pass = (got == tc.expected);
        if (!pass) {
            ++failures;
            if (idx == 0) skeleton_ok = false;
        }
        printf("[%s] %s (expected=%d got=%d)\n",
               pass ? "PASS" : "FAIL",
               tc.name,
               static_cast<int>(tc.expected),
               static_cast<int>(got));
        if (got == pe_loader::map_error::ok) pe_loader::unmap(img);
    }

    printf("\n%d/%d passed\n", total - failures, total);
    if (!skeleton_ok) {
        printf("FAIL: skeleton invalid (case 0) - all other tests unreliable\n");
    }
    return failures;
}
