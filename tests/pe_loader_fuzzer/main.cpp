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
