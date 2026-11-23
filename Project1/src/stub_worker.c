// Project1/src/stub_worker.c — Phase B.2:
//   AES-GCM decrypt + watermark verify + PE map + DllMain, all inside
//   the injected target process. No CRT, no string literals, no IAT.
//
// Compiled as a freestanding x86 COFF object by the BuildStubWorkerBlob
// target in Project1.vcxproj; the .text section is then extracted by
// scripts/extract_blob.ps1 and embedded as RCDATA resource
// SB_RESOURCE_WORKER_BLOB (= 101) in the loader image.
//
// Hard constraints:
//   - NO CRT calls (memcpy/memset are intrinsified to rep movsb/stosb).
//   - NO string literals / globals => no .rdata relocations into .text.
//   - NO libraries linked => no IAT.
//   - EVERY external API reached through pointers in `sb_worker_args`.
//   - EVERY Unicode string reached through fixed-size fields in args.

#include "../include/stub_worker.h"

// Only x86 intrinsics are used. __movsb is `rep movsb` inline; cl.exe
// never emits an external _memcpy for it. We avoid the standard memcpy
// identifier entirely so there is no chance cl.exe falls back to the
// CRT symbol.
void __movsb(unsigned char*, unsigned char const*, unsigned int);
#pragma intrinsic(__movsb)

// Replacement for u64 shifts — the ((uint64_t)hi << 32) idiom pulls in
// __allshl on x86. Everywhere we need to assemble a uint64_t from two
// uint32_t halves we go through this macro, which compiles to two
// plain `mov` instructions with no runtime helper call.
#define SB_U64_FROM_HI_LO(dst, hi32, lo32)         \
    do {                                           \
        uint32_t _parts[2];                        \
        _parts[0] = (uint32_t)(lo32);              \
        _parts[1] = (uint32_t)(hi32);              \
        __movsb((unsigned char*)&(dst),            \
                (unsigned char const*)_parts, 8);  \
    } while (0)

// ------------------- Function-pointer typedefs -------------------

typedef int32_t (__stdcall *pfn_open_alg)       (uint32_t*, const uint16_t*, const uint16_t*, uint32_t);
typedef int32_t (__stdcall *pfn_set_prop)       (uint32_t,  const uint16_t*, uint8_t*, uint32_t, uint32_t);
typedef int32_t (__stdcall *pfn_gen_sym_key)    (uint32_t,  uint32_t*, uint8_t*, uint32_t, uint8_t*, uint32_t, uint32_t);
typedef int32_t (__stdcall *pfn_decrypt)        (uint32_t,  uint8_t*, uint32_t, void*, uint8_t*, uint32_t, uint8_t*, uint32_t, uint32_t*, uint32_t);
typedef int32_t (__stdcall *pfn_destroy_key)    (uint32_t);
typedef int32_t (__stdcall *pfn_close_alg)      (uint32_t,  uint32_t);
typedef int32_t (__stdcall *pfn_create_hash)    (uint32_t,  uint32_t*, uint8_t*, uint32_t, uint8_t*, uint32_t, uint32_t);
typedef int32_t (__stdcall *pfn_hash_data)      (uint32_t,  uint8_t*, uint32_t, uint32_t);
typedef int32_t (__stdcall *pfn_finish_hash)    (uint32_t,  uint8_t*, uint32_t, uint32_t);
typedef int32_t (__stdcall *pfn_destroy_hash)   (uint32_t);

typedef void*   (__stdcall *pfn_virtual_alloc)  (void*, uint32_t, uint32_t, uint32_t);
typedef int32_t (__stdcall *pfn_virtual_free)   (void*, uint32_t, uint32_t);
typedef int32_t (__stdcall *pfn_virtual_protect)(void*, uint32_t, uint32_t, uint32_t*);
typedef int32_t (__stdcall *pfn_flush_icache)   (void*, const void*, uint32_t);
typedef void*   (__stdcall *pfn_get_current_proc)(void);
typedef void*   (__stdcall *pfn_load_library_a) (const char*);
typedef void*   (__stdcall *pfn_get_proc_address)(void*, const char*);
typedef void    (__stdcall *pfn_get_system_time)(void*);

typedef int32_t (__stdcall *pfn_dll_main)       (void*, uint32_t, void*);

// ------------------- PE32 structural mirrors ---------------------

#pragma pack(push, 2)
struct sb_dos_header {
    uint16_t e_magic;
    uint8_t  _pad[58];
    int32_t  e_lfanew;
};
#pragma pack(pop)

#pragma pack(push, 4)
struct sb_file_header {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct sb_data_directory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct sb_opt_header32 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    struct sb_data_directory DataDirectory[16];
};

struct sb_nt_headers32 {
    uint32_t Signature;
    struct sb_file_header  FileHeader;
    struct sb_opt_header32 OptionalHeader;
};

struct sb_section_header {
    uint8_t  Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct sb_import_descriptor {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};

struct sb_base_reloc {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
};
#pragma pack(pop)

// ------------------- PE constants --------------------------------
#define SB_DOS_SIG            0x5A4Du
#define SB_NT_SIG             0x00004550u
#define SB_MACH_I386          0x014Cu
#define SB_OPT_PE32           0x010Bu
#define SB_DIR_IMPORT         1
#define SB_DIR_BASERELOC      5
#define SB_SCN_EXEC           0x20000000u
#define SB_SCN_READ           0x40000000u
#define SB_SCN_WRITE          0x80000000u
#define SB_REL_ABSOLUTE       0
#define SB_REL_HIGHLOW        3
#define SB_IMPORT_BY_ORDINAL  0x80000000u

#define SB_MEM_COMMIT         0x1000u
#define SB_MEM_RESERVE        0x2000u
#define SB_MEM_RELEASE        0x8000u
#define SB_PAGE_NOACCESS      0x01u
#define SB_PAGE_READONLY      0x02u
#define SB_PAGE_READWRITE     0x04u
#define SB_PAGE_EXECUTE       0x10u
#define SB_PAGE_EXECUTE_READ  0x20u
#define SB_PAGE_EXECUTE_RW    0x40u

#define SB_DLL_PROCESS_ATTACH 1u

// ------------------- Small helpers -------------------------------

static struct sb_section_header* sb_first_section(struct sb_nt_headers32* nt) {
    return (struct sb_section_header*)
        ((uint8_t*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
}

static int sb_ct_eq32(const uint8_t* a, const uint8_t* b) {
    uint8_t acc = 0;
    for (int i = 0; i < 32; ++i) acc |= (uint8_t)(a[i] ^ b[i]);
    return acc == 0;
}

static uint64_t sb_rd_u64_le(const uint8_t* p) {
    // Byte-wise OR with 64-bit shifts pulls in __allshl. x86 is
    // little-endian so a direct copy is equivalent and helper-free.
    uint64_t v;
    __movsb((unsigned char*)&v, (unsigned char const*)p, 8);
    return v;
}

static uint32_t sb_prot(uint32_t c) {
    int e = (c & SB_SCN_EXEC)  != 0;
    int r = (c & SB_SCN_READ)  != 0;
    int w = (c & SB_SCN_WRITE) != 0;
    if (e && w) return SB_PAGE_EXECUTE_RW;
    if (e && r) return SB_PAGE_EXECUTE_READ;
    if (e)      return SB_PAGE_EXECUTE;
    if (r && w) return SB_PAGE_READWRITE;
    if (w)      return SB_PAGE_READWRITE;
    if (r)      return SB_PAGE_READONLY;
    return SB_PAGE_NOACCESS;
}

// Number of bytes (including trailing L"\0") in a fixed wide buffer.
static uint32_t sb_wcslen_bytes(const uint16_t* s) {
    uint32_t cb = 0;
    while (s[cb / 2] != 0) cb += 2;
    return cb + 2;
}

// ------------------- HMAC-SHA256 via BCrypt ----------------------
static int sb_hmac_sha256(
    struct sb_worker_args* a,
    const uint8_t* key, uint32_t key_len,
    const uint8_t* data, uint32_t data_len,
    uint8_t out[32])
{
    pfn_open_alg     open_alg     = (pfn_open_alg)    a->p_open_alg;
    pfn_create_hash  create_hash  = (pfn_create_hash) a->p_create_hash;
    pfn_hash_data    hash_data    = (pfn_hash_data)   a->p_hash_data;
    pfn_finish_hash  finish_hash  = (pfn_finish_hash) a->p_finish_hash;
    pfn_destroy_hash destroy_hash = (pfn_destroy_hash)a->p_destroy_hash;
    pfn_close_alg    close_alg    = (pfn_close_alg)   a->p_close_alg;

    uint32_t h_alg = 0, h_hash = 0;
    int ok = 0;
    if (open_alg(&h_alg, a->s_sha256, (const uint16_t*)0, SB_BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0)
        return 0;
    if (create_hash(h_alg, &h_hash, (uint8_t*)0, 0, (uint8_t*)key, key_len, 0) >= 0) {
        if (hash_data(h_hash, (uint8_t*)data, data_len, 0) >= 0) {
            if (finish_hash(h_hash, out, 32, 0) >= 0) ok = 1;
        }
    }
    if (h_hash) destroy_hash(h_hash);
    close_alg(h_alg, 0);
    return ok;
}

// ------------------- Watermark verify ----------------------------
// wm[0..32]   = hwid_hash
// wm[32..64]  = license_hash
// wm[64..72]  = issued_at (u64 LE)
// wm[72..80]  = ttl (u64 LE)
// wm[80..96]  = nonce (opaque)
// wm[96..128] = HMAC-SHA256(k_watermark, wm[0..96])
static uint32_t sb_verify_watermark(struct sb_worker_args* a) {
    const uint8_t* wm = (const uint8_t*)(uintptr_t)a->pt_ptr;

    if (!sb_ct_eq32(a->hwid_bytes,    wm + 0))   return SB_RC_WM_HWID_MISMATCH;
    if (!sb_ct_eq32(a->license_hash,  wm + 32))  return SB_RC_WM_LICENSE_MISMATCH;

    uint64_t issued_at = sb_rd_u64_le(wm + 64);
    uint64_t ttl       = sb_rd_u64_le(wm + 72);

    pfn_get_system_time get_time = (pfn_get_system_time)a->p_get_system_time;
    struct sb_filetime ft;
    get_time(&ft);

    // Load FILETIME as a single uint64_t without the ((hi << 32) | lo)
    // idiom, which emits __allshl on x86.
    uint64_t ft100;
    SB_U64_FROM_HI_LO(ft100, ft.dwHighDateTime, ft.dwLowDateTime);

    uint64_t deadline_unix = issued_at + ttl;
    if (deadline_unix < issued_at) return SB_RC_WM_EXPIRED; // u64 overflow

    // Compute deadline_100ns = SB_UNIX_EPOCH_100NS + deadline_unix * 1e7
    // without invoking __allmul or __aulldiv. We expand u64 * u32 as two
    // 32x32->64 multiplies (which cl emits as inline MUL edx:eax) and
    // reassemble by dword — never using a u64 shift.
    uint32_t a_lo = (uint32_t)deadline_unix;
    uint32_t a_hi = (uint32_t)(deadline_unix >> 32); // emits `mov reg, [dl+4]`
    uint64_t lo64 = (uint64_t)a_lo * 10000000u;
    uint64_t hi64 = (uint64_t)a_hi * 10000000u;
    uint32_t lo_lo = (uint32_t)lo64;
    uint32_t lo_hi = (uint32_t)(lo64 >> 32);
    uint32_t hi_lo = (uint32_t)hi64;
    uint32_t sum_hi = lo_hi + hi_lo;
    uint64_t deadline_100ns;
    SB_U64_FROM_HI_LO(deadline_100ns, sum_hi, lo_lo);
    deadline_100ns += SB_UNIX_EPOCH_100NS;

    if (ft100 > deadline_100ns) return SB_RC_WM_EXPIRED;

    uint8_t sig[32];
    if (!sb_hmac_sha256(a, a->k_watermark, 32, wm, 96, sig))
        return SB_RC_WM_SIG_FAIL;
    if (!sb_ct_eq32(sig, wm + 96))
        return SB_RC_WM_SIG_FAIL;

    return SB_RC_OK;
}

// ------------------- PE map (i386) -------------------------------
static uint32_t sb_map_pe(struct sb_worker_args* a,
                          const uint8_t* pe_bytes, uint32_t pe_size)
{
    if (pe_size < sizeof(struct sb_dos_header)) return SB_RC_PE_BAD_DOS;
    const struct sb_dos_header* dos = (const struct sb_dos_header*)pe_bytes;
    if (dos->e_magic != SB_DOS_SIG)   return SB_RC_PE_BAD_DOS;
    if (dos->e_lfanew < 0)            return SB_RC_PE_BAD_NT;
    if ((uint32_t)dos->e_lfanew + sizeof(struct sb_nt_headers32) > pe_size) return SB_RC_PE_BAD_NT;

    const struct sb_nt_headers32* nt_src =
        (const struct sb_nt_headers32*)(pe_bytes + dos->e_lfanew);
    if (nt_src->Signature != SB_NT_SIG)               return SB_RC_PE_BAD_NT;
    if (nt_src->FileHeader.Machine != SB_MACH_I386)   return SB_RC_PE_BAD_MACHINE;
    if (nt_src->OptionalHeader.Magic != SB_OPT_PE32)  return SB_RC_PE_BAD_NT;
    if (nt_src->FileHeader.SizeOfOptionalHeader < sizeof(struct sb_opt_header32)) return SB_RC_PE_BAD_NT;
    if (nt_src->OptionalHeader.SectionAlignment < 0x1000) return SB_RC_PE_BAD_NT;

    uint16_t n_sec = nt_src->FileHeader.NumberOfSections;
    if (n_sec == 0 || n_sec > 96) return SB_RC_PE_BAD_NT;

    uint32_t image_size = nt_src->OptionalHeader.SizeOfImage;
    if (image_size == 0 || image_size > 0x10000000u) return SB_RC_PE_ALLOC_FAIL;

    pfn_virtual_alloc    valloc   = (pfn_virtual_alloc)   a->p_virtual_alloc;
    pfn_virtual_free     vfree    = (pfn_virtual_free)    a->p_virtual_free;
    pfn_virtual_protect  vprot    = (pfn_virtual_protect) a->p_virtual_protect;
    pfn_flush_icache     ficache  = (pfn_flush_icache)    a->p_flush_icache;
    pfn_get_current_proc gcurproc = (pfn_get_current_proc)a->p_get_current_proc;
    pfn_load_library_a   lla      = (pfn_load_library_a)  a->p_load_library_a;
    pfn_get_proc_address gpa      = (pfn_get_proc_address)a->p_get_proc_address;

    uint8_t* base = (uint8_t*)valloc(
        (void*)0, image_size, SB_MEM_COMMIT | SB_MEM_RESERVE, SB_PAGE_READWRITE);
    if (!base) return SB_RC_PE_ALLOC_FAIL;

    uint32_t sz_hdrs = nt_src->OptionalHeader.SizeOfHeaders;
    if (sz_hdrs > pe_size || sz_hdrs > image_size) {
        vfree(base, 0, SB_MEM_RELEASE);
        return SB_RC_PE_BAD_NT;
    }
    __movsb((unsigned char*)base, (unsigned char const*)pe_bytes, sz_hdrs);

    struct sb_nt_headers32*  nt_dst = (struct sb_nt_headers32*)(base + dos->e_lfanew);
    struct sb_section_header* sec   = sb_first_section(nt_dst);

    // --- Copy sections ---
    for (uint16_t i = 0; i < n_sec; ++i) {
        if (sec[i].SizeOfRawData == 0) continue;
        if (sec[i].VirtualAddress > image_size ||
            sec[i].SizeOfRawData > image_size ||
            (uint64_t)sec[i].VirtualAddress + sec[i].SizeOfRawData > image_size ||
            (uint64_t)sec[i].PointerToRawData + sec[i].SizeOfRawData > pe_size)
        {
            vfree(base, 0, SB_MEM_RELEASE);
            return SB_RC_PE_SEC_COPY_FAIL;
        }
        __movsb((unsigned char*)(base + sec[i].VirtualAddress),
                (unsigned char const*)(pe_bytes + sec[i].PointerToRawData),
                sec[i].SizeOfRawData);
    }

    // --- Apply base relocations ---
    {
        struct sb_data_directory* rdir =
            &nt_dst->OptionalHeader.DataDirectory[SB_DIR_BASERELOC];
        if (rdir->Size && rdir->VirtualAddress) {
            if (rdir->VirtualAddress > image_size ||
                (uint64_t)rdir->VirtualAddress + rdir->Size > image_size)
            {
                vfree(base, 0, SB_MEM_RELEASE);
                return SB_RC_PE_RELOC_FAIL;
            }
            uint32_t delta = (uint32_t)(uintptr_t)base - nt_src->OptionalHeader.ImageBase;
            if (delta != 0) {
                struct sb_base_reloc* block =
                    (struct sb_base_reloc*)(base + rdir->VirtualAddress);
                uint8_t* r_end = (uint8_t*)block + rdir->Size;
                while ((uint8_t*)block < r_end && block->SizeOfBlock != 0) {
                    if (block->SizeOfBlock < sizeof(struct sb_base_reloc) ||
                        (uint8_t*)block + block->SizeOfBlock > r_end)
                    {
                        vfree(base, 0, SB_MEM_RELEASE);
                        return SB_RC_PE_RELOC_FAIL;
                    }
                    uint32_t count  = (block->SizeOfBlock - sizeof(struct sb_base_reloc)) / sizeof(uint16_t);
                    uint16_t* entries = (uint16_t*)(block + 1);
                    for (uint32_t j = 0; j < count; ++j) {
                        uint16_t type = entries[j] >> 12;
                        uint16_t offs = entries[j] & 0x0FFFu;
                        if (type == SB_REL_ABSOLUTE) continue;
                        if (type == SB_REL_HIGHLOW) {
                            if ((uint64_t)block->VirtualAddress + offs + 4 > image_size) {
                                vfree(base, 0, SB_MEM_RELEASE);
                                return SB_RC_PE_RELOC_FAIL;
                            }
                            uint32_t* target =
                                (uint32_t*)(base + block->VirtualAddress + offs);
                            *target += delta;
                            continue;
                        }
                        vfree(base, 0, SB_MEM_RELEASE);
                        return SB_RC_PE_RELOC_FAIL;
                    }
                    block = (struct sb_base_reloc*)((uint8_t*)block + block->SizeOfBlock);
                }
            }
        }
    }

    // --- Resolve imports ---
    {
        struct sb_data_directory* idir =
            &nt_dst->OptionalHeader.DataDirectory[SB_DIR_IMPORT];
        if (idir->Size && idir->VirtualAddress) {
            if (idir->VirtualAddress > image_size ||
                (uint64_t)idir->VirtualAddress + idir->Size > image_size)
            {
                vfree(base, 0, SB_MEM_RELEASE);
                return SB_RC_PE_IMPORT_FAIL;
            }
            struct sb_import_descriptor* desc =
                (struct sb_import_descriptor*)(base + idir->VirtualAddress);
            uint8_t* image_end = base + image_size;
            while ((uint8_t*)desc + sizeof(struct sb_import_descriptor) <= image_end
                   && desc->Name != 0)
            {
                if (desc->Name >= image_size) {
                    vfree(base, 0, SB_MEM_RELEASE);
                    return SB_RC_PE_IMPORT_FAIL;
                }
                char* mod_name = (char*)(base + desc->Name);
                void* mod = lla(mod_name);
                if (!mod) {
                    vfree(base, 0, SB_MEM_RELEASE);
                    return SB_RC_PE_IMPORT_FAIL;
                }
                uint32_t thunk_rva = desc->OriginalFirstThunk
                                     ? desc->OriginalFirstThunk
                                     : desc->FirstThunk;
                uint32_t iat_rva   = desc->FirstThunk;
                if (!thunk_rva || !iat_rva ||
                    thunk_rva >= image_size || iat_rva >= image_size)
                {
                    vfree(base, 0, SB_MEM_RELEASE);
                    return SB_RC_PE_IMPORT_FAIL;
                }
                uint32_t* orig = (uint32_t*)(base + thunk_rva);
                uint32_t* iat  = (uint32_t*)(base + iat_rva);
                while ((uint8_t*)orig + 4 <= image_end &&
                       (uint8_t*)iat  + 4 <= image_end &&
                       *orig != 0)
                {
                    if (*orig & SB_IMPORT_BY_ORDINAL) {
                        vfree(base, 0, SB_MEM_RELEASE);
                        return SB_RC_PE_IMPORT_FAIL; // ordinal unsupported
                    }
                    uint32_t name_rva = *orig;
                    if (name_rva + 3 >= image_size) {
                        vfree(base, 0, SB_MEM_RELEASE);
                        return SB_RC_PE_IMPORT_FAIL;
                    }
                    // IMAGE_IMPORT_BY_NAME = WORD Hint; char Name[].
                    char* fn_name = (char*)(base + name_rva + 2);
                    void* fn = gpa(mod, fn_name);
                    if (!fn) {
                        vfree(base, 0, SB_MEM_RELEASE);
                        return SB_RC_PE_IMPORT_FAIL;
                    }
                    *iat = (uint32_t)(uintptr_t)fn;
                    orig++; iat++;
                }
                desc++;
            }
        }
    }

    // --- Per-section protection ---
    for (uint16_t i = 0; i < n_sec; ++i) {
        if (sec[i].VirtualSize == 0) continue;
        if (sec[i].VirtualAddress > image_size ||
            sec[i].VirtualSize > image_size ||
            (uint64_t)sec[i].VirtualAddress + sec[i].VirtualSize > image_size)
        {
            vfree(base, 0, SB_MEM_RELEASE);
            return SB_RC_PE_PROTECT_FAIL;
        }
        uint32_t old = 0;
        if (!vprot(base + sec[i].VirtualAddress,
                   sec[i].VirtualSize,
                   sb_prot(sec[i].Characteristics), &old))
        {
            vfree(base, 0, SB_MEM_RELEASE);
            return SB_RC_PE_PROTECT_FAIL;
        }
    }

    // --- Anti-dump wipe of headers, then read-only ---
    {
        uint32_t old = 0;
        if (!vprot(base, sz_hdrs, SB_PAGE_READWRITE, &old)) {
            vfree(base, 0, SB_MEM_RELEASE);
            return SB_RC_PE_PROTECT_FAIL;
        }
        struct sb_dos_header* dos_dst = (struct sb_dos_header*)base;
        dos_dst->e_magic = 0;
        nt_dst->Signature = 0;
        dos_dst->e_lfanew = 0;
        if (!vprot(base, sz_hdrs, SB_PAGE_READONLY, &old)) {
            vfree(base, 0, SB_MEM_RELEASE);
            return SB_RC_PE_PROTECT_FAIL;
        }
    }

    ficache(gcurproc(), base, image_size);

    if (nt_src->OptionalHeader.AddressOfEntryPoint >= image_size) {
        vfree(base, 0, SB_MEM_RELEASE);
        return SB_RC_PE_BAD_NT;
    }

    a->mapped_base = (uint32_t)(uintptr_t)base;
    a->mapped_size = image_size;
    a->entry_point = (uint32_t)(uintptr_t)
        (base + nt_src->OptionalHeader.AddressOfEntryPoint);
    return SB_RC_OK;
}

// ------------------- Entry point ---------------------------------
// __stdcall: the caller (stub.asm) pushes `args`, the worker clears via
// `ret 4`. x86 linker decorates to `_worker_entry@4`; the extracted
// blob starts with this function's prologue because /Gy- forces every
// static-inlined local into the same `.text$mn` as the entry point.
uint32_t __stdcall worker_entry(struct sb_worker_args* args) {
    if (!args)                                              return SB_RC_ARGS_NULL;
    if (args->stop_flag)                                    return SB_RC_STOP_FLAG;
    if (!args->p_load_library_a || !args->p_get_proc_address) return SB_RC_MISSING_PFN;
    if (!args->p_open_alg || !args->p_set_prop ||
        !args->p_gen_sym_key || !args->p_decrypt ||
        !args->p_destroy_key || !args->p_close_alg)         return SB_RC_MISSING_PFN;
    if (!args->p_create_hash || !args->p_hash_data ||
        !args->p_finish_hash || !args->p_destroy_hash)      return SB_RC_MISSING_PFN;
    if (!args->p_virtual_alloc || !args->p_virtual_free ||
        !args->p_virtual_protect || !args->p_flush_icache ||
        !args->p_get_current_proc || !args->p_get_system_time) return SB_RC_MISSING_PFN;
    if (args->pt_cap < args->ct_len)                        return SB_RC_PT_CAP_TOO_SMALL;

    // ---------- AES-GCM decrypt ----------
    pfn_open_alg    open_alg    = (pfn_open_alg)   args->p_open_alg;
    pfn_set_prop    set_prop    = (pfn_set_prop)   args->p_set_prop;
    pfn_gen_sym_key gen_sym_key = (pfn_gen_sym_key)args->p_gen_sym_key;
    pfn_decrypt     decrypt     = (pfn_decrypt)    args->p_decrypt;
    pfn_destroy_key destroy_key = (pfn_destroy_key)args->p_destroy_key;
    pfn_close_alg   close_alg   = (pfn_close_alg)  args->p_close_alg;

    uint32_t h_alg_aes = 0, h_key = 0;
    int32_t st = open_alg(&h_alg_aes, args->s_aes, (const uint16_t*)0, 0);
    if (st < 0) { args->result_code = SB_RC_OPEN_ALG_FAILED; return SB_RC_OPEN_ALG_FAILED; }

    {
        uint32_t cb = sb_wcslen_bytes(args->s_chaining_mode_gcm);
        st = set_prop(h_alg_aes, args->s_chaining_mode,
                      (uint8_t*)args->s_chaining_mode_gcm, cb, 0);
        if (st < 0) {
            close_alg(h_alg_aes, 0);
            args->result_code = SB_RC_SET_CHAIN_FAILED;
            return SB_RC_SET_CHAIN_FAILED;
        }
    }

    st = gen_sym_key(h_alg_aes, &h_key, (uint8_t*)0, 0,
                     args->k_payload_aes, 32, 0);
    if (st < 0) {
        close_alg(h_alg_aes, 0);
        args->result_code = SB_RC_GEN_KEY_FAILED;
        return SB_RC_GEN_KEY_FAILED;
    }

    struct sb_bcrypt_auth_info info;
    info.cbSize        = sizeof(info);
    info.dwInfoVersion = SB_BCRYPT_AUTH_MODE_INFO_VERSION;
    info.pbNonce       = (uint32_t)(uintptr_t)args->iv;
    info.cbNonce       = 12;
    info.pbAuthData    = 0;
    info.cbAuthData    = 0;
    info.pbTag         = (uint32_t)(uintptr_t)args->tag;
    info.cbTag         = 16;
    info.pbMacContext  = 0;
    info.cbMacContext  = 0;
    info.cbAAD         = 0;
    info.cbData        = 0;
    info.dwFlags       = 0;

    uint32_t pt_written = 0;
    st = decrypt(h_key,
                 (uint8_t*)(uintptr_t)args->ct_ptr, args->ct_len,
                 &info,
                 (uint8_t*)0, 0,
                 (uint8_t*)(uintptr_t)args->pt_ptr, args->pt_cap,
                 &pt_written, 0);
    destroy_key(h_key);
    close_alg(h_alg_aes, 0);
    if (st < 0) {
        args->result_code = SB_RC_DECRYPT_FAILED;
        return SB_RC_DECRYPT_FAILED;
    }
    args->pt_len_out = pt_written;

    // ---------- Watermark verify ----------
    if (pt_written < 128) {
        args->result_code = SB_RC_WM_SHORT;
        return SB_RC_WM_SHORT;
    }
    uint32_t rc = sb_verify_watermark(args);
    if (rc != SB_RC_OK) { args->result_code = rc; return rc; }

    // ---------- PE map ----------
    const uint8_t* pe_bytes = (const uint8_t*)(uintptr_t)args->pt_ptr + 128;
    uint32_t       pe_size  = pt_written - 128;
    rc = sb_map_pe(args, pe_bytes, pe_size);
    if (rc != SB_RC_OK) { args->result_code = rc; return rc; }

    // ---------- Call DllMain(DLL_PROCESS_ATTACH) ----------
    pfn_dll_main dll_main = (pfn_dll_main)(uintptr_t)args->entry_point;
    int32_t dr = dll_main((void*)(uintptr_t)args->mapped_base,
                          SB_DLL_PROCESS_ATTACH, (void*)0);
    args->dll_main_rc = (uint32_t)dr;
    if (dr == 0) {
        args->result_code = SB_RC_DLLMAIN_FAIL;
        return SB_RC_DLLMAIN_FAIL;
    }

    args->result_code = SB_RC_OK;
    return SB_RC_OK;
}
