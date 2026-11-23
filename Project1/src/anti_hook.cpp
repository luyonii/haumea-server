#include "anti_hook.h"
#include "dynapi.h"
#include "obfstr.h"

#include <Windows.h>

namespace anti_hook {

// Up to 4 trusted module hashes per watched API; 0 terminates the set.
struct watched {
    uint32_t api_hash;
    uint32_t resolve_module_hash;
    uint32_t trust_module_hashes[4];
};

// bcryptprimitives.dll — hash computed at runtime below (may not be loaded).
static const uint32_t MOD_BCRYPT_PRIMITIVES = MOD_HASH("bcryptprimitives.dll");

// 16 slots. kernel32 APIs trust {kernel32, kernelbase, ntdll}; ntdll APIs trust
// {ntdll}; BCryptDecrypt trusts {bcrypt, bcryptPrimitives, ntdll}.
static const watched WATCH[16] = {
    { API_HASH("NtQueryInformationProcess"), dynapi::modules::NTDLL,
        { dynapi::modules::NTDLL, 0, 0, 0 } },
    { API_HASH("NtQuerySystemInformation"),  dynapi::modules::NTDLL,
        { dynapi::modules::NTDLL, 0, 0, 0 } },
    { API_HASH("NtSetInformationThread"),    dynapi::modules::NTDLL,
        { dynapi::modules::NTDLL, 0, 0, 0 } },
    { API_HASH("NtProtectVirtualMemory"),    dynapi::modules::NTDLL,
        { dynapi::modules::NTDLL, 0, 0, 0 } },
    { API_HASH("NtAllocateVirtualMemory"),   dynapi::modules::NTDLL,
        { dynapi::modules::NTDLL, 0, 0, 0 } },
    { API_HASH("NtWriteVirtualMemory"),      dynapi::modules::NTDLL,
        { dynapi::modules::NTDLL, 0, 0, 0 } },
    { API_HASH("NtReadVirtualMemory"),       dynapi::modules::NTDLL,
        { dynapi::modules::NTDLL, 0, 0, 0 } },
    { API_HASH("NtCreateThreadEx"),          dynapi::modules::NTDLL,
        { dynapi::modules::NTDLL, 0, 0, 0 } },
    { API_HASH("LoadLibraryA"),              dynapi::modules::KERNEL32,
        { dynapi::modules::KERNEL32, dynapi::modules::KERNELBASE, dynapi::modules::NTDLL, 0 } },
    { API_HASH("LoadLibraryW"),              dynapi::modules::KERNEL32,
        { dynapi::modules::KERNEL32, dynapi::modules::KERNELBASE, dynapi::modules::NTDLL, 0 } },
    { API_HASH("VirtualAlloc"),              dynapi::modules::KERNEL32,
        { dynapi::modules::KERNEL32, dynapi::modules::KERNELBASE, dynapi::modules::NTDLL, 0 } },
    { API_HASH("VirtualProtect"),            dynapi::modules::KERNEL32,
        { dynapi::modules::KERNEL32, dynapi::modules::KERNELBASE, dynapi::modules::NTDLL, 0 } },
    { API_HASH("GetProcAddress"),            dynapi::modules::KERNEL32,
        { dynapi::modules::KERNEL32, dynapi::modules::KERNELBASE, dynapi::modules::NTDLL, 0 } },
    { API_HASH("CreateFileW"),               dynapi::modules::KERNEL32,
        { dynapi::modules::KERNEL32, dynapi::modules::KERNELBASE, dynapi::modules::NTDLL, 0 } },
    { API_HASH("WriteFile"),                 dynapi::modules::KERNEL32,
        { dynapi::modules::KERNEL32, dynapi::modules::KERNELBASE, dynapi::modules::NTDLL, 0 } },
    { API_HASH("BCryptDecrypt"),             dynapi::modules::BCRYPT,
        { dynapi::modules::BCRYPT, MOD_BCRYPT_PRIMITIVES, dynapi::modules::NTDLL, 0 } },
};

static bool in_module(void* p, void* base) {
    if (!p || !base) return false;
    auto mod = static_cast<uint8_t*>(base);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto size = nt->OptionalHeader.SizeOfImage;
    auto addr = static_cast<uint8_t*>(p);
    return addr >= mod && addr < mod + size;
}

static bool in_any_trusted(void* tgt, void* const* trusted, size_t n) {
    for (size_t i = 0; i < n; ++i)
        if (trusted[i] && in_module(tgt, trusted[i])) return true;
    return false;
}

// shortcut: inspects only first-byte / prologue patterns (E9, E8, FF 25, CC).
// Mid-prologue inline hooks and push-ret / mov-rax-jmp-rax detours slip past.
// Upgrade: scan first ~15 bytes with a mini-disassembler.
static bool is_hooked(void* api, void* const* trusted, size_t n_trusted) {
    if (!api) return false;
    auto b = static_cast<uint8_t*>(api);

    if (b[0] == 0xCC) return true;

    if (b[0] == 0xE9) {
        auto rel = *reinterpret_cast<int32_t*>(b + 1);
        void* tgt = b + 5 + rel;
        return !in_any_trusted(tgt, trusted, n_trusted);
    }
    if (b[0] == 0xE8) {
        auto rel = *reinterpret_cast<int32_t*>(b + 1);
        void* tgt = b + 5 + rel;
        return !in_any_trusted(tgt, trusted, n_trusted);
    }
    if (b[0] == 0xFF && b[1] == 0x25) {
#if defined(_M_X64)
        // FF 25 rel32 -> RIP-relative on x64
        auto rel = *reinterpret_cast<int32_t*>(b + 2);
        auto slot = reinterpret_cast<void**>(b + 6 + rel);
#else
        // FF 25 abs32 -> absolute address on x86
        auto addr = *reinterpret_cast<uintptr_t*>(b + 2);
        auto slot = reinterpret_cast<void**>(addr);
#endif
        void* tgt = *slot;
        return !in_any_trusted(tgt, trusted, n_trusted);
    }
    return false;
}

uint32_t check_critical_apis() {
    uint32_t mask = 0;
    for (uint32_t i = 0; i < 16; ++i) {
        auto base = dynapi::get_module(WATCH[i].resolve_module_hash);
        if (!base) continue;
        auto api = dynapi::resolve(base, WATCH[i].api_hash);
        if (!api) continue;

        // Build trusted bases list (skip unloaded modules silently).
        void* trusted[4] = { nullptr, nullptr, nullptr, nullptr };
        size_t n = 0;
        for (size_t k = 0; k < 4; ++k) {
            uint32_t h = WATCH[i].trust_module_hashes[k];
            if (!h) break;
            void* mb = dynapi::get_module(h);
            if (mb) trusted[n++] = mb;
        }
        if (n == 0) continue;

        if (is_hooked(api, trusted, n))
            mask |= (1u << i);
    }
    return mask;
}

} // namespace anti_hook
