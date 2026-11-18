#include "dynapi.h"

#include <Windows.h>
#include <intrin.h>

namespace dynapi {

// ---------------------------------------------------------------------------
// Runtime wide-string hash (case-insensitive). Must produce the same value as
// hash_module() for the same ASCII input so that compile-time constants match.
// ---------------------------------------------------------------------------
// Runtime FNV-1a over an ASCII name, lower-casing A-Z and simulating the
// wchar_t high byte (0 for ASCII) so output matches compile-time hash_module()
// and the PEB-walk wide-char hash.
uint32_t hash_module_runtime(const char* str) {
    uint32_t h = 2166136261u;
    while (*str) {
        uint8_t c = static_cast<uint8_t>(*str++);
        if (c >= 'A' && c <= 'Z') c |= 0x20;
        h ^= c;
        h *= 16777619u;
        h ^= 0u;
        h *= 16777619u;
    }
    return h;
}

static uint32_t hash_wide_lower(const wchar_t* str, size_t char_count) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < char_count; ++i) {
        wchar_t c = str[i];
        if (c >= L'A' && c <= L'Z') c |= 0x20;
        h ^= static_cast<uint8_t>(c & 0xFF);
        h *= 16777619u;
        h ^= static_cast<uint8_t>((c >> 8) & 0xFF);
        h *= 16777619u;
    }
    return h;
}

// ---------------------------------------------------------------------------
// PEB walk — x64 only
// ---------------------------------------------------------------------------
//
// TEB+0x60  -> PEB
// PEB+0x18  -> PEB_LDR_DATA
// Ldr+0x20  -> InMemoryOrderModuleList (LIST_ENTRY head)
//
// Each link points into LDR_DATA_TABLE_ENTRY at offset 0x10 (InMemoryOrderLinks).
// Relative to that link:
//   +0x20  DllBase
//   +0x48  BaseDllName.Length   (uint16, bytes)
//   +0x50  BaseDllName.Buffer   (wchar_t*)

static void* find_module_peb(uint32_t target_hash) {
    auto peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
    if (!peb) return nullptr;

    auto ldr = *reinterpret_cast<uint8_t**>(peb + 0x18);
    if (!ldr) return nullptr;

    auto head = reinterpret_cast<LIST_ENTRY*>(ldr + 0x20);

    size_t steps = 0;
    for (auto curr = head->Flink; curr != head; curr = curr->Flink) {
        if (++steps > 256) return nullptr;  // defensive: corrupted/looped Ldr list
        auto base_ptr = reinterpret_cast<uint8_t*>(curr);
        auto name_len = *reinterpret_cast<uint16_t*>(base_ptr + 0x48);
        auto name_buf = *reinterpret_cast<wchar_t**>(base_ptr + 0x50);

        if (name_buf && name_len > 0) {
            if (hash_wide_lower(name_buf, name_len / sizeof(wchar_t)) == target_hash)
                return *reinterpret_cast<void**>(base_ptr + 0x20);
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// PE export table walk
// ---------------------------------------------------------------------------

static void* walk_exports(void* base, uint32_t func_hash, int depth = 0) {
    // Guard A→B→A forwarder loops. 8 hops is far past any real Windows chain.
    if (depth >= 8) return nullptr;

    auto mod = static_cast<uint8_t*>(base);

    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress) return nullptr;

    const uint32_t export_dir_rva  = dir.VirtualAddress;
    const uint32_t export_dir_size = dir.Size;
    const uint32_t image_size      = nt->OptionalHeader.SizeOfImage;

    auto exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(mod + export_dir_rva);

    // Validate the three parallel arrays fit inside the loaded image.
    if ((uint64_t)exp->AddressOfNames        + (uint64_t)exp->NumberOfNames     * sizeof(uint32_t) > image_size) return nullptr;
    if ((uint64_t)exp->AddressOfNameOrdinals + (uint64_t)exp->NumberOfNames     * sizeof(uint16_t) > image_size) return nullptr;
    if ((uint64_t)exp->AddressOfFunctions    + (uint64_t)exp->NumberOfFunctions * sizeof(uint32_t) > image_size) return nullptr;

    auto names     = reinterpret_cast<uint32_t*>(mod + exp->AddressOfNames);
    auto ordinals  = reinterpret_cast<uint16_t*>(mod + exp->AddressOfNameOrdinals);
    auto functions = reinterpret_cast<uint32_t*>(mod + exp->AddressOfFunctions);

    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        // Name RVA must land inside the loaded image; strings may live outside
        // the export directory on packers/exotic compilers.
        uint32_t name_rva = names[i];
        if (name_rva >= image_size) continue;

        auto name = reinterpret_cast<const char*>(mod + name_rva);
        if (hash_api(name) == func_hash) {
            // Ordinal must index within the functions array.
            uint16_t ord = ordinals[i];
            if (ord >= exp->NumberOfFunctions) continue;

            uint32_t rva = functions[ord];
            // Function RVA must land inside the loaded image.
            if (rva == 0 || rva >= image_size) continue;

            if (rva >= export_dir_rva && rva < export_dir_rva + export_dir_size) {
                // Forwarder string: "ModuleName.FunctionName".
                const char* fwd = reinterpret_cast<const char*>(mod + rva);
                char modname[80] = {0};
                char fn[192] = {0};
                size_t i_dot = 0;
                while (fwd[i_dot] && fwd[i_dot] != '.' && i_dot < sizeof(modname) - 5) {
                    modname[i_dot] = fwd[i_dot];
                    ++i_dot;
                }
                if (fwd[i_dot] != '.') return nullptr;
                size_t ml = i_dot;
                modname[ml++] = '.'; modname[ml++] = 'd'; modname[ml++] = 'l'; modname[ml++] = 'l';
                modname[ml] = 0;
                size_t fi = 0;
                for (size_t j = i_dot + 1; fwd[j] && fi < sizeof(fn) - 1; ++j)
                    fn[fi++] = fwd[j];
                // shortcut: ordinal forwarders ("Module.#123") not supported
                if (fn[0] == '#') return nullptr;
                void* tgt = dynapi::get_module(dynapi::hash_module_runtime(modname));
                if (!tgt) tgt = dynapi::load_module(modname);
                if (!tgt) return nullptr;
                return walk_exports(tgt, hash_api(fn), depth + 1);
            }
            return mod + rva;
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Bootstrap — resolve LoadLibraryA from kernel32 once
// ---------------------------------------------------------------------------

static void* s_kernel32 = nullptr;

using fn_LoadLibraryA = void*(__stdcall*)(const char*);
static fn_LoadLibraryA s_load_library = nullptr;

static bool ensure_bootstrap() {
    if (s_kernel32) return true;

    s_kernel32 = find_module_peb(modules::KERNEL32);
    if (!s_kernel32) return false;

    s_load_library = reinterpret_cast<fn_LoadLibraryA>(
        walk_exports(s_kernel32, hash_api("LoadLibraryA")));
    return s_load_library != nullptr;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void* get_module(uint32_t module_hash) {
    return find_module_peb(module_hash);
}

void* load_module(const char* name) {
    if (!ensure_bootstrap()) return nullptr;
    return s_load_library(name);
}

void* resolve(void* module_base, uint32_t func_hash) {
    if (!module_base) return nullptr;
    return walk_exports(module_base, func_hash);
}

void* resolve(uint32_t module_hash, uint32_t func_hash) {
    auto mod = find_module_peb(module_hash);
    if (!mod) return nullptr;
    return walk_exports(mod, func_hash);
}

} // namespace dynapi
