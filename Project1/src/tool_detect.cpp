#include "tool_detect.h"
#include "dynapi.h"
#include "obfstr.h"

#include <Windows.h>

namespace tool_detect {

using NTSTATUS_t = LONG;

using fn_NtQuerySystemInformation = NTSTATUS_t(NTAPI*)(
    ULONG, PVOID, ULONG, PULONG);
using fn_VirtualAlloc = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using fn_VirtualFree  = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD);
using fn_GetCurrentProcessId = DWORD(WINAPI*)();

struct UNICODE_STRING_T {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

struct SYSTEM_PROCESS_INFORMATION_T {
    ULONG            NextEntryOffset;
    ULONG            NumberOfThreads;
    LARGE_INTEGER    Reserved1[3];
    LARGE_INTEGER    CreateTime;
    LARGE_INTEGER    UserTime;
    LARGE_INTEGER    KernelTime;
    UNICODE_STRING_T ImageName;
    LONG             BasePriority;
    HANDLE           UniqueProcessId;
    HANDLE           InheritedFromUniqueProcessId;
    // (we only touch fields above; NextEntryOffset walks the chain)
};

static inline wchar_t lower_w(wchar_t c) {
    return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c | 0x20) : c;
}

// Case-insensitive wide-vs-narrow compare; narrow is already lowercase ASCII.
static bool ieq(const wchar_t* w, size_t wlen, const char* a) {
    size_t alen = 0; while (a[alen]) ++alen;
    if (wlen != alen) return false;
    for (size_t i = 0; i < alen; ++i) {
        wchar_t lc = lower_w(w[i]);
        if (lc != static_cast<wchar_t>(static_cast<uint8_t>(a[i]))) return false;
    }
    return true;
}

struct entry {
    const char* name;
    uint32_t    bit;
};

uint32_t enumerate() {
    auto ntdll    = dynapi::get_module(dynapi::modules::NTDLL);
    auto kernel32 = dynapi::get_module(dynapi::modules::KERNEL32);
    auto pNtQSI = reinterpret_cast<fn_NtQuerySystemInformation>(
        dynapi::resolve(ntdll, API_HASH("NtQuerySystemInformation")));
    auto pVA = reinterpret_cast<fn_VirtualAlloc>(
        dynapi::resolve(kernel32, API_HASH("VirtualAlloc")));
    auto pVF = reinterpret_cast<fn_VirtualFree>(
        dynapi::resolve(kernel32, API_HASH("VirtualFree")));
    auto pGetPid = reinterpret_cast<fn_GetCurrentProcessId>(
        dynapi::resolve(kernel32, API_HASH("GetCurrentProcessId")));
    if (!pNtQSI || !pVA || !pVF) return 0;
    // Pseudo-handle math doesn't give the real PID; use GetCurrentProcessId.
    const uintptr_t own_pid = pGetPid ? static_cast<uintptr_t>(pGetPid()) : 0;

    SIZE_T cap = 4 * 1024 * 1024;
    uint8_t* buf = static_cast<uint8_t*>(pVA(nullptr, cap, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!buf) return 0;

    ULONG needed = 0;
    NTSTATUS_t st = 0;
    for (int tries = 0; tries < 6; ++tries) {
        st = pNtQSI(5 /*SystemProcessInformation*/, buf, static_cast<ULONG>(cap), &needed);
        if (st == 0) break;
        // STATUS_INFO_LENGTH_MISMATCH 0xC0000004
        if (static_cast<ULONG>(st) != 0xC0000004u) {
            pVF(buf, 0, MEM_RELEASE);
            return 0;
        }
        pVF(buf, 0, MEM_RELEASE);
        cap *= 2;
        buf = static_cast<uint8_t*>(pVA(nullptr, cap, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!buf) return 0;
    }
    if (st != 0) {
        pVF(buf, 0, MEM_RELEASE);
        return 0;
    }

    // Decrypt names (lowercase ASCII).
    auto d_x64dbg    = OBF("x64dbg.exe");
    auto d_x32dbg    = OBF("x32dbg.exe");
    auto d_olly      = OBF("ollydbg.exe");
    auto d_windbg    = OBF("windbg.exe");
    auto d_imm       = OBF("immunitydebugger.exe");
    auto d_r2        = OBF("radare2.exe");
    auto d_r2s       = OBF("r2.exe");
    auto d_cdb       = OBF("cdb.exe");

    auto d_ida       = OBF("ida.exe");
    auto d_ida64     = OBF("ida64.exe");
    auto d_ghidra    = OBF("ghidra.exe");
    auto d_ghidrarun = OBF("ghidrarun.bat");
    auto d_binja     = OBF("binaryninja.exe");

    auto d_ph        = OBF("processhacker.exe");
    auto d_px        = OBF("procexp.exe");
    auto d_px64      = OBF("procexp64.exe");
    auto d_hxd       = OBF("hxd.exe");
    auto d_pebear    = OBF("pebear.exe");
    auto d_pestudio  = OBF("pestudio.exe");
    auto d_cff       = OBF("cff explorer.exe");

    auto d_ce        = OBF("cheatengine.exe");
    auto d_ce64      = OBF("cheatengine-x86_64.exe");
    auto d_ce32      = OBF("cheatengine-i386.exe");
    auto d_reclass   = OBF("reclass.net.exe");
    auto d_scylla    = OBF("scylla.exe");

    auto d_vmmap     = OBF("vmmap.exe");
    auto d_vbox      = OBF("vboxtray.exe");
    auto d_vmtool    = OBF("vmtoolsd.exe");

    const entry table[] = {
        { d_x64dbg,    static_cast<uint32_t>(detection::debugger)   },
        { d_x32dbg,    static_cast<uint32_t>(detection::debugger)   },
        { d_olly,      static_cast<uint32_t>(detection::debugger)   },
        { d_windbg,    static_cast<uint32_t>(detection::debugger)   },
        { d_imm,       static_cast<uint32_t>(detection::debugger)   },
        { d_r2,        static_cast<uint32_t>(detection::debugger)   },
        { d_r2s,       static_cast<uint32_t>(detection::debugger)   },
        { d_cdb,       static_cast<uint32_t>(detection::debugger)   },
        { d_ida,       static_cast<uint32_t>(detection::disasm)     },
        { d_ida64,     static_cast<uint32_t>(detection::disasm)     },
        { d_ghidra,    static_cast<uint32_t>(detection::disasm)     },
        { d_ghidrarun, static_cast<uint32_t>(detection::disasm)     },
        { d_binja,     static_cast<uint32_t>(detection::disasm)     },
        { d_ph,        static_cast<uint32_t>(detection::inspector)  },
        { d_px,        static_cast<uint32_t>(detection::inspector)  },
        { d_px64,      static_cast<uint32_t>(detection::inspector)  },
        { d_hxd,       static_cast<uint32_t>(detection::inspector)  },
        { d_pebear,    static_cast<uint32_t>(detection::inspector)  },
        { d_pestudio,  static_cast<uint32_t>(detection::inspector)  },
        { d_cff,       static_cast<uint32_t>(detection::inspector)  },
        { d_ce,        static_cast<uint32_t>(detection::memhack)    },
        { d_ce64,      static_cast<uint32_t>(detection::memhack)    },
        { d_ce32,      static_cast<uint32_t>(detection::memhack)    },
        { d_reclass,   static_cast<uint32_t>(detection::memhack)    },
        { d_scylla,    static_cast<uint32_t>(detection::memhack)    },
        { d_vmmap,     static_cast<uint32_t>(detection::hypervisor) },
        { d_vbox,      static_cast<uint32_t>(detection::hypervisor) },
        { d_vmtool,    static_cast<uint32_t>(detection::hypervisor) },
    };
    constexpr size_t TABLE_N = sizeof(table) / sizeof(table[0]);

    uint32_t mask = 0;
    auto* pi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION_T*>(buf);
    while (true) {
        uintptr_t entry_pid = reinterpret_cast<uintptr_t>(pi->UniqueProcessId);
        if (own_pid && entry_pid == own_pid) {
            // Skip our own entry.
        } else if (pi->ImageName.Buffer && pi->ImageName.Length > 0) {
            size_t wlen = pi->ImageName.Length / sizeof(wchar_t);
            // Strip any path prefix (NT path format safeguard — usually bare basename).
            const wchar_t* w = pi->ImageName.Buffer;
            for (size_t j = 0; j < wlen; ++j) {
                if (w[j] == L'\\' || w[j] == L'/') {
                    w += j + 1;
                    wlen -= j + 1;
                    j = 0;
                }
            }
            for (size_t k = 0; k < TABLE_N; ++k) {
                if (ieq(w, wlen, table[k].name))
                    mask |= table[k].bit;
            }
        }
        if (pi->NextEntryOffset == 0) break;
        pi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION_T*>(
            reinterpret_cast<uint8_t*>(pi) + pi->NextEntryOffset);
    }

    pVF(buf, 0, MEM_RELEASE);
    return mask;
}

} // namespace tool_detect
