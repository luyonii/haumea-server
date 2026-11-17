#include "anti_debug.h"
#include "dynapi.h"
#include "obfstr.h"

#include <Windows.h>
#include <intrin.h>

namespace anti_debug {

// ---- NT prototypes (resolved via dynapi) ----
using NTSTATUS_t = LONG;

using fn_NtQueryInformationProcess = NTSTATUS_t(NTAPI*)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);
using fn_NtQuerySystemInformation = NTSTATUS_t(NTAPI*)(
    ULONG, PVOID, ULONG, PULONG);
using fn_NtSetInformationThread = NTSTATUS_t(NTAPI*)(
    HANDLE, ULONG, PVOID, ULONG);
using fn_CheckRemoteDebuggerPresent = BOOL(WINAPI*)(HANDLE, PBOOL);
using fn_GetThreadContext  = BOOL(WINAPI*)(HANDLE, LPCONTEXT);
using fn_SetLastError      = void(WINAPI*)(DWORD);
using fn_GetLastError      = DWORD(WINAPI*)();
using fn_OutputDebugStringA = void(WINAPI*)(LPCSTR);

struct SYSTEM_KERNEL_DEBUGGER_INFO {
    BOOLEAN DebuggerEnabled;
    BOOLEAN DebuggerNotPresent;
};

static uint32_t check_peb(uint32_t& out) {
    auto peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
    if (!peb) return 0;

    if (peb[0x02])
        out |= static_cast<uint32_t>(detection::peb_being_debugged);

    // NtGlobalFlag at PEB+0xBC (DWORD). Debug heap flags: 0x70.
    auto ngf = *reinterpret_cast<uint32_t*>(peb + 0xBC);
    if (ngf & 0x70)
        out |= static_cast<uint32_t>(detection::peb_nt_global_flag);

    // Process heap flags anomaly.
    auto heap = *reinterpret_cast<uint8_t**>(peb + 0x30);
    if (heap) {
        auto flags      = *reinterpret_cast<uint32_t*>(heap + 0x70);
        auto forceFlags = *reinterpret_cast<uint32_t*>(heap + 0x74);
        // HEAP_GROWABLE == 2. Debug heaps typically add HEAP_TAIL_CHECKING_ENABLED (0x20)
        // or HEAP_FREE_CHECKING_ENABLED (0x40); ForceFlags should be 0 on a normal heap.
        if ((flags & ~0x2u) != 0 || forceFlags != 0)
            out |= static_cast<uint32_t>(detection::peb_heap_flags);
    }
    return out;
}

uint32_t check_all() {
    uint32_t mask = 0;
    check_peb(mask);

    auto ntdll      = dynapi::get_module(dynapi::modules::NTDLL);
    auto kernelbase = dynapi::get_module(dynapi::modules::KERNELBASE);
    auto kernel32   = dynapi::get_module(dynapi::modules::KERNEL32);

    // Pseudo-handles: process = -1, thread = -2. No resolve needed.
    HANDLE hProc = reinterpret_cast<HANDLE>(static_cast<intptr_t>(-1));
    HANDLE hThr  = reinterpret_cast<HANDLE>(static_cast<intptr_t>(-2));

    auto pNtQIP = reinterpret_cast<fn_NtQueryInformationProcess>(
        dynapi::resolve(ntdll, API_HASH("NtQueryInformationProcess")));
    if (pNtQIP) {
        // ProcessDebugPort (0x7)
        HANDLE port = nullptr;
        ULONG ret = 0;
        if (pNtQIP(hProc, 0x7, &port, sizeof(port), &ret) == 0 && port != nullptr)
            mask |= static_cast<uint32_t>(detection::debug_port);

        // ProcessDebugObjectHandle (0x1E)
        HANDLE dobj = nullptr;
        if (pNtQIP(hProc, 0x1E, &dobj, sizeof(dobj), &ret) == 0 && dobj != nullptr)
            mask |= static_cast<uint32_t>(detection::debug_object);

        // ProcessDebugFlags (0x1F): 0 == debugged (DEBUG_INHERIT inverted).
        DWORD flags = 1;
        if (pNtQIP(hProc, 0x1F, &flags, sizeof(flags), &ret) == 0 && flags == 0)
            mask |= static_cast<uint32_t>(detection::debug_flags);
    }

    auto pNtQSI = reinterpret_cast<fn_NtQuerySystemInformation>(
        dynapi::resolve(ntdll, API_HASH("NtQuerySystemInformation")));
    if (pNtQSI) {
        SYSTEM_KERNEL_DEBUGGER_INFO info{};
        ULONG ret = 0;
        if (pNtQSI(0x23, &info, sizeof(info), &ret) == 0) {
            if (info.DebuggerEnabled && !info.DebuggerNotPresent)
                mask |= static_cast<uint32_t>(detection::kernel_debugger);
        }
    }

    // HW breakpoints on current thread.
    auto pGetCtx = reinterpret_cast<fn_GetThreadContext>(
        dynapi::resolve(kernel32, API_HASH("GetThreadContext")));
    if (pGetCtx) {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (pGetCtx(hThr, &ctx)) {
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr7)
                mask |= static_cast<uint32_t>(detection::hw_breakpoint);
        }
    }

    // Remote debugger (lives in kernelbase on modern Windows).
    auto pCRDP = reinterpret_cast<fn_CheckRemoteDebuggerPresent>(
        dynapi::resolve(kernelbase, API_HASH("CheckRemoteDebuggerPresent")));
    if (!pCRDP)
        pCRDP = reinterpret_cast<fn_CheckRemoteDebuggerPresent>(
            dynapi::resolve(kernel32, API_HASH("CheckRemoteDebuggerPresent")));
    if (pCRDP) {
        BOOL present = FALSE;
        if (pCRDP(hProc, &present) && present)
            mask |= static_cast<uint32_t>(detection::remote_debugger);
    }

    // OutputDebugStringA trick, Windows 10+ behavior:
    //   no debugger attached  -> SetLastError(0) by the API
    //   debugger attached     -> last error stays at the sentinel
    auto pOutDbg  = reinterpret_cast<fn_OutputDebugStringA>(
        dynapi::resolve(kernelbase, API_HASH("OutputDebugStringA")));
    auto pSetErr  = reinterpret_cast<fn_SetLastError>(
        dynapi::resolve(kernel32, API_HASH("SetLastError")));
    auto pGetErr  = reinterpret_cast<fn_GetLastError>(
        dynapi::resolve(kernel32, API_HASH("GetLastError")));
    // OutputDebugStringA trick disabled: on Win 11 24H2+ the API no longer
    // resets GetLastError in the clean path, causing false positives. Keep
    // the resolve above so the dynapi call sites stay warm, but skip the test.
    (void)pOutDbg; (void)pSetErr; (void)pGetErr;

    return mask;
}

void hide_current_thread() {
    auto ntdll = dynapi::get_module(dynapi::modules::NTDLL);
    auto pNtSIT = reinterpret_cast<fn_NtSetInformationThread>(
        dynapi::resolve(ntdll, API_HASH("NtSetInformationThread")));
    if (!pNtSIT) return;

    // ThreadHideFromDebugger == 0x11; pseudo-handle -2 for current thread.
    HANDLE hThr = reinterpret_cast<HANDLE>(static_cast<intptr_t>(-2));
    pNtSIT(hThr, 0x11, nullptr, 0);
}

} // namespace anti_debug
