#include "game_launcher.h"
#include "dynapi.h"
#include "obfstr.h"

#include <Windows.h>
#include <cstdint>

namespace game_launcher {

using NTSTATUS_t = LONG;

using fn_NtQuerySystemInformation = NTSTATUS_t(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using fn_VirtualAlloc       = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using fn_VirtualFree        = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD);
using fn_OpenProcess        = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
using fn_TerminateProcess   = BOOL(WINAPI*)(HANDLE, UINT);
using fn_WaitForSingleObject= DWORD(WINAPI*)(HANDLE, DWORD);
using fn_CloseHandle        = BOOL(WINAPI*)(HANDLE);
using fn_CreateProcessW     = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                            LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                                            LPVOID, LPCWSTR, LPSTARTUPINFOW,
                                            LPPROCESS_INFORMATION);
using fn_GetLastError       = DWORD(WINAPI*)();

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
};

static inline wchar_t lower_w(wchar_t c) {
    return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c | 0x20) : c;
}

// Case-insensitive wide compare, ASCII-only lowercase fold.
static bool wieq(const wchar_t* a, size_t alen, const wchar_t* b, size_t blen) {
    if (alen != blen) return false;
    for (size_t i = 0; i < alen; ++i) {
        if (lower_w(a[i]) != lower_w(b[i])) return false;
    }
    return true;
}

static size_t wlen_of(const wchar_t* s) {
    size_t n = 0; while (s[n]) ++n; return n;
}

// Finds first PID whose basename matches `exe_name` (case-insensitive).
// Returns 0 when no match. `out_status` reports the enumeration outcome.
static DWORD find_pid_by_name(const wchar_t* exe_name, stop_result* out_status) {
    *out_status = stop_result::enum_failed;

    auto ntdll    = dynapi::get_module(dynapi::modules::NTDLL);
    auto kernel32 = dynapi::get_module(dynapi::modules::KERNEL32);
    auto pNtQSI = reinterpret_cast<fn_NtQuerySystemInformation>(
        dynapi::resolve(ntdll, API_HASH("NtQuerySystemInformation")));
    auto pVA = reinterpret_cast<fn_VirtualAlloc>(
        dynapi::resolve(kernel32, API_HASH("VirtualAlloc")));
    auto pVF = reinterpret_cast<fn_VirtualFree>(
        dynapi::resolve(kernel32, API_HASH("VirtualFree")));
    if (!pNtQSI || !pVA || !pVF) return 0;

    SIZE_T cap = 4 * 1024 * 1024;
    uint8_t* buf = static_cast<uint8_t*>(pVA(nullptr, cap, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!buf) return 0;

    ULONG needed = 0;
    NTSTATUS_t st = 0;
    for (int tries = 0; tries < 6; ++tries) {
        st = pNtQSI(5 /*SystemProcessInformation*/, buf, static_cast<ULONG>(cap), &needed);
        if (st == 0) break;
        if (static_cast<ULONG>(st) != 0xC0000004u) { // STATUS_INFO_LENGTH_MISMATCH
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

    const size_t want_len = wlen_of(exe_name);
    DWORD found_pid = 0;
    auto* pi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION_T*>(buf);
    while (true) {
        if (pi->ImageName.Buffer && pi->ImageName.Length > 0) {
            size_t wlen = pi->ImageName.Length / sizeof(wchar_t);
            const wchar_t* w = pi->ImageName.Buffer;
            // Strip any NT path prefix down to the basename.
            size_t start = 0;
            for (size_t j = 0; j < wlen; ++j) {
                if (w[j] == L'\\' || w[j] == L'/') start = j + 1;
            }
            w += start;
            wlen -= start;
            if (wieq(w, wlen, exe_name, want_len)) {
                found_pid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(pi->UniqueProcessId));
                break;
            }
        }
        if (pi->NextEntryOffset == 0) break;
        pi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION_T*>(
            reinterpret_cast<uint8_t*>(pi) + pi->NextEntryOffset);
    }

    pVF(buf, 0, MEM_RELEASE);
    *out_status = found_pid ? stop_result::stopped : stop_result::not_running;
    return found_pid;
}

stop_result stop_by_name(const wchar_t* exe_name) {
    if (!exe_name || !exe_name[0]) return stop_result::enum_failed;

    stop_result scan_status = stop_result::enum_failed;
    DWORD pid = find_pid_by_name(exe_name, &scan_status);
    if (scan_status == stop_result::enum_failed) return stop_result::enum_failed;
    if (pid == 0) return stop_result::not_running;

    auto kernel32 = dynapi::get_module(dynapi::modules::KERNEL32);
    auto pOpen = reinterpret_cast<fn_OpenProcess>(
        dynapi::resolve(kernel32, API_HASH("OpenProcess")));
    auto pTerm = reinterpret_cast<fn_TerminateProcess>(
        dynapi::resolve(kernel32, API_HASH("TerminateProcess")));
    auto pWait = reinterpret_cast<fn_WaitForSingleObject>(
        dynapi::resolve(kernel32, API_HASH("WaitForSingleObject")));
    auto pClose = reinterpret_cast<fn_CloseHandle>(
        dynapi::resolve(kernel32, API_HASH("CloseHandle")));
    if (!pOpen || !pTerm || !pWait || !pClose) return stop_result::terminate_failed;

    HANDLE h = pOpen(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (!h) return stop_result::access_denied;

    stop_result r = stop_result::stopped;
    if (!pTerm(h, 0)) {
        r = stop_result::terminate_failed;
    } else {
        pWait(h, 5000);
    }
    pClose(h);
    return r;
}

static unsigned long g_last_create_err = 0;

unsigned long last_create_error() { return g_last_create_err; }

start_result start(const wchar_t* exe_path, bool suspended, process* out) {
    g_last_create_err = 0;
    if (!exe_path || !exe_path[0] || !out) return start_result::create_failed;

    auto kernel32 = dynapi::get_module(dynapi::modules::KERNEL32);
    auto pCreate = reinterpret_cast<fn_CreateProcessW>(
        dynapi::resolve(kernel32, API_HASH("CreateProcessW")));
    auto pErr = reinterpret_cast<fn_GetLastError>(
        dynapi::resolve(kernel32, API_HASH("GetLastError")));
    if (!pCreate) return start_result::create_failed;

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    const DWORD flags = suspended ? CREATE_SUSPENDED : 0;

    // Derive cwd = dirname(exe_path) so the game finds Data/, Config/, etc.
    wchar_t cwd_buf[MAX_PATH]{};
    const wchar_t* cwd = nullptr;
    {
        size_t n = wlen_of(exe_path);
        size_t last = 0;
        for (size_t j = 0; j < n; ++j) {
            if (exe_path[j] == L'\\' || exe_path[j] == L'/') last = j;
        }
        if (last > 0 && last < MAX_PATH) {
            for (size_t j = 0; j < last; ++j) cwd_buf[j] = exe_path[j];
            cwd_buf[last] = 0;
            cwd = cwd_buf;
        }
    }

    if (!pCreate(exe_path, nullptr, nullptr, nullptr, FALSE, flags,
                 nullptr, cwd, &si, &pi)) {
        DWORD e = pErr ? pErr() : 0;
        g_last_create_err = e;
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND)
            return start_result::invalid_path;
        return start_result::create_failed;
    }

    out->hProcess = pi.hProcess;
    out->hThread  = pi.hThread;
    out->pid      = pi.dwProcessId;
    out->tid      = pi.dwThreadId;
    return start_result::ok;
}

using fn_K32EnumProcessModulesEx = BOOL(WINAPI*)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD);
using fn_K32GetModuleBaseNameW   = DWORD(WINAPI*)(HANDLE, HMODULE, LPWSTR, DWORD);
using fn_Sleep_t                 = void(WINAPI*)(DWORD);
using fn_GetTickCount            = DWORD(WINAPI*)();

bool wait_for_module(void* hProc, const wchar_t* module_name, unsigned long timeout_ms) {
    if (!hProc || !module_name || !module_name[0]) return false;

    auto kernel32 = dynapi::get_module(dynapi::modules::KERNEL32);
    if (!kernel32) return false;

    auto pEnum = reinterpret_cast<fn_K32EnumProcessModulesEx>(
        dynapi::resolve(kernel32, API_HASH("K32EnumProcessModulesEx")));
    auto pName = reinterpret_cast<fn_K32GetModuleBaseNameW>(
        dynapi::resolve(kernel32, API_HASH("K32GetModuleBaseNameW")));
    auto pSleep = reinterpret_cast<fn_Sleep_t>(
        dynapi::resolve(kernel32, API_HASH("Sleep")));
    auto pGetTick = reinterpret_cast<fn_GetTickCount>(
        dynapi::resolve(kernel32, API_HASH("GetTickCount")));
    if (!pEnum || !pName || !pSleep || !pGetTick) return false;

    const size_t want_len = wlen_of(module_name);
    const DWORD  start    = pGetTick();

    HMODULE mods[256];
    wchar_t name_buf[260];

    for (;;) {
        DWORD needed = 0;
        if (pEnum(hProc, mods, sizeof(mods), &needed, 0x03 /*LIST_MODULES_ALL*/)) {
            DWORD count = needed / sizeof(HMODULE);
            if (count > 256) count = 256;
            for (DWORD i = 0; i < count; ++i) {
                DWORD n = pName(hProc, mods[i], name_buf, 260);
                if (!n) continue;
                if (wieq(name_buf, n, module_name, want_len)) return true;
            }
        }
        // Enum may transiently fail while the target is still initializing.
        // Treat that as "not yet"; only time-out is final.

        const DWORD elapsed = pGetTick() - start;
        if (elapsed >= timeout_ms) return false;

        const DWORD remaining = timeout_ms - elapsed;
        pSleep(remaining > 500 ? 500 : remaining);
    }
}

} // namespace game_launcher
