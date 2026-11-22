#pragma once
// Remote manual mapper: injects an x86 DLL into a target x86 process.
// The loader runs in the target's address space, so no LoadLibrary trace,
// no file on disk, no new module in the PEB loader list.

#include <cstdint>

namespace injector {

enum class result {
    ok,
    bad_pe,              // not a PE32 or machine != i386
    oom,                 // VirtualAllocEx failed in loader or target
    write_failed,        // WriteProcessMemory failed
    stub_failed,         // CreateRemoteThread failed or stub returned error
    bad_target,          // hProc is null or inaccessible
};

// Inject `dll_bytes` (size bytes) into target `hProc`. The caller is responsible
// for keeping the target thread suspended until this returns; the main thread
// should be resumed by the caller afterwards.
// On success, the DLL's DllMain(DLL_PROCESS_ATTACH) has run inside the target.
result inject(void* hProc, const uint8_t* dll_bytes, size_t size);

// Diagnostic surface — stub_size() reports the measured delta between the
// stub and its end marker inside the loader binary. last_error() holds the
// last GetLastError captured during inject() (0 on success paths that did
// not surface one, otherwise the value from the failing CRT/Win32 call).
size_t          stub_size();
unsigned long   last_error();
unsigned long   stub_addr();
unsigned long   stub_end_addr();

} // namespace injector
