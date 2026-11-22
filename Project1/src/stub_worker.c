// Project1/src/stub_worker.c — Phase B.0 skeleton.
//
// Compiled as a freestanding x86 COFF object by the PreBuildEvent in
// Project1.vcxproj; the .text section is then extracted by
// build/extract_blob.ps1 and embedded as RCDATA resource
// SB_RESOURCE_WORKER_BLOB (= 101) in the loader image.
//
// Hard constraints:
//   - NO CRT calls (no memset/memcpy/strlen/__chkstk).
//   - NO string literals / globals => no .rdata relocations into .text.
//   - NO libraries linked => no IAT.
//   - EVERY external API reached through pointers in `sb_worker_args`.
//
// The worker is position-independent. Its .text is the resource body
// that the stub (stub.asm, milestone B.0 refresh) copies into the
// target process and then jumps to.

#include "../include/stub_worker.h"

// __stdcall: the caller (stub.asm) pushes `args`, the worker clears via
// `ret 4`. x86 linker decorates to `_worker_entry@4`; the extracted blob
// starts with this function's prologue because stub_worker.c has only
// this function.
uint32_t __stdcall worker_entry(struct sb_worker_args* args) {
    if (!args)              return 0xDEAD0001u;
    if (args->stop_flag)    return 0xDEAD0002u;
    // Smoke-test: confirm the required function pointers were delivered.
    // Phase B.1 starts using them to load bcrypt.dll.
    if (!args->p_load_library_a || !args->p_get_proc_address)
        return 0xDEAD0003u;
    args->result_code = 0;
    return 0;
}
