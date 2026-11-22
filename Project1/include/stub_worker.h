#pragma once
// Shared layout of the "worker" blob that the Phase B pipeline builds
// out of Project1/src/stub_worker.c and embeds as RCDATA resource #101
// in the loader image. The loader (payload.cpp) populates the input
// fields, writes the blob into the target process, then schedules the
// stub (stub.asm) which jumps into the worker's .text.
//
// Milestones grow this layout:
//   B.0: pLoadLibraryA / pGetProcAddress / result_code / stop_flag only.
//   B.1: + AES-GCM parameters (ct_ptr, ct_len, iv, tag, k_payload_aes).
//   B.2: + watermark parameters (k_watermark, hwid_bytes, license_hash).
//   B.3: payload.cpp starts emitting this blob.
//   B.4: crypto / watermark / pe_loader removed from the loader binary.
//
// Keep the struct trivially copyable: no padding tricks, no unions, no
// bitfields. Every field is an explicit-width unsigned integer so the
// layout matches byte-for-byte between the 32-bit worker and whatever
// toolchain builds the loader.

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Resource id the loader uses to FindResource / LoadResource the blob.
#define SB_RESOURCE_WORKER_BLOB 101

struct sb_worker_args {
    uint32_t p_load_library_a;    // in  : kernel32!LoadLibraryA
    uint32_t p_get_proc_address;  // in  : kernel32!GetProcAddress
    uint32_t result_code;         // out : 0 on success, nonzero code on failure
    uint32_t stop_flag;           // in  : nonzero => worker aborts early
};

#ifdef __cplusplus
}
#endif
