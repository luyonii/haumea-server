#pragma once
// Phase B.3 bridge between payload::load_and_execute and the target-side
// stub_worker.c blob (RCDATA #SB_RESOURCE_WORKER_BLOB).
//
// This translation unit never touches the plaintext DLL body: the
// ciphertext envelope the server returned, the AES-256-GCM key, the
// watermark key and binding data are all handed to the worker running
// inside the target process. The loader keeps only the ciphertext on
// its side, which cannot be mapped or executed without the symmetric
// keys the worker receives in-target.
//
// Milestones:
//   B.3: `schedule` is implemented and called from payload.cpp.
//   B.4: crypto / watermark / pe_loader translation units are pulled
//        from the loader; only this bridge remains between fetch and
//        DllMain.

#include <cstdint>

namespace payload_worker {

enum class result {
    ok,
    resource_missing,     // RCDATA #101 not present in the loader image
    resolve_failed,       // kernel32 / ntdll / bcrypt API lookup failed
    oom,                  // VirtualAlloc(Ex) refused the allocation
    write_failed,         // WriteProcessMemory / ReadProcessMemory failed
    thread_failed,        // NtCreateThreadEx returned a failing NTSTATUS
    worker_timeout,       // worker thread did not finish in the timeout
    worker_failed,        // worker reported a non-zero result_code
};

struct outcome {
    result   res;
    uint32_t worker_rc;    // sb_worker_args::result_code
    uint32_t dll_main_rc;  // sb_worker_args::dll_main_rc
};

// Schedule the stub_worker blob inside `hProc`. Writes the ciphertext
// and the arg struct into target memory, kicks off a remote thread
// pointed at the blob, waits up to `timeout_ms`, then reads back the
// worker's self-reported result_code.
//
// Inputs match the data payload::load_and_execute already holds:
//   ciphertext/ct_len  — raw AES-GCM output from the server envelope.
//   iv[12], tag[16]    — GCM nonce + authentication tag.
//   k_payload_aes[32]  — AES-256 key.
//   k_watermark[32]    — HMAC-SHA256 key for the watermark.
//   local_hwid         — 64-character hex SHA-256 hwid string.
//   license_hash[32]   — SHA-256 of the license id (raw bytes).
outcome schedule(void*          hProc,
                 const uint8_t* ciphertext, uint32_t ct_len,
                 const uint8_t  iv[12],
                 const uint8_t  tag[16],
                 const uint8_t  k_payload_aes[32],
                 const uint8_t  k_watermark[32],
                 const char*    local_hwid,
                 const uint8_t  license_hash[32],
                 uint32_t       timeout_ms = 30000);

} // namespace payload_worker
