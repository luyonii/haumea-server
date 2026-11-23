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

// Worker result codes. 0 = success. Non-zero encodes the failing step
// so the loader can diagnose without any strings crossing the boundary.
#define SB_RC_OK                 0x00000000u
#define SB_RC_ARGS_NULL          0xDEAD0001u
#define SB_RC_STOP_FLAG          0xDEAD0002u
#define SB_RC_MISSING_PFN        0xDEAD0003u
#define SB_RC_OPEN_ALG_FAILED    0xDEAD0010u
#define SB_RC_SET_CHAIN_FAILED   0xDEAD0011u
#define SB_RC_GEN_KEY_FAILED     0xDEAD0012u
#define SB_RC_DECRYPT_FAILED     0xDEAD0013u
#define SB_RC_PT_CAP_TOO_SMALL   0xDEAD0014u

#pragma pack(push, 8)
struct sb_worker_args {
    // ---- Kernel APIs (B.0, kept for B.2 DLL import resolution) ----
    uint32_t p_load_library_a;    // kernel32!LoadLibraryA
    uint32_t p_get_proc_address;  // kernel32!GetProcAddress

    // ---- BCrypt APIs pre-resolved by the loader (B.1) --------------
    // The worker never calls LoadLibrary/GetProcAddress for these; the
    // loader hands over fully-resolved pointers so the worker contains
    // zero api-name strings in its .text.
    uint32_t p_open_alg;          // BCryptOpenAlgorithmProvider
    uint32_t p_set_prop;          // BCryptSetProperty
    uint32_t p_gen_sym_key;       // BCryptGenerateSymmetricKey
    uint32_t p_decrypt;           // BCryptDecrypt
    uint32_t p_destroy_key;       // BCryptDestroyKey
    uint32_t p_close_alg;         // BCryptCloseAlgorithmProvider

    // ---- AES-GCM parameters (B.1) ---------------------------------
    uint32_t ct_ptr;              // in : ciphertext bytes (target VA)
    uint32_t ct_len;              // in : ciphertext length
    uint32_t pt_ptr;              // in : plaintext output buffer (target VA)
    uint32_t pt_cap;              // in : capacity of pt_ptr (>= ct_len)
    uint32_t pt_len_out;          // out: bytes written to pt_ptr
    uint8_t  iv[12];              // in : GCM nonce
    uint8_t  tag[16];             // in : GCM authentication tag
    uint8_t  k_payload_aes[32];   // in : AES-256 key

    // ---- Wide strings the worker needs for BCrypt (B.1) -----------
    // Fixed capacity, null-terminated. The loader fills these from
    // OBF_W-protected literals so neither the loader binary nor the
    // worker blob contains BCRYPT_* strings at rest.
    uint16_t s_aes[8];                     // L"AES"
    uint16_t s_chaining_mode[24];          // L"ChainingMode"
    uint16_t s_chaining_mode_gcm[24];      // L"ChainingModeGCM"

    // ---- Smoke / control (B.0) ------------------------------------
    uint32_t result_code;         // out: SB_RC_* code
    uint32_t stop_flag;           // in : nonzero => worker aborts early
};
#pragma pack(pop)

// BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO mirror. Declared here so the
// worker can build one on the stack without pulling bcrypt.h (which
// would drag windows.h into the blob and bloat .text).
#pragma pack(push, 8)
struct sb_bcrypt_auth_info {
    uint32_t cbSize;
    uint32_t dwInfoVersion;
    uint32_t pbNonce;        // pointer: 4 bytes on x86
    uint32_t cbNonce;
    uint32_t pbAuthData;
    uint32_t cbAuthData;
    uint32_t pbTag;
    uint32_t cbTag;
    uint32_t pbMacContext;
    uint32_t cbMacContext;
    uint32_t cbAAD;
    uint64_t cbData;
    uint32_t dwFlags;
};
#pragma pack(pop)

#define SB_BCRYPT_AUTH_MODE_INFO_VERSION 1u

#ifdef __cplusplus
}
#endif
