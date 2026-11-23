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
//   B.2: + watermark (HMAC-SHA256 verify), PE map (i386), call DllMain.
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
#define SB_RC_OK                    0x00000000u
#define SB_RC_ARGS_NULL             0xDEAD0001u
#define SB_RC_STOP_FLAG             0xDEAD0002u
#define SB_RC_MISSING_PFN           0xDEAD0003u
#define SB_RC_OPEN_ALG_FAILED       0xDEAD0010u
#define SB_RC_SET_CHAIN_FAILED      0xDEAD0011u
#define SB_RC_GEN_KEY_FAILED        0xDEAD0012u
#define SB_RC_DECRYPT_FAILED        0xDEAD0013u
#define SB_RC_PT_CAP_TOO_SMALL      0xDEAD0014u
#define SB_RC_WM_SHORT              0xDEAD0020u
#define SB_RC_WM_HWID_MISMATCH      0xDEAD0021u
#define SB_RC_WM_LICENSE_MISMATCH   0xDEAD0022u
#define SB_RC_WM_EXPIRED            0xDEAD0023u
#define SB_RC_WM_SIG_FAIL           0xDEAD0024u
#define SB_RC_PE_BAD_DOS            0xDEAD0030u
#define SB_RC_PE_BAD_NT             0xDEAD0031u
#define SB_RC_PE_BAD_MACHINE        0xDEAD0032u
#define SB_RC_PE_ALLOC_FAIL         0xDEAD0033u
#define SB_RC_PE_SEC_COPY_FAIL      0xDEAD0034u
#define SB_RC_PE_RELOC_FAIL         0xDEAD0035u
#define SB_RC_PE_IMPORT_FAIL        0xDEAD0036u
#define SB_RC_PE_PROTECT_FAIL       0xDEAD0037u
#define SB_RC_DLLMAIN_FAIL          0xDEAD0038u
#define SB_RC_BCRYPT_LOAD_FAIL      0xDEAD0039u
#define SB_RC_PE_TLS_FAIL           0xDEAD003Au

#pragma pack(push, 8)
struct sb_worker_args {
    // ---- Kernel APIs (B.0, B.2 uses them for PE imports) ----------
    uint32_t p_load_library_a;    // kernel32!LoadLibraryA
    uint32_t p_get_proc_address;  // kernel32!GetProcAddress

    // ---- BCrypt crypto (B.1) --------------------------------------
    uint32_t p_open_alg;          // BCryptOpenAlgorithmProvider
    uint32_t p_set_prop;          // BCryptSetProperty
    uint32_t p_gen_sym_key;       // BCryptGenerateSymmetricKey
    uint32_t p_decrypt;           // BCryptDecrypt
    uint32_t p_destroy_key;       // BCryptDestroyKey
    uint32_t p_close_alg;         // BCryptCloseAlgorithmProvider

    // ---- BCrypt hash (B.2 watermark HMAC) -------------------------
    uint32_t p_create_hash;       // BCryptCreateHash
    uint32_t p_hash_data;         // BCryptHashData
    uint32_t p_finish_hash;       // BCryptFinishHash
    uint32_t p_destroy_hash;      // BCryptDestroyHash

    // ---- kernel32 memory APIs (B.2 PE map) ------------------------
    uint32_t p_virtual_alloc;     // VirtualAlloc
    uint32_t p_virtual_free;      // VirtualFree
    uint32_t p_virtual_protect;   // VirtualProtect
    uint32_t p_flush_icache;      // FlushInstructionCache
    uint32_t p_get_current_proc;  // GetCurrentProcess
    uint32_t p_get_system_time;   // GetSystemTimeAsFileTime (expiry check)

    // ---- AES-GCM parameters (B.1) ---------------------------------
    uint32_t ct_ptr;              // in : ciphertext bytes (target VA)
    uint32_t ct_len;              // in : ciphertext length
    uint32_t pt_ptr;              // in : plaintext output buffer (target VA)
    uint32_t pt_cap;              // in : capacity of pt_ptr (>= ct_len)
    uint32_t pt_len_out;          // out: bytes written to pt_ptr
    uint8_t  iv[12];              // in : GCM nonce
    uint8_t  tag[16];             // in : GCM authentication tag
    uint8_t  k_payload_aes[32];   // in : AES-256 key

    // ---- Watermark verification (B.2) -----------------------------
    uint8_t  k_watermark[32];     // in : HMAC-SHA256 key
    uint8_t  hwid_bytes[32];      // in : local hwid hash (32 raw bytes)
    uint8_t  license_hash[32];    // in : sha256(license_id) from loader

    // ---- Wide strings for BCrypt (loader fills from OBF_W) --------
    uint16_t s_aes[8];                     // L"AES"
    uint16_t s_sha256[8];                  // L"SHA256"
    uint16_t s_chaining_mode[24];          // L"ChainingMode"
    uint16_t s_chaining_mode_gcm[24];      // L"ChainingModeGCM"

    // ---- ANSI "bcrypt.dll" so the worker can force bcrypt into the
    //      target process before calling the pre-resolved BCrypt pfns.
    //      Under same-boot ASLR the module base in the target matches
    //      the loader's, so the pre-resolved function pointers remain
    //      valid once LoadLibraryA returns.
    char     s_bcrypt_dll[16];             // "bcrypt.dll"

    // ---- PE map outputs (B.2) -------------------------------------
    uint32_t mapped_base;         // out: VirtualAlloc base of the mapped DLL
    uint32_t mapped_size;         // out: image size
    uint32_t entry_point;         // out: base + AddressOfEntryPoint (DllMain)
    uint32_t dll_main_rc;         // out: DllMain return value (BOOL)

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
#define SB_BCRYPT_ALG_HANDLE_HMAC_FLAG   8u

// FILETIME mirror (used by GetSystemTimeAsFileTime).
struct sb_filetime {
    uint32_t dwLowDateTime;
    uint32_t dwHighDateTime;
};

// Unix epoch in 100-ns FILETIME ticks (since 1601-01-01).
#define SB_UNIX_EPOCH_100NS 116444736000000000ULL

#ifdef __cplusplus
}
#endif
