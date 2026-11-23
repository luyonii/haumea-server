// Project1/src/stub_worker.c — Phase B.1: AES-GCM decrypt inside target.
//
// Compiled as a freestanding x86 COFF object by the BuildStubWorkerBlob
// target in Project1.vcxproj; the .text section is then extracted by
// scripts/extract_blob.ps1 and embedded as RCDATA resource
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

// BCrypt function pointer typedefs. x86 BCrypt entries are __stdcall.
typedef int32_t (__stdcall *pfn_open_alg)(uint32_t*, const uint16_t*, const uint16_t*, uint32_t);
typedef int32_t (__stdcall *pfn_set_prop)(uint32_t, const uint16_t*, uint8_t*, uint32_t, uint32_t);
typedef int32_t (__stdcall *pfn_gen_sym_key)(uint32_t, uint32_t*, uint8_t*, uint32_t, uint8_t*, uint32_t, uint32_t);
typedef int32_t (__stdcall *pfn_decrypt)(uint32_t, uint8_t*, uint32_t, void*, uint8_t*, uint32_t, uint8_t*, uint32_t, uint32_t*, uint32_t);
typedef int32_t (__stdcall *pfn_destroy_key)(uint32_t);
typedef int32_t (__stdcall *pfn_close_alg)(uint32_t, uint32_t);

// __stdcall: the caller (stub.asm) pushes `args`, the worker clears via
// `ret 4`. x86 linker decorates to `_worker_entry@4`; the extracted blob
// starts with this function's prologue because stub_worker.c has only
// this function.
uint32_t __stdcall worker_entry(struct sb_worker_args* args) {
    if (!args)                                              return SB_RC_ARGS_NULL;
    if (args->stop_flag)                                    return SB_RC_STOP_FLAG;
    if (!args->p_load_library_a || !args->p_get_proc_address) return SB_RC_MISSING_PFN;
    if (!args->p_open_alg || !args->p_set_prop ||
        !args->p_gen_sym_key || !args->p_decrypt ||
        !args->p_destroy_key || !args->p_close_alg)         return SB_RC_MISSING_PFN;
    if (args->pt_cap < args->ct_len)                        return SB_RC_PT_CAP_TOO_SMALL;

    pfn_open_alg      open_alg    = (pfn_open_alg)     args->p_open_alg;
    pfn_set_prop      set_prop    = (pfn_set_prop)     args->p_set_prop;
    pfn_gen_sym_key   gen_sym_key = (pfn_gen_sym_key)  args->p_gen_sym_key;
    pfn_decrypt       decrypt     = (pfn_decrypt)      args->p_decrypt;
    pfn_destroy_key   destroy_key = (pfn_destroy_key)  args->p_destroy_key;
    pfn_close_alg     close_alg   = (pfn_close_alg)    args->p_close_alg;

    uint32_t h_alg = 0;
    uint32_t h_key = 0;
    uint32_t rc = SB_RC_OK;

    int32_t st = open_alg(&h_alg, args->s_aes, (const uint16_t*)0, 0);
    if (st < 0) { rc = SB_RC_OPEN_ALG_FAILED; goto done; }

    // BCryptSetProperty(h_alg, L"ChainingMode", (PUCHAR)L"ChainingModeGCM", byte_len, 0).
    // byte_len includes the null terminator; L"ChainingModeGCM" is 16 wchars = 32 bytes.
    {
        uint32_t cb = 0;
        while (args->s_chaining_mode_gcm[cb / 2] != 0) cb += 2;
        cb += 2; // trailing null wchar
        st = set_prop(h_alg, args->s_chaining_mode, (uint8_t*)args->s_chaining_mode_gcm, cb, 0);
        if (st < 0) { rc = SB_RC_SET_CHAIN_FAILED; goto done; }
    }

    st = gen_sym_key(h_alg, &h_key, (uint8_t*)0, 0, args->k_payload_aes, 32, 0);
    if (st < 0) { rc = SB_RC_GEN_KEY_FAILED; goto done; }

    // Build BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO on the stack. Every
    // field is written explicitly so cl.exe never lowers a zero-init to
    // _memset (which would add a .text reloc and break extract_blob).
    struct sb_bcrypt_auth_info info;
    info.cbSize        = (uint32_t)sizeof(info);
    info.dwInfoVersion = SB_BCRYPT_AUTH_MODE_INFO_VERSION;
    info.pbNonce       = (uint32_t)(uintptr_t)args->iv;
    info.cbNonce       = 12;
    info.pbAuthData    = 0;
    info.cbAuthData    = 0;
    info.pbTag         = (uint32_t)(uintptr_t)args->tag;
    info.cbTag         = 16;
    info.pbMacContext  = 0;
    info.cbMacContext  = 0;
    info.cbAAD         = 0;
    info.cbData        = 0;
    info.dwFlags       = 0;

    uint32_t pt_written = 0;
    st = decrypt(h_key,
                 (uint8_t*)(uintptr_t)args->ct_ptr, args->ct_len,
                 &info,
                 (uint8_t*)0, 0,
                 (uint8_t*)(uintptr_t)args->pt_ptr, args->pt_cap,
                 &pt_written,
                 0);
    if (st < 0) { rc = SB_RC_DECRYPT_FAILED; goto done; }

    args->pt_len_out = pt_written;

done:
    if (h_key)  destroy_key(h_key);
    if (h_alg)  close_alg(h_alg, 0);
    args->result_code = rc;
    return rc;
}
