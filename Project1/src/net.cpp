#include "net.h"
#include "dynapi.h"
#include "obfstr.h"

#include <Windows.h>
#include <cstring>
#include <string>

namespace net {

// ---- WinHTTP types / constants (no winhttp.h include to avoid potential #pragma lib) ----

constexpr DWORD WHTTP_ACCESS_AUTO   = 4;          // WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
constexpr DWORD WHTTP_FLAG_SECURE   = 0x00800000; // WINHTTP_FLAG_SECURE
constexpr DWORD WHTTP_OPT_PROTOCOLS = 84;         // WINHTTP_OPTION_SECURE_PROTOCOLS
constexpr DWORD WHTTP_TLS13         = 0x00002000; // WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
constexpr DWORD WHTTP_OPT_CERT_CTX  = 78;         // WINHTTP_OPTION_SERVER_CERT_CONTEXT
constexpr DWORD WHTTP_QUERY_STATUS  = 19;         // WINHTTP_QUERY_STATUS_CODE
constexpr DWORD WHTTP_QUERY_NUM     = 0x20000000; // WINHTTP_QUERY_FLAG_NUMBER

// Matches CERT_CONTEXT layout — avoids wincrypt.h
struct cert_ctx {
    DWORD encoding_type;
    BYTE* encoded;
    DWORD encoded_size;
    void* cert_info;
    void* cert_store;
};

// ---- Function pointer typedefs ----

using fn_HttpOpen        = void*(WINAPI*)(const wchar_t*, DWORD, const wchar_t*, const wchar_t*, DWORD);
using fn_HttpConnect     = void*(WINAPI*)(void*, const wchar_t*, uint16_t, DWORD);
using fn_HttpOpenReq     = void*(WINAPI*)(void*, const wchar_t*, const wchar_t*, const wchar_t*, const wchar_t*, const wchar_t**, DWORD);
using fn_HttpSetOpt      = BOOL(WINAPI*)(void*, DWORD, void*, DWORD);
using fn_HttpSendReq     = BOOL(WINAPI*)(void*, const wchar_t*, DWORD, void*, DWORD, DWORD, DWORD_PTR);
using fn_HttpRecvResp    = BOOL(WINAPI*)(void*, void*);
using fn_HttpQueryAvail  = BOOL(WINAPI*)(void*, DWORD*);
using fn_HttpReadData    = BOOL(WINAPI*)(void*, void*, DWORD, DWORD*);
using fn_HttpQueryOpt    = BOOL(WINAPI*)(void*, DWORD, void*, DWORD*);
using fn_HttpQueryHdr    = BOOL(WINAPI*)(void*, DWORD, const wchar_t*, void*, DWORD*, DWORD*);
using fn_HttpClose       = BOOL(WINAPI*)(void*);

using fn_CertFreeCtx     = BOOL(WINAPI*)(const cert_ctx*);

using fn_InitCS          = void(WINAPI*)(CRITICAL_SECTION*);
using fn_EnterCS         = void(WINAPI*)(CRITICAL_SECTION*);
using fn_LeaveCS         = void(WINAPI*)(CRITICAL_SECTION*);
using fn_DeleteCS        = void(WINAPI*)(CRITICAL_SECTION*);

// CNG types (for cert pin SHA-256)
using fn_BCOpen          = long(WINAPI*)(void**, const wchar_t*, const wchar_t*, ULONG);
using fn_BCCreate        = long(WINAPI*)(void*, void**, uint8_t*, ULONG, uint8_t*, ULONG, ULONG);
using fn_BCHash          = long(WINAPI*)(void*, uint8_t*, ULONG, ULONG);
using fn_BCFinish        = long(WINAPI*)(void*, uint8_t*, ULONG, ULONG);
using fn_BCDestroy       = long(WINAPI*)(void*);
using fn_BCClose         = long(WINAPI*)(void*, ULONG);

// ---- Module state ----

static void*   s_winhttp  = nullptr;
static void*   s_session  = nullptr;
static void*   s_conn     = nullptr;
static bool    s_ready    = false;

static CRITICAL_SECTION s_cs;
static CRITICAL_SECTION s_req_cs;        // guards s_req only (short critical section, safe to grab from another thread while s_cs is held)
static void*            s_req = nullptr; // in-flight request handle, or nullptr

static fn_HttpOpen       pOpen;
static fn_HttpConnect    pConnect;
static fn_HttpOpenReq    pOpenReq;
static fn_HttpSetOpt     pSetOpt;
static fn_HttpSendReq    pSendReq;
static fn_HttpRecvResp   pRecvResp;
static fn_HttpQueryAvail pQueryAvail;
static fn_HttpReadData   pReadData;
static fn_HttpQueryOpt   pQueryOpt;
static fn_HttpQueryHdr   pQueryHdr;
static fn_HttpClose      pClose;

static fn_CertFreeCtx   pCertFree;

static fn_InitCS   pInitCS;
static fn_EnterCS  pEnterCS;
static fn_LeaveCS  pLeaveCS;
static fn_DeleteCS pDeleteCS;

static fn_BCOpen    pBCOpen;
static fn_BCCreate  pBCCreate;
static fn_BCHash    pBCHash;
static fn_BCFinish  pBCFinish;
static fn_BCDestroy pBCDestroy;
static fn_BCClose   pBCClose;

// ---- Helpers ----

static void to_wide(const char* src, wchar_t* dst, size_t max_chars) {
    size_t i = 0;
    while (src[i] && i < max_chars - 1) {
        dst[i] = static_cast<wchar_t>(static_cast<uint8_t>(src[i]));
        ++i;
    }
    dst[i] = 0;
}

// SHA-256 of raw bytes via CNG -> 64-char lowercase hex
static bool sha256_hex(const uint8_t* data, size_t len, char out[65]) {
    if (!pBCOpen) return false;

    auto alg_n = OBF("SHA256");
    wchar_t alg_w[7]{};
    for (int i = 0; i < 7; ++i)
        alg_w[i] = static_cast<wchar_t>(static_cast<uint8_t>(alg_n.c_str()[i]));

    void* alg = nullptr;
    if (pBCOpen(&alg, alg_w, nullptr, 0) != 0) return false;

    void* hash = nullptr;
    if (pBCCreate(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
        pBCClose(alg, 0);
        return false;
    }

    pBCHash(hash, const_cast<uint8_t*>(data), static_cast<ULONG>(len), 0);

    uint8_t digest[32]{};
    long st = pBCFinish(hash, digest, 32, 0);
    pBCDestroy(hash);
    pBCClose(alg, 0);

    volatile wchar_t* wp = alg_w;
    for (int i = 0; i < 7; ++i) wp[i] = 0;

    if (st != 0) return false;

    constexpr char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[i * 2]     = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0F];
    }
    out[64] = 0;

    volatile uint8_t* dp = digest;
    for (int i = 0; i < 32; ++i) dp[i] = 0;
    return true;
}

// Verify leaf cert SHA-256 against hardcoded pins.
// To compute pin: openssl x509 -in cert.der -inform der -noout -fingerprint -sha256
static bool verify_cert_pin(void* hRequest) {
    cert_ctx* cert = nullptr;
    DWORD sz = sizeof(cert);
    if (!pQueryOpt(hRequest, WHTTP_OPT_CERT_CTX, &cert, &sz) || !cert)
        return false;

    char hash[65]{};
    bool ok = sha256_hex(cert->encoded, cert->encoded_size, hash);
    pCertFree(cert);
    if (!ok) return false;

    // Integration test cert pin (secblind.local self-signed).
    // Replace AMBOS no deploy por hashes reais distintos (leaf atual + leaf backup);
    // mesmo valor nos dois slots = sem rotação segura de cert.
    // pin_leaf_current — hash do cert de testes `secblind.local` (harness de integração); substituir pelo hash do cert real de prod no deploy
    auto pin1 = OBF("822696bb26c49b6269b46d41457587c112f9b1248c4c5b322604ae66bcdfbdca");
    // pin_leaf_backup — substituir no deploy
    auto pin2 = OBF("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    return strcmp(hash, pin1.c_str()) == 0
        || strcmp(hash, pin2.c_str()) == 0;
}

// ---- Public API ----

bool init(const char* server_host, uint16_t port) {
    if (s_ready) return true;

    // Load winhttp, crypt32, bcrypt
    s_winhttp       = dynapi::load_module(OBF("winhttp.dll"));
    auto crypt32    = dynapi::load_module(OBF("crypt32.dll"));
    auto bcrypt_mod = dynapi::load_module(OBF("bcrypt.dll"));
    if (!s_winhttp || !crypt32 || !bcrypt_mod) return false;

    // Resolve WinHTTP exports
    pOpen       = reinterpret_cast<fn_HttpOpen>      (dynapi::resolve(s_winhttp, API_HASH("WinHttpOpen")));
    pConnect    = reinterpret_cast<fn_HttpConnect>    (dynapi::resolve(s_winhttp, API_HASH("WinHttpConnect")));
    pOpenReq    = reinterpret_cast<fn_HttpOpenReq>    (dynapi::resolve(s_winhttp, API_HASH("WinHttpOpenRequest")));
    pSetOpt     = reinterpret_cast<fn_HttpSetOpt>     (dynapi::resolve(s_winhttp, API_HASH("WinHttpSetOption")));
    pSendReq    = reinterpret_cast<fn_HttpSendReq>    (dynapi::resolve(s_winhttp, API_HASH("WinHttpSendRequest")));
    pRecvResp   = reinterpret_cast<fn_HttpRecvResp>   (dynapi::resolve(s_winhttp, API_HASH("WinHttpReceiveResponse")));
    pQueryAvail = reinterpret_cast<fn_HttpQueryAvail> (dynapi::resolve(s_winhttp, API_HASH("WinHttpQueryDataAvailable")));
    pReadData   = reinterpret_cast<fn_HttpReadData>   (dynapi::resolve(s_winhttp, API_HASH("WinHttpReadData")));
    pQueryOpt   = reinterpret_cast<fn_HttpQueryOpt>   (dynapi::resolve(s_winhttp, API_HASH("WinHttpQueryOption")));
    pQueryHdr   = reinterpret_cast<fn_HttpQueryHdr>   (dynapi::resolve(s_winhttp, API_HASH("WinHttpQueryHeaders")));
    pClose      = reinterpret_cast<fn_HttpClose>      (dynapi::resolve(s_winhttp, API_HASH("WinHttpCloseHandle")));

    if (!pOpen || !pConnect || !pOpenReq || !pSetOpt || !pSendReq ||
        !pRecvResp || !pQueryAvail || !pReadData || !pQueryOpt ||
        !pQueryHdr || !pClose)
        return false;

    // crypt32: CertFreeCertificateContext
    pCertFree = reinterpret_cast<fn_CertFreeCtx>(
        dynapi::resolve(crypt32, API_HASH("CertFreeCertificateContext")));
    if (!pCertFree) return false;

    // bcrypt: SHA-256 for cert pinning
    pBCOpen    = reinterpret_cast<fn_BCOpen>   (dynapi::resolve(bcrypt_mod, API_HASH("BCryptOpenAlgorithmProvider")));
    pBCCreate  = reinterpret_cast<fn_BCCreate> (dynapi::resolve(bcrypt_mod, API_HASH("BCryptCreateHash")));
    pBCHash    = reinterpret_cast<fn_BCHash>   (dynapi::resolve(bcrypt_mod, API_HASH("BCryptHashData")));
    pBCFinish  = reinterpret_cast<fn_BCFinish> (dynapi::resolve(bcrypt_mod, API_HASH("BCryptFinishHash")));
    pBCDestroy = reinterpret_cast<fn_BCDestroy>(dynapi::resolve(bcrypt_mod, API_HASH("BCryptDestroyHash")));
    pBCClose   = reinterpret_cast<fn_BCClose>  (dynapi::resolve(bcrypt_mod, API_HASH("BCryptCloseAlgorithmProvider")));

    if (!pBCOpen || !pBCCreate || !pBCHash || !pBCFinish || !pBCDestroy || !pBCClose)
        return false;

    // kernel32: critical section
    auto k32 = dynapi::get_module(dynapi::modules::KERNEL32);
    pInitCS   = reinterpret_cast<fn_InitCS>  (dynapi::resolve(k32, API_HASH("InitializeCriticalSection")));
    pEnterCS  = reinterpret_cast<fn_EnterCS> (dynapi::resolve(k32, API_HASH("EnterCriticalSection")));
    pLeaveCS  = reinterpret_cast<fn_LeaveCS> (dynapi::resolve(k32, API_HASH("LeaveCriticalSection")));
    pDeleteCS = reinterpret_cast<fn_DeleteCS>(dynapi::resolve(k32, API_HASH("DeleteCriticalSection")));

    if (!pInitCS || !pEnterCS || !pLeaveCS || !pDeleteCS) return false;

    pInitCS(&s_cs);
    pInitCS(&s_req_cs);

    // Create session
    s_session = pOpen(nullptr, WHTTP_ACCESS_AUTO, nullptr, nullptr, 0);
    if (!s_session) return false;

    // Enforce TLS 1.3
    DWORD protocols = WHTTP_TLS13;
    pSetOpt(s_session, WHTTP_OPT_PROTOCOLS, &protocols, sizeof(protocols));

    // Connect to server
    wchar_t whost[256]{};
    to_wide(server_host, whost, 256);

    s_conn = pConnect(s_session, whost, port, 0);

    // Scrub hostname from stack
    volatile wchar_t* p = whost;
    for (int i = 0; i < 256; ++i) p[i] = 0;

    s_ready = (s_conn != nullptr);
    return s_ready;
}

// Closes s_req under s_req_cs, if set. Single-close guaranteed: whoever grabs
// s_req_cs first calls pClose and nulls the pointer; the other caller is a
// no-op. Used by both the worker thread (normal close) and cancel_in_flight.
static void close_request_locked() {
    pEnterCS(&s_req_cs);
    void* h = s_req;
    s_req = nullptr;
    pLeaveCS(&s_req_cs);
    if (h) pClose(h);
}

response post(const char* path, const std::string& json_body) {
    response resp{};
    if (!s_ready) return resp;

    pEnterCS(&s_cs);

    wchar_t wpath[512]{};
    to_wide(path, wpath, 512);

    auto method_n = OBF("POST");
    wchar_t wmethod[8]{};
    to_wide(method_n.c_str(), wmethod, 8);

    void* hReq = pOpenReq(s_conn, wmethod, wpath, nullptr, nullptr, nullptr, WHTTP_FLAG_SECURE);
    if (!hReq) {
        pLeaveCS(&s_cs);
        return resp;
    }

    // Publish handle so cancel_in_flight() can close it from another thread.
    pEnterCS(&s_req_cs);
    s_req = hReq;
    pLeaveCS(&s_req_cs);

    // Content-Type header
    auto ct_n = OBF("Content-Type: application/json\r\n");
    wchar_t ct_w[64]{};
    to_wide(ct_n.c_str(), ct_w, 64);

    void* body_ptr = json_body.empty() ? nullptr : const_cast<char*>(json_body.data());
    DWORD  body_len = static_cast<DWORD>(json_body.size());

    BOOL ok = pSendReq(hReq, ct_w, static_cast<DWORD>(-1),
                        body_ptr, body_len, body_len, 0);

    if (!ok || !pRecvResp(hReq, nullptr)) {
        close_request_locked();
        pLeaveCS(&s_cs);
        return resp;
    }

    // Certificate pinning — verify leaf cert after TLS handshake
    if (!verify_cert_pin(hReq)) {
        close_request_locked();
        pLeaveCS(&s_cs);
        return resp;   // status_code stays 0, caller sees pin failure
    }

    // HTTP status code
    DWORD status = 0, status_sz = sizeof(status), idx = 0;
    pQueryHdr(hReq, WHTTP_QUERY_STATUS | WHTTP_QUERY_NUM,
              nullptr, &status, &status_sz, &idx);
    resp.status_code = static_cast<int>(status);

    // Read response body
    DWORD avail = 0;
    while (pQueryAvail(hReq, &avail) && avail > 0) {
        size_t off = resp.body.size();
        resp.body.resize(off + avail);
        DWORD rd = 0;
        if (pReadData(hReq, &resp.body[off], avail, &rd))
            resp.body.resize(off + rd);
        else {
            resp.body.resize(off);
            break;
        }
    }

    close_request_locked();
    pLeaveCS(&s_cs);
    return resp;
}

void cancel_in_flight() {
    if (!s_ready) return;
    close_request_locked();
}

void shutdown() {
    if (!s_ready) return;
    // If a request is still in flight the worker thread may still touch
    // s_conn / s_session / s_req_cs. Skip teardown — OS reclaims on exit.
    pEnterCS(&s_req_cs);
    bool in_flight = (s_req != nullptr);
    pLeaveCS(&s_req_cs);
    if (in_flight) { s_ready = false; return; }
    if (s_conn)    { pClose(s_conn);    s_conn    = nullptr; }
    if (s_session) { pClose(s_session); s_session = nullptr; }
    pDeleteCS(&s_req_cs);
    pDeleteCS(&s_cs);
    s_ready = false;
}

} // namespace net
