# Architecture Briefing — Commercial Licensed Software Distribution Platform

**Status:** C++ client complete (phases 1–6 implemented and reviewed). Go server not implemented.

---

## 1. Architecture Overview

Commercial licensed Windows software distribution platform. Two components: **activation client** (C++ native, Windows x64, first-party vendor application) and **licensing server** (REST/TLS 1.3, Go). The client authenticates the user license, receives a per-seat encrypted copy of the vendor's commercial binary, and loads it in memory — a common pattern among paid-software vendors (commercial DRM SDKs such as VMProtect, Apple FairPlay, trading clients, enterprise license dongles).

Product goals:
- **License enforcement:** per-seat activation codes, bound to a hardware fingerprint id (device fingerprint), so an activation code cannot be freely redistributed across machines.
- **Integrity verification:** at runtime the client verifies that its own code has not been modified in memory and that the delivered binary came from the real server (TLS certificate fingerprint check, authenticated encryption, keyed message integrity tag for session binding).
- **Secure distribution:** the licensed binary is delivered encrypted, decrypted in memory, and never written to disk — standard practice for protecting commercial IP against casual copying.
- **Runtime environment checks:** the client periodically verifies its own code integrity, debugger-presence (support diagnostic), Windows API runtime integrity, and overall execution environment; if the integrity contract breaks it exits cleanly — the same behavior shown by trading clients, paid commercial games, and licensed enterprise software.
- **Observability and entitlement revocation:** the server records session activity and can suspend licenses.

**Main flow implemented in the client:**

1. Integrity boot: `anti_debug::hide_current_thread` → `canary::install` → baseline `text_crc` (CRC32 of `.text`) + `code_fingerprint` (CRC32 of the first 64 B of each runtime guard) → `sentinel::scan` (debugger-presence check, runtime API integrity, unsupported diagnostic tools, code-integrity check abort; environment-integrity check is WARN only).
2. Device fingerprint: SHA-256 of `NVMe serial || SMBIOS UUID || CPUID` (3 leafs). MAC removed.
3. User enters the activation code via stdin. Client computes `g_license_hash = SHA-256(activation_code)` and zeroes the immediate buffer.
4. `net::init` opens WinHTTP TLS 1.3 with dual TLS certificate fingerprint check (SHA-256 of leaf cert, current + backup).
5. Two-step auth:
   - `POST /api/v1/auth/challenge` with `{hwid}` → `{challenge, expires_at}`.
   - `POST /api/v1/auth/login` with `challenge_response = keyed-tag(nonce, HKDF-SHA256(ikm=activation_code, salt=hwid_hex_bytes || "SecBlind_HKDF_v1", info=<empty>))` → `{session_token, session_key, ttl, heartbeat_interval, next_nonce}`.
6. `sentinel::set_scrub_callback` + `sentinel::start_monitor(text_crc, code_fp)` — 30 s thread that re-checks integrity and, on failure, zeros `g_payload_key`/`g_license_hash` → `heartbeat::stop` → `TerminateProcess` → `ExitProcess` → `for(;;)`.
7. `heartbeat::start`: dedicated thread, interval provided by the server, rotating nonce (replay-protection token), 3 failures → `stop_reason::failed`.
8. `payload::load_and_execute(session_token, session_key, hwid, license_hash, is_dll)`:
   - `POST /api/v1/payload/fetch` with `{session_token}`.
   - JSON response `{iv, tag, ciphertext}` base64 RFC 4648.
   - `aes256_gcm_decrypt` via BCrypt symbol resolver → plaintext = `session_binding[128] || PE`.
   - `watermark::verify` constant-time against HWID + license + TTL + keyed message integrity tag (per-session integrity tag).
   - `pe_loader::map` (bounds-checked: DOS, NT, Machine=x86_64, `SizeOfOptionalHeader==sizeof(IMAGE_OPTIONAL_HEADER64)`, `SizeOfHeaders`, `SizeOfBlock` of reloc, VA/SizeOfRawData of sections, reloc delta within `image_size`, `AddressOfEntryPoint`).
   - Imports by symbol hash lookup of the name (ordinal fail-closed, forwarders `Module.Func` resolved recursively).
   - Protect per-section, `FlushInstructionCache`, zero the in-memory MZ/PE header (prevents casual module copy from memory).
   - Execute entry.
9. Zero key/token; `while (heartbeat::is_running()) Sleep(1000)`.
10. Shutdown canonical order: `sentinel::stop_monitor` → `heartbeat::stop` → `net::shutdown`.

**Remote entitlement revocation:** the server replies to heartbeat with `kill=true` or `revoked=true` → `heartbeat::stop_reason` → main leaves the loop and exits cleanly.

---

## 2. Module breakdown — real state

### Client (`Project1/`)

#### Headers (`Project1/include/`)
| File | Responsibility |
|---|---|
| `obfstr.h` | Compile-time string protection by XOR (`__COUNTER__` seed), zeroes the volatile buffer on destruction. `OBF("...")` wraps every literal. |
| `dynapi.h` / `dynapi.cpp` | Runtime symbol resolver via process-module enumeration on x64 (TEB+0x60→PEB+0x18→Ldr+0x20), export table via symbol hash lookup (compile-time hashing of names), forwarder support (`Module.Func`), `LoadLibraryA` bootstrap for DLLs not yet present. Build uses the lazy-symbol-binder import policy (all sensitive APIs bound at runtime). |
| `hwid.h` / `hwid.cpp` | Device fingerprint derivation: SHA-256 of `IOCTL_STORAGE_QUERY_PROPERTY` (NVMe serial) + `GetSystemFirmwareTable` (SMBIOS Type 1 UUID) + CPUID (3 leafs). 64-char lowercase hex. |
| `base64.h` | Header-only RFC 4648 encode/decode. |
| `json_lite.h` | Minimal flat-object parser (`get_string`, `get_int`, `get_bool`). Replaces nlohmann to keep the lazy-symbol-binder import policy and reduce binary size. |
| `net.h` / `net.cpp` | WinHTTP via symbol resolver, TLS 1.3 flag `0x2000`, dual TLS certificate fingerprint check on leaf (SHA-256), critical section for serialization. |
| `auth.h` / `auth.cpp` | Keyed message integrity tag (HMAC-SHA256) via BCrypt (`BCRYPT_ALG_HANDLE_HMAC_FLAG=0x8`), key derivation (RFC 5869 / HKDF-SHA256), nonce-based authentication flow, session key material zeroization after use. |
| `heartbeat.h` / `heartbeat.cpp` | Thread, `WaitForSingleObject` with `stop_event`, nonce rotation, kill/revoke detection, 3-failure threshold, join-before-zero. |
| `crypto.h` / `crypto.cpp` | Authenticated encryption (AES-256-GCM) via BCrypt (`BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO v1`). Tag mismatch clears `out`. |
| `pe_loader.h` / `pe_loader.cpp` | Custom in-memory module loader for the encrypted entitled module delivered by the server. Maps x64 PE in memory with every validation listed in phase 3. |
| `payload.h` / `payload.cpp` | End-to-end fetch+decrypt+verify+map+execute. JSON keys via OBF. Volatile zeroization of iv/tag/ct/pe_bytes on all paths. |
| `anti_debug.h` / `.cpp` | Debugger-presence check (support diagnostic): PEB `BeingDebugged`/`NtGlobalFlag`/`HeapFlags`, `NtQueryInformationProcess` (DebugPort/Object/Flags), `NtQuerySystemInformation` (kernel debugger), `GetThreadContext` DR0–3/DR7, `CheckRemoteDebuggerPresent`, `OutputDebugString` trick. Pseudo-handles `-1`/`-2`. `hide_current_thread` via `NtSetInformationThread(ThreadHideFromDebugger=0x11)`. |
| `anti_vm.h` / `.cpp` | Environment integrity check (hint for environments not supported by the product): CPUID leaf 1 ECX bit 31 (hv), leaf `0x40000000` (KVMKVMKVM, Microsoft Hv, VMwareVMware, XenVMMXenVMM, VBoxVBoxVBox via OBF), RDTSC-CPUID fence sandwich (9 samples, median, threshold 50k), `GetAdaptersAddresses` retry-with-grow via HeapAlloc with hand-declared `IP_ADAPTER_ADDRESSES_LITE` (VMware/VBox/MS-virt OUIs), registry keys. |
| `anti_hook.h` / `.cpp` | Runtime API integrity validation on 16 watched APIs (IsDebuggerPresent, NtQueryInformationProcess, CheckRemoteDebuggerPresent, GetThreadContext, BCryptEncrypt/Decrypt, BCryptHash, BCryptGenRandom, WinHttpOpen/Connect/SendRequest/ReceiveResponse, NtSetInformationThread, etc.). Compares in-memory prologue with the DLL on disk: detects `0xE9`/`0xE8`/`FF 25`/`0xCC`. Multi-module trust set: kernel32/kernelbase/ntdll; bcrypt/bcryptprimitives/ntdll (resolves forwarders on Win10+). **shortcut: prologue only, upgrade when the attack surface shifts to mid-function stubs.** |
| `anti_tamper.h` / `.cpp` | Self-integrity check on code: CRC32 bitwise poly `0xEDB88320` of `.text` section. Lookup by name; fallback via `Characteristics & (CNT_CODE|MEM_EXECUTE)`. `SENTINEL_NOT_FOUND = 0xFFFFFFFF`. |
| `tool_detect.h` / `.cpp` | Diagnostic environment detection — environments the product does not support (attached research tools). Same policy used by commercial DRM that enumerates incompatible environments for a licensed product. `NtQuerySystemInformation(5)` buffer-grow loop. Hashed blocklists (debugger/disasm/inspector/memhack/hypervisor). Own PID skipped via `GetCurrentProcessId`. |
| `sentinel.h` / `.cpp` | `scan(report&)`, `start_monitor(text_crc, code_fp)`, `stop_monitor`, `set_scrub_callback`. Fault-handler-based diagnostic watchdog thread with cancellable event. Trip: scrub_cb → `heartbeat::stop` → `terminate_silent` (TerminateProcess → ExitProcess → `for(;;)`). |
| `watermark.h` / `.cpp` | 128-byte per-session integrity tag prefixed to the PE: `hwid_hash[32] || license_hash[32] || issued_at_u64_le[8] || ttl_u64_le[8] || nonce[16] || keyed-tag[32]`. `verify` constant-time (`ct_eq`), `FILETIME`→unix u64, deadline overflow check, keyed-tag covers `[0..96)`, compares `[96..128)`. SHA-256 via BCrypt. |
| `canary.h` / `.cpp` | 4 volatile data runtime guards (MAGIC_A/B/C/D) + 4 trap funcs `__declspec(noinline)` with a single unique volatile sink per trap (defeats `/OPT:ICF`). `code_fingerprint` = CRC32 of the first 64 B of each `trap_*`. |
| `rpc.h` / `.cpp` | `call(method, token, key, params_json) → response`. Canonical: `method || "|" || token || "|" || ts || "|" || params_json`. keyed-tag (HMAC-SHA256) key = `session_key`. 44-char padded base64. Fail-fast if `GetSystemTimeAsFileTime` fails. Zeroes buffers on all paths. |

#### Main (`Project1/src/Main.cpp`)
Flow described in section 1. `g_payload_key[32]` and `g_license_hash[32]` are file-scope `static volatile uint8_t` so the sentinel scrub_cb can reach them from another thread.

### Project infra
| File | Purpose |
|---|---|
| `SERVER_SPEC.md` | API spec of the 5 licensing-server endpoints (see section 3). |
| `POST_BUILD.md` | Commercial release checklist: order VMProtect → Themida (optional) → SignTool. Never virtualize `canary::trap_*`. |
| `TESTING.md` | Integrity-check matrix, FP matrix, fuzzer runbook, thread audit CONFIRMED, lazy-symbol-binder import policy conformance runbook, residual risks. |
| `tests/pe_loader_fuzzer/` | Standalone vcxproj. 15 cases: clean_ok sanity + 14 malformed. Robustness test of the in-memory loader against malformed input. Links `Project1\src\pe_loader.cpp` + `dynapi.cpp`. |
| `scripts/verify_zero_iat.ps1` | Build import-policy compliance check: `dumpbin /IMPORTS` + hardFail list (BCrypt*, WinHttp*, Nt*, VirtualAlloc, GetAdaptersAddresses, RegOpenKeyExA, LoadLibrary*, GetProcAddress, CheckRemoteDebuggerPresent, GetThreadContext, FlushInstructionCache, OutputDebugStringA, IsDebuggerPresent). Strict Mode. Exit 1 on hard-fail. Ensures the build matches the deploy policy. |
| `scripts/stress_sentinel.ps1` | Load test of the health-check subsystem: 5 parallel instances, 10 s timeout, hang/race detection. |

### Server — not implemented
Spec in `SERVER_SPEC.md`. Go implementation plan in section 4 of this document.

---

## 3. Real tech stack

### Client (implemented)
| Need | Choice | Note |
|---|---|---|
| Crypto | **Windows CNG (bcrypt.dll)** via symbol resolver | Lazy dynamic symbol binding (lazy-symbol-binder build policy). `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` manually redefined (if SDK changes layout, decrypt breaks). |
| TLS + HTTP | **WinHTTP** via symbol resolver | `WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 = 0x2000`. |
| TLS certificate fingerprint check | Dual callback (current + backup SHA-256 of leaf) | Placeholders at `net.cpp:161-162`. |
| JSON | `json_lite.h` custom | Flat objects. No external dependency. |
| Compile-time string protection | `obfstr.h` custom | Compile-time XOR + volatile zeroization. |
| Symbol resolution | `dynapi.cpp` process-module enumeration + symbol hash lookup | Pre-computed module name hashes (kernel32/kernelbase/ntdll/winhttp/crypt32/bcrypt). Forwarders supported. |
| Compile | **Visual Studio 2026**, MSVC x64, C++20, `/O2 /GS /DYNAMICBASE /HIGHENTROPYVA` | |
| Packer | **VMProtect → Themida → SignTool** (see `POST_BUILD.md`) | Never virtualize `canary::trap_*`. |

### Server (planned — section 4)
Go 1.23+, native `net/http`, PostgreSQL + Redis, Nginx TLS, Let's Encrypt.

---

## 4. Go server plan

Authoritative spec: `SERVER_SPEC.md` (5 endpoints). Crypto parameters must **match byte-for-byte** with the client, otherwise auth/decrypt/session-binding verification fails.

### 4.1. Suggested directory layout

```
sec-blind-server/
  cmd/server/main.go               # entry: parse flags, start HTTP+DB+Redis
  internal/
    api/                           # HTTP handlers (5 endpoints)
      challenge.go
      login.go
      heartbeat.go
      payload.go
      rpc.go
    auth/                          # keyed-tag, key derivation, nonce-based auth verify
    session/                       # Redis-backed session store, nonce chain
    hwid/                          # bind, cooldown, reset
    payload/                       # session-binding gen, authenticated encrypt, build store
    rpc/                           # method dispatch (compute_x etc.)
    abuse/                         # rate limit, entitlement revocation
    db/                            # postgres queries
    cache/                         # redis client
  pkg/crypto/                      # shared primitives
  migrations/                      # SQL schema
  config.yaml                      # port, DSN, redis addr, secrets paths
  go.mod
```

### 4.2. Crypto parameters — mandatory

| Item | Value | Where the client uses it |
|---|---|---|
| Key derivation salt (login) | `hwid_hex_bytes || "SecBlind_HKDF_v1"` (64 + 16 = 80 bytes). Info **empty**. | `auth.cpp` |
| Key derivation salt (session key) | literal `"SecBlind_HKDF_v1"` (16 bytes). Info = `session_id_bytes \|\| hwid_hash_bytes`. | server |
| Key derivation algo | keyed-tag SHA-256, RFC 5869, output 32 bytes (1 block) | `auth.cpp` |
| Keyed message integrity tag algo | SHA-256 via `crypto/hmac` + `crypto/sha256` | `auth.cpp`, `heartbeat.cpp`, `rpc.cpp`, `watermark.cpp` |
| Key separation (RFC 5869 §3.3) | `session_key` is the **PRK**; each use receives a 32 B sub-key via **HKDF-Expand(SHA-256)**. `OKM = keyed-tag(PRK, info \|\| 0x01)` (1 block). ASCII literal info-tags. | server `api.go` + client `crypto.cpp`/`auth.cpp` |
| Authenticated encryption mode | AES-256-GCM, 12 B IV, 16 B tag | `crypto.cpp` |
| Base64 | **RFC 4648 with `=` padding** (`base64.StdEncoding`, not URL encoding, not RawStd) | everywhere |
| Device fingerprint | SHA-256 hex lowercase 64 chars (UTF-8 of the hex) | `hwid.cpp` |
| Session key derivation | `HKDF(master_secret, info = session_id_bytes \|\| hwid_hash_bytes, salt = "SecBlind_HKDF_v1")`. `hwid_hash_bytes` = 32 raw B from `hex.DecodeString(hwid_hex)`. | spec SERVER_SPEC.md §Notes |
| Challenge response | `keyed-tag(nonce, HKDF-SHA256(ikm=activation_code, salt=hwid_hex_bytes \|\| "SecBlind_HKDF_v1", info=<empty>))`. **No** per-license `session_salt`. | `auth.cpp` |

**Key derivation (key separation):**

```
login:  session_key (PRK) = HKDF(master_secret, salt="SecBlind_HKDF_v1",
                                  info = session_id || hwid_hash)   [32 B]
         |  returned to the client as today (no new JSON field)
         v
HKDF-Expand(SHA-256), OKM = keyed-tag(PRK, info || 0x01):
  k_payload_aes = HKDF-Expand(session_key, "sb.v1.payload.aes256gcm", 32)  -> payload authenticated encryption
  k_heartbeat   = HKDF-Expand(session_key, "sb.v1.heartbeat.hmac",    32)  -> heartbeat keyed-tag
  k_watermark   = HKDF-Expand(session_key, "sb.v1.watermark.hmac",    32)  -> session-binding keyed-tag
  k_rpc         = HKDF-Expand(session_key, "sb.v1.rpc.hmac",          32)  -> /rpc/call keyed-tag
```

Server derives the sub-key at each handler's point of use (`/heartbeat`, `/payload/fetch`, `/rpc/call`); client derives all four right after login (`auth.cpp`) and zeroes the PRK. Byte-exact vector in `server/pkg/crypto/hkdf_test.go`.

**Gotchas that block the client:**
- Base64 without padding → client `base64.h` expects `=`. Use `base64.StdEncoding`, not `RawStdEncoding`.
- HKDF-Expand info-tags are ASCII literals **without** a null terminator. Client uses `OBF(...).size()` (= `N-1`), matching Go `[]byte("...")`.
- Little-endian order for `issued_at`/`ttl` in the session binding. Go: `binary.LittleEndian.PutUint64`.
- `ttl == 0` is rejected by the client as expired. Always `>= 1`.
- Session-binding keyed-tag covers bytes `[0..96)` of the binding itself. Nothing else.

### 4.3. Endpoints — contract summaries

#### `POST /api/v1/auth/challenge`
- **In:** `{"hwid": "<hex64>"}`.
- **Out 200:** `{"challenge": "<b64 32B>", "expires_at": <unix>}`.
- **Logic:** generate 32 B random (`crypto/rand`), store in Redis under key `challenge:<hwid>`, TTL 60 s. Rate limit by IP+HWID.
- **Error 429:** `{"error":"rate_limited","retry_after":30}`.

#### `POST /api/v1/auth/login`
- **In:** `{"license_key","hwid","challenge","challenge_response"}`.
- **Verify:**
  1. `challenge` exists in Redis for that HWID and has not expired. Consume (one-shot).
  2. `license_key` exists in Postgres and is not suspended.
  3. `derived_key = HKDF(ikm=license_key, salt=hwid_hex_bytes || "SecBlind_HKDF_v1", info=<empty>)`. There is no per-license `session_salt`.
  4. `keyed-tag(challenge, derived_key) == challenge_response`? Constant-time compare (`hmac.Equal`).
  5. HWID bind: if new → bind (respect 30 d cooldown); if different → 401 `hwid_mismatch` or `hwid_cooldown`.
  6. Terminate prior session if present (at most 1 active per license).
- **Out 200:** generate `session_token` (32 B random hex), `session_key` = `HKDF(master_secret, session_id || hwid_hash)` 32 B base64, `ttl=900`, `heartbeat_interval=60`, `next_nonce` = 32 B random base64.
- **Store:** Redis `session:<token>` → `{license_id, hwid, session_key_b64, next_nonce_b64, expires_at}` TTL 900 s.

#### `POST /api/v1/session/heartbeat`
- **In:** `{session_token, hmac, timestamp, next_nonce}`.
- **Verify:**
  1. Session exists and has not expired.
  2. Received `next_nonce` == stored `next_nonce` from the previous response (replay-protection token).
  3. `hmac == keyed-tag(key=session_key, data=timestamp_string)`. Constant-time.
  4. `timestamp` within a window (e.g. ±5 min of server now).
- **Out 200:** refresh TTL to 900 s, generate a new `next_nonce`, return `{next_nonce, kill, revoked}`.
- **Entitlement revocation:** look up `license_kill` or `session_revoked`. If true, do not refresh TTL.

#### `POST /api/v1/payload/fetch`
- **In:** `{session_token}`.
- **Logic:**
  1. Valid session? Otherwise 401.
  2. Load the license's base build (or build with session binding).
  3. Generate a 128 B session-binding:
     - `hwid_bytes = hex.DecodeString(hwid_hex)` — 32 raw bytes from the hex. **Not** `SHA-256(hwid_hex)`.
     - `license_hash = SHA-256(license_key_bytes)` (32 B, raw key bytes).
     - `issued_at = time.Now().Unix()` u64 LE.
     - `ttl = 86400` (24 h, pick a policy) u64 LE. **Never 0.**
     - `nonce = crypto/rand` 16 B.
     - `signature = keyed-tag(session_key, binding[0..96])` (32 B).
  4. `plaintext = binding || pe_bytes`.
  5. `iv = crypto/rand` 12 B. `aesgcm.Seal(nil, iv, plaintext, nil)` → `ciphertext || tag`. Split the tag (last 16 B).
  6. Return JSON `{iv, tag, ciphertext}` base64 StdEncoding.
- **Out 401/403:** `{"error":"session_expired|not_authorized","message":"..."}`.

#### `POST /api/v1/rpc/call`
- **In:** `{method, session_token, payload (object), timestamp, hmac}`.
- **Canonical verify:**
  - **Exact serialization:** `payload_json` must be **the serialization the client sent**, not a Go re-serialization. Read the raw body and extract the `payload` span without re-marshal (or store the original). Go `encoding/json` reorders keys — that breaks the keyed-tag. **Solution:** the client sends `payload` as a compact JSON string without whitespace and the server reads the raw body to extract the span. Or: the client sends a separate canonical. Decide and document first.
  - `canonical = method || "|" || session_token || "|" || timestamp || "|" || payload_json`.
  - `keyed-tag(session_key, canonical) == hmac`.
- **Dispatch:** switch by `method`. Each method has its own `payload` schema.
- **Out 200:** method-specific JSON.

### 4.4. PostgreSQL schema

```sql
CREATE TABLE licenses (
    id            BIGSERIAL PRIMARY KEY,
    license_key   TEXT UNIQUE NOT NULL,
    banned        BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE hwid_binds (
    license_id    BIGINT REFERENCES licenses(id) ON DELETE CASCADE,
    hwid          CHAR(64) NOT NULL,
    bound_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (license_id)
);

CREATE TABLE hwid_cooldown (
    license_id    BIGINT REFERENCES licenses(id) ON DELETE CASCADE,
    last_change   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (license_id)
);

CREATE TABLE abuse_log (
    id            BIGSERIAL PRIMARY KEY,
    license_id    BIGINT,
    ip            INET,
    reason        TEXT,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE payload_builds (
    id            BIGSERIAL PRIMARY KEY,
    license_id    BIGINT REFERENCES licenses(id),
    pe_bytes      BYTEA NOT NULL,         -- base build or build with session binding on disk
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 4.5. Redis keys
- `challenge:<hwid>` → `<b64 nonce>`, TTL 60 s.
- `session:<token>` → hash `{license_id, hwid, session_key, next_nonce, expires_at}`, TTL 900 s.
- `rate:ip:<ip>`, `rate:hwid:<hwid>` → counter with window TTL.

### 4.6. Server secrets
| Secret | Format | Use |
|---|---|---|
| `master_secret` | 32 B random | Input to the session-key HKDF. Store outside the repo (env, vault). |
| TLS cert leaf | PEM | SHA-256 hash must match the pin hardcoded in `net.cpp:161-162`. |
| Optional signing key | Ed25519 | If using JWT instead of an opaque token. |

### 4.7. Suggested implementation order
1. **Scaffold + migrations** — `go mod init`, Postgres conn, migrations tool (goose/sql-migrate).
2. **Primitives** — `pkg/crypto`: HKDF, keyed-tag, AES-GCM wrappers. Unit tests with RFC 5869 vectors.
3. **Challenge + login** — the most critical flow. Test with the real client: point the client at `https://localhost:8443` with a self-signed cert whose hash is in the pin.
4. **Heartbeat** — add nonce chain + entitlement revocation flag.
5. **Payload fetch** — session-binding gen + AES-GCM. First with a dummy PE (a `MessageBoxA`).
6. **RPC** — last; depends on a real defined method.
7. **Nginx + Let's Encrypt** — production.

### 4.8. Hooks still blocking client deploy
The 9 TODOs in `feedback_secblind_decisions.md` must resolve before deploy:
1. Real TLS certificate fingerprint check hashes at `net.cpp:161-162`.
2. Real hostname in `Main.cpp` (replace `your-server.example.com`).
3. HKDF salt must be exactly `"SecBlind_HKDF_v1"` in Go.
4. Ordinal imports in `pe_loader.cpp` (simple entitled modules don't use them — OK for v1).
5. SEH callbacks / `.pdata` (likewise).
6. Runtime API integrity check shortcut (acceptable).
7. Environment integrity check false positives (WARN-only reduces them).
8. Forwarders by ordinal in the symbol resolver (rare).
9. ~~HKDF key-separation~~ ✅ **Resolved.** `session_key` becomes PRK; four sub-keys via HKDF-Expand (info-tags `sb.v1.*`) on both sides. See §4.2.

---

## 5. Risks and caveats

1. **No client-side protection is unbreakable.** Goal: raise the cost of casual piracy.
2. **VMProtect/Themida are detected by AV.** EV code signing required.
3. **Environment integrity check may block legitimate users.** In the current project it is WARN-only in the sentinel.
4. **TLS certificate fingerprint check complicates rotation.** Mitigated by the dual pin (current + backup).
5. **Server-side partial execution** — `/rpc/call` opens that path. Latency + failure point; use sparingly.
6. **Device fingerprint is not 100% stable.** Cooldown + manual admin reset.
7. **Session binding can be stripped by diffing builds.** Mitigation: spread + per-user codegen variations (out of scope for the client).
8. **Heartbeat depends on stable internet.** 3 consecutive failures, not 2.

---

## 6. Phase history

| Phase | Deliverables |
|---|---|
| **Phase 1** ✅ | Foundation: `obfstr.h`, `dynapi.h/.cpp` (process-module enumeration, symbol hash lookup). |
| **Phase 2** ✅ | Network + Auth + Heartbeat: `net`, `auth`, `heartbeat`, `hwid`, `base64`, `json_lite`, `Main.cpp`. |
| **Phase 3** ✅ | Entitled module: `crypto` (authenticated encryption via BCrypt), `pe_loader` (in-memory map + header zeroization), `payload` (end-to-end). Review 2 HIGH + 4 MED + 4 LOW applied. Client compiles. |
| **Phase 4** ✅ | Integrity verification: `anti_debug`, `anti_vm`, `anti_hook` (multi-module trust set), `anti_tamper` (CRC32 `.text` + fallback), `tool_detect` (skip own PID), `sentinel` (monitor thread + scrub callback). Review: 2 HIGH + 5 MED + 8 LOW. Symbol resolver gained forwarder support. |
| **Phase 5** ✅ | Hardening: session-binding module (128 B record), `canary` (4 data + 4 code guards), `rpc` (`/api/v1/rpc/call` canonical `\|` delimited + keyed-tag), sentinel extended with canary checks, `POST_BUILD.md`. Review: 5 MED + 4 LOW. HKDF key-separation logged as TODO 9. |
| **Phase 6** ✅ | Robustness and integrity tests: PE loader fuzzer (15 cases), `verify_lazy-import.ps1`, `stress_sentinel.ps1`, `TESTING.md`. Review: 1 HIGH + 6 MED + 4 LOW. Thread audit CONFIRMED: join-before-zero in `heartbeat::stop`, shutdown order `sentinel→heartbeat→net`. |

**Client: ready to build.** Server: pending (section 4 is the plan to ship).
