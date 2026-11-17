# Briefing de Arquitetura — Plataforma Comercial de Distribuição de Software Licenciado

**Status:** cliente C++ completo (Fases 1–6 implementadas e revisadas). Servidor Go não implementado.

---

## 1. Visão Geral da Arquitetura

Plataforma comercial de distribuição de software Windows licenciado. Dois componentes: **loader** (cliente, C++ nativo, Windows x64, aplicativo first-party do fornecedor) e **servidor de licenciamento** (REST/TLS 1.3, Go). O loader autentica a licença do usuário, recebe uma cópia cifrada per-seat do binário comercial do fornecedor e o carrega em memória — padrão comum entre vendedores de software pago (DRM comercial, SDKs tipo VMProtect, FairPlay da Apple, clientes de trading, dongles de licença corporativa).

Objetivos do produto:
- **Enforcement de licença:** licenças por assento, vinculadas a um identificador de hardware (HWID), para que uma licença não possa ser livremente redistribuída entre máquinas.
- **Verificação de integridade:** o cliente verifica em runtime que seu próprio código não foi modificado em memória e que o binário entregue veio do servidor real (certificate pinning, AES-GCM authenticated encryption, HMAC de ligação por sessão).
- **Distribuição segura:** o binário licenciado é entregue cifrado, decriptografado em memória e nunca gravado em disco — prática padrão para proteger IP comercial de cópia casual.
- **Checks de integridade em runtime:** o cliente verifica periodicamente integridade do código, presença de depurador, integridade da API e ambiente de execução; se o contrato de integridade quebra, encerra de forma limpa — mesmo comportamento de clientes de trading, jogos comerciais pagos e softwares corporativos licenciados.
- **Observabilidade e revogação:** o servidor registra atividade de sessão e pode revogar licenças.

**Fluxo principal implementado no cliente:**

1. Boot de integridade: `anti_debug::hide_current_thread` → `canary::install` → baseline `text_crc` (CRC32 da `.text`) + `code_fingerprint` (CRC32 das primeiras 64 B de cada trap) → `sentinel::scan` (checks de depurador, integridade de API, ferramentas não suportadas, integridade de código abortam; check de ambiente virtualizado apenas WARN).
2. HWID: SHA-256 de `NVMe serial || SMBIOS UUID || CPUID` (3 leafs). MAC removido.
3. Usuário informa a license key via stdin. Cliente computa `g_license_hash = SHA-256(license_key)` e zera o buffer imediato.
4. `net::init` abre WinHTTP TLS 1.3 com dual cert pinning (SHA-256 do leaf cert, current + backup).
5. Auth em dois passos:
   - `POST /api/v1/auth/challenge` com `{hwid}` → `{challenge, expires_at}`.
   - `POST /api/v1/auth/login` com `challenge_response = HMAC-SHA256(nonce, HKDF-SHA256(ikm=license_key, salt=hwid_hex_bytes || "SecBlind_HKDF_v1", info=<empty>))` → `{session_token, session_key, ttl, heartbeat_interval, next_nonce}`.
6. `sentinel::set_scrub_callback` + `sentinel::start_monitor(text_crc, code_fp)` — thread de 30 s que re-verifica integridade e, se a verificação falha, zera `g_payload_key`/`g_license_hash` → `heartbeat::stop` → `TerminateProcess` → `ExitProcess` → `for(;;)`.
7. `heartbeat::start`: thread dedicada, intervalo recebido do server, nonce rotativo, 3 falhas → `stop_reason::failed`.
8. `payload::load_and_execute(session_token, session_key, hwid, license_hash, is_dll)`:
   - `POST /api/v1/payload/fetch` com `{session_token}`.
   - Resposta JSON `{iv, tag, ciphertext}` base64 RFC 4648.
   - `aes256_gcm_decrypt` via BCrypt dynapi → plaintext = `session_binding[128] || PE`.
   - `watermark::verify` em constant-time contra HWID + license + TTL + HMAC (per-session integrity tag).
   - `pe_loader::map` (bounds-checked: DOS, NT, Machine=x86_64, `SizeOfOptionalHeader==sizeof(IMAGE_OPTIONAL_HEADER64)`, `SizeOfHeaders`, `SizeOfBlock` de reloc, VA/SizeOfRawData de seções, delta de reloc dentro de `image_size`, `AddressOfEntryPoint`).
   - Imports por FNV-1a hash do nome (ordinal fail-closed, forwarders `Module.Func` resolvidos recursivamente).
   - Protect per-section, `FlushInstructionCache`, zeragem do header MZ/PE in-memory (impede cópia casual do módulo a partir de memória).
   - Executa entry.
9. Zera key/token; `while (heartbeat::is_running()) Sleep(1000)`.
10. Shutdown ordem canônica: `sentinel::stop_monitor` → `heartbeat::stop` → `net::shutdown`.

**Revogação remota:** servidor responde heartbeat com `kill=true` ou `revoked=true` → `heartbeat::stop_reason` → main sai do loop e encerra limpo.

---

## 2. Breakdown de Módulos — Estado Real

### Cliente (`Project1/`)

#### Headers (`Project1/include/`)
| Arquivo | Responsabilidade |
|---|---|
| `obfstr.h` | Compile-time string hiding por XOR (`__COUNTER__` seed), zera o buffer volatile no destrutor. `OBF("...")` em todos os literais. |
| `dynapi.h` / `dynapi.cpp` | Runtime API resolution via PEB walk x64 (TEB+0x60→PEB+0x18→Ldr+0x20), export table por FNV-1a hash (compile-time hashing dos nomes), forwarder support (`Module.Func`), `LoadLibraryA` bootstrap para DLLs não presentes. Build com import policy lazy-import (todas as APIs sensíveis são ligadas em runtime). |
| `hwid.h` / `hwid.cpp` | HWID derivation: SHA-256 de `IOCTL_STORAGE_QUERY_PROPERTY` (NVMe serial) + `GetSystemFirmwareTable` (SMBIOS Type 1 UUID) + CPUID (3 leafs). 64-char lowercase hex. |
| `base64.h` | Header-only RFC 4648 encode/decode. |
| `json_lite.h` | Parser minimal flat object (`get_string`, `get_int`, `get_bool`). Substitui nlohmann para manter a import policy lazy-import e reduzir tamanho binário. |
| `net.h` / `net.cpp` | WinHTTP via dynapi, TLS 1.3 flag `0x2000`, dual cert pin SHA-256 leaf, critical section para serialização. |
| `auth.h` / `auth.cpp` | HMAC-SHA256 via BCrypt (`BCRYPT_ALG_HANDLE_HMAC_FLAG=0x8`), HKDF-SHA256 RFC 5869, challenge-response flow, zeragem da sessão após uso. |
| `heartbeat.h` / `heartbeat.cpp` | Thread, `WaitForSingleObject` com `stop_event`, nonce rotation, kill/revoke detect, 3-failure threshold, join-before-zero. |
| `crypto.h` / `crypto.cpp` | AES-256-GCM via BCrypt (`BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO v1`). Tag mismatch limpa `out`. |
| `pe_loader.h` / `pe_loader.cpp` | Custom in-memory loader para o payload DLL cifrado entregue pelo servidor. Mapeia x64 PE em memória com todas as validações listadas na Fase 3. |
| `payload.h` / `payload.cpp` | End-to-end fetch+decrypt+verify+map+execute. JSON keys via OBF. Zeragem volatile de iv/tag/ct/pe_bytes em todos os paths. |
| `anti_debug.h` / `.cpp` | Debugger presence check: PEB `BeingDebugged`/`NtGlobalFlag`/`HeapFlags`, `NtQueryInformationProcess` (DebugPort/Object/Flags), `NtQuerySystemInformation` (kernel debugger), `GetThreadContext` DR0–3/DR7, `CheckRemoteDebuggerPresent`, `OutputDebugString` trick. Pseudo-handles `-1`/`-2`. `hide_current_thread` via `NtSetInformationThread(ThreadHideFromDebugger=0x11)`. |
| `anti_vm.h` / `.cpp` | Virtualization environment check (hint para ambientes não suportados pelo produto): CPUID leaf 1 ECX bit 31 (hv), leaf `0x40000000` (KVMKVMKVM, Microsoft Hv, VMwareVMware, XenVMMXenVMM, VBoxVBoxVBox via OBF), RDTSC-CPUID fence sandwich (9 samples, mediana, threshold 50k), `GetAdaptersAddresses` retry-with-grow via HeapAlloc com `IP_ADAPTER_ADDRESSES_LITE` hand-declared (OUIs VMware/VBox/MS-virt), registry keys. |
| `anti_hook.h` / `.cpp` | API integrity check sobre 16 APIs vigiadas (IsDebuggerPresent, NtQueryInformationProcess, CheckRemoteDebuggerPresent, GetThreadContext, BCryptEncrypt/Decrypt, BCryptHash, BCryptGenRandom, WinHttpOpen/Connect/SendRequest/ReceiveResponse, NtSetInformationThread, etc.). Compara prólogo em memória com DLL em disco: detecta `0xE9`/`0xE8`/`FF 25`/`0xCC`. Trust set multi-módulo: kernel32/kernelbase/ntdll; bcrypt/bcryptprimitives/ntdll (resolve forwarders no Win10+). **Shortcut:** só prólogo. |
| `anti_tamper.h` / `.cpp` | Code integrity verification: CRC32 bitwise poly `0xEDB88320` da seção `.text`. Busca por nome; fallback por `Characteristics & (CNT_CODE|MEM_EXECUTE)`. `SENTINEL_NOT_FOUND = 0xFFFFFFFF`. |
| `tool_detect.h` / `.cpp` | Detecta ambientes de execução não suportados (ferramentas de pesquisa anexadas) — mesma política de DRM comercial que lista ambientes incompatíveis com o produto licenciado. `NtQuerySystemInformation(5)` buffer-grow loop. Blocklists hashed (debugger/disasm/inspector/memhack/hypervisor). Skip próprio PID via `GetCurrentProcessId`. |
| `sentinel.h` / `.cpp` | `scan(report&)`, `start_monitor(text_crc, code_fp)`, `stop_monitor`, `set_scrub_callback`. Monitor thread (watchdog) com event cancelável. Trip: scrub_cb → `heartbeat::stop` → `terminate_silent` (TerminateProcess → ExitProcess → `for(;;)`). |
| `watermark.h` / `.cpp` | Per-session integrity tag de 128 bytes prefixada ao PE: `hwid_hash[32] || license_hash[32] || issued_at_u64_le[8] || ttl_u64_le[8] || nonce[16] || HMAC-SHA256[32]`. `verify` constant-time (`ct_eq`), `FILETIME`→unix u64, overflow check no deadline, HMAC cobre `[0..96)`, compara `[96..128)`. SHA-256 via BCrypt. |
| `canary.h` / `.cpp` | 4 data canaries volatile (MAGIC_A/B/C/D) + 4 trap funcs `__declspec(noinline)` com volatile sink único por trap (defeats `/OPT:ICF`). `code_fingerprint` = CRC32 dos primeiros 64 B de cada `trap_*`. |
| `rpc.h` / `.cpp` | `call(method, token, key, params_json) → response`. Canonical: `method || "|" || token || "|" || ts || "|" || params_json`. HMAC-SHA256 key = `session_key`. Base64 44-char padded. Fail-fast se `GetSystemTimeAsFileTime` falha. Zera buffers em todos os paths. |

#### Main (`Project1/src/Main.cpp`)
Fluxo descrito na seção 1. `g_payload_key[32]` e `g_license_hash[32]` são `static volatile uint8_t` file-scope para o sentinel scrub_cb acessá-los de outra thread.

### Infra do projeto
| Arquivo | Propósito |
|---|---|
| `SERVER_SPEC.md` | API spec dos 5 endpoints do servidor de licenciamento (ver seção 3). |
| `POST_BUILD.md` | Checklist de release comercial: ordem VMProtect → Themida (opcional) → SignTool. Nunca virtualizar `canary::trap_*`. |
| `TESTING.md` | Matriz de verificação de integridade, FP matrix, runbook do fuzzer, auditoria de threads CONFIRMED, runbook de conformidade da import policy lazy-import, riscos residuais. |
| `tests/pe_loader_fuzzer/` | vcxproj independente. 15 cases: clean_ok sanity + 14 malformed. Teste de robustez do in-memory loader contra entrada mal formada. Linka `Project1\src\pe_loader.cpp` + `dynapi.cpp`. |
| `scripts/verify_lazy-import.ps1` | Compliance check da import policy do build: `dumpbin /IMPORTS` + hardFail list (BCrypt*, WinHttp*, Nt*, VirtualAlloc, GetAdaptersAddresses, RegOpenKeyExA, LoadLibrary*, GetProcAddress, CheckRemoteDebuggerPresent, GetThreadContext, FlushInstructionCache, OutputDebugStringA, IsDebuggerPresent). Strict Mode. Exit 1 em hard-fail. Garante que o build bate com a política de deploy. |
| `scripts/stress_sentinel.ps1` | Teste de carga do subsistema de health checks: 5 instâncias paralelas, timeout 10 s, detecção de hang/race. |

### Servidor — não implementado
Spec em `SERVER_SPEC.md`. Plano de implementação Go na seção 4 deste documento.

---

## 3. Tech Stack Real

### Cliente (implementado)
| Necessidade | Escolha | Observação |
|---|---|---|
| Crypto | **Windows CNG (bcrypt.dll)** via dynapi | Lazy dynamic imports (lazy-import build policy). `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` redefinido manualmente (se SDK mudar layout, decrypt quebra). |
| TLS + HTTP | **WinHTTP** via dynapi | `WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 = 0x2000`. |
| Cert pinning | Callback dual (current + backup SHA-256 do leaf) | Placeholders em `net.cpp:161-162`. |
| JSON | `json_lite.h` custom | Flat objects. Sem dependência externa. |
| Compile-time string hiding | `obfstr.h` custom | XOR compile-time + zeragem volatile. |
| API resolution | `dynapi.cpp` PEB walk + FNV-1a | Pre-computed hashes de módulos (kernel32/kernelbase/ntdll/winhttp/crypt32/bcrypt). Forwarders suportados. |
| Compile | **Visual Studio 2026**, MSVC x64, C++20, `/O2 /GS /DYNAMICBASE /HIGHENTROPYVA` | |
| Packer | **VMProtect → Themida → SignTool** (ver `POST_BUILD.md`) | Nunca virtualizar `canary::trap_*`. |

### Servidor (planejado — seção 4)
Go 1.23+, `net/http` nativo, PostgreSQL + Redis, Nginx TLS, Let's Encrypt.

---

## 4. Plano do Servidor Go

Spec autoritativa: `SERVER_SPEC.md` (5 endpoints). Parâmetros criptográficos devem **bater byte-a-byte** com o cliente, senão auth/decrypt/verificação do session binding falham.

### 4.1. Estrutura de diretórios sugerida

```
sec-blind-server/
  cmd/server/main.go               # entry: parse flags, inicia HTTP+DB+Redis
  internal/
    api/                           # handlers HTTP (5 endpoints)
      challenge.go
      login.go
      heartbeat.go
      payload.go
      rpc.go
    auth/                          # HMAC, HKDF, challenge-response verify
    session/                       # Redis-backed session store, nonce chain
    hwid/                          # bind, cooldown, reset
    payload/                       # session-binding gen, AES-GCM encrypt, build store
    rpc/                           # method dispatch (compute_x etc.)
    abuse/                         # rate limit, revogação
    db/                            # postgres queries
    cache/                         # redis client
  pkg/crypto/                      # primitives compartilhadas
  migrations/                      # SQL schema
  config.yaml                      # porta, DSN, redis addr, secrets paths
  go.mod
```

### 4.2. Parâmetros criptográficos — obrigatórios

| Item | Valor | Onde o cliente usa |
|---|---|---|
| HKDF salt (login) | `hwid_hex_bytes || "SecBlind_HKDF_v1"` (64 + 16 = 80 bytes). Info **vazio**. | `auth.cpp` |
| HKDF salt (session key) | literal `"SecBlind_HKDF_v1"` (16 bytes). Info = `session_id_bytes \|\| hwid_hash_bytes`. | server |
| HKDF algo | HMAC-SHA256, RFC 5869, output 32 bytes (1 bloco) | `auth.cpp` |
| HMAC algo | SHA-256 via `crypto/hmac` + `crypto/sha256` | `auth.cpp`, `heartbeat.cpp`, `rpc.cpp`, `watermark.cpp` |
| Key separation (RFC 5869 §3.3) | `session_key` é o **PRK**; cada uso recebe uma sub-chave de 32 B via **HKDF-Expand(SHA-256)**. `OKM = HMAC-SHA256(PRK, info \|\| 0x01)` (1 bloco). Info-tags ASCII literais. | server `api.go` + cliente `crypto.cpp`/`auth.cpp` |
| AES mode | AES-256-GCM, IV 12 B, tag 16 B | `crypto.cpp` |
| Base64 | **RFC 4648 com padding `=`** (`base64.StdEncoding`, não URL encoding, não RawStd) | tudo |
| HWID | SHA-256 hex lowercase 64 chars (UTF-8 do hex) | `hwid.cpp` |
| Session key derivation | `HKDF(master_secret, info = session_id_bytes \|\| hwid_hash_bytes, salt = "SecBlind_HKDF_v1")`. `hwid_hash_bytes` = 32 B crus de `hex.DecodeString(hwid_hex)`. | spec SERVER_SPEC.md §Notes |
| Challenge response | `HMAC-SHA256(nonce, HKDF-SHA256(ikm=license_key, salt=hwid_hex_bytes \|\| "SecBlind_HKDF_v1", info=<empty>))`. **Sem** `session_salt` per-license. | `auth.cpp` |

**Derivação de chaves (key separation):**

```
login:  session_key (PRK) = HKDF(master_secret, salt="SecBlind_HKDF_v1",
                                  info = session_id || hwid_hash)   [32 B]
         |  retornada ao cliente como hoje (sem campo JSON novo)
         v
HKDF-Expand(SHA-256), OKM = HMAC-SHA256(PRK, info || 0x01):
  k_payload_aes = HKDF-Expand(session_key, "sb.v1.payload.aes256gcm", 32)  -> AES-256-GCM do payload
  k_heartbeat   = HKDF-Expand(session_key, "sb.v1.heartbeat.hmac",    32)  -> HMAC do heartbeat
  k_watermark   = HKDF-Expand(session_key, "sb.v1.watermark.hmac",    32)  -> HMAC do session binding
  k_rpc         = HKDF-Expand(session_key, "sb.v1.rpc.hmac",          32)  -> HMAC do /rpc/call
```

Servidor deriva a sub-chave no ponto de uso de cada handler (`/heartbeat`, `/payload/fetch`, `/rpc/call`); cliente deriva as quatro logo após o login (`auth.cpp`) e zera o PRK. Vetor byte-exato em `server/pkg/crypto/hkdf_test.go`.

**Pegadinhas que bloqueiam o cliente:**
- Base64 sem padding → `base64.h` do cliente espera `=`. Use `base64.StdEncoding`, não `RawStdEncoding`.
- Info-tags do HKDF-Expand são ASCII literais **sem** null terminator. Cliente usa `OBF(...).size()` (= `N-1`), que bate com `[]byte("...")` do Go.
- Ordem little-endian em `issued_at`/`ttl` do session binding. Go: `binary.LittleEndian.PutUint64`.
- `ttl == 0` é rejeitado pelo cliente como expirado. Sempre `>= 1`.
- HMAC do session binding cobre bytes `[0..96)` do próprio binding. Nada além.

### 4.3. Endpoints — contratos resumidos

#### `POST /api/v1/auth/challenge`
- **In:** `{"hwid": "<hex64>"}`.
- **Out 200:** `{"challenge": "<b64 32B>", "expires_at": <unix>}`.
- **Logic:** gerar 32 B random (`crypto/rand`), armazenar no Redis com chave `challenge:<hwid>`, TTL 60 s. Rate limit por IP+HWID.
- **Erro 429:** `{"error":"rate_limited","retry_after":30}`.

#### `POST /api/v1/auth/login`
- **In:** `{"license_key","hwid","challenge","challenge_response"}`.
- **Verify:**
  1. `challenge` existe em Redis para esse HWID e não expirou. Consome (one-shot).
  2. `license_key` existe no Postgres e não está banida.
  3. `derived_key = HKDF(ikm=license_key, salt=hwid_hex_bytes || "SecBlind_HKDF_v1", info=<empty>)`. Não existe `session_salt` per-license.
  4. `HMAC-SHA256(challenge, derived_key) == challenge_response`? Comparar em constant-time (`hmac.Equal`).
  5. HWID bind: se nova → bind (respeitar cooldown 30 d); se diferente → 401 `hwid_mismatch` ou `hwid_cooldown`.
  6. Mata sessão anterior se existir (máximo 1 ativa por license).
- **Out 200:** gerar `session_token` (32 B random hex), `session_key` = `HKDF(master_secret, session_id || hwid_hash)` 32 B base64, `ttl=900`, `heartbeat_interval=60`, `next_nonce` = 32 B random base64.
- **Store:** Redis `session:<token>` → `{license_id, hwid, session_key_b64, next_nonce_b64, expires_at}` TTL 900 s.

#### `POST /api/v1/session/heartbeat`
- **In:** `{session_token, hmac, timestamp, next_nonce}`.
- **Verify:**
  1. Sessão existe e não expirou.
  2. `next_nonce` recebido == `next_nonce` armazenado da resposta anterior (anti-replay).
  3. `hmac == HMAC-SHA256(key=session_key, data=timestamp_string)`. Constant-time.
  4. `timestamp` dentro de janela (ex: ±5 min do server now).
- **Out 200:** renova TTL para 900 s, gera novo `next_nonce`, retorna `{next_nonce, kill, revoked}`.
- **Revogação:** consulta tabela `license_kill` ou `session_revoked`. Se true, não renovar TTL.

#### `POST /api/v1/payload/fetch`
- **In:** `{session_token}`.
- **Logic:**
  1. Sessão válida? Senão 401.
  2. Carregar build base da license (ou build com session binding).
  3. Gerar session-binding de 128 B:
     - `hwid_bytes = hex.DecodeString(hwid_hex)` — 32 bytes crus do hex. **Não** `SHA-256(hwid_hex)`.
     - `license_hash = SHA-256(license_key_bytes)` (32 B, raw bytes da key).
     - `issued_at = time.Now().Unix()` u64 LE.
     - `ttl = 86400` (24 h, escolher política) u64 LE. **Nunca 0.**
     - `nonce = crypto/rand` 16 B.
     - `signature = HMAC-SHA256(session_key, binding[0..96])` (32 B).
  4. `plaintext = binding || pe_bytes`.
  5. `iv = crypto/rand` 12 B. `aesgcm.Seal(nil, iv, plaintext, nil)` → `ciphertext || tag`. Separar tag (últimos 16 B).
  6. Retornar JSON `{iv, tag, ciphertext}` base64 StdEncoding.
- **Out 401/403:** `{"error":"session_expired|not_authorized","message":"..."}`.

#### `POST /api/v1/rpc/call`
- **In:** `{method, session_token, payload (object), timestamp, hmac}`.
- **Verify canonical:**
  - **Serialização exata:** `payload_json` deve ser **a serialização que o cliente enviou**, não uma re-serialização Go. Ler o raw body, extrair o span de `payload` sem re-marshal (ou armazenar o original). `encoding/json` do Go reordena keys — isso quebra o HMAC. **Solução:** o cliente envia `payload` como string JSON compacta sem espaços e o servidor lê o raw body e extrai o span. Ou: cliente envia canônico separado. Decidir e documentar antes.
  - `canonical = method || "|" || session_token || "|" || timestamp || "|" || payload_json`.
  - `HMAC-SHA256(session_key, canonical) == hmac`.
- **Dispatch:** switch por `method`. Cada método tem schema próprio de `payload`.
- **Out 200:** JSON método-específico.

### 4.4. Schema PostgreSQL

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
    pe_bytes      BYTEA NOT NULL,         -- build base ou com session binding em disco
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 4.5. Redis keys
- `challenge:<hwid>` → `<b64 nonce>`, TTL 60 s.
- `session:<token>` → hash `{license_id, hwid, session_key, next_nonce, expires_at}`, TTL 900 s.
- `rate:ip:<ip>`, `rate:hwid:<hwid>` → counter com TTL janela.

### 4.6. Secrets do servidor
| Secret | Formato | Uso |
|---|---|---|
| `master_secret` | 32 B random | Entrada do HKDF de `session_key`. Armazenar fora do repo (env, vault). |
| TLS cert leaf | PEM | Hash SHA-256 deve coincidir com o pin hardcoded em `net.cpp:161-162`. |
| Signing key opcional | Ed25519 | Se usar JWT em vez de token opaco. |

### 4.7. Ordem de implementação sugerida
1. **Scaffold + migrations** — `go mod init`, Postgres conn, migrations tool (goose/sql-migrate).
2. **Primitives** — `pkg/crypto`: HKDF, HMAC, AES-GCM wrappers. Testes unitários com vetores do RFC 5869.
3. **Challenge + login** — fluxo mais crítico. Testar com cliente real: fazer o cliente apontar para `https://localhost:8443` com cert self-signed cujo hash está no pin.
4. **Heartbeat** — adicionar nonce chain + flag de revogação.
5. **Payload fetch** — session-binding gen + AES-GCM. Primeiro com PE dummy (um `MessageBoxA`).
6. **RPC** — por último; depende de método real definido.
7. **Nginx + Let's Encrypt** — produção.

### 4.8. Ganchos para o cliente ainda não deployável
Os 9 TODOs em `feedback_secblind_decisions.md` precisam resolver antes de deploy:
1. Cert pin hashes reais em `net.cpp:161-162`.
2. Hostname real em `Main.cpp` (substituir `your-server.example.com`).
3. HKDF salt deve ser exatamente `"SecBlind_HKDF_v1"` no Go.
4. Ordinal imports em `pe_loader.cpp` (payloads simples não usam — OK pra v1).
5. SEH callbacks / `.pdata` (idem).
6. Shortcut do API integrity check (aceitável).
7. Falsos positivos de ambiente virtualizado (WARN-only já reduz).
8. Forwarders por ordinal no dynapi (raro).
9. ~~HKDF key-separation~~ ✅ **Resolvido.** `session_key` vira PRK; quatro sub-chaves via HKDF-Expand (info-tags `sb.v1.*`) em ambos os lados. Ver §4.2.

---

## 5. Riscos e Ressalvas

1. **Nenhuma proteção client-side é inquebrável.** Objetivo: elevar o custo de pirataria casual.
2. **VMProtect/Themida são detectados por AV.** Exigir code signing EV.
3. **Check de ambiente virtualizado pode bloquear legítimos.** No projeto atual é WARN-only no sentinel.
4. **Certificate pinning dificulta rotação.** Mitigado pelo dual pin (atual + backup).
5. **Execução parcial server-side** — RPC `/rpc/call` abre esse caminho. Latência + ponto de falha; usar com moderação.
6. **HWID não é 100% estável.** Cooldown + reset manual admin.
7. **Session binding pode ser removido por diff entre builds.** Mitigação: espalhar + variações de codegen por user (fora de escopo cliente).
8. **Heartbeat depende de internet estável.** 3 falhas consecutivas, não 2.

---

## 6. Histórico das Fases

| Fase | Entregas |
|---|---|
| **Fase 1** ✅ | Fundação: `obfstr.h`, `dynapi.h/.cpp` (PEB walk, FNV-1a). |
| **Fase 2** ✅ | Rede + Auth + Heartbeat: `net`, `auth`, `heartbeat`, `hwid`, `base64`, `json_lite`, `Main.cpp`. |
| **Fase 3** ✅ | Payload: `crypto` (AES-256-GCM via BCrypt), `pe_loader` (in-memory map + zeragem do header), `payload` (end-to-end). Review Opus 5.5 High: 2 HIGH + 4 MED + 4 LOW aplicados. Cliente compilou. |
| **Fase 4** ✅ | Verificação de integridade: `anti_debug`, `anti_vm`, `anti_hook` (trust set multi-módulo), `anti_tamper` (CRC32 `.text` + fallback), `tool_detect` (skip own PID), `sentinel` (monitor thread + scrub callback). Review: 2 HIGH + 5 MED + 8 LOW. Dynapi ganhou forwarder support. |
| **Fase 5** ✅ | Hardening: `watermark` (128 B session binding), `canary` (4 data + 4 code traps), `rpc` (`/api/v1/rpc/call` canonical `\|` delimitado + HMAC), sentinel extended com canary checks, `POST_BUILD.md`. Review: 5 MED + 4 LOW. HKDF key-separation registrado como TODO 9. |
| **Fase 6** ✅ | Testes de robustez e integridade: PE loader fuzzer (15 cases), `verify_lazy-import.ps1`, `stress_sentinel.ps1`, `TESTING.md`. Review: 1 HIGH + 6 MED + 4 LOW. Thread audit CONFIRMED: join-before-zero em `heartbeat::stop`, shutdown order `sentinel→heartbeat→net`. |

**Cliente: pronto para compilar.** Servidor: pendente (seção 4 é o plano a entregar).
