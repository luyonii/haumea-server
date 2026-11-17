# Server Plan — Sec-blind Commercial License Server (Go)

Prompt-ready spec para implementar o backend Go do servidor de licenciamento. Linguagem neutra; os parâmetros criptográficos **devem** bater byte-a-byte com o cliente.

---

## 1. Visão

Servidor de licenciamento para um produto comercial Windows. Serviço REST sobre TLS 1.3 que autentica licenças com HWID binding (enforcement per-seat), mantém sessões curtas via heartbeat com nonce rotativo, entrega o binário licenciado cifrado (AES-256-GCM) com per-session integrity tag, e expõe RPC autenticado opcional. Mesmas primitivas que DRMs comerciais e servidores de licença corporativos.

**Stack:** Go 1.23+, PostgreSQL 16+, Redis 7+, Nginx + Let's Encrypt.

**Base URL:** `https://<host>/api/v1`.

---

## 2. Parâmetros criptográficos (obrigatórios)

| Item | Valor |
|---|---|
| HKDF | RFC 5869, HMAC-SHA256, salt literal `"SecBlind_HKDF_v1"` (16 bytes ASCII), output 32 B |
| HMAC | SHA-256 (`crypto/hmac` + `crypto/sha256`) |
| AES | AES-256-GCM, IV 12 B random, auth tag 16 B |
| Base64 | RFC 4648 **com padding `=`** — use `base64.StdEncoding`, **não** `RawStdEncoding` nem URL encoding |
| HWID (cliente) | SHA-256 hex lowercase 64 chars |
| Randomness | `crypto/rand` sempre; nunca `math/rand` |
| Compare | `hmac.Equal` (constant-time) em todas as comparações de HMAC/token |

---

## 3. Endpoints

### 3.1. `POST /auth/challenge`
- **Request:** `{"hwid": "<64-char lowercase hex>"}`.
- **Logic:**
  - Rate limit por IP+HWID.
  - Gera `nonce = crypto/rand(32)`.
  - Armazena em Redis `challenge:<hwid> = nonce`, TTL 60 s.
- **Response 200:** `{"challenge": "<b64 nonce>", "expires_at": <unix>}`.
- **Response 429:** `{"error": "rate_limited", "retry_after": 30}`.

### 3.2. `POST /auth/login`
- **Request:** `{"license_key","hwid","challenge","challenge_response"}`.
- **Verify (em ordem, fail-closed):**
  1. `license_key` existe e não está `banned`.
  2. `challenge` existe em Redis para esse `hwid`, consumir one-shot.
  3. `derived_key = HKDF(ikm=license_key_bytes, salt=hwid_hex_bytes || "SecBlind_HKDF_v1", info=<empty>, len=32)`
     — o HWID aparece no **salt** (concatenado com o literal fixo), não no info. Não há `session_salt` per-license.
  4. `expected = HMAC-SHA256(key=derived_key, data=raw_nonce_bytes)`. Comparar com `challenge_response` em constant-time.
  5. HWID bind:
     - sem bind → bind atual (respeitar cooldown de 30 d desde o último `last_change`).
     - bind diferente dentro do cooldown → 401 `hwid_cooldown`.
     - bind diferente após cooldown → atualizar `hwid_binds`, atualizar `hwid_cooldown.last_change = now()`.
  6. Mata sessão anterior dessa license (se houver).
- **Session creation:**
  - `session_id = crypto/rand(16)`, hex.
  - `session_token = crypto/rand(32)`, hex ou base64 (opaco).
  - `session_key = HKDF(ikm=master_secret, salt="SecBlind_HKDF_v1", info=session_id_bytes || hwid_hash_bytes, len=32)`.
  - `next_nonce = crypto/rand(32)`.
  - Armazenar em Redis `session:<token> = {license_id, hwid, session_key_b64, next_nonce_b64, expires_at}`, TTL 900 s.
- **Response 200:**
  ```json
  {
    "session_token": "<opaque>",
    "session_key":   "<b64 32B>",
    "ttl":           900,
    "heartbeat_interval": 60,
    "next_nonce":    "<b64 32B>"
  }
  ```
- **Response 401:** `{"error":"invalid_credentials|hwid_mismatch|hwid_cooldown|banned","message":"..."}`.

### 3.3. `POST /session/heartbeat`
- **Request:** `{"session_token","hmac","timestamp","next_nonce"}`.
- **Verify:**
  1. `session:<token>` existe e não expirou.
  2. `next_nonce` recebido == `next_nonce` armazenado (anti-replay, constant-time compare).
  3. `timestamp` dentro de ±5 min do server now.
  4. `HMAC-SHA256(key=session_key, data=timestamp_string_bytes)` == `hmac` recebido. Constant-time.
- **Logic:** renova TTL para 900 s, gera novo `next_nonce`, consulta flags de revogação.
- **Response 200:** `{"next_nonce":"<b64>","kill":false,"revoked":false}`.
- **Response 401:** `{"error":"session_expired|invalid_token|invalid_hmac","message":"..."}`.

### 3.4. `POST /payload/fetch`
- **Request:** `{"session_token":"<opaque>"}`.
- **Logic:**
  1. Sessão válida? Senão 401.
  2. Carregar PE build para essa license (coluna `payload_builds.pe_bytes`).
  3. Montar session-binding record de 128 bytes **nesta ordem exata** (per-session integrity tag prefixado ao PE):

     | Offset | Tamanho | Campo | Como gerar |
     |---|---|---|---|
     | 0 | 32 | `hwid_bytes` | 32 bytes crus de `hex.DecodeString(hwid_hex)` — o cliente usa `hex_to_bytes_32`, **não** `SHA-256(hwid_hex)` |
     | 32 | 32 | `license_hash` | `SHA-256(license_key_raw_bytes)` |
     | 64 | 8 | `issued_at` | `uint64 little-endian` de `time.Now().Unix()` |
     | 72 | 8 | `ttl_seconds` | `uint64 little-endian`, **nunca 0** (cliente rejeita como expirado). Sugerido: 86400 (24 h) |
     | 80 | 16 | `nonce` | `crypto/rand(16)` |
     | 96 | 32 | `signature` | `HMAC-SHA256(key=session_key, data=binding[0:96])` |

  4. `plaintext = binding || pe_bytes` (128 B + PE body).
  5. `iv = crypto/rand(12)`.
  6. `aead, _ := cipher.NewGCM(block)`, `sealed := aead.Seal(nil, iv, plaintext, nil)`.
     - Go concatena ciphertext + tag. Separar: `tag = sealed[len(sealed)-16:]`, `ciphertext = sealed[:len(sealed)-16]`.
  7. Serializar JSON:
     ```json
     {
       "iv":         "<b64 12B>",
       "tag":        "<b64 16B>",
       "ciphertext": "<b64 of ciphertext only, without tag>"
     }
     ```
- **Response 401/403:** `{"error":"session_expired|not_authorized","message":"..."}`.

### 3.5. `POST /rpc/call`
- **Request:** `{"method","session_token","payload": {...}, "timestamp","hmac"}`.
- **Canonical message para o HMAC:**

  `method || "|" || session_token || "|" || timestamp || "|" || payload_json`

  onde `payload_json` é **exatamente** o span do campo `payload` como enviado pelo cliente — não pode ser re-marshal pelo Go (encoding/json reordena keys).
  
  **Implementação sugerida:** ler o raw body, parsear com `encoding/json.RawMessage` para capturar o span exato de `payload`.

  ```go
  type rpcReq struct {
      Method       string          `json:"method"`
      SessionToken string          `json:"session_token"`
      Payload      json.RawMessage `json:"payload"`
      Timestamp    string          `json:"timestamp"`
      HMAC         string          `json:"hmac"`
  }
  ```
- **Verify:**
  1. Sessão válida.
  2. `timestamp` dentro da janela.
  3. `canonical := req.Method + "|" + req.SessionToken + "|" + req.Timestamp + "|" + string(req.Payload)`.
  4. `HMAC-SHA256(key=session_key, data=canonical)` == `req.HMAC`. Constant-time.
- **Dispatch:** `switch req.Method` por método. Começar com um stub `ping` que retorna `{"pong": true}`.
- **Response 200:** JSON método-específico.

---

## 4. Schema PostgreSQL

```sql
CREATE TABLE licenses (
    id            BIGSERIAL PRIMARY KEY,
    license_key   TEXT UNIQUE NOT NULL,
    banned        BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE hwid_binds (
    license_id    BIGINT PRIMARY KEY REFERENCES licenses(id) ON DELETE CASCADE,
    hwid          CHAR(64) NOT NULL,
    bound_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE hwid_cooldown (
    license_id    BIGINT PRIMARY KEY REFERENCES licenses(id) ON DELETE CASCADE,
    last_change   TIMESTAMPTZ NOT NULL
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
    pe_bytes      BYTEA NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE license_kill (
    license_id    BIGINT PRIMARY KEY REFERENCES licenses(id) ON DELETE CASCADE,
    killed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason        TEXT
);
```

---

## 5. Redis keys

| Key | Value | TTL |
|---|---|---|
| `challenge:<hwid>` | b64 nonce (32 B) | 60 s |
| `session:<token>` | hash `{license_id, hwid, session_key, next_nonce, expires_at}` | 900 s (renovado em cada heartbeat) |
| `rate:ip:<ip>` | counter | janela 60 s |
| `rate:hwid:<hwid>` | counter | janela 60 s |

---

## 6. Estrutura de diretórios sugerida

```
sec-blind-server/
  cmd/server/main.go
  internal/
    api/          # 5 handlers HTTP
    auth/         # HKDF + HMAC verify + challenge-response
    session/      # Redis-backed session store
    hwid/         # bind + cooldown
    payload/      # session-binding gen + AES-GCM seal
    rpc/          # method dispatch
    abuse/        # rate limit + revogação
    db/           # postgres
    cache/        # redis
  pkg/crypto/     # hkdf.go, hmac.go, aesgcm.go — com testes
  migrations/
  config.yaml
  go.mod
```

---

## 7. Config (exemplo `config.yaml`)

```yaml
listen:          "0.0.0.0:8443"
tls:
  cert:          "/etc/sec-blind/cert.pem"
  key:           "/etc/sec-blind/key.pem"
postgres_dsn:    "postgres://user:pass@localhost/secblind?sslmode=require"
redis_addr:      "localhost:6379"
master_secret:   "env:SB_MASTER_SECRET"    # 32 B hex via env var
session_ttl_s:   900
heartbeat_s:     60
hwid_cooldown_d: 30
rate:
  per_ip_rpm:    30
  per_hwid_rpm:  10
```

---

## 8. Testes mínimos

1. **Vetores RFC 5869** em `pkg/crypto/hkdf_test.go`.
2. **Round-trip AES-GCM** com vetores conhecidos.
3. **Integration test**: cliente mock que faz `challenge → login → heartbeat → payload_fetch` e verifica decrypt + bytes do session-binding contra uma fixture.
4. **Replay test**: reusar `next_nonce` deve falhar com 401.
5. **HMAC fail-closed**: mutar 1 bit do HMAC enviado, deve falhar.

---

## 9. Ordem de implementação

1. Scaffold + `pkg/crypto` (com testes).
2. Migrations + seed de 1 license de teste.
3. `/auth/challenge` + `/auth/login`.
4. `/session/heartbeat`.
5. `/payload/fetch` com PE dummy (ex: `MessageBoxA`).
6. `/rpc/call` com método `ping`.
7. Nginx TLS termination + Let's Encrypt (produção).

---

## 10. Pegadinhas conhecidas (não confunda)

- **Base64:** cliente usa padding `=`. `RawStdEncoding` quebra tudo.
- **Session-binding:** `ttl == 0` é rejeitado como expirado. Sempre `>= 1`.
- **Session-binding:** `uint64` **little-endian** (`binary.LittleEndian`).
- **AES-GCM:** o `tag` sai concatenado ao ciphertext em Go; separar antes de serializar.
- **HKDF salt:** literal ASCII `"SecBlind_HKDF_v1"` — 16 bytes. Não adicionar null terminator.
- **HMAC do session-binding:** cobre bytes `[0..96)` apenas — não inclui o próprio signature nem bytes além.
- **RPC canonical:** `payload_json` é o span do wire, não o resultado de um re-marshal.
- **Challenge response HKDF:** salt = `hwid_hex_bytes || "SecBlind_HKDF_v1"`, info **vazio**. Não existe `session_salt`.
- **Session key HKDF info:** `session_id_bytes || hwid_hash_bytes` nessa ordem — `hwid_hash_bytes` é `hex.DecodeString(hwid_hex)` (32 B crus), igual ao session-binding `[0..32)`.
- **Session-binding `[0..32)`:** 32 bytes crus do `hex.DecodeString(hwid_hex)`, **não** `SHA-256(hwid_hex)`.
