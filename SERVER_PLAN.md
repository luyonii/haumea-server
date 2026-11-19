# Server Plan — Sec-blind Commercial License Server (Go)

Prompt-ready spec to implement the Go backend of the licensing server. Neutral language; crypto parameters **must** match byte-for-byte with the client.

---

## 1. Vision

Licensing server for a commercial Windows product. REST service over TLS 1.3 that authenticates activation codes with HWID binding (per-seat enforcement), keeps short sessions via heartbeat with a rotating nonce, delivers the licensed binary encrypted (AES-256-GCM) with a per-session integrity tag, and exposes optional authenticated RPC. Same primitives as commercial DRM and enterprise licensing servers.

**Stack:** Go 1.23+, PostgreSQL 16+, Redis 7+, Nginx + Let's Encrypt.

**Base URL:** `https://<host>/api/v1`.

---

## 2. Crypto parameters (mandatory)

| Item | Value |
|---|---|
| HKDF | RFC 5869, HMAC-SHA256, literal salt `"SecBlind_HKDF_v1"` (16 ASCII bytes), output 32 B |
| HMAC | SHA-256 (`crypto/hmac` + `crypto/sha256`) |
| AES | AES-256-GCM, 12 B random IV, 16 B auth tag |
| Base64 | RFC 4648 **with `=` padding** — use `base64.StdEncoding`, **not** `RawStdEncoding` or URL encoding |
| HWID (client) | SHA-256 hex lowercase 64 chars |
| Randomness | `crypto/rand` always; never `math/rand` |
| Compare | `hmac.Equal` (constant-time) on every HMAC/token comparison |

---

## 3. Endpoints

### 3.1. `POST /auth/challenge`
- **Request:** `{"hwid": "<64-char lowercase hex>"}`.
- **Logic:**
  - Rate limit by IP+HWID.
  - Generate `nonce = crypto/rand(32)`.
  - Store in Redis `challenge:<hwid> = nonce`, TTL 60 s.
- **Response 200:** `{"challenge": "<b64 nonce>", "expires_at": <unix>}`.
- **Response 429:** `{"error": "rate_limited", "retry_after": 30}`.

### 3.2. `POST /auth/login`
- **Request:** `{"license_key","hwid","challenge","challenge_response"}`.
- **Verify (in order, fail-closed):**
  1. `license_key` exists and is not `banned`.
  2. `challenge` exists in Redis for that `hwid`, consume one-shot.
  3. `derived_key = HKDF(ikm=license_key_bytes, salt=hwid_hex_bytes || "SecBlind_HKDF_v1", info=<empty>, len=32)`
     — the HWID goes in the **salt** (concatenated to the fixed literal), not in info. No per-license `session_salt`.
  4. `expected = HMAC-SHA256(key=derived_key, data=raw_nonce_bytes)`. Constant-time compare with `challenge_response`.
  5. HWID bind:
     - no bind → bind current (respect 30 d cooldown since last `last_change`).
     - different bind inside the cooldown → 401 `hwid_cooldown`.
     - different bind after the cooldown → update `hwid_binds`, update `hwid_cooldown.last_change = now()`.
  6. Terminate the prior session for that license (if any).
- **Session creation:**
  - `session_id = crypto/rand(16)`, hex.
  - `session_token = crypto/rand(32)`, hex or base64 (opaque).
  - `session_key = HKDF(ikm=master_secret, salt="SecBlind_HKDF_v1", info=session_id_bytes || hwid_hash_bytes, len=32)`.
  - `next_nonce = crypto/rand(32)`.
  - Store in Redis `session:<token> = {license_id, hwid, session_key_b64, next_nonce_b64, expires_at}`, TTL 900 s.
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
  1. `session:<token>` exists and has not expired.
  2. Received `next_nonce` == stored `next_nonce` (replay-protection token, constant-time compare).
  3. `timestamp` within ±5 min of server now.
  4. `HMAC-SHA256(key=session_key, data=timestamp_string_bytes)` == received `hmac`. Constant-time.
- **Logic:** refresh TTL to 900 s, generate new `next_nonce`, consult revocation flags.
- **Response 200:** `{"next_nonce":"<b64>","kill":false,"revoked":false}`.
- **Response 401:** `{"error":"session_expired|invalid_token|invalid_hmac","message":"..."}`.

### 3.4. `POST /payload/fetch`
- **Request:** `{"session_token":"<opaque>"}`.
- **Logic:**
  1. Valid session? Otherwise 401.
  2. Load the PE build for that license (column `payload_builds.pe_bytes`).
  3. Assemble the 128-byte session-binding record **in exactly this order** (per-session integrity tag prefixed to the PE):

     | Offset | Size | Field | How to generate |
     |---|---|---|---|
     | 0 | 32 | `hwid_bytes` | 32 raw bytes from `hex.DecodeString(hwid_hex)` — the client uses `hex_to_bytes_32`, **not** `SHA-256(hwid_hex)` |
     | 32 | 32 | `license_hash` | `SHA-256(license_key_raw_bytes)` |
     | 64 | 8 | `issued_at` | `uint64 little-endian` of `time.Now().Unix()` |
     | 72 | 8 | `ttl_seconds` | `uint64 little-endian`, **never 0** (client rejects it as expired). Suggested: 86400 (24 h) |
     | 80 | 16 | `nonce` | `crypto/rand(16)` |
     | 96 | 32 | `signature` | `HMAC-SHA256(key=session_key, data=binding[0:96])` |

  4. `plaintext = binding || pe_bytes` (128 B + PE body).
  5. `iv = crypto/rand(12)`.
  6. `aead, _ := cipher.NewGCM(block)`, `sealed := aead.Seal(nil, iv, plaintext, nil)`.
     - Go concatenates ciphertext + tag. Split: `tag = sealed[len(sealed)-16:]`, `ciphertext = sealed[:len(sealed)-16]`.
  7. Serialize JSON:
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
- **Canonical message for the HMAC:**

  `method || "|" || session_token || "|" || timestamp || "|" || payload_json`

  where `payload_json` is **exactly** the span of the `payload` field as the client sent it — it cannot be re-marshaled by Go (encoding/json reorders keys).
  
  **Suggested implementation:** read the raw body, parse with `encoding/json.RawMessage` to capture the exact `payload` span.

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
  1. Valid session.
  2. `timestamp` within window.
  3. `canonical := req.Method + "|" + req.SessionToken + "|" + req.Timestamp + "|" + string(req.Payload)`.
  4. `HMAC-SHA256(key=session_key, data=canonical)` == `req.HMAC`. Constant-time.
- **Dispatch:** `switch req.Method` per method. Start with a `ping` stub returning `{"pong": true}`.
- **Response 200:** method-specific JSON.

---

## 4. PostgreSQL schema

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
| `session:<token>` | hash `{license_id, hwid, session_key, next_nonce, expires_at}` | 900 s (refreshed on each heartbeat) |
| `rate:ip:<ip>` | counter | 60 s window |
| `rate:hwid:<hwid>` | counter | 60 s window |

---

## 6. Suggested directory layout

```
sec-blind-server/
  cmd/server/main.go
  internal/
    api/          # 5 HTTP handlers
    auth/         # HKDF + HMAC verify + nonce-based auth
    session/      # Redis-backed session store
    hwid/         # bind + cooldown
    payload/      # session-binding gen + AES-GCM seal
    rpc/          # method dispatch
    abuse/        # rate limit + revocation
    db/           # postgres
    cache/        # redis
  pkg/crypto/     # hkdf.go, hmac.go, aesgcm.go — with tests
  migrations/
  config.yaml
  go.mod
```

---

## 7. Config (example `config.yaml`)

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

## 8. Minimum tests

1. **RFC 5869 vectors** in `pkg/crypto/hkdf_test.go`.
2. **AES-GCM round-trip** with known vectors.
3. **Integration test**: mock client that runs `challenge → login → heartbeat → payload_fetch` and verifies decrypt + session-binding bytes against a fixture.
4. **Replay test**: reusing `next_nonce` must fail with 401.
5. **HMAC fail-closed**: mutate 1 bit of the sent HMAC, must fail.

---

## 9. Implementation order

1. Scaffold + `pkg/crypto` (with tests).
2. Migrations + seed a single test license.
3. `/auth/challenge` + `/auth/login`.
4. `/session/heartbeat`.
5. `/payload/fetch` with dummy PE (e.g. `MessageBoxA`).
6. `/rpc/call` with method `ping`.
7. Nginx TLS termination + Let's Encrypt (production).

---

## 10. Known gotchas (don't mix these up)

- **Base64:** client uses `=` padding. `RawStdEncoding` breaks everything.
- **Session-binding:** `ttl == 0` rejected as expired. Always `>= 1`.
- **Session-binding:** `uint64` **little-endian** (`binary.LittleEndian`).
- **AES-GCM:** the `tag` comes concatenated to the ciphertext in Go; split it before serializing.
- **HKDF salt:** ASCII literal `"SecBlind_HKDF_v1"` — 16 bytes. Do not add a null terminator.
- **Session-binding HMAC:** covers bytes `[0..96)` only — does not include the signature itself or bytes beyond.
- **RPC canonical:** `payload_json` is the wire span, not the result of a re-marshal.
- **Challenge-response HKDF:** salt = `hwid_hex_bytes || "SecBlind_HKDF_v1"`, info **empty**. No `session_salt`.
- **Session key HKDF info:** `session_id_bytes || hwid_hash_bytes` in that order — `hwid_hash_bytes` is `hex.DecodeString(hwid_hex)` (32 raw B), matching session-binding `[0..32)`.
- **Session-binding `[0..32)`:** 32 raw bytes from `hex.DecodeString(hwid_hex)`, **not** `SHA-256(hwid_hex)`.
