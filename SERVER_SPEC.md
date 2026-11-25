# Commercial License Server API Specification (Phase 2)

Base URL: `https://<host>/api/v1`  
Transport: TLS 1.3 only.

REST API for the licensing server of the commercial product. Every endpoint serves the vendor's first-party client.

---

## POST /auth/challenge

Request a time-limited nonce before login.

### Request

```json
{
    "hwid": "<64-char lowercase hex SHA-256>"
}
```

### Response 200

```json
{
    "challenge": "<base64 32-byte nonce>",
    "expires_at": 1700000000
}
```

### Response 429

```json
{
    "error": "rate_limited",
    "retry_after": 30
}
```

---

## POST /auth/login

Authenticate with activation code + device fingerprint id + solved nonce.

The `challenge_response` field is `HMAC-SHA256(nonce, derived_key)` where  
`derived_key = HKDF-SHA256(ikm=license_key, salt=hwid_hex_bytes || "SecBlind_HKDF_v1" || running_digest(32) || LE32(anti_debug) || LE32(anti_hook) || LE32(tool_detect) || LE32(anti_vm), info=<empty>)`.

Salt layout (128 bytes):

| bytes | field |
|-------|-------|
| 0..63   | HWID hex (64 ASCII) |
| 64..79  | fixed literal `"SecBlind_HKDF_v1"` (16 bytes) |
| 80..111 | `running_digest` (32 bytes) — interleaved multi-sample code-integrity digest |
| 112..115| `LE32(anti_debug_mask)` — raw `anti_debug::check_all()` bitmask at boot |
| 116..119| `LE32(anti_hook_mask)` — raw `anti_hook::check_critical_apis()` bitmask at boot |
| 120..123| `LE32(tool_detect_mask)` — raw `tool_detect::enumerate()` bitmask at boot |
| 124..127| `LE32(anti_vm_mask)` — raw `anti_vm::check_all()` bitmask at boot |

`info` empty. There is no per-license `session_salt`.

**Binary-integrity + detection binding (audit #1/#10, Fix B).** The last 48 bytes
bind the client's code integrity AND its four anti-analysis detection masks into
`derived_key`. The masks are the raw bitmasks captured by `sentinel::scan` at
boot, *before* the local abort gate — so a runtime patch that NOPs the gate no
longer yields clean masks for the salt.

`running_digest` is a 32-byte SHA-256 running digest folded over the client's
`.text` CRC32 + `canary::code_fingerprint()` sampled at **four points** along
the single `wmain` path (after canary install, after the abort gate, after HWID,
immediately before `authenticate`). At each point `k`:

```
sample_k      = LE32(text_crc32) || LE32(code_fingerprint) || LE32(k)
running_digest = SHA256(running_digest || sample_k)   // start from 32 zero bytes
```

`.text` is read live from process memory at every sample, so a runtime patch
that is clean at one sample but not another perturbs the digest. This closes the
"sample early, use late" window of the old single-snapshot design (the attacker
must keep `.text` intact across all four samples, not just the first). The server
cannot recompute this value; it stores the expected digest captured once from
`Project1.exe --print-baseline` on a clean reference machine.

The server computes the same salt suffix using five startup envs, all
**required** (empty → fatal, fail-closed):

- `SECBLIND_EXPECTED_RUNNING_DIGEST` — 64 hex chars, the expected 32-byte running digest (from `Project1.exe --print-baseline`).
- `SECBLIND_EXPECTED_ANTI_DEBUG_MASK` — 8 hex chars; `00000000` on a clean reference machine.
- `SECBLIND_EXPECTED_ANTI_HOOK_MASK` — 8 hex chars; `00000000` on a clean reference machine.
- `SECBLIND_EXPECTED_TOOL_DETECT_MASK` — 8 hex chars; `00000000` on a clean reference machine.
- `SECBLIND_EXPECTED_ANTI_VM_MASK` — 8 hex chars; `00000000` on bare metal.

If the shipped client binary diverges from this baseline (modification, wrong
version, tamper, or a runtime `.text` patch that perturbs any sample) *or* runs
in a detected environment (debugger, API hook, analysis tool, VM) so that any
mask is non-zero, its `derived_key` diverges, the challenge HMAC fails to
verify, and `/auth/login` returns `401 invalid_credentials`. There is no
isolated boolean on the client to patch out. (Residual limit: an attacker who
decompiles the flow and restores the original `.text` bytes between every sample
and its use still derives the right key — but that is orders of magnitude more
costly than NOPing a single gate, and is the unpacker/virtualization follow-up.)

### Request

```json
{
    "license_key": "XXXXX-XXXXX-XXXXX-XXXXX",
    "hwid": "<64-char lowercase hex SHA-256>",
    "challenge": "<base64 nonce from /auth/challenge>",
    "challenge_response": "<base64 HMAC-SHA256>"
}
```

### Response 200

```json
{
    "session_token": "<opaque token>",
    "session_key": "<base64 AES-256 key>",
    "ttl": 900,
    "heartbeat_interval": 60,
    "next_nonce": "<base64 32-byte nonce for first heartbeat>"
}
```

### Response 401

```json
{
    "error": "invalid_credentials | hwid_mismatch | hwid_cooldown | banned",
    "message": "<human-readable detail>"
}
```

### Response 429

```json
{
    "error": "rate_limited",
    "retry_after": 30
}
```

---

## POST /session/heartbeat

Keep the session alive. Must be sent every `heartbeat_interval` seconds.

The `hmac` field is `HMAC-SHA256(key=session_key, data=timestamp)`.
`next_nonce` is the nonce received from the previous response (login or last heartbeat).
All base64 fields (`hmac`, `next_nonce`) use standard RFC 4648 padding
(`=`). HMAC values are 44 chars.

### Request

```json
{
    "session_token": "<opaque token from login>",
    "hmac": "<base64 HMAC-SHA256>",
    "timestamp": "<unix timestamp string>",
    "next_nonce": "<base64 nonce from previous response>"
}
```

### Response 200

```json
{
    "next_nonce": "<base64 32-byte nonce for next heartbeat>",
    "kill": false,
    "revoked": false
}
```

When `kill` is `true`, the client must terminate the licensed binary and exit (remote license suspension).
When `revoked` is `true`, the session is no longer valid.

### Response 401

```json
{
    "error": "session_expired | invalid_token | invalid_hmac",
    "message": "<human-readable detail>"
}
```

---

## POST /payload/fetch

Download the encrypted licensed binary for the authenticated session. The
response carries the vendor's legitimate commercial binary, encrypted so
it is protected in transit and never written to disk on the user's
machine — the same pattern used by commercial DRM SDKs and licensed
enterprise clients.

### Request

```json
{
    "session_token": "<opaque token>"
}
```

### Response 200

JSON envelope carrying the AES-256-GCM encrypted entitled module. All
three fields are base64-encoded with standard RFC 4648 padding (`=`). The
ciphertext is decrypted with the `session_key` returned by `/auth/login`.

```json
{
    "iv": "<base64 12-byte IV>",
    "tag": "<base64 16-byte GCM auth tag>",
    "ciphertext": "<base64 of AES-256-GCM encrypted (session_binding || PE)>",
    "target_exe_path": "<utf-8 path to the host executable, may be empty>"
}
```

`target_exe_path` is sourced from `licenses.target_exe_path` (nullable column
added by migration `0004_license_target_exe_path.sql`). When the field is
empty the client falls back to its `argv[1]`; when both are empty the
client aborts with `launch_failed`. ASCII-only paths are expected.

**Plaintext layout.** The decrypted plaintext is a 128-byte **per-session
integrity tag** (session binding) followed by the PE body. The client
verifies the record binds the binary to this HWID + license before
mapping the PE; a failed verification aborts the load.

| Offset | Size | Field              | Notes |
|--------|------|--------------------|-------|
| 0      | 32   | `hwid_hash`        | SHA-256 of the client HWID string (64-char lowercase hex, UTF-8 bytes of the hex string). |
| 32     | 32   | `license_hash`     | SHA-256 of the raw license key bytes. |
| 64     | 8    | `issued_at_unix`   | u64 little-endian, server timestamp (seconds since epoch). |
| 72     | 8    | `ttl_seconds`      | u64 little-endian. Must be `> 0`; a record with `ttl_seconds == 0` is rejected as expired. |
| 80     | 16   | `nonce`            | server-chosen random bytes. |
| 96     | 32   | `signature`        | HMAC-SHA256(key = session_key, data = bytes[0..96]). |

### Response 401 / 403

```json
{
    "error": "session_expired | not_authorized",
    "message": "<human-readable detail>"
}
```

---

---

## POST /rpc/call

Authenticated server-side RPC. The client POSTs a method name plus a JSON
`payload` object (the method's parameters) under an HMAC envelope.

### Request

```json
{
    "method": "<method name, e.g. compute_x>",
    "session_token": "<opaque token from login>",
    "payload": { "...": "method-specific JSON object" },
    "timestamp": "<unix timestamp string>",
    "hmac": "<base64 HMAC-SHA256>"
}
```

**Canonical message** for `hmac`:
`method || "|" || session_token || "|" || timestamp || "|" || payload_json`
(where `payload_json` is the exact serialization of the `payload` field
as sent over the wire). Key = `session_key`. The literal `|` byte (0x7C)
is the field delimiter; it cannot occur inside base64 and is not valid in
an unquoted JSON field name, so none of the four pieces can forge it.

All base64 fields in this endpoint (`hmac`) use standard RFC 4648 padding
(`=`). HMAC values are 44 chars.

### Response 200

Method-specific JSON body. Callers parse it with `json::get_string` /
`json::get_int` etc.

### Response 401 / 429 / other

Shape matches other endpoints (`error` + `message`). The client treats
any non-200 as failure and does not consume the body.

---

## Notes

- Session key derivation: `HKDF(master_secret, session_id || hwid_hash)`.
- Maximum 1 active session per license key; a new login terminates the previous.
- First login with a new HWID triggers automatic bind.
- HWID change cooldown: 30 days (or admin reset).
- Heartbeat nonce chain: each response carries the nonce for the next request, a replay-protection token.
- 3 consecutive missed heartbeats: server suspends the session.
