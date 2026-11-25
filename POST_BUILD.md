# Commercial Release Hardening Chain

Post-build pipeline for the shipped loader binary. Standard commercial-software
release chain: compile/link, apply the licensed packer SDK, outer wrap
(optional), then Authenticode sign.

Order (strict): `cl` compile/link -> **VMProtect** -> (optional) **Themida** -> **Authenticode sign** -> distribute.

> Never apply VMProtect *after* Themida. VMProtect transforms source-level
> code regions; Themida wraps the final binary. VMProtect first, Themida outer.

---

## VMProtect (required)

Profile: **Ultra** on crypto entry points, **Mutation + Virtualization**
elsewhere.

Functions to protect:

| Protection                 | Function                              |
|----------------------------|---------------------------------------|
| Ultra                      | `crypto::aes256_gcm_decrypt`          |
| Mutation + Virtualization  | `main`                                 |
| Mutation + Virtualization  | `auth::authenticate`                  |
| Mutation + Virtualization  | `heartbeat::heartbeat_proc`           |
| Mutation + Virtualization  | `payload::load_and_execute`           |
| Mutation + Virtualization  | `pe_loader::map`                      |
| Mutation + Virtualization  | `sentinel::monitor_proc`              |
| Mutation + Virtualization  | `watermark::verify`                   |
| Mutation + Virtualization  | `canary::verify_data`, `canary::verify_code` |

VMProtect options:

- Debugger-presence check: **import on** (user-mode).
- Check integrity: **on**.
- Memory protection: **on**.
- VMProtect license system: **off** (we run our own).
- Pack output: optional; leave off if signing trips AV.

---

## Themida (optional outer wrap)

Only after VMProtect has run. Use the bundle output as Themida input.

- Memory image protection: **on** (both on-disk and in-memory).
- Environment integrity check: **off** (handled by `anti_vm`).
- Delphi/VB detection: **off**.
- Encrypt resources: **on**.
- Themida license system: **off**.

---

## Signing

Authenticode sign **after** VMProtect and Themida.

```powershell
signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 Project1.exe
```

Use an EV code-signing certificate — without it, VMProtect/Themida output
is almost always flagged by AV.

---

## Server bind baseline (audit #1/#10)

Before deploying the server against a new client build, set **all six**
`SECBLIND_EXPECTED_*` envs (the server fails closed at startup if any is empty).
They are folded into the `/auth/login` HKDF salt; see SERVER_SPEC.md `/auth/login`.

| env | value | source |
|-----|-------|--------|
| `SECBLIND_EXPECTED_TEXT_CRC32` | 8 hex | CRC32 of the shipped `.text` (final, post-pack) |
| `SECBLIND_EXPECTED_CODE_FINGERPRINT` | ≤16 hex | client `canary::code_fingerprint()` of the shipped build |
| `SECBLIND_EXPECTED_ANTI_DEBUG_MASK` | `00000000` | clean reference machine (no debugger) |
| `SECBLIND_EXPECTED_ANTI_HOOK_MASK` | `00000000` | clean reference machine (no API hooks) |
| `SECBLIND_EXPECTED_TOOL_DETECT_MASK` | `00000000` | clean reference machine (no analysis tools) |
| `SECBLIND_EXPECTED_ANTI_VM_MASK` | `00000000` | bare-metal reference machine |

The four detection masks are **zero on a legitimate machine**, so the operator
normally sets them to `00000000` — no extraction step is required for them.

> Note: `SECBLIND_EXPECTED_ANTI_VM_MASK = 00000000` means a client running under
> a hypervisor (non-zero `anti_vm`) derives a different key and is **rejected at
> login**, not merely flagged. If virtualised customers must be supported, this
> binding needs rethinking (it conflicts with the anti_vm=WARN telemetry policy).
> See the audit #1 Fix B / anti_vm follow-up.

The crc / fingerprint baseline extraction (and the planned interleaved
multi-sample running digest, audit #1 Fix B) is tracked separately.

## Reproducibility

- Pin the exact VMProtect and Themida versions in CI.
- Record SHA-256 of each stage output (post-link, post-VMProtect,
  post-Themida, post-sign) for provenance.
- Build inputs (source commit, toolchain version, `.vmp` profile file,
  `.tmd` project file) must be checked in.
