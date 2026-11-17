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

- Debugger presence check: **import on** (user-mode).
- Check integrity: **on**.
- Memory protection: **on**.
- VMProtect license system: **off** (we run our own).
- Pack output: optional; leave off if signing trips AV.

---

## Themida (optional outer wrap)

Only after VMProtect has run. Use the bundle output as Themida input.

- Memory image protection: **on** (both on-disk and in-memory).
- Virtualization environment check: **off** (handled by `anti_vm`).
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

## Reproducibility

- Pin the exact VMProtect and Themida versions in CI.
- Record SHA-256 of each stage output (post-link, post-VMProtect,
  post-Themida, post-sign) for provenance.
- Build inputs (source commit, toolchain version, `.vmp` profile file,
  `.tmd` project file) must be checked in.
