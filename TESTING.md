# TESTING.md — Phase 6: Robustness and integrity verification

Verification matrix, runbooks and thread-safety audit for the Sec-blind loader.

Target: `Project1\x64\Release\Project1.exe` (Release build, ideally post-VMProtect and EV-signed).

This document covers three axes:
1. Build conformance against the lazy-symbol-binder import policy and the commercial release string policy.
2. Runtime integrity checks behavior (debugger-presence check, API runtime integrity, code integrity, unsupported environments).
3. Robustness of the custom in-memory loader against malformed PE (fuzzer).

---

## 4.1. Static-build conformance

Checks on the produced binary to make sure the release matches the deploy policy.

| Tool | Expected behavior | PASS criterion |
|---|---|---|
| **IDA Pro** (x64 disasm + Hex-Rays) | VMProtect-virtualized functions appear as opaque stubs. No API or URL string in plaintext (compile-time string protection active). Resolution flow via `dynapi::resolve` indexed by symbol hashes. | Build with the release policy applied. |
| **Binary Ninja** | Identical to IDA: no symbols, no direct strings, lazy dynamic symbol binding in place of the IAT. | Same criterion. |
| **strings.exe / rabin2 -z** | Zero matches for the sensitive-string blocklist (below). | The command below returns empty. |
| **PE-bear / CFF Explorer** | IAT contains only baseline CRT (KERNEL32, VCRUNTIME140, api-ms-win-crt-*). `.vmp*` sections after the packer. Sensitive APIs (`bcrypt.dll` / `winhttp.dll` / `advapi32.dll`) resolved at runtime, not in the IAT. | `scripts\verify_zero_iat.ps1` returns exit 0. |

### String blocklist (grep = fail)

```
BCryptDecrypt
BCryptOpenAlgorithmProvider
BCryptHashData
BCryptHmac
WinHttpOpen
WinHttpConnect
WinHttpSendRequest
WinHttpReceiveResponse
NtQueryInformationProcess
NtQuerySystemInformation
NtSetInformationThread
GetAdaptersAddresses
RegOpenKeyExA
LoadLibraryA
LoadLibraryW
GetProcAddress
CheckRemoteDebuggerPresent
SecBlind_HKDF_v1
.example.com
bcrypt.dll
winhttp.dll
```

Suggested command (Developer PowerShell):

```powershell
$blk = Get-Content .\TESTING.strings.blocklist.txt
strings .\Project1\x64\Release\Project1.exe |
    Where-Object { $blk -contains $_ }
```

(Any returned line = FAIL. If `strings.exe` is unavailable, use `rabin2 -z` or `sigcheck -s`.)

---

## 4.2. Runtime integrity checks

Expected behavior of the client's integrity verification subsystem (debugger-presence check, runtime API integrity, code integrity, unsupported environments).

| Scenario | Trigger | PASS |
|---|---|---|
| **x64dbg attach-at-start** | Debugger-presence check (`anti_debug::peb_being_debugged` / `nt_global_flag` / `process_debug_port`) fires on the first `sentinel::scan()`. | Loader exits cleanly, no output. |
| **x64dbg attach-after-start** | Monitor thread (`sentinel::monitor_proc`, 30 s) detects on the next round. | Loader exits cleanly within ≤ 30 s. |
| **Hardware breakpoint** (Dr0-Dr3 set via x64dbg) | `anti_debug::hw_breakpoint` fires. | Loader exits cleanly. |
| **Debugger plugin that modifies `NtSetInformationThread`** | Runtime API integrity (`anti_hook::check_critical_apis`) compares ntdll from disk vs memory, detects divergence in the first 16 bytes. | Monitor trips → clean exit. |
| **In-memory image inspection** | After `pe_loader::map`, DOS `e_magic`=0, `e_lfanew`=0, NT `Signature`=0 on the licensed-binary page (defensive header zeroization). | Inspector reports "invalid PE at image base". |
| **Unsupported execution environments** | `tool_detect::enumerate` checks window/process against the list of incompatible environments (symbol hash lookup). The product does not support runtime in those environments, matching the policy of commercial licensing products. | Loader exits cleanly. |

Notes:
- `anti_debug::rdtsc_timing` and `trap_flag_seh` also fire on singlestep; they are complementary.
- Header zeroization is best-effort: a kernel-mode driver may snapshot before the zero. A commercial packer (optional, in the final build) covers the rest.

---

## 4.3. Legitimate-user false-positive matrix

Scenarios where legitimate users of the product may trip checks. Documented behavior:

| Scenario | Flag fired | Severity | PASS |
|---|---|---|---|
| **Windows 11 with Hyper-V / VBS / Memory Integrity** | `anti_vm::hypervisor_bit` (CPUID bit 31 of ECX) | WARN only | Loader proceeds; only `report.anti_vm` != 0, no abort. |
| **Dev with Visual Studio open** | — | — | `vshost.exe`, `devenv.exe` are **not** in the blocklist. No trigger. |
| **WSL2 / Docker Desktop (Hyper-V backend)** | `anti_vm::vm_mac_prefix` (Hyper-V OUI 00:15:5D), `anti_vm::hypervisor_bit` | WARN only | Loader proceeds. |
| **PerfView / WPR** | — | — | Does not alter user-mode APIs. `anti_hook` clean. No trigger. |
| **Procmon running** | — | — | Kernel driver, does not alter user-mode ntdll. `anti_hook` clean. Name `procmon64.exe` is **not** in the blocklist. |

**Policy:** the environment integrity check never aborts on its own. `sentinel::scan()` only aborts on debugger-presence, API integrity trip, unsupported tool, or code-integrity/guard failure.

---

## 4.4. Fuzzer runbook

Robustness test of the in-memory loader against malformed PE.

Build:

```powershell
msbuild tests\pe_loader_fuzzer\pe_loader_fuzzer.vcxproj /p:Configuration=Release /p:Platform=x64
```

Run:

```powershell
.\tests\pe_loader_fuzzer\x64\Release\pe_loader_fuzzer.exe
```

Expected output: `15/15 passed`, exit code 0.

**Fail criteria:**
- Any case crashes (unhandled SEH, AV).
- Any case hangs > 5 s.
- Returned enum != expected.
- Case 0 (`clean_ok`) FAIL → invalid skeleton, all other tests unreliable.

Cases covered (see `tests/pe_loader_fuzzer/main.cpp`):
0. **`clean_ok`** — valid skeleton → `ok` (sanity; if it fails, the rest is garbage)
1. null ptr → `bad_dos_header`
2. size 0 → `bad_dos_header`
3. wrong MZ magic → `bad_dos_header`
4. `e_lfanew` out-of-bounds → `bad_nt_header`
5. wrong PE sig → `bad_nt_header`
6. Machine != AMD64 → `bad_machine`
7. `SizeOfHeaders > pe_size` → `bad_nt_header`
8. invalid `SizeOfOptionalHeader` → `bad_nt_header`
9. Reloc block with `SizeOfBlock < 8` → `reloc_failed`
10. Reloc with VA overflow → `reloc_failed`
11. Section `VA + SRD > SizeOfImage` → `section_copy_failed`
12. Section `PRD + SRD > pe_size` → `section_copy_failed`
13. Ordinal import (`IMAGE_ORDINAL_FLAG64` set) → `import_failed`
14. `SizeOfImage = 0x7FFFFFFF` → `alloc_failed`

---

## 4.5. Thread safety audit

Shared state between threads (main / heartbeat / sentinel monitor):

| State | Writer | Reader | Risk | Mitigation | Status |
|---|---|---|---|---|---|
| `net::` critsec | `net::init` (main) | `net::post` (heartbeat), `net::shutdown` (main) | Shutdown destroys critsec while heartbeat_proc is still in `post`. | `heartbeat::stop` must join the thread before `net::shutdown`. | **CONFIRMED** — `Main.cpp:197-212` calls `sentinel::stop_monitor()` → `heartbeat::stop()` → `net::shutdown()`, exactly the reverse of start. Same path in the failure exit paths (`Main.cpp:172-175` and `186-189`). Residual window: `heartbeat::stop` waits at most 10 s in `pWaitFor(s_thread, 10000)` (`heartbeat.cpp:149`); if a `net::post` is inflight > 10 s, `net::shutdown` runs with the thread still alive. Acceptable: HTTP connection timeout < 10 s in any practical case. |
| `heartbeat::s_key` (32 bytes) | `heartbeat::start` | `heartbeat_proc` (HMAC), `heartbeat::stop` (zeroes) | Zero in the middle of HMAC → garbage tag. | `stop` must set the stop-event, wait for `WaitForSingleObject(thread, ...)`, and only then zero. | **CONFIRMED** — `heartbeat.cpp:147` signals stop_event, `:149` `pWaitFor(s_thread, 10000)` joins, `:161` zeroes `s_key`. Join happens before the zeroization. (The thread also zeroes `s_key` at `:97-98` before exiting; double-zero is benign.) |
| `sentinel::s_scrub_cb` (fn ptr) | `sentinel::set_scrub_callback` (main, before `start_monitor`) | `monitor_proc` | Non-atomic pointer read on x64 is aligned and benign. | Set-once pattern. | **OK.** |
| `sentinel::s_baseline`, `s_code_baseline` (uint32) | `sentinel::start_monitor` | `monitor_proc` | Set-once before the thread exists — publication covered by `CreateThread`. | — | **OK.** |
| `sentinel::s_running` (volatile bool) | `start_monitor`, `monitor_proc` (exit), `stop_monitor` | `start_monitor` (guard) | `volatile bool` is not `std::atomic`. On x64 an aligned read/write is atomic by hardware but has no memory barrier. The flag is only a double-start guard, it does not synchronize data. | Ideally `std::atomic<bool>`. **Current:** acceptable, because synchronized data is published via `CreateThread` / stop-event. | **CONFIRMED** — `sentinel.cpp:27` declares `static volatile bool s_running = false;` (plain volatile, not `std::atomic`). Writes at `:60`, `:81`, `:86` (guard), `:100`, `:102`, `:125`. No explicit memory barrier; synchronization is via `CreateThread`/stop-event. Semantics sufficient for the current use (guard). Upgrading to `std::atomic<bool>` stays as debt. |
| `g_payload_key`, `g_license_hash` (globals in main.cpp) | main (pre-monitor) | `monitor_proc` → `scrub_cb` (zeroes on trip) | Single-writer before start; single-reader only on trip. | None. | **OK.** |

Resolved items:
1. ~~Confirm heartbeat join-before-zero.~~ **CONFIRMED** (`heartbeat.cpp:149` joins before `:161` zero). Note: 10 s timeout; a `net::post` stuck > 10 s creates a window — practical HTTP timeout < 10 s.
2. ~~Confirm shutdown order.~~ **CONFIRMED** — `sentinel::stop_monitor()` → `heartbeat::stop()` → `net::shutdown()` on every exit path (`Main.cpp:172-175`, `186-189`, `197-212`).
3. (Optional) Swap `volatile bool s_running` for `std::atomic<bool>` for portability — no urgency on x64.

---

## 4.6. Import-policy compliance runbook

Verifies that the Release build matches the release import policy (lazy dynamic symbol binding for sensitive APIs).

Release x64 build (ideally post-VMProtect):

```powershell
msbuild Project1\Project1.vcxproj /p:Configuration=Release /p:Platform=x64
.\scripts\verify_zero_iat.ps1 -Path .\Project1\x64\Release\Project1.exe
```

Expected: exit 0, "PASS: no blacklisted imports."

Any hard-fail hit means a direct Win32 leaked into the IAT — grep the source for the function name:

```powershell
Select-String -Path .\Project1\src\*.cpp -Pattern '\bFunctionName\b'
```

The expected fix is to move the call to `dynapi::resolve(dynapi::modules::XYZ, API_HASH("FunctionName"))`.

**Note:** `dumpbin` requires Developer PowerShell for VS, or loading `VsDevCmd.bat`.

---

## 4.7. Known residual risks (ship as-is unless listed)

Risks accepted in the current release. Each item is a conscious decision, not a bug:

1. **Ordinal imports in the entitled module PE** — `pe_loader::resolve_imports` returns an error. The entitled module must use by-name imports. Documented in `pe_loader.cpp` as TODO.
2. **Commercial release packer on `canary::trap_*`** — if the code is virtualized by the packer, the code hash (`canary::verify_code`) breaks. **Packer config:** exclude `trap_a`..`trap_d` and `canary::verify_code` from the virtualization list; apply mutation only, or nothing.
3. **`rpc::call` canonical delimiter** — pipe (`|`). The server must parse identically. If it changes, change it here and on the server together.
4. **HKDF key-separation not implemented** — `session_key` is used directly for the AES-GCM payload and the session-binding HMAC. Routing per info-tag is best practice. Open issue in `feedback_secblind_decisions #9`.
5. **In-memory header zeroization is best-effort** — zeroing the header does not prevent a kernel-mode snapshot. A commercial release packer covers the rest.
6. **Runtime API integrity compares only the first bytes** — mid-function modifications (JMP after prologue, trampoline) escape. Acceptable for the current layer.
7. **`volatile bool` in sentinel** — see 4.5. Acceptable on x64.
8. **Device fingerprint does not cover hardware virtualization** — WSL/Hyper-V can mask the NVMe serial. Mitigation is server-side (abuse detection by usage pattern), not client-side.

---

## Adding the fuzzer to the solution (manual)

Spec says not to edit `Project1.sln` automatically. To add it in Visual Studio:

1. Open `Project1.sln`.
2. `File → Add → Existing Project...`
3. Select `tests\pe_loader_fuzzer\pe_loader_fuzzer.vcxproj`.
4. In the Solution Configuration Manager, make sure the new project has Debug|x64 and Release|x64 mapped (the only configs of the fuzzer).
5. Build with `Ctrl+B` on the `pe_loader_fuzzer` project.

---

## Server-primary auto-ban E2E — 2026-11-23

Status: **PASS on 2026-11-23** against staging VPS `65.108.60.114`.
Exercised the server-side path with `server/cmd/e2e_autoban` (small Go
driver that signs and sends two heartbeats with `sentinel_mask=1`).
Client-side wiring in `sentinel.cpp` is unit-covered by
`test_compose_sentinel_mask` and the full trip path is review-only
(image-corruption required to drive it in-process).

Driver run (`e2e_autoban -key <test license>`) produced:
- `hb1 -> {kill:false, revoked:false}`
- `hb2 -> {kill:true,  revoked:true}`

Postgres on the VPS after the run:
- `abuse_log`: two rows `sentinel_trip:s=1,t=0` on the test license, 0.5 s apart.
- `licenses.banned = t` on the test license.

Prometheus `/metrics` on the VPS:
- `sentinel_autoban_total 1` (was `0` before the run).

Fresh `/auth/login` with the banned license and a valid challenge:
- `HTTP 401 {"error":"invalid_credentials","message":""}`.

Required a coordinated deploy of client + server because the heartbeat
HMAC canonical changed in lockstep.

Steps:

1. Deploy server commits `23cb81b` + `a88e42d` to the VPS via
   `dist/deploy-server.ps1`.
2. Rebuild the client from `main` (includes commits `22e7d5b` + the Task 4
   wire commit).
3. On a Windows VM pointed at the staging server, run the rebuilt client
   under a debugger attached early enough to be visible to
   `anti_debug::check_all()`. Expect the client to silently terminate within
   one monitor tick (≤ 30 s).
4. On the server (SSH `admin-secblind@65.108.60.114`), confirm:
   - `psql -c "SELECT id, reason, occurred_at FROM abuse_log WHERE license_id=<X> AND reason LIKE 'sentinel_trip:%' ORDER BY id DESC LIMIT 2"`
     shows one row after the first run.
   - Prometheus `sentinel_autoban_total` metric is unchanged (threshold not met).
5. Repeat the client run. On the server confirm:
   - `abuse_log` shows a second `sentinel_trip:%` row for the same license.
   - `sentinel_autoban_total` increased by exactly `1`.
   - `psql -c "SELECT banned FROM licenses WHERE id=<X>"` → `t`.
6. Attempt a fresh `/auth/login` with the same license from a clean HWID.
   Expect `invalid_credentials` (internal reason `banned` in `abuse_log`).

Rollback: `UPDATE licenses SET banned=false WHERE id=<X>` from the admin UI.
Count row in `abuse_log` is intentionally **not** cleared — the next trip
inside the 24h window will re-ban.

---

## Fail criteria summary (one place)

- `scripts\verify_zero_iat.ps1` returns != 0.
- `pe_loader_fuzzer.exe` prints anything other than `15/15 passed` or returns != 0.
- `scripts\stress_sentinel.ps1` reports "HANG" on any instance.
- Debugger attached at any point → loader does not exit within ≤ 30 s.
- Memory inspector can read valid MZ/PE at the licensed-binary base.
- Grep of the string blocklist returns any line.
