# TESTING.md — Fase 6: Testes adversariais

Matriz de defesas, runbooks e auditoria de thread safety para o Sec-blind loader.

Alvo: `Project1\x64\Release\Project1.exe` (build Release, idealmente pós-VMProtect e com assinatura EV).

---

## 4.1. Static analysis defenses

| Ferramenta | Comportamento esperado | Critério de PASS |
|---|---|---|
| **IDA Pro** (x64 disasm + Hex-Rays) | Funções virtualizadas pelo VMProtect aparecem como stubs opacos. Nenhuma string de API ou URL em plaintext. Fluxo de resolução via `dynapi::resolve` embaralhado por FNV-1a hashes. | Analista não consegue localizar `auth::authenticate` em < 30 min. |
| **Binary Ninja** | Idêntico ao IDA: sem símbolos, sem strings, sem IAT utilizável para seguir controle. | Mesmo critério. |
| **strings.exe / rabin2 -z** | Zero matches para a blocklist de strings sensíveis (abaixo). | Comando abaixo retorna vazio. |
| **PE-bear / CFF Explorer** | IAT contém apenas baseline CRT (KERNEL32, VCRUNTIME140, api-ms-win-crt-*). Seções `.vmp*` após packer. Nada de `bcrypt.dll` / `winhttp.dll` / `advapi32.dll` visível. | `scripts\verify_zero_iat.ps1` retorna exit 0. |

### Blocklist de strings (grep = fail)

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

Comando sugerido (Developer PowerShell):

```powershell
$blk = Get-Content .\TESTING.strings.blocklist.txt
strings .\Project1\x64\Release\Project1.exe |
    Where-Object { $blk -contains $_ }
```

(Qualquer linha retornada = FAIL. Se não houver `strings.exe`, usar `rabin2 -z` ou `sigcheck -s`.)

---

## 4.2. Dynamic analysis defenses

| Cenário | Mecanismo acionado | PASS |
|---|---|---|
| **x64dbg attach-at-start** | `anti_debug::peb_being_debugged` / `nt_global_flag` / `process_debug_port` disparam na primeira `sentinel::scan()`. | Processo encerra silenciosamente, sem output. |
| **x64dbg attach-after-start** | Thread de monitor (`sentinel::monitor_proc`, 30 s) detecta na próxima volta. | Processo encerra silenciosamente em ≤ 30 s. |
| **Hardware breakpoint** (Dr0-Dr3 setados via x64dbg) | `anti_debug::hw_breakpoint` fires. | Processo encerra silenciosamente. |
| **ScyllaHide / NtSetInformationThread hook** | `anti_hook::check_critical_apis` compara ntdll fresh-from-disk ↔ memória, detecta divergência nos primeiros 16 bytes. | Monitor trips → terminate silent. |
| **Scylla dump do PE em memória** | Após `pe_loader::map`, DOS `e_magic`=0, `e_lfanew`=0, NT `Signature`=0 na página do payload. | Scylla reporta "invalid PE at image base". |
| **Cheat Engine** | `tool_detect::enumerate` detecta janela/processo `cheatengine-x86_64.exe` por hash FNV-1a. | Processo encerra silenciosamente. |

Observações:
- `anti_debug::rdtsc_timing` e `trap_flag_seh` também disparam em singlestep; são complementares.
- `anti_dump` é melhor-esforço: um atacante com driver pode tirar snapshot antes do zero. VMProtect resolve o resto.

---

## 4.3. Legitimate-user false-positive matrix

Cenários em que usuários legítimos podem acionar defesas. Comportamento documentado:

| Cenário | Flag disparada | Severidade | PASS |
|---|---|---|---|
| **Windows 11 com Hyper-V / VBS / Memory Integrity** | `anti_vm::hypervisor_bit` (CPUID bit 31 de ECX) | WARN only | Loader prossegue; apenas `report.anti_vm` != 0, não aborta. |
| **Dev com Visual Studio aberto** | — | — | `vshost.exe`, `devenv.exe` **não** estão na blocklist. Nenhum trigger. |
| **WSL2 / Docker Desktop (Hyper-V backend)** | `anti_vm::vm_mac_prefix` (Hyper-V OUI 00:15:5D), `anti_vm::hypervisor_bit` | WARN only | Loader prossegue. |
| **PerfView / WPR** | — | — | Não hooka user-mode APIs. `anti_hook` clean. Sem trigger. |
| **Procmon rodando** | — | — | Driver em kernel, não altera ntdll user-mode. `anti_hook` clean. Nome `procmon64.exe` **não** na blocklist (decisão: capturas de I/O não são threat; adicionar apenas se política mudar). |

**Política:** `anti_vm` nunca aborta sozinho. `sentinel::scan()` só aborta se `anti_debug`, `anti_hook`, `tool_mask`, ou tamper/canary trip.

---

## 4.4. Fuzzer runbook

Build:

```powershell
msbuild tests\pe_loader_fuzzer\pe_loader_fuzzer.vcxproj /p:Configuration=Release /p:Platform=x64
```

Rodar:

```powershell
.\tests\pe_loader_fuzzer\x64\Release\pe_loader_fuzzer.exe
```

Expected output: `15/15 passed`, exit code 0.

**Fail criteria:**
- Qualquer caso crasha (SEH não tratado, AV).
- Qualquer caso trava > 5 s.
- Enum retornado != esperado.
- Case 0 (`clean_ok`) FAIL → skeleton inválido, todos os outros testes não confiáveis.

Casos cobertos (ver `tests/pe_loader_fuzzer/main.cpp`):
0. **`clean_ok`** — skeleton válido → `ok` (sanity; se falhar, os demais são lixo)
1. null ptr → `bad_dos_header`
2. size 0 → `bad_dos_header`
3. MZ magic errado → `bad_dos_header`
4. `e_lfanew` out-of-bounds → `bad_nt_header`
5. PE sig errado → `bad_nt_header`
6. Machine != AMD64 → `bad_machine`
7. `SizeOfHeaders > pe_size` → `bad_nt_header`
8. `SizeOfOptionalHeader` inválido → `bad_nt_header`
9. Reloc block com `SizeOfBlock < 8` → `reloc_failed`
10. Reloc com VA overflow → `reloc_failed`
11. Section `VA + SRD > SizeOfImage` → `section_copy_failed`
12. Section `PRD + SRD > pe_size` → `section_copy_failed`
13. Ordinal import (`IMAGE_ORDINAL_FLAG64` set) → `import_failed`
14. `SizeOfImage = 0x7FFFFFFF` → `alloc_failed`

---

## 4.5. Thread safety audit

Estado compartilhado entre threads (main / heartbeat / sentinel monitor):

| Estado | Escritor | Leitor | Risco | Mitigação | Status |
|---|---|---|---|---|---|
| `net::` critsec | `net::init` (main) | `net::post` (heartbeat), `net::shutdown` (main) | Shutdown destrói critsec enquanto heartbeat_proc ainda está em `post`. | `heartbeat::stop` precisa joinar a thread antes de `net::shutdown`. | **CONFIRMED** — `Main.cpp:197-212` chama `sentinel::stop_monitor()` → `heartbeat::stop()` → `net::shutdown()`, exatamente a ordem reversa do start. Mesmo caminho nos exit paths de falha (`Main.cpp:172-175` e `186-189`). Janela residual: `heartbeat::stop` espera no máximo 10 s em `pWaitFor(s_thread, 10000)` (`heartbeat.cpp:149`); se um `net::post` ficar inflight > 10 s, `net::shutdown` roda com thread ainda viva. Aceitável: timeout da conexão HTTP < 10 s em qualquer caso prático. |
| `heartbeat::s_key` (32 bytes) | `heartbeat::start` | `heartbeat_proc` (HMAC), `heartbeat::stop` (zera) | Zero no meio de HMAC → tag garbage. | `stop` deve setar stop-event, aguardar `WaitForSingleObject(thread, ...)`, e só então zerar. | **CONFIRMED** — `heartbeat.cpp:147` sinaliza stop_event, `:149` `pWaitFor(s_thread, 10000)` joina, `:161` zera `s_key`. Join acontece antes do scrub. (A thread também zera `s_key` em `:97-98` antes de sair; double-scrub é benigno.) |
| `sentinel::s_scrub_cb` (fn ptr) | `sentinel::set_scrub_callback` (main, antes de `start_monitor`) | `monitor_proc` | Leitura não-atômica de ponteiro em x64 é alinhada e benigna. | Set-once pattern. | **OK.** |
| `sentinel::s_baseline`, `s_code_baseline` (uint32) | `sentinel::start_monitor` | `monitor_proc` | Set-once antes da thread existir — publicação coberta pelo `CreateThread`. | — | **OK.** |
| `sentinel::s_running` (volatile bool) | `start_monitor`, `monitor_proc` (exit), `stop_monitor` | `start_monitor` (guard) | `volatile bool` não é `std::atomic`. Em x64 leitura/escrita alinhada é atômica por hardware, mas sem barreira de memória. Flag é só guard contra double-start, não sincroniza dados. | Idealmente `std::atomic<bool>`. **Atual**: aceitável, pois dados sincronizados são publicados via `CreateThread` / stop-event. | **CONFIRMED** — `sentinel.cpp:27` declara `static volatile bool s_running = false;` (plain volatile, não `std::atomic`). Writes em `:60`, `:81`, `:86` (guard), `:100`, `:102`, `:125`. Nenhuma barreira de memória explícita; sincronização é pelo `CreateThread`/stop-event. Semântica suficiente para o uso atual (guard). Upgrade para `std::atomic<bool>` fica como débito. |
| `g_payload_key`, `g_license_hash` (globals em main.cpp) | main (pré-monitor) | `monitor_proc` → `scrub_cb` (zera no trip) | Single-writer antes de start; single-reader só no trip. | Nenhuma. | **OK.** |

Pendências resolvidas:
1. ~~Confirmar heartbeat join-before-zero.~~ **CONFIRMED** (`heartbeat.cpp:149` joina antes de `:161` zerar). Nota: timeout de 10 s; um `net::post` preso > 10 s cria janela — HTTP timeout prático < 10 s.
2. ~~Confirmar ordem de shutdown.~~ **CONFIRMED** — `sentinel::stop_monitor()` → `heartbeat::stop()` → `net::shutdown()` em todos os exit paths (`Main.cpp:172-175`, `186-189`, `197-212`).
3. (Opcional) Trocar `volatile bool s_running` por `std::atomic<bool>` para portabilidade — sem urgência em x64.

---

## 4.6. Zero-IAT runbook

Build Release x64 (idealmente pós-VMProtect):

```powershell
msbuild Project1\Project1.vcxproj /p:Configuration=Release /p:Platform=x64
.\scripts\verify_zero_iat.ps1 -Path .\Project1\x64\Release\Project1.exe
```

Expected: exit 0, "PASS: no blacklisted imports."

Qualquer hard-fail hit significa que uma Win32 direta vazou — grep o source pelo nome da função:

```powershell
Select-String -Path .\Project1\src\*.cpp -Pattern '\bFunctionName\b'
```

A fix esperada é mover a call para `dynapi::resolve(dynapi::modules::XYZ, API_HASH("FunctionName"))`.

**Note:** `dumpbin` requer Developer PowerShell for VS, ou carregar `VsDevCmd.bat`.

---

## 4.7. Known residual risks (ship as-is unless listed)

Riscos aceitos no release atual. Cada item é uma decisão consciente, não um bug:

1. **Imports por ordinal no payload PE** — `pe_loader::resolve_imports` retorna erro. Payload deve usar imports por nome. Documentado em `pe_loader.cpp` como TODO.
2. **VMProtect virtualization em `canary::trap_*`** — se virtualizado, o fingerprint de código (`canary::verify_code`) quebra. **Config do VMProtect:** excluir `trap_a`..`trap_d` e `canary::verify_code` da lista de virtualização; aplicar apenas mutation ou nada.
3. **Delimitador canônico de `rpc::call`** — pipe (`|`). Servidor precisa parsear idêntico. Se mudar, mudar aqui e no servidor juntos.
4. **HKDF key-separation não implementado** — session_key é usada direto para AES-GCM payload e HMAC watermark. Rotear por info-tag diferentes é melhor prática. Issue aberto em `feedback_secblind_decisions #9`.
5. **Anti-dump é best-effort** — zero do header em memória não impede snapshot kernel-mode. VMProtect + obfuscação de seções cobrem o resto.
6. **`anti_hook` compara só os primeiros bytes** — inline hooks mais profundos (JMP após prólogo, trampoline mid-function) escapam. Aceitável para a camada atual.
7. **`volatile bool` em sentinel** — ver 4.5. Aceitável em x64.
8. **HWID não cobre virtualização de hardware** — WSL/Hyper-V podem mascarar serial NVMe. Mitigação é server-side (anti-abuse por padrão de uso), não client-side.

---

## Adicionar o fuzzer à solução (manual)

Spec diz para não editar `Project1.sln` automaticamente. Para adicionar no Visual Studio:

1. Abrir `Project1.sln`.
2. `File → Add → Existing Project...`
3. Selecionar `tests\pe_loader_fuzzer\pe_loader_fuzzer.vcxproj`.
4. No Solution Configuration Manager, garantir que o projeto novo tem Debug|x64 e Release|x64 mapeados (os únicos configs do fuzzer).
5. Build com `Ctrl+B` sobre o projeto `pe_loader_fuzzer`.

---

## Fail criteria resumido (um só lugar)

- `scripts\verify_zero_iat.ps1` retorna != 0.
- `pe_loader_fuzzer.exe` imprime algo diferente de `12/12 passed` ou retorna != 0.
- `scripts\stress_sentinel.ps1` reporta "HANG" em qualquer instância.
- Debugger anexado em qualquer ponto → processo não encerra em ≤ 30 s.
- Scylla consegue dump com MZ/PE válidos no base do payload.
- Grep da blocklist de strings retorna qualquer linha.
