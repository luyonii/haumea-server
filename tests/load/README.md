# Sec-blind — Load / stress test harness (k6)

Scripts de carga para o server Go. Não editam o server. k6 roda fora,
bate nos endpoints `/api/v1/*`.

## Pré-requisitos

1. **k6 instalado** no host:
   - Windows (choco): `choco install k6`
   - Windows (winget): `winget install k6 --source winget`
   - Linux (apt):  `sudo apt-get install k6`
   - macOS (brew): `brew install k6`
   - Binário direto: https://github.com/grafana/k6/releases
2. **Server up** apontando para Postgres+Redis de teste. Nunca rodar
   contra produção.
3. **Licenças de teste** semeadas no Postgres. Os scripts leem a lista
   da env `SB_LICENSES` (CSV). Exemplo:
   ```powershell
   $env:SB_LICENSES = "TEST-AAAA-0001,TEST-AAAA-0002,TEST-AAAA-0003"
   ```
   Semeie-as com:
   ```sql
   INSERT INTO licenses (key, status, hwid, hwid_bound_at)
   VALUES ('TEST-AAAA-0001','active',NULL,NULL),
          ('TEST-AAAA-0002','active',NULL,NULL),
          ('TEST-AAAA-0003','active',NULL,NULL);
   ```
   Para o cenário `03_rpc_burst` e `04_rate_limit_hit`, crie **mais**
   licenças (uma por VU) ou aceite o compartilhamento conforme a nota
   em cada script.
4. **Base URL**: `SB_BASE_URL` (default `http://127.0.0.1:8080`).
5. **Rate-limit config** do server (`per_ip_rpm`, `per_hwid_rpm`): ajuste
   em `config.yaml` para teste. Rodar scripts com defaults muito baixos
   fecha a porta logo.

## Rodar

```powershell
# individual
k6 run tests/load/00_baseline.js

# com env
$env:SB_BASE_URL = "http://127.0.0.1:8080"
$env:SB_LICENSES = "TEST-AAAA-0001,TEST-AAAA-0002,..."
k6 run tests/load/01_login_flow.js

# summary JSON pro CI
k6 run --summary-export=summary.json tests/load/01_login_flow.js

# tudo (sequencial)
pwsh tests/load/run_all.ps1

# só o smoke
pwsh tests/load/run_all.ps1 -Quick
```

## Cenários

| # | script | VUs | duração | foco |
|---|--------|-----|---------|------|
| 00 | `00_baseline.js`                | 10  | 1m  | sanidade de `/auth/challenge` |
| 01 | `01_login_flow.js`              | 50  | 7m  | challenge→login HMAC completo |
| 02 | `02_heartbeat_sustained.js`     | 100 | 10m | heartbeat loop sustentado     |
| 03 | `03_rpc_burst.js`               | 20  | burst | nonce anti-replay Redis    |
| 04 | `04_rate_limit_hit.js`          | 30  | 2m  | validar 429 + Retry-After     |
| 05 | `05_payload_fetch_concurrency.js` | 50 | 3m | `/payload/fetch` concorrente  |

## SLOs (thresholds) — exit != 0 no CI quando falham

- Baseline:    P95 < 100ms, erro < 1%
- Login flow:  P95 < 300ms, success > 99%
- Heartbeat:   P95 < 150ms, success > 99.5%
- RPC burst:   nonce_replay = 0, P95 < 200ms
- Rate limit:  429_count > 0, 5xx = 0
- Payload fetch: P99 < 500ms, 5xx = 0

## Métricas-chave para Grafana

Todas as métricas k6 saem via `--out` para InfluxDB/Prometheus. As
principais já estão nomeadas com tag `route`:

- `http_req_duration{route="challenge|login|heartbeat|rpc|fetch"}`
- `http_req_failed` por route
- `login_success_rate` (custom, `01_login_flow`)
- `nonce_replay_total` (custom, `03_rpc_burst`)
- `rate_limited_total` (custom, `04_rate_limit_hit`)
- `vus`, `vus_max`
- `iterations` por route

Exemplo Prometheus remote-write:
```powershell
k6 run --out experimental-prometheus-rw tests/load/02_heartbeat_sustained.js
```

## Notas técnicas

- **HKDF**: k6 não traz HKDF na stdlib. `_lib.js` implementa
  HKDF-Extract + Expand (bloco único, saída 32 B) via `k6/crypto` HMAC.
  Confere com `server/pkg/crypto/hkdf.go`.
- **HWID**: exatamente 64 hex minúsculos (regra do server). O lib gera
  um HWID único por VU.
- **GCM decrypt do payload**: fora de escopo deste harness. k6 mede
  server-side. Para medir cliente-side, ver `05_payload_fetch_concurrency.js`
  nota `OUT-OF-BAND`.
- **TLS / cert pin**: o cliente C++ faz pin do cert. k6 não. Para rodar
  contra server com TLS, passe `--insecure-skip-tls-verify` ou
  `SB_CERT_FILE=cert.pem` (script tenta `__ENV.CERT_FILE || "cert.pem"`).

## Troubleshooting

- Todos os logins falham com `unknown_license` → licenças não
  semeadas ou `SB_LICENSES` errada.
- `unknown_hwid` após primeiro login OK → HWID binding gravou e VUs
  reusam HWID; solução: cada VU gera HWID próprio (já é o padrão).
- 100% 429 → rate-limit do server está apertado. Ajuste `per_ip_rpm`
  no `config.yaml` para teste ou rode com menos VUs.
