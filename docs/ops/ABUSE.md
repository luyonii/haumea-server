# ABUSE — Playbook

## Fontes

- Tabela `abuse_log` em Postgres: `(id, license_id, ip, reason, ts)`.
- Reasons observadas em `server/internal/api/api.go`:
  - `fetch_license_lookup` — sessão aponta para license inexistente.
  - `fetch_killed` — kill flag ativo, cliente tentou fetch.
  - `fetch_no_payload` — payload ausente na fase de fetch.
  - `hwid_cooldown` — HWID diferente do registrado dentro da janela de cooldown.
  - (prefixo `failAuth`) demais reasons autenticação: `unknown_license`, `banned`, `bad_hmac`, `nonce_replay`, `rate_limit_exceeded`, `hwid_mismatch`.
- Full list: `grep -n LogAbuse server/internal/api/api.go` para auditoria.

## Triage

### Automática (script `auto_ban.sh`)
- Janela 10min, agregar por IP.
- Threshold IP: > 50 eventos distintos → iptables DROP + log em `/var/log/secblind/autoban.log`.
- Threshold license: > 20 fails/hora → marca `needs_review` em tabela adjunta (ou dispara alerta se tabela não existe).
- Duração do ban: 24h (unban via cron). Reinfrações: ban permanente após 3 ocorrências.

### Manual
- HWID flip-flop: mesma `license_id` com `hwid_mismatch` recorrente de IPs diferentes → sharing/crack. Revogar.
- Burst de `bad_hmac`: tentativa de key brute-force ou cliente desatualizado. Investigar versão.
- `nonce_replay` em volume: replay attack ativo. P1.

## Revogação

**Endpoint** (assumido): `POST /api/v1/admin/revoke`
Body: `{"license_id": 1234, "reason": "sharing"}`
Auth: header `Authorization: Bearer <ADMIN_TOKEN>`.

Curl ref:
```bash
curl -X POST https://api.secblind.example/api/v1/admin/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"license_id": 1234, "reason": "hwid_flipflop"}'
```

## Evidence package (antes de revogar)

Query SQL:
```sql
SELECT id, license_id, ip, reason, ts
FROM abuse_log
WHERE license_id = $1
ORDER BY ts DESC
LIMIT 100;
```

Export JSON + salvar em `/var/log/secblind/evidence/<license_id>-<ts>.json`. Retenção 1 ano, read-only.

Query por IP (ban):
```sql
SELECT license_id, reason, count(*) AS n
FROM abuse_log
WHERE ip = $1 AND ts > now() - interval '24 hours'
GROUP BY license_id, reason
ORDER BY n DESC;
```

## SLA

| Severidade | Gatilho | Response |
|---|---|---|
| HIGH | Replay attack ativo, mass bad_hmac, leak confirmado | < 1h |
| MED | Suspeita de sharing (HWID flip), burst isolado | < 24h |
| LOW | Fail isolado, falha de rate limit aparente | < 7d |

## Fluxo

1. Alert fired → acknowledge.
2. Pull evidence (SQL acima + nginx logs se disponível).
3. Classificar severidade.
4. Decisão: ban IP (temp/perm), revogar license, ou monitorar.
5. Executar: `auto_ban.sh --apply` ou curl `/admin/revoke`.
6. Pós-ação: evidence salvo, ticket criado, post-mortem se HIGH.

## Riscos cobertos manualmente
- `/admin/revoke` ainda não implementado — confirmar com dev antes de confiar no fluxo em produção.
- IP ban via iptables não persiste reboot — usar `iptables-save` + `netfilter-persistent` ou nftables com arquivo.
- Falso positivo: CGNAT/NAT grande pode acumular eventos de usuários legítimos. Threshold calibrar após 30d de dados.
- Logs de evidence contêm IP + license_id → PII, cuidar com acesso.
