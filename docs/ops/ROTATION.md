# ROTATION — Credentials, Certs, Keys

## TLS leaf cert — pinned no cliente

Cliente valida pin SHA-256 do SubjectPublicKeyInfo. Dois pins em `Project1/src/net.cpp`:
- `pin1` — leaf ativo
- `pin2` — leaf backup (`pin_leaf_backup`)

**Rotate SÓ é seguro se o novo leaf bate com `pin1` OU `pin2`.** Se não bate, cliente recusa handshake.

### Procedimento
1. Gerar/obter novo cert (LE, interno, etc).
2. Calcular hash SPKI:
   ```bash
   openssl x509 -in new-cert.pem -pubkey -noout \
     | openssl pkey -pubin -outform DER \
     | openssl dgst -sha256 -binary \
     | xxd -p -c 256
   ```
3. Comparar com `pin2` em `Project1/src/net.cpp` (linha ~168).
4. Se MATCH: rotate no server, trocar `pin1 := pin2`, gerar novo `pin2` para o próximo ciclo (novo release do cliente).
5. Se MISMATCH: **ABORT**. Fluxo pre-rotate:
   - Gerar key/cert do próximo rotate.
   - Atualizar `pin2` no cliente para o SPKI desse novo cert.
   - Novo release do cliente publicado, aguardar adoção > 95% (telemetria de versão).
   - Então rotate server.

Script: `scripts/ops/rotate_cert_check.sh` / `.ps1`. Lê novo cert como argumento, extrai pins do `net.cpp`, reporta MATCH/MISMATCH.

### Cadência
- LE: 60 dias (renewal 30 antes do expiry).
- CA interna: 1 ano. Key reuse permitido só 1 ciclo; rotate key a cada 2 anos.

## HKDF salt

Constante `"SecBlind_HKDF_v1"` compartilhada cliente+server. Todas as sessões derivam dela.

### Rotation
- Normal: 24 meses.
- Forçado: suspeita de compromise do server, leak de key material, incidente crypto.
- Procedimento:
  1. Novo valor: `"SecBlind_HKDF_v2"`.
  2. Server aceita v1 **E** v2 por janela de 72h (dual-accept): tenta v2 primeiro, fallback v1.
  3. Cliente novo release com v2.
  4. Após adoção > 99% + 72h, remover v1 do server. Sessions antigas invalidadas, clientes velhos param de autenticar — comportamento intencional.

## Admin token (`/api/v1/admin/revoke` e endpoints admin)

- Armazenamento: HashiCorp Vault (`secret/secblind/admin-token`) ou AWS Secrets Manager.
- Rotation: mensal, automática via Vault dynamic secret ou script agendado.
- Procedimento:
  1. Gerar novo token (32B random, `openssl rand -hex 32`).
  2. Deploy server com `ADMIN_TOKEN_NEXT=<novo>` + `ADMIN_TOKEN=<atual>` (dual-accept).
  3. Rotar o token em uso pelos operadores (CLI, dashboards).
  4. Deploy final: `ADMIN_TOKEN=<novo>`, remover `ADMIN_TOKEN_NEXT`.
- Revogação emergencial: invalidar e redeploy sem window. Operadores pegam novo token do Vault.

## Postgres + Redis passwords

- Rotation: trimestral.
- Zero-downtime via dual-password overlap (Postgres: `CREATE USER secblind_new`; Redis >= 6: ACL com dois users).
- Procedimento Postgres:
  1. `ALTER USER secblind WITH PASSWORD '<new>';`
  2. Secrets manager atualizado.
  3. Rolling restart do server.
- Procedimento Redis 6+:
  1. `ACL SETUSER secblind on >newpass ~* +@all`
  2. Secrets atualizado + rolling restart.
  3. Remover senha antiga: `ACL SETUSER secblind <newpass only>`.

## Checklist de rotation (qualquer tipo)

- [ ] Backup do segredo atual em cofre offline (quebra-emergência).
- [ ] Novo segredo gerado com fonte CSPRNG (não `rand()`, não timestamps).
- [ ] Dual-accept window configurada antes do deploy.
- [ ] Rollback plan testado em staging.
- [ ] Monitoramento ligado para spike de erros de auth no período de rotation.
- [ ] Post-mortem no log de rotation (`docs/ops/rotation-log.md`).

## Riscos cobertos manualmente
- Vault/ASM: alta disponibilidade + backup próprio do cofre (perder o cofre = perder tudo).
- MFA no acesso humano ao cofre.
- Audit log de leitura do segredo (SIEM).
