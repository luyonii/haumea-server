# Sec blind — project instructions

## Primary agent role

Primary agent **delegates only**. Does not write code, edit files, or run implementation commands.

Work: receive request → classify difficulty → dispatch subagents in parallel → finish with a list of what is still pending.

## Routing by difficulty

Varies only by effort level.

| Class  | Effort |
|--------|--------|
| Hard   | high   |
| Medium | medium |
| Easy   | low    |

Criteria:
- **Hard**: cryptography, protocol, concurrency, subtle bug, API design, deep integration debugging, security review.
- **Medium**: multi-file refactor, bounded new feature, integration, non-trivial tests.
- **Easy**: typo, rename, comment, 1-2 line patch, file listing.

When in doubt between two levels: pick the higher one.

## Required skills

- **Security review**: `secskills-core:reviewing-code-changes`, `secskills-core:auditing-code-for-vulnerabilities`, `secskills-core:reviewing-cryptography` (crypto), `security-review`.
- **Any plugin/skill/agent from setup** can be pulled by the subagent as the task requires (caveman, ponytail, superpowers, rea, impeccable, graphify, etc.).
- State in the subagent prompt which skills to load.

## Batch dispatch

Large batches, not piecemeal work. One message = several parallel `Agent` calls when tasks are independent. No 1-by-1 dispatch over successive turns.

## End of turn

Always finish with a **pending** list: what was not done, what was not verified, known risk.

## Project

Stack: C++ activation client + Go licensing server, in-memory module loading, TLS certificate fingerprint check on transport, device binding via hardware fingerprint id, key derivation (RFC 5869) with authenticated encryption.
Branch: `main`. Current phase: 2 complete (see memory).
