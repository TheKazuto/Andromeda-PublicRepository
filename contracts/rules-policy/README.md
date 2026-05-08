# RulesPolicy

Programa Solana (Quasar) que controla a authority de uma dWallet Ika e aplica políticas de recovery on-chain — chave primária com bypass total ou quórum M-of-N com limites e cooldown.

## Status

- **Pre-alpha.** Depende da Ika Solana pre-alpha (devnet only). Dados são wipados na transição para Alpha 1.
- **Quasar beta, não auditado.** APIs podem mudar.
- **v2 (2026-05-07)**: redesign completo para verificação de assinaturas 100 % on-chain via precompiles Solana (Ed25519 / Secp256k1 / Secp256r1) e quórum sem limite via PDA staging multi-tx. Sem attestor, sem dependência de validade no backend.

## Build

Pré-requisitos:
- Rust (edition 2021+)
- Solana CLI 3.x (Anza)
- Quasar CLI: `cargo install quasar-cli`

```bash
cd contracts/rules-policy
cargo build-sbf            # ou: quasar build
quasar test
```

O artifact compilado fica em `target/deploy/rules_policy.so`. O cliente TypeScript correspondente é mantido manualmente em `ika-backend/src/clients/rulesPolicy/` (codecs, instructions, PDAs, program metadata) — espelho 1-a-1 do layout zero-copy do programa.

## Deploy (devnet)

```bash
quasar deploy --url devnet --keypair ~/.config/solana/devnet.json
```

Capture o Program ID e configure:
```env
IKA_RECOVERY_POLICY_PROGRAM_ID=<program_id>
```

Atualize `declare_id!` em `src/lib.rs` antes do build se necessário.

> A v2 quebra ABI das policies da v1 (layout do `RulesPolicy` mudou). Em devnet, decisão é wipe + redeploy.

## Trust model

- Toda assinatura — primary OU member do quórum — é validada pelo runtime Solana via precompile (`Ed25519SigVerify…`, `KeccakSecp256k1…`, `Secp256r1SigVerify…`).
- Backend Andromeda comprometido **não** consegue forjar signature de ninguém. Atacante consegue derrubar serviço (DoS), nunca burlar quórum.
- Toda flow é challenge-based: usuário assina off-chain um digest único de 32 bytes; o programa recomputa o mesmo digest a partir dos dados on-chain e exige uma precompile invocation com `(public_key_or_eth_address, message=challenge, signature)` na mesma transação.

## Schemes suportados

Cada credencial é um **member-slot canônico de 34 bytes**: `[scheme, ...identifier, 0..0]`.

| Scheme | Tag | Identifier (bytes) | Cobertura |
|--------|-----|--------------------|-----------|
| Ed25519 | `0` | 32 (pubkey) | Solana, Sui, NEAR, Aptos, Cosmos ed25519, Substrate ed25519 |
| Secp256k1 | `1` | 20 (eth_address) | EVM, Bitcoin, Cosmos secp256k1, Substrate ECDSA |
| Secp256r1 | `2` | 33 (compressed pubkey) | Passkeys com pubkey raw |
| WebAuthn | `3` | 33 (compressed P-256 pubkey) | Passkeys com assertion completa (challenge dentro do `clientDataJSON`) |

Primary slot aceita schemes 0/1/2 (não WebAuthn). Members do quórum aceitam todos os 4. `sr25519`, Ristretto e Bitcoin Taproot puro não têm precompile no Solana — ficam fora.

## Estado on-chain

### `RulesPolicy` (PDA seeds: `[b"rules_policy", dwallet]`)

Campos principais:
- `dwallet`, `primary_slot[34]`, `attestor_pubkey[32]` (reservado, não usado em v2)
- 3 nonces: `next_admin_nonce`, `next_primary_recover_nonce`, `next_session_nonce`
- `quorum_threshold`, `member_count`, `members_flat[16 × 34]`
- `daily_limit_some`, `daily_limit`, `daily_used`, `last_reset_ts`
- `allowed_destinations_some`, `allowed_destinations_count`, `allowed_destinations_flat[16 × 32]`
- `policy_change_cooldown_seconds`
- `pending_change_some` (kind tag: 0=none, 1=quorum, 2=daily_limit, 3=cooldown), `pending_activates_at`, e os campos `pending_*` correspondentes

### `QuorumSession` (PDA seeds: `[b"quorum_session", dwallet, session_nonce_le_u64]`)

Snapshot do roster + parâmetros da recovery em flight:
- `dwallet`, `policy`, `payer_for_close` (rent destination = quem fundou no open)
- `session_nonce`, `message_digest`, `metadata_digest`, `user_pubkey`, `destination`, `amount`
- `members_snapshot[16 × 34]`, `member_count_snapshot`, `threshold_snapshot`
- `signature_scheme`, `message_approval_bump`
- `contributions_count`, `contributions_bitmap` (u16 — bit i = member i contribuiu)
- `expires_at`, `created_at`, `finalized_at`

Constantes:
- `MAX_MEMBERS = 16`
- `MAX_DESTINATIONS = 16`
- `MIN_COOLDOWN_SECONDS = 3600` (1h)
- `MAX_SESSION_TTL_SECONDS = 7 dias`
- `WEBAUTHN_AUTH_DATA_MAX = 64`, `WEBAUTHN_CLIENT_DATA_JSON_MAX = 192`

## Instructions (20)

### Bootstrap / read

| Disc | Nome | Auth | Resumo |
|------|------|------|--------|
| 0 | `init_policy` | payer signs | Cria PDA com primary_slot + config. Authority real vem do `transfer_ownership` Ika subsequente. |

### Primary recovery (single-tx)

| Disc | Nome | Auth | Resumo |
|------|------|------|--------|
| 1 | `recover_as_primary` | challenge primary | Valida `primary_recover_challenge` via precompile + CPI Ika `approve_message`. Incrementa `next_primary_recover_nonce`. |

### Quorum staging (multi-tx)

| Disc | Nome | Auth | Resumo |
|------|------|------|--------|
| 2 | `quorum_session_open` | challenge primary | Cria session PDA, snapshota roster + threshold + parâmetros. Incrementa `next_session_nonce`. |
| 3 | `quorum_session_contribute` | challenge member (Ed25519 / Secp256k1 / Secp256r1) | Marca bit i no `contributions_bitmap`. |
| 4 | `quorum_session_contribute_webauthn` | challenge member (WebAuthn) | Idem, com payload inline. Programa valida challenge dentro de `clientDataJSON`. |
| 5 | `quorum_session_finalize` | none (anyone) | Quando `contributions_count >= threshold_snapshot`: enforça `daily_limit` + `allowed_destinations`, faz CPI Ika `approve_message`. |
| 6 | `quorum_session_close` | session.payer_for_close match | Refunda rent. |

### Admin (challenge-based, single-tx)

Todas validam `next_admin_nonce` + challenge primary. Primary scheme limitado a Ed25519 / Secp256k1 / Secp256r1.

| Disc | Nome | Resumo |
|------|------|--------|
| 7 | `add_member` | Append idempotente em `members_flat`. |
| 8 | `remove_member` | Swap-with-tail O(N). |
| 9 | `add_destination` | Append idempotente. |
| 10 | `remove_destination` | Swap-with-tail O(N). |
| 11 | `revoke` | Zera quórum (member_count = 0, threshold = 1). |
| 12 | `set_primary` | Rotaciona primary slot (próxima signature usa novo). |
| 13 | `set_quorum_threshold_immediate` | Bypass cooldown. |
| 14 | `set_daily_limit_immediate` | Bypass cooldown. |
| 15 | `set_cooldown_immediate` | Bypass cooldown. |
| 16 | `propose_quorum_threshold_change` | Arma cooldown; `apply_pending_change` aplica depois. |
| 17 | `propose_daily_limit_change` | Idem. |
| 18 | `propose_cooldown_change` | Idem. |

### Pending apply (no auth — cooldown gate)

| Disc | Nome | Auth | Resumo |
|------|------|------|--------|
| 19 | `apply_pending_change` | none | Qualquer caller após `pending_activates_at`. Lê o kind e aplica o campo correspondente. |

> **Sysvar `Instructions`** é exigido em todas as instructions challenge-based para o programa parsear precompile invocations. Sysvar `Clock` não é usado — timestamps vêm como argumento.

## Módulo `auth/`

Verificação de credenciais 100 % on-chain. Fonte da verdade:

- `auth/precompile.rs` — parse do `Instructions` sysvar e match de records `(pubkey/eth_address, message, signature)`.
  - Layout 14-byte offsets + sentinela `0xFFFF` para Ed25519 e Secp256r1.
  - Layout 11-byte offsets + sentinela `0xFF` para Secp256k1.
  - Rejeita cross-instruction references (precompile invocation deve ser self-contained).
- `auth/challenge.rs` — 14 funções `*_challenge(...)` domain-separated. Mirror byte-a-byte em TS (`ika-backend/src/recovery/challenge.ts`).
- `auth/hash.rs` — wrapper minimal sobre a syscall `sol_sha256` (evita pull de `solana-sha256-hasher`, que arrasta `std`).
- `auth/mod.rs` — `verify_signature(VerifyInput)` orquestra por scheme. Para WebAuthn member, valida que o `challenge` aparece base64url-no-pad dentro do `clientDataJSON` e reconstrói `authenticator_data || sha256(clientDataJSON)` antes de bater com a precompile Secp256r1.

## CPI no Ika dWallet program

`recover_as_primary` e `quorum_session_finalize` chamam `DWalletContext::approve_message`:

```rust
ctx.approve_message(
    coordinator, message_approval, dwallet, payer, system_program,
    message_digest, metadata_digest, user_pubkey,
    signature_scheme, message_approval_bump,
)?;
```

Discriminator 8 do programa Ika `87W54kGYFQ1rgWqMeu4XTPHWXWmXSQCcjm8vCTfiq1oY`. Ver skill `ika-solana-prealpha` §10.

## Eventos

Emitidos via `emit_cpi!`:
- `PolicyDeployed { policy, dwallet, ts }` — disc 0
- `SignatureRequested { policy, request_hash, ts }` — disc 1 (no início de cada recovery)
- `SignatureApproved { policy, request_hash, ts }` — disc 2 (após CPI Ika confirmado)

## Erros

Custom error offset 6000. Lista completa em `src/lib.rs::RulesPolicyError`. Strings amigáveis no off-chain em `ika-backend/src/safeError.ts`.

## Testing

```bash
cargo build-sbf             # build SBF puro
quasar test                 # quasar-svm harness
quasar profile --expand     # CU report
```

## Próximos passos

- E2E test contra devnet usando o gas sponsor do Andromeda.
- Telemetria de CU por instruction (importante para dimensionar tamanho do quórum em flight).
- Considerar `propose_admin` via quórum (membros propondo mudanças, não só primary) — fica como v3.
