# `andromeda_auth` — shared on-chain auth crate

Rust crate (`#![no_std]`) compartilhado por todos os programas Quasar da Andromeda — `rules-policy` + os 7 templates (`allowlist-destinations`, `velocity-guard`, `time-lock`, `oracle-conditional`, `passkey-step-up`, `session-keys`, `fhe-gated`).

Reúne em um só lugar a lógica que torna toda a stack on-chain da Andromeda **wallet-agnostic + zero-attestor**:

| Módulo | Função |
|---|---|
| `lib.rs` | Schemes (Ed25519/Secp256k1/Secp256r1/WebAuthn), `MEMBER_SLOT_LEN = 34`, `build_member_slot`, `validate_slot`, `verify_signature(VerifyInput)` |
| `precompile.rs` | Parser do `Instructions` sysvar + `verify_ed25519`, `verify_secp256k1`, `verify_secp256r1`. Suporta layouts long-format (14-byte offsets, sentinela `0xFFFF`) e short-format (Secp256k1, 11-byte offsets, sentinela `0xFF`) |
| `challenge.rs` | 14 challenges canônicas para a `rules-policy` (recovery + admin) — domain-separated `andromeda::rules-policy::v1` |
| `hash.rs` | Wrapper minimal sobre a syscall `sol_sha256` (evita pull de `solana-sha256-hasher` que arrasta `std`) |
| `admin.rs` | `verify_owner_admin(expected_nonce, on_chain_nonce, owner_slot, challenge, sysvar_data) -> Result<u64>` — gate compartilhado pelos 7 templates owner-style |

## Por que existe

Sem o crate, cada um dos 8 programas teria que duplicar:
- Constantes de program id dos 3 precompiles Solana
- Parser do Instructions sysvar (long + short layouts)
- Helper `Hashv` da syscall `sol_sha256`
- Tabela de scheme → identifier length
- Validação canônica do member-slot 34-byte
- Lógica de matching WebAuthn (`auth_data || sha256(client_data_json)` + base64url-no-pad challenge in JSON)

Como tudo isso é primitiva criptográfica, ter uma cópia única + auditável reduz drasticamente a superfície de bug.

## Schemes suportados

```text
0 = Ed25519      identifier = 32 bytes (pubkey)
1 = Secp256k1    identifier = 20 bytes (eth_address = keccak256(uncompressed_pubkey)[12..])
2 = Secp256r1    identifier = 33 bytes (compressed P-256)
3 = WebAuthn     identifier = 33 bytes (compressed P-256, used for full WebAuthn assertion)
```

`sr25519` / Ristretto / Bitcoin Taproot puro **não** são suportados — Solana não tem precompile/syscall para eles. Substrate users enrollam com Ed25519 ou Secp256k1 (Substrate suporta os dois nativos).

## Member-slot canônico (34 bytes)

```text
slot[0]      = scheme tag
slot[1..1+L] = identifier (L = 20 / 32 / 33 dependendo do scheme)
slot[..]     = zero padding até 34 bytes
```

`build_member_slot(scheme, identifier)` valida o length contra o scheme e zera o padding. `validate_slot(slot)` confirma que um slot lido on-chain está bem formado (scheme conhecido + padding zero).

## Como cada template usa

```rust
// Cada template Quasar declara sua própria DOMAIN:
const DOMAIN: &[u8] = b"andromeda::<template>::v1";

// Constrói challenges com domain-separation:
fn admin_action_challenge(...) -> [u8; 32] {
    hashv(&[DOMAIN, op_tag, dwallet, &nonce_le, owner_slot, ...extras])
}

// E em cada admin handler:
let new_nonce = andromeda_auth::admin::verify_owner_admin(
    expected_nonce,
    self.policy.next_admin_nonce.into(),
    &self.policy.owner_slot,
    &challenge,
    &sysvar_data,
)?;
self.policy.next_admin_nonce = new_nonce.into();
```

`verify_owner_admin` rejeita `WebAuthn` no slot (owner é credencial estável; passkey assertion é session-scoped) — isso é uma decisão deliberada de segurança, parte da primitiva.

## Mirror em Go

`gateway/internal/auth/` é o mirror byte-a-byte deste crate em Go (`core.go`, `errors.go`, `hashv.go`, `precompile.go`, `challenges_recovery.go`, `challenges_templates.go`). Toda mudança aqui exige update equivalente do mirror — os bytes têm que bater até o último.

## Build

```bash
cd contracts/auth
cargo build-sbf      # via qualquer crate dependente; o auth crate é library-only
```

> **Host build (`cargo build`) cai** porque `solana-address` 2.6.0 host removeu `from_str_const`. O crate é projetado para target SBF; build verifica via os crates dependentes (rules-policy, allowlist-destinations, etc).

## Status

Estável. v1 da auth shared layer — usada por 8 programas em produção devnet. Próximos itens são puros add-ons (e.g., wrapper para um futuro precompile sr25519 quando o SIMD apropriado pousar no Solana).
