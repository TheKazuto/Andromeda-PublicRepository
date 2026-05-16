# `andromeda_auth` — shared on-chain auth crate

Rust crate (`#![no_std]`) compartilhado pelos programas Quasar da Andromeda — `policy-engine` (que unifica todas as 8 rule kinds num programa só), além de `jwk-registry` e `oidc-verifier`.

Reúne em um só lugar a lógica que torna toda a stack on-chain da Andromeda **wallet-agnostic + zero-attestor**:

| Módulo | Função |
|---|---|
| `lib.rs` | Schemes (Ed25519/Secp256k1/Secp256r1/WebAuthn), `MEMBER_SLOT_LEN = 34`, `build_member_slot`, `validate_slot`, `verify_signature(VerifyInput)` |
| `precompile.rs` | Parser do `Instructions` sysvar + `verify_ed25519`, `verify_secp256k1`, `verify_secp256r1`. Suporta layouts long-format (14-byte offsets, sentinela `0xFFFF`) e short-format (Secp256k1, 11-byte offsets, sentinela `0xFF`) |
| `challenge.rs` | Challenges canônicas do `policy-engine` (init, add-rule por kind, items/add, request-signature, recover-as-primary, quorum-session-{open,contribute}, passkey-session-{open}, passkey-primary-use) — domain-separated `andromeda::policy-engine::v3` |
| `hash.rs` | Wrapper minimal sobre a syscall `sol_sha256` (evita pull de `solana-sha256-hasher` que arrasta `std`) |
| `admin.rs` | `verify_owner_admin(expected_nonce, on_chain_nonce, owner_slot, challenge, sysvar_data) -> Result<u64>` — gate compartilhado pelos 7 templates owner-style |

## Por que existe

Sem o crate, cada handler do `policy-engine` (e os programas auxiliares `jwk-registry` / `oidc-verifier`) teria que duplicar:
- Constantes de program id dos 3 precompiles Solana
- Parser do Instructions sysvar (long + short layouts)
- Helper `Hashv` da syscall `sol_sha256`
- Tabela de scheme → identifier length
- Validação canônica do member-slot 34-byte
- Lógica de matching WebAuthn (`auth_data || sha256(client_data_json)` + base64url-no-pad challenge in JSON)

Como tudo isso é primitiva criptográfica, ter uma cópia única + auditável reduz drasticamente a superfície de bug. Como o `policy-engine` é um programa só, o crate também é o mecanismo que mantém a paridade byte-a-byte entre Rust (on-chain) e os mirrors em Go (gateway) + TypeScript (ika-backend) — os fixtures de drift em `fixtures/` testam isso a cada PR.

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
    // M2 audit fix (2026-05-16): cada extra é precedido por u16_le(len(extra))
    // para que dois extras de tamanho variável jamais concatenem de forma
    // ambígua. Mirror em Go (gateway), TS (ika-backend), Python (tools/) e
    // SBF tests precisam emitir o mesmo wire format byte-a-byte.
    hashv(&[
        DOMAIN, op_tag, dwallet, &nonce_le, owner_slot,
        &(extra0.len() as u16).to_le_bytes(), extra0,
        &(extra1.len() as u16).to_le_bytes(), extra1,
        // ...
    ])
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

## Feature `host-test`

`hashv` chama a syscall `sol_sha256` em SBF e **panica** em qualquer outro target (defesa contra usos host acidentais que retornavam digest zerado). Para permitir testes host-side cross-language (e.g. fixture parity entre Rust ↔ Go ↔ TypeScript), o crate expõe a feature opcional `host-test`:

```toml
# Dev-only dependency em outro crate:
andromeda_auth = { path = "../auth", features = ["host-test"] }
```

Com `host-test` ligada, `hashv` em target não-SBF passa a usar `sha2::Sha256` (resultado idêntico ao da syscall). Em SBF a feature é inerte. **Nunca ativar em build de produção** — quebra a invariante de "todo hash criptográfico passa pela runtime do Solana".

Uso atual: `contracts/sbf-tests` lê `fixtures/fhe-decision-vectors.json` e valida que `decision_canonical_bytes` produz o mesmo digest que o gateway (Go) e o encrypt-backend (TS).

## Build

```bash
cd contracts/auth
cargo build-sbf      # via qualquer crate dependente; o auth crate é library-only
```

> **Host build (`cargo build`) cai** porque `solana-address` 2.6.0 host removeu `from_str_const`. O crate é projetado para target SBF; build verifica via os crates dependentes (`policy-engine`, `jwk-registry`, `oidc-verifier`). O host-side de testes usa a feature `host-test` para reaproveitar `challenge.rs` e os renderers de human-message.

## Status

Estável. v1 da auth shared layer — consumida pelos 3 programas Quasar Andromeda em devnet. Próximos itens são puros add-ons (e.g., wrapper para um futuro precompile sr25519 quando o SIMD apropriado pousar no Solana).
