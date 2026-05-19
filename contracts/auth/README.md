# `andromeda_auth` — shared on-chain auth crate

Rust crate (`#![no_std]`) shared by the Andromeda Quasar programs — `policy-engine` (which unifies all 8 rule kinds into a single program), along with `jwk-registry` and `oidc-verifier`.

Centralizes the logic that makes Andromeda's entire on-chain stack **wallet-agnostic + zero-attestor**:

| Module | Purpose |
|---|---|
| `lib.rs` | Schemes (Ed25519/Secp256k1/Secp256r1/WebAuthn), `MEMBER_SLOT_LEN = 34`, `build_member_slot`, `validate_slot`, `verify_signature(VerifyInput)` |
| `precompile.rs` | Parser for the `Instructions` sysvar + `verify_ed25519`, `verify_secp256k1`, `verify_secp256r1`. Supports both long-format (14-byte offsets, `0xFFFF` sentinel) and short-format (Secp256k1, 11-byte offsets, `0xFF` sentinel) layouts |
| `challenge.rs` | Canonical `policy-engine` challenges (init, add-rule per kind, items/add, request-signature, recover-as-primary, quorum-session-{open,contribute}, passkey-session-{open}, passkey-primary-use) — domain-separated under `andromeda::policy-engine::v3` |
| `hash.rs` | Minimal wrapper over the `sol_sha256` syscall (avoids pulling in `solana-sha256-hasher`, which drags `std`) |
| `admin.rs` | `verify_owner_admin(expected_nonce, on_chain_nonce, owner_slot, challenge, sysvar_data) -> Result<u64>` — the gate shared by every owner-style admin path |

## Why it exists

Without the crate, every `policy-engine` handler (plus the auxiliary `jwk-registry` / `oidc-verifier` programs) would have to duplicate:
- The program ids for the 3 Solana precompiles
- The Instructions sysvar parser (long + short layouts)
- The `hashv` wrapper around `sol_sha256`
- The scheme → identifier length table
- The canonical 34-byte member-slot validation
- The WebAuthn matching logic (`auth_data || sha256(client_data_json)` + base64url-no-pad challenge inside the JSON)

Because all of that is cryptographic primitive, having a single auditable copy drastically shrinks the bug surface. Since `policy-engine` is one program, the crate is also the mechanism that keeps byte-for-byte parity between Rust (on-chain) and the Go (gateway) / TypeScript (ika-backend) mirrors — the drift fixtures under `fixtures/` test this on every PR.

## Supported schemes

```text
0 = Ed25519      identifier = 32 bytes (pubkey)
1 = Secp256k1    identifier = 20 bytes (eth_address = keccak256(uncompressed_pubkey)[12..])
2 = Secp256r1    identifier = 33 bytes (compressed P-256)
3 = WebAuthn     identifier = 33 bytes (compressed P-256, used for the full WebAuthn assertion)
```

`sr25519` / Ristretto / pure Bitcoin Taproot are **not** supported — Solana has no precompile / syscall for them. Substrate users enroll with Ed25519 or Secp256k1 (Substrate supports both natively).

## Canonical member slot (34 bytes)

```text
slot[0]      = scheme tag
slot[1..1+L] = identifier (L = 20 / 32 / 33 depending on the scheme)
slot[..]     = zero padding up to 34 bytes
```

`build_member_slot(scheme, identifier)` validates the length against the scheme and zero-pads. `validate_slot(slot)` confirms an on-chain slot is well-formed (known scheme + zero padding).

## How each template uses it

```rust
// Each Quasar template declares its own DOMAIN:
const DOMAIN: &[u8] = b"andromeda::<template>::v1";

// Builds challenges with domain separation. Every `extra` is prefixed by
// `u16_le(len(extra))` so two variable-length extras can never concatenate
// ambiguously. The wire format is emitted byte-for-byte by the Go mirror
// (gateway), TS mirror (ika-backend), Python (tools/), and the SBF tests —
// any change here requires a synchronized update across all of them.
fn admin_action_challenge(...) -> [u8; 32] {
    hashv(&[
        DOMAIN, op_tag, dwallet, &nonce_le, owner_slot,
        &(extra0.len() as u16).to_le_bytes(), extra0,
        &(extra1.len() as u16).to_le_bytes(), extra1,
        // ...
    ])
}

// And in each admin handler:
let new_nonce = andromeda_auth::admin::verify_owner_admin(
    expected_nonce,
    self.policy.next_admin_nonce.into(),
    &self.policy.owner_slot,
    &challenge,
    &sysvar_data,
)?;
self.policy.next_admin_nonce = new_nonce.into();
```

`verify_owner_admin` rejects `WebAuthn` in the slot (owner is a stable credential; a passkey assertion is session-scoped) — this is a deliberate security choice, part of the primitive.

## Go mirror

`gateway/internal/auth/` is the byte-for-byte Go mirror of this crate (`core.go`, `errors.go`, `hashv.go`, `precompile.go`, `challenges_recovery.go`, `challenges_templates.go`). Every change here requires the matching update on the mirror — the bytes have to match down to the last one.

## Feature `host-test`

`hashv` calls the `sol_sha256` syscall on SBF and **panics** on any other target (a defense against accidental host-side usage that would return a zero digest). To allow host-side cross-language tests (e.g. fixture parity between Rust ↔ Go ↔ TypeScript), the crate exposes the optional `host-test` feature:

```toml
# Dev-only dependency in another crate:
andromeda_auth = { path = "../auth", features = ["host-test"] }
```

With `host-test` on, `hashv` on a non-SBF target uses `sha2::Sha256` (identical result to the syscall). On SBF the feature is inert. **Never enable it in a production build** — it breaks the invariant of "every cryptographic hash goes through the Solana runtime".

Current use: `contracts/sbf-tests` reads `fixtures/fhe-decision-vectors.json` and asserts that `decision_canonical_bytes` produces the same digest as the gateway (Go) and encrypt-backend (TS).

## Build

```bash
cd contracts/auth
cargo build-sbf      # via any dependent crate; the auth crate is library-only
```

> **Host build (`cargo build`) fails** because `solana-address` 2.6.0 host removed `from_str_const`. The crate is designed for the SBF target; verify the build through the dependent crates (`policy-engine`, `jwk-registry`, `oidc-verifier`). Host-side tests use the `host-test` feature to reuse `challenge.rs` and the human-message renderers.

## Status

Stable. v1 of the auth shared layer — consumed by the 3 Andromeda Quasar programs on devnet. Future items are pure add-ons (e.g. a wrapper for a future sr25519 precompile once the appropriate SIMD lands on Solana).
