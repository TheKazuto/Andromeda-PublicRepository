# `andromeda_jwk_registry` — on-chain JWK registry (Quasar program)

Trust root for Andromeda's social-login recovery flow. Stores the OIDC RSA signing keys (Google / Apple) — modulus `n` + exponent `e` + validity window — that the `policy-engine` program uses to verify a provider's `id_token` on-chain (`sol_big_mod_exp`) when opening the OIDC primary session (`scheme = 4 = OidcJwt`).

| | |
|---|---|
| Program ID (devnet) | `8xL2mrQ2amDpinQMHJPaEELbgEXWRVGn4PQ7kzDm7vNM` |
| Deploy keypair | `contracts/.deploy-keys/jwk-registry.json` (devnet only — rotate before any mainnet deploy; same convention as `policy-engine`) |
| Cluster | devnet |
| Deps | `quasar-lang` only (no `andromeda_auth` / `andromeda_policy_shared` — this program does no precompile/CPI work) |

> **Build / lockfile:** `cd contracts/jwk-registry && cargo build-sbf` generates `Cargo.lock` and `target/deploy/andromeda_jwk_registry.so`. Deploy standalone with `solana program deploy target/deploy/andromeda_jwk_registry.so --program-id ../.deploy-keys/jwk-registry.json --keypair <upgrade-authority>.json --url devnet`.

---

## Trust model

Two **separate** privileged roles, both real Solana transaction signers (this program is ops-facing, not user-facing — there is no challenge/precompile flow):

- **`authority`** — devnet: a single ops key (Fase -1 decision). Later: an M-of-N multisig (Squads), reached via `rotate_role` → timelock → `activate_role_rotation`. Can `propose_jwk`, `activate_jwk` (only after `timelock_seconds`), `expire_jwk`, `bootstrap_jwk` (genesis only), and rotate either role. **Cannot bypass the timelock for an `ACTIVE` key.**
- **`emergency_revoker`** — a deliberately separate, lower-privilege key. Can **only** `revoke_jwk` — immediate, ignores the grace period, and (via the `policy-engine`'s per-use re-check) kills already-open OIDC sessions.

The off-chain watcher (`jwk-rotator/`) fetches the providers' JWKS, diffs against the on-chain state, and `propose_jwk`s new keys — **it never activates anything**. A human (the `authority` holder / multisig) approves the activation after the timelock.

What a compromised `authority` can do: add a bogus key for a legitimate issuer after the timelock — mitigated by the timelock window + the public watcher (which alerts if a key appears on-chain that is not in the real JWKS) + `emergency_revoker` (which can kill it before the timelock elapses). What a compromised backend / gateway **cannot** do: anything — the RSA signature of the provider is verified by the Solana runtime; the registry only stores public moduli.

---

## Account: `JwkRegistry`

- PDA seeds: `[b"jwk_registry", registry_seed: Address]`. The **canonical** registry (the one `ika-backend` / `policy-engine` / clients pin) uses `registry_seed = <the all-zero Address>`. Non-zero seeds create independent registries (test harnesses, a future "staging" registry); they are isolated and harmless. `ika-backend` reads the resolved address from `IKA_OIDC_JWK_REGISTRY_ADDRESS`.
- Discriminator `1`. Fixed size (`set_inner`, no `realloc`).
- Fields: `version`, `entry_count` (slots not `EMPTY`), `authority`, `pending_authority`, `emergency_revoker`, `pending_emergency_revoker`, `timelock_seconds`, `grace_period_seconds`, `grace_period_post_revoke_seconds` (minimum delay between `revoke_jwk` and any `propose_jwk` that recycles the same slot; floor of 1200s = 2× OIDC session TTL prevents a compromised `authority` from resurrecting a slot the `emergency_revoker` just killed before live sessions expire), `authority_rotation_ready_at`, `emergency_revoker_rotation_ready_at`, `entries_flat: [u8; MAX_JWKS * JWK_ENTRY_LEN]`.
- `MAX_JWKS = 8`, `JWK_ENTRY_LEN = 400` ⇒ `entries_flat` = 3200 bytes; account ≈ 3.4 KB; rent ≈ 0.025 SOL. `MAX_JWKS` is kept small so the `set_inner` temporary stays well under the 4 KB BPF stack frame. 8 slots cover Google (2–3 keys) + Apple (2–4 keys) on devnet pre-alpha; if it ever gets tight the account can be re-created larger (the watcher alerts on `RegistryFull`).
- Per-entry layout (within a 400-byte slot, 8-aligned, no padding): `status(1) alg(1) _resv(6) issuer_hash(32) audience_hash(32) kid_hash(32) modulus_n(256, BE) exponent_e(4, u32 LE) _resv(4) proposed_at(8, i64 LE) valid_from(8) valid_until(8) revoked_at(8)`.
- Entry status: `0 EMPTY · 1 PENDING · 2 ACTIVE · 3 REVOKED · 4 EXPIRED`. A `REVOKED` or `EXPIRED` slot is recyclable by a future `propose_jwk` (which abruptly invalidates any session that still referenced the old `(issuer, audience, kid)` triple — by design; sessions are ≤ 10 min and only past-grace/revoked keys get recycled).

---

## Instructions

| Disc | Name | Signer(s) | Effect |
|---|---|---|---|
| 0 | `init_registry(registry_seed, authority, emergency_revoker, timelock_seconds, grace_period_seconds, grace_period_post_revoke_seconds)` | `payer` + `authority` (co-signs to prove consent / prevent PDA squat) | Create the registry. `timelock_seconds ≤ 30d`, `grace_period_seconds ≤ 30d`, `1200s ≤ grace_period_post_revoke_seconds ≤ 30d` (lower bound = `2 × OIDC_SESSION_TTL` so a revoked slot can never be recycled while a session opened against the old modulus is still live), `authority ≠ emergency_revoker`, neither zero. Devnet runbook: 7d post-revoke; mainnet: 30d. |
| 1 | `propose_jwk(registry_seed, issuer_hash, audience_hash, kid_hash, alg, modulus_n[256], exponent_e)` | `payer` + `authority` | Add a PENDING entry. Rejects: `alg ≠ RS256`; modulus not a full odd 2048-bit value (`n[0] & 0x80 != 0 && n[255] & 1 == 1`); `exponent_e ≠ 65537`; an entry for this triple already exists in any non-EMPTY status; no free slot AND the only recyclable slots are REVOKED still inside the `grace_period_post_revoke_seconds` window (returns `RevokeGraceNotElapsed`). EXPIRED slots are preferred over REVOKED ones, so an emergency revoke blocks recycling for the full post-revoke grace even when other recyclable slots exist. **Operational requirement:** the on-chain program accepts the 32-byte SHA-256 hashes opaquely. The gateway / watcher MUST validate `issuer_hash == sha256(iss)`, `audience_hash == sha256(aud)`, `kid_hash == sha256(kid)` against the actual JWKS values before submitting; a bug here detaches the registry entry from any provider and is invisible to on-chain checks. |
| 2 | `activate_jwk(registry_seed, issuer_hash, audience_hash, kid_hash, valid_until_ts)` | `payer` + `authority` | PENDING → ACTIVE. Requires `now ≥ proposed_at + timelock_seconds`; `now < valid_until_ts ≤ now + 30d`. Sets `valid_from = now`, `valid_until = valid_until_ts`. |
| 3 | `revoke_jwk(registry_seed, issuer_hash, audience_hash, kid_hash)` | `payer` + (`authority` **or** `emergency_revoker`) | PENDING/ACTIVE → REVOKED, `revoked_at = now`. Immediate; ignores grace. |
| 4 | `expire_jwk(registry_seed, issuer_hash, audience_hash, kid_hash)` | `payer` (permissionless) | ACTIVE → EXPIRED. Requires `now > valid_until + grace_period_seconds`. Cleanup; the slot becomes recyclable. |
| 5 | `bootstrap_jwk(registry_seed, issuer_hash, audience_hash, kid_hash, alg, modulus_n[256], exponent_e, valid_until_ts)` | `payer` + `authority` | **Genesis only:** insert the first key directly as ACTIVE, skipping the timelock. Requires `entry_count == 0`. Production should prefer `propose_jwk` + (timelock) + `activate_jwk`; this exists so devnet does not have to wait the timelock for the very first key. Emits `JwkProposed` + `JwkActivated`. |
| 6 | `rotate_role(registry_seed, role, new_key)` | `payer` + `authority` | `role`: `0 = authority`, `1 = emergency_revoker`. Sets `pending_*` + `*_rotation_ready_at = now + timelock_seconds`. `new_key` must be non-zero and must not equal either the current OR the pending value of the other role (blocks two concurrent rotations from collapsing both roles to the same key). |
| 7 | `activate_role_rotation(registry_seed, role)` | `payer` (permissionless) | Finalize a pending rotation once `now ≥ *_rotation_ready_at`. Re-checks role non-collision against current + pending values of the sibling role. |
| 8 | `cancel_role_rotation(registry_seed, role)` | `payer` + `authority` | Clear a pending rotation. |

**Account slices** (in order):
- `init_registry`: `registry(init)`, `authority(Signer)`, `payer(Signer,mut)`, `clock`, `rent`, `system_program`, `event_authority`, `program`.
- `propose_jwk` / `activate_jwk` / `bootstrap_jwk` / `rotate_role` / `cancel_role_rotation`: `registry(mut)`, `authority(Signer)`, `payer(Signer,mut)`, `clock`, `event_authority`, `program`.
- `revoke_jwk`: `registry(mut)`, `revoker(Signer)`, `payer(Signer,mut)`, `clock`, `event_authority`, `program`.
- `expire_jwk` / `activate_role_rotation`: `registry(mut)`, `payer(Signer,mut)`, `clock`, `event_authority`, `program`.

On devnet the single ops key is both `authority`/`revoker` and `payer` — pass the same pubkey twice; Solana dedups signers.

## Events

`RegistryInitialized(0)`, `JwkProposed(1)`, `JwkActivated(2)`, `JwkRevoked(3)`, `JwkExpired(4)`, `RoleRotationProposed(5)`, `RoleRotated(6)`, `RoleRotationCancelled(7)` — all zero-copy, padding-free, `(registry, hashes…, timestamps…, role?)`. They are the audit trail (recycling a slot loses its account state, never its event history). The webhook listener / `ika-backend` audit log consume these.

---

## Companion / consumers

- `jwk-rotator/` — the off-chain watcher: fetches Google/Apple JWKS, diffs vs. on-chain, `propose_jwk`s new keys, alerts ops. Never activates.
- `scripts/test_jwk_registry.go` — devnet integration test (init → bootstrap/propose → activate → revoke → expire → role rotation), analogous to the other `scripts/test_*.go`. Run **after** deploy.
- `contracts/oidc-verifier/` — re-derives `sha256(iss)/sha256(aud)/sha256(kid)` from the JWT and looks up the ACTIVE entry; mirrors the strict RSA-2048/RS256 profile check.
- `contracts/policy-engine/` — the OIDC session-open handler reads the ACTIVE entry's `n`/`e`; the per-use OIDC primary handler re-checks the entry is still ACTIVE on every signature use.

