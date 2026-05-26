# `policy-engine` — Andromeda PolicyEngine v3 (Quasar)

> **Deployed (devnet):** `ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL`
> **Authority:** `B98zhthMGHUexMAwuJvud83M4LKTQgw6CbtgXS5vPgBZ`
> **Compiled:** `cargo build-sbf --no-default-features` (devnet pre-alpha, `sol_big_mod_exp` not active — Login Social OIDC verification is rejected on-chain until the syscall lights up and the program is rebuilt with `--features oidc-rsa`).

Unified Quasar program that holds the authority of any Andromeda dWallet and dispatches at signing time across 9 composable rule kinds. The hot-path `request_signature` walks every active rule slot in order, runs the per-kind dispatch, and CPIs Ika `approve_message` as the last side-effect — fail-closed by design (a single failing rule fails the whole signature).

## Rule kinds

| Kind | Const | Sub-PDA seeds | Purpose |
|---|---|---|---|
| Allowlist | `KIND_ALLOWLIST = 1` | `[b"rule_allowlist", engine, rule_index]` | Destination whitelist for normal-path signing. |
| Velocity | `KIND_VELOCITY = 2` | `[b"rule_velocity", engine, rule_index]` | Count-based rate limit across rolling windows. |
| TimeLock | `KIND_TIME_LOCK = 3` | `[b"rule_time_lock", engine, rule_index]` | Window restrictions (cron-style time gates). |
| Oracle | `KIND_ORACLE = 4` | `[b"rule_oracle", engine, rule_index]` | Price gating: reads the adapter's canonical `FeedCache` (see `contracts/pyth-adapter/`); enforces price band + freshness + confidence cap. |
| Passkey | `KIND_PASSKEY = 5` | `[b"rule_passkey", engine, rule_index]` | WebAuthn step-up assertion required for the tx. |
| FheGated | `KIND_FHE_GATED = 6` | `[b"rule_fhe_gated", engine, rule_index]` | Decision body signed by an FHE authority. |
| SessionKey | `KIND_SESSION_KEY = 7` | `[b"rule_session_key", engine, rule_index]` | Ephemeral keypair authorized for bounded signing. |
| Recovery | `KIND_RECOVERY = 8` | `[b"rule_recovery", engine, rule_index]` | Primary recovery + multi-member quorum. Includes OIDC primary (`scheme = 4`), WebAuthn primary, and Ed25519/Secp256k1/Secp256r1 quorum members. |
| SpendingUsd | `KIND_SPENDING_USD = 9` | `[b"rule_spending_usd", engine, rule_index]` | USD-denominated spending cap: per-tx / per-day / per-week ceilings, converted on-chain from the moved asset's `amount` via the Pyth `FeedCache` price (canonical 1e8). Up to 16 assets per rule; exactly one feed (the moved asset) is attached + verified per signature; day/week accumulators are mutated in the sub-PDA. |

Up to 16 active slots per dWallet. Each rule lives in its own sub-PDA; the engine indexes them through a flat 96-byte `RuleEntry` per slot (`rules_flat`).

## Instructions (discriminators)

Hot path + admin:

| Disc | Name | Notes |
|---|---|---|
| 0 | `init_engine` | Init authority signs the canonical init challenge over `sha256(init_authority_slot)` so the engine PDA cannot be front-run. |
| 1 | `request_signature` | Walks every active rule's sub-PDA in order. Caller MUST attach exactly one remaining account per active slot. Header drift + discriminator + ownership checks before per-kind dispatch. **ABI V2:** carries `amount: u64` + `asset_index: u8` (bound into the metadata digest under `andromeda::policy-engine::request::v2`) so a `KIND_SPENDING_USD` rule can be enforced end-to-end; both are 0 when no spending rule is active. **ABI V3 (Update 6):** also carries `ika_msg_metadata_digest: [u8; 32]` — opaque, forwarded verbatim to Ika `approve_message`; `0` (the default for every chain except Zcash) reproduces the prior behaviour. Independent of the Andromeda metadata digest. **Update 7 (2026-05-26) — ABI BREAKING:** 10 extra typed params: `signing_kind` (0=NORMAL / 1=SWAP) + 4 swap fields (`swap_{from_token,to_token,min_amount_out,chain_tag}`) selecting the V3 `swap_metadata_digest` + `swap_sign_message` renderer when `signing_kind = 1`; plus 5 bundle fields (`bundle_total`, `bundle_this_index`, three `bundle_other_digest_*`) selecting the op-tag-agnostic `bundle_use_challenge` when `bundle_total >= 2` so ONE owner signature unlocks N (≤ 4) legs (e.g. EVM 2-step approve+swap). Legacy callers pass zeros for every new field to reproduce the prior behaviour. |
| 60 / 61 | `pause` / `resume` | Engine-wide. While paused, ALL signing and session-open paths reject. |
| 80 | `recover_as_primary` | Ed25519/Secp256k1/Secp256r1 primary signs the canonical primary-recover challenge off-chain; precompile verifies; CPIs Ika after destination + daily-limit + cooldown enforcement. |

Add rule (one disc per kind, 10..18):

| Disc | Name |
|---|---|
| 10 | `add_rule_allowlist` |
| 11 | `add_rule_velocity` |
| 12 | `add_rule_time_lock` |
| 13 | `add_rule_oracle` |
| 14 | `add_rule_passkey` |
| 15 | `add_rule_fhe_gated` |
| 16 | `add_rule_session_key` |
| 17 | `add_rule_recovery` |
| 18 | `add_rule_spending_usd` — creates the rule with `feeds_count = 0` + the USD ceilings; assets are added via disc 19. |

OIDC session flow (Login Social):

| Disc | Name |
|---|---|
| 87 | `oidc_session_open` — verify JWT (RSA-2048 via `sol_big_mod_exp`), pin `jwk_registry`, open `OidcSession` PDA bound to an ephemeral Ed25519 key. |
| 81 | `recover_as_primary_oidc` — consume the open session for one Ika `approve_message`. |
| 88 | `oidc_session_close` |

Quorum session flow (M-of-N recovery):

| Disc | Name |
|---|---|
| 82 | `quorum_session_open` — primary authorizes a session bound to `(message, amount, destination, expiry)`. Snapshots the member roster + threshold so admin updates can't affect in-flight recoveries. |
| 83 | `quorum_session_contribute` — Ed25519/Secp256k1/Secp256r1 member signs the contribute challenge. |
| 84 | `quorum_session_contribute_webauthn` — WebAuthn (Secp256r1 assertion) variant. |
| 85 | `quorum_session_finalize` — permissionless once `count >= threshold`. Takes `rule_index` so multi-rule dWallets dispatch the right policy. |
| 86 | `quorum_session_close` |

Passkey session flow (WebAuthn primary):

| Disc | Name |
|---|---|
| 89 | `passkey_session_open` — WebAuthn assertion + ephemeral Ed25519. |
| 90 | `recover_as_primary_passkey_session` |
| 91 | `passkey_session_close` |

Session-key flow (bounded ephemeral signing — disc 100..106):

| Disc | Name |
|---|---|
| 100 | `session_open` — owner authorizes; bounds checked against the SessionKey rule's limits. |
| 101 | `request_signature_via_session` — session keypair signs natively (bypasses the normal dispatch loop). |
| 102 / 103 / 104 | `session_revoke` / `session_close` / `close_expired_session` |
| 105 / 106 | `session_add_destination` / `session_remove_destination` |

Incremental updates (list-style configs):

| Disc | Name |
|---|---|
| 120 / 121 | `update_rule_allowlist_add_destination` / `..._remove_destination` |
| 122 | `update_rule_oracle_add_feed` — append a `(feed_account, feed_owner, min, max)` feed to a `KIND_ORACLE` rule (feeds are added incrementally after `add_rule_oracle`). |
| 19 | `update_rule_spending_usd_add_feed` — append a `(feed_cache_account, decimals)` asset to a `KIND_SPENDING_USD` rule. The `feed_cache` account is passed in and its owner is checked against `ALLOWED_ORACLE_OWNERS` (defense-in-depth). |
| 126 | `update_rule_fhe_gated_update_authorities` |
| 130 / 131 | `update_rule_recovery_add_member` / `..._remove_member` |
| 132 / 133 | `update_rule_recovery_add_destination` / `..._remove_destination` |

## Update 7 (2026-05-26) — SWAP clear-signing + BUNDLE challenge

ABI BREAK on disc 1. Two follow-ups landed together in one handler extension:

* **SWAP signing kind (`signing_kind = 1`).** The dWallet owner reads a semantic `swap_sign_message` (`"Swap X of <from_token> for at least Y of <to_token> on <chain> for dWallet ..."`) instead of the generic `normal_sign_message`. Token addresses go as raw 32-byte hex (the program cannot verify symbols); the wallet UI rotula names em cima dos endereços bound. `chain_tag` is 8 bytes ASCII null-padded (`"solana\0\0"`, `"evm:1\0\0\0"`). Domain bump to `andromeda::policy-engine::request::v3` makes the SWAP metadata digest disjoint from V2 — a swap signing cannot be replayed as a NORMAL signature.

* **Bundle challenge (`bundle_total >= 2`).** ONE owner signature covers up to `MAX_BUNDLE_TOTAL = 4` distinct `request_signature` legs. The `bundle_use_challenge` is **op-tag-agnostic**: legs can mix `signing_kind`s (e.g. NORMAL approve + SWAP swap), each one's `metadata_digest` is reordered into its `this_index` of `bundle_total` slots, the concatenation is hashed, and every leg arrives at the SAME hash from its own viewpoint. The Andromeda gateway uses this for the EVM 2-step swap path (approve + swap in one signing prompt).

Cross-language layout is locked by fixtures under [`fixtures/policy_engine_v3/challenges/runtime/`](../../fixtures/policy_engine_v3/challenges/runtime/): `swap_sign_message.json`, `swap_metadata_digest.json`, `swap_use_challenge.json`, `bundle_use_challenge_2.json`. Both the Rust unit tests in this crate (`#[cfg(test)] mod update7_tests`) and the Go mirror (`gateway/internal/policy/update7_fixtures_test.go`) re-compute against the fixtures.

To regenerate fixtures after a wire-format change:

```bash
cd contracts/policy-engine
cargo test --features host-test --lib gen_update7_fixtures -- --ignored
```

CI runs without `--ignored`, so committed fixtures stay frozen between deliberate regenerations.

## Update 8 (2026-05-26) — sessions surfaced as REST (no on-chain change)

The session-key lifecycle (disc 100..106) already existed on-chain and was validated in earlier audits. Update 8 exposed the primitives as REST in the gateway (`/v1/policy/session/*`) so dApps can build their own delegation layer (AI trading agents, DCA, multi-tenant) without Andromeda custodying the session keypair. The session-signer is generated client-side and signs `request_signature_via_session` (disc 101) natively as a Solana `Signer`. **No code in this crate changed for Update 8.**

## Build & deploy

```bash
cd contracts/policy-engine

# Devnet (no sol_big_mod_exp): OIDC verify rejects with BadSignature.
cargo build-sbf --no-default-features

# Mainnet / any cluster where sol_big_mod_exp is active:
cargo build-sbf

# Deploy (program ID is fixed in declare_id! — same keypair across redeploys).
solana program deploy target/deploy/policy_engine.so \
  --program-id ../.deploy-keys/policy-engine.json \
  --url devnet
```

## Layout

Single `src/lib.rs` (Quasar requires `#[program] mod ...` and all `#[account]` derives in the same crate). Organized into clearly-marked sections:

```
src/lib.rs
├── Constants — KIND_*, MAX_RULES, scheme tags, TTLs, JWK_REGISTRY_PROGRAM_ID
├── Errors — PolicyEngineError (ABI §4)
├── Events — RuleAdded/Updated/Removed, SignatureRequested/Approved, etc.
├── State — PolicyEngine, RuleEntry helpers, AllowlistRule, VelocityRule, ...,
│           RecoveryRule, OidcSession, QuorumSession, PasskeySession, Session
├── Challenges — mirrored byte-for-byte against gateway (Go) + ika-backend (TS)
└── #[program] mod policy_engine { ... entrypoints ... }
```

`RuleEntry` is stored as `[u8; MAX_RULES * 96]` (`rules_flat`) inside `PolicyEngine` because Quasar zero-copy account derives don't currently accept arrays of nested custom structs. Encode/decode via `read_rule_entry` / `write_rule_entry`.

## Cross-references

- Auth primitives (precompiles, member slots, challenges, admin gate): `andromeda_auth` (`contracts/auth/`).
- OIDC JWT verifier (RSA-2048 / RS256 with `sol_big_mod_exp`): `andromeda_oidc_verifier` (`contracts/oidc-verifier/`).
- Ika `approve_message` CPI helper: `andromeda_policy_shared` (`contracts/shared/`).
- JWK trust root for Login Social (separate program; pinned per-`RecoveryRule`): `contracts/jwk-registry/`.
- Off-chain gateway client: `gateway/internal/policy/`.
- Off-chain ika-backend client: `ika-backend/src/clients/policyEngine/`.
- SBF integration suite (`policy-engine` v3, `jwk-registry`, passkey fixtures): `contracts/sbf-tests/`.

## Features

| Feature | Default | Effect |
|---|---|---|
| `oidc-rsa` | ON | Forwards to `andromeda_oidc_verifier/oidc-rsa`. With it OFF, `rsa2048_modexp` returns `BadSignature` explicitly, so every OIDC verify rejects — Login Social via OIDC is unavailable. Use `--no-default-features` for devnet pre-alpha until the cluster ships `sol_big_mod_exp`. |
| `mainnet` | OFF | Compile-time enforces non-empty `ALLOWED_*` allowlists (issuers, audiences, oracle owners, FHE authorities). Required on mainnet builds. |
| `host-test` | OFF | Forwards `host-test` to `andromeda_auth/host-test` so the host-side unit tests (Update 7 + fixture generator) can run a real `sha2`-backed `hashv`. **NEVER enable in `cargo build-sbf`** — would link `sha2` into the program. Use only with `cargo test --features host-test`. |
