# `policy-engine` — Andromeda PolicyEngine v3 (Quasar)

> **Status:** F0.5 skeleton — exists to compile and measure, not yet to ship. See `docs/F0_5_VIABILITY_REPORT.md`.

Unified Quasar program that holds the authority of any Andromeda dWallet and dispatches at signing time across 8 rule kinds (allowlist, velocity, time-lock, oracle, passkey step-up, fhe-gated, session-keys, recovery). Replaces the 8 legacy templates in `contracts/<template>/`.

- **Spec:** `docs/POLICY_ENGINE_ABI_V3.md` (ABI v3 frozen).
- **ADRs:** `docs/adr/PE-001..PE-010`.
- **Plan:** `POLICY_ENGINE_PLAN.md` (root).

## What's in F0.5 (this file)

| Item | Status |
|---|---|
| Cargo.toml with heavy imports (`andromeda_auth`, `andromeda_oidc_verifier`, `ika_dwallet_quasar`, `andromeda_policy_shared`) | wired |
| Quasar.toml | wired |
| `declare_id!` | **placeholder = System Program** (regenerate before build, see §Build) |
| `PolicyEngine` PDA header + `RuleEntry` helpers (read/write) | implemented |
| `init_engine` (PE-003 default_recovery opt-in) | implemented |
| `request_signature` (normal path, dispatch loop stubbed) | implemented (no per-rule validate yet) |
| `add_rule_allowlist` (F2 vertical slice exemplar) | implemented |
| `add_rule_recovery` (size stress-test — 1232 bytes config) | implemented (semantics in F9) |
| `pause` / `resume` | implemented |
| `recover_as_primary_oidc` | stub (forces `oidc_verifier` import; F9 implements) |
| All other instructions in ABI v3 | **not in F0.5** — F1+ |

## Build

```bash
cd contracts/policy-engine

# 1) Mandatory: regenerate the program keypair before first build.
solana-keygen grind --starts-with PE3:1
mv PE3<found>.json target/deploy/policy_engine-keypair.json
solana address -k target/deploy/policy_engine-keypair.json
# Replace declare_id! in src/lib.rs with the printed address.

# 2) Build (release).
cargo build-sbf --release
# or, for clusters without sol_big_mod_exp (devnet pre-alpha 2026-05):
cargo build-sbf --release --no-default-features

# 3) Measure (record in docs/F0_5_VIABILITY_REPORT.md).
stat -c "%s" target/deploy/policy_engine.so
```

## Layout

Single `src/lib.rs` (Quasar requires `#[program] mod ...` and all `#[account]` derives in the same crate). The file is organized into clearly-marked sections:

```
src/lib.rs
├── Constants (mirrors of ABI §1, §3.3)
├── Errors (PolicyEngineError — ABI §4)
├── Events (ABI §5)
├── State: PolicyEngine, RuleEntry (flat helpers), AllowlistRule, RecoveryRule
├── Challenges (init, admin, request_metadata — ABI §6)
└── #[program] mod policy_engine { ... entrypoints ... }
```

`RuleEntry` is stored as `[u8; MAX_RULES * 96]` (`rules_flat`) inside `PolicyEngine` because Quasar zero-copy account derives don't currently accept arrays of nested custom structs. Encode/decode via `read_rule_entry` / `write_rule_entry`.

## Not in this crate (yet)

- The remaining 6 rule kinds (Velocity, TimeLock, Oracle, Passkey, FheGated, SessionKey) — each lands in its own F3-F8 phase.
- Recovery instructions other than the stub (`recover_as_primary`, `quorum_session_*`, `oidc_jwt_staging_*`, `passkey_session_*`) — F9.
- `request_signature_via_session` — F8.
- Cross-language fixtures with real preimages — `fixtures/policy_engine_v3/` is placeholder-only until F2.

## Cross-references

- Authority CPI helper: `andromeda_policy_shared::invoke_ika_approve_message` (`contracts/shared/`).
- Precompile + member slot primitives: `andromeda_auth` (`contracts/auth/`).
- OIDC JWT verifier: `andromeda_oidc_verifier` (`contracts/oidc-verifier/`).
- JWK trust root: separate program `contracts/jwk-registry/` (read-only mirror, not a dependency).
- Off-chain gateway client: `gateway/internal/policy/` (to be created — replaces `gateway/internal/policies/`).
- Off-chain ika-backend client: `ika-backend/src/clients/policyEngine/` (to be created — replaces `clients/rulesPolicy/`).
