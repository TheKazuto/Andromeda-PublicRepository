//! Andromeda PolicyEngine v3 — unified policy program for Ika dWallets.
//!
//! This crate consolidates the 8 legacy templates (allowlist-destinations,
//! velocity-guard, time-lock, oracle-conditional, passkey-step-up, fhe-gated,
//! session-keys, rules-policy) into a single Quasar `#[program]` that holds
//! the authority of any Andromeda dWallet and dispatches at signing time.
//!
//! Spec: `docs/POLICY_ENGINE_ABI_V3.md`. ADRs: `docs/adr/PE-001..PE-010`.
//!
//! ## F0.5 status (2026-05-15)
//!
//! This file is the F0.5 viability spike. It is **deliberately incomplete**:
//!
//! - `init_engine`, `request_signature`, `pause`, `resume`, `revoke`,
//!   `add_rule_allowlist`, `add_rule_recovery`, `remove_rule`,
//!   `update_rule_allowlist`, `recover_as_primary_oidc`, and
//!   `quorum_session_contribute_webauthn` are wired through enough to force
//!   the linker to keep every heavy import (`andromeda_auth`,
//!   `andromeda_oidc_verifier`, `ika_dwallet_quasar`, `andromeda_policy_shared`).
//! - The remaining `add_rule_*`, `update_rule_*`, recovery and session
//!   instructions are declared with the canonical signature but their bodies
//!   are minimal stubs returning `Ok(())` or `PolicyEngineError::GenericError`.
//! - The dispatch loop in `request_signature` validates the header of each
//!   active sub-PDA but does NOT yet enforce per-kind policy logic — that is
//!   the work of F2–F8.
//!
//! The goal of F0.5 is to measure:
//!   1. SBF binary size after `cargo build-sbf --release`.
//!   2. CU consumption of `request_signature` worst-case (16 sub-PDAs).
//!   3. Transaction size for `add_rule_recovery` (1232-byte config).
//!   4. That `__ika_cpi_authority` derivation in `andromeda_policy_shared`
//!      remains usable from this crate.
//!
//! See `docs/F0_5_VIABILITY_REPORT.md` for the measurement template.

#![no_std]
#![allow(dead_code)]

use andromeda_auth::admin::verify_owner_admin;
use andromeda_auth::challenge::{
    oidc_primary_use_challenge, oidc_session_open_challenge, passkey_primary_use_challenge,
    passkey_session_open_challenge, primary_recover_challenge, quorum_contribute_challenge,
    quorum_session_open_challenge,
};
use andromeda_auth::hash::hashv;
use andromeda_auth::human_message::{self, HumanMessageError, MAX_HUMAN_MESSAGE_BYTES};
use andromeda_auth::precompile::{check_sysvar_address, ED25519_PRECOMPILE_ID};
use andromeda_auth::{
    validate_oidc_slot, validate_slot, verify_signature, AuthError, VerifyInput, MEMBER_SLOT_LEN,
    SCHEME_ED25519, SCHEME_OIDC_JWT, SCHEME_SECP256K1, SCHEME_SECP256R1, SCHEME_WEBAUTHN,
};
use andromeda_oidc_verifier as oidc_verifier;
use andromeda_policy_shared::{invoke_ika_approve_message, validate_ika_cpi_accounts};
use quasar_lang::prelude::*;
use solana_address::Address;

// ─── Program ID ──────────────────────────────────────────────────────────────
//
// F0.5 keypair (grinded 2026-05-15, vanity prefix `PE3`). The matching keypair
// lives at `target/deploy/policy_engine-keypair.json`. Regenerate with
// `solana-keygen grind --starts-with PE3:1` if a new deploy keypair is needed.
declare_id!("ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL");

// ── Constants (mirrors of docs/POLICY_ENGINE_ABI_V3.md §1, §3) ──────────────

pub const ENGINE_LAYOUT_V1: u8 = 1;
pub const RULE_HEADER_V1: u8 = 1;
pub const MAX_RULES: usize = 16;
pub const MIN_COOLDOWN_SECONDS: u64 = 3_600;
pub const MAX_COOLDOWN_SECONDS: u64 = 365 * 24 * 3_600;
pub const MAX_SESSION_TTL_SECONDS: i64 = 7 * 24 * 3_600;

// RuleKind tag (mirror of ABI §3.3).
pub const KIND_EMPTY: u8 = 0;
pub const KIND_ALLOWLIST: u8 = 1;
pub const KIND_VELOCITY: u8 = 2;
pub const KIND_TIME_LOCK: u8 = 3;
pub const KIND_ORACLE: u8 = 4;
pub const KIND_PASSKEY: u8 = 5;
pub const KIND_FHE_GATED: u8 = 6;
pub const KIND_SESSION_KEY: u8 = 7;
pub const KIND_RECOVERY: u8 = 8;
// Update 3: USD spending limit (tag 9).
pub const KIND_SPENDING_USD: u8 = 9;

// RuleAppliesTo (mirror of ABI §3.5, ADR PE-006).
pub const APPLIES_NORMAL: u8 = 1;
pub const APPLIES_RECOVERY: u8 = 2;
pub const APPLIES_SESSION: u8 = 4;
pub const APPLIES_ALL: u8 = APPLIES_NORMAL | APPLIES_RECOVERY | APPLIES_SESSION;

// Signing paths.
pub const PATH_NORMAL: u8 = APPLIES_NORMAL;
pub const PATH_RECOVERY: u8 = APPLIES_RECOVERY;
pub const PATH_SESSION: u8 = APPLIES_SESSION;

// Config sizes (bytes — mirror of ABI §3.5).
pub const ALLOWLIST_CONFIG_BYTES: usize = 1032;
pub const VELOCITY_CONFIG_BYTES: usize = 200;
pub const TIME_LOCK_CONFIG_BYTES: usize = 32;
pub const ORACLE_CONFIG_BYTES: usize = 328;
pub const PASSKEY_CONFIG_BYTES: usize = 520;
pub const FHE_GATED_CONFIG_BYTES: usize = 136;
pub const SESSION_KEY_CONFIG_BYTES: usize = 608;
pub const RECOVERY_CONFIG_BYTES: usize = 1232;
// Update 3: config payload of `KIND_SPENDING_USD` (8 hdr + 24 caps + 32 accum
// + 16×33 feeds = 592 bytes). See `SpendingUsdRule`.
pub const SPENDING_USD_CONFIG_BYTES: usize = 592;

pub const RULE_HEADER_BYTES: usize = 96;

// PDA seed prefixes (mirror of ABI §2).
pub const SEED_ENGINE: &[u8] = b"policy_engine";
pub const SEED_RULE_ALLOWLIST: &[u8] = b"rule_allowlist";
pub const SEED_RULE_VELOCITY: &[u8] = b"rule_velocity";
pub const SEED_RULE_TIME_LOCK: &[u8] = b"rule_time_lock";
pub const SEED_RULE_ORACLE: &[u8] = b"rule_oracle";
pub const SEED_RULE_PASSKEY: &[u8] = b"rule_passkey";
pub const SEED_RULE_FHE_GATED: &[u8] = b"rule_fhe_gated";
pub const SEED_RULE_SESSION_KEY: &[u8] = b"rule_session_key";
pub const SEED_RULE_RECOVERY: &[u8] = b"rule_recovery";
pub const SEED_RULE_SPENDING_USD: &[u8] = b"rule_spending_usd";

// Challenge domains (mirror of ABI §6.1).
pub const DOMAIN_INIT_V1: &[u8] = b"andromeda::policy-engine::init::v1";
pub const DOMAIN_V3: &[u8] = b"andromeda::policy-engine::v3";
pub const DOMAIN_REQUEST_V1: &[u8] = b"andromeda::policy-engine::request::v1";
// Update 3: V2 binds `amount` + `asset_index` into the request metadata digest
// so a USD spending limit (KIND_SPENDING_USD) can be enforced end-to-end.
pub const DOMAIN_REQUEST_V2: &[u8] = b"andromeda::policy-engine::request::v2";
pub const DOMAIN_RECOVERY_V3: &[u8] = b"andromeda::policy-engine::recovery::v3";

// Op tags (mirror of ABI §6.3).
pub const OP_INIT: &[u8] = b"init";
pub const OP_INIT_WITH_RECOVERY: &[u8] = b"init-with-recovery";
// Fase 1 (A1, 2026-05-25): op tag for the NORMAL signing-path owner
// authorization (disc 1). The owner_slot signs this so the gateway cannot
// relay a signature without the dWallet owner's consent.
pub const OP_NORMAL_SIGN: &[u8] = b"normal-sign";
pub const OP_ADD_ALLOWLIST: &[u8] = b"add-rule-allowlist";
pub const OP_ALLOWLIST_ADD_DEST: &[u8] = b"allowlist-add-destination";
pub const OP_ALLOWLIST_REMOVE_DEST: &[u8] = b"allowlist-remove-destination";
pub const OP_ADD_VELOCITY: &[u8] = b"add-rule-velocity";
pub const OP_ADD_TIME_LOCK: &[u8] = b"add-rule-time-lock";
pub const OP_ADD_ORACLE: &[u8] = b"add-rule-oracle";
pub const OP_ADD_PASSKEY: &[u8] = b"add-rule-passkey";
pub const OP_ADD_FHE_GATED: &[u8] = b"add-rule-fhe-gated";
pub const OP_ADD_SESSION_KEY: &[u8] = b"add-rule-session-key";
pub const OP_ADD_RECOVERY: &[u8] = b"add-rule-recovery";
pub const OP_ADD_SPENDING_USD: &[u8] = b"add-rule-spending-usd";
pub const OP_UPDATE_ALLOWLIST: &[u8] = b"update-rule-allowlist";
pub const OP_ORACLE_ADD_FEED: &[u8] = b"oracle-add-feed";
pub const OP_SPENDING_USD_ADD_FEED: &[u8] = b"spending-usd-add-feed";
pub const OP_UPDATE_FHE_AUTH: &[u8] = b"update-rule-fhe-authorities";
// B1 audit fix (2026-05-25): `remove-rule` op tag is now used by `remove_rule`
// (disc 110). The `revoke` and `update-rule-recovery` op tags were removed —
// no handler ever implemented them (dead code).
pub const OP_REMOVE_RULE: &[u8] = b"remove-rule";
pub const OP_PAUSE: &[u8] = b"pause";
pub const OP_RESUME: &[u8] = b"resume";
pub const OP_PRIMARY_RECOVER: &[u8] = b"primary-recover";
pub const OP_OIDC_PRIMARY_USE: &[u8] = b"oidc-primary-use";
pub const OP_RECOVERY_ADD_MEMBER: &[u8] = b"recovery-add-member";
pub const OP_RECOVERY_REMOVE_MEMBER: &[u8] = b"recovery-remove-member";
pub const OP_RECOVERY_ADD_DEST: &[u8] = b"recovery-add-destination";
pub const OP_RECOVERY_REMOVE_DEST: &[u8] = b"recovery-remove-destination";

// F9b: quorum session ops (challenge mirrors `andromeda_auth::challenge`).
pub const OP_QUORUM_SESSION_OPEN: &[u8] = b"quorum-session-open";
pub const OP_QUORUM_CONTRIBUTE: &[u8] = b"quorum-contribute";

pub const SEED_QUORUM_SESSION: &[u8] = b"quorum_session";

// F9d: passkey session ops (challenges via `andromeda_auth::challenge`).
pub const SEED_PASSKEY_SESSION: &[u8] = b"passkey_session";

// C1: OIDC session ops (challenges via `andromeda_auth::challenge`).
pub const SEED_OIDC_SESSION: &[u8] = b"oidc_session";

pub const MAX_RECOVERY_MEMBERS: usize = 16;
pub const MAX_RECOVERY_DESTINATIONS: usize = 16;

// `static` so the buffers live in .rodata (not on the SBF stack — which is
// only 4096 bytes per frame). Used only by `hashv` calls that need a
// canonical zero-pad input for the recovery config_hash; never copied into
// local frames.
static ZERO_RECOVERY_MEMBERS: [u8; MAX_RECOVERY_MEMBERS * MEMBER_SLOT_LEN] =
    [0u8; MAX_RECOVERY_MEMBERS * MEMBER_SLOT_LEN];
static ZERO_RECOVERY_DESTINATIONS: [u8; MAX_RECOVERY_DESTINATIONS * 32] =
    [0u8; MAX_RECOVERY_DESTINATIONS * 32];

pub const OP_SESSION_OPEN: &[u8] = b"session-open";
pub const OP_SESSION_REVOKE: &[u8] = b"session-revoke";
pub const OP_SESSION_CLOSE: &[u8] = b"session-close";
pub const OP_SESSION_ADD_DEST: &[u8] = b"session-add-destination";
pub const OP_SESSION_REMOVE_DEST: &[u8] = b"session-remove-destination";

// PDA seed prefix for ephemeral Session accounts (F8b).
pub const SEED_SESSION: &[u8] = b"session";

// ── Errors (mirror of ABI §4) ────────────────────────────────────────────────

#[error_code]
pub enum PolicyEngineError {
    GenericError = 6000,
    EnginePaused,
    AccountAlreadyInitialized,
    AccountNotInitialized,
    TooManyRules,
    RuleAlreadyActive,
    RuleSlotInUse,
    RuleNotFound,
    InvalidRuleVersion,
    InvalidRuleKind,
    InvalidRuleHeader,
    RuleNotApplicable,
    RuleDisabled,

    InvalidNonce = 6020,
    InvalidOwnerSlot,
    InvalidInitAuthoritySlot,
    UnsupportedScheme,
    AuthFailed,
    ClearSigningRenderFailed,

    AllowlistDestinationNotAllowed = 6030,
    VelocityCapExceeded,
    TimeLocked,
    OracleStale,
    OracleOutOfBand,
    OracleOwnerMismatch,
    PasskeyStepUpRequired,
    PasskeyStepUpInvalid,
    FheDecisionMissing,
    FheDecisionInvalid,
    SessionExpired,
    SessionCapExceeded,
    SessionDestinationNotAllowed,
    SessionNotFound,
    OracleConfidenceExceeded,

    RecoveryQuorumNotReached = 6050,
    RecoveryMemberNotInQuorum,
    RecoveryDailyLimitExceeded,
    RecoveryCooldownActive,
    RecoveryDestinationNotAllowed,
    PendingChangeMismatch,
    PendingChangeNotReady,

    OidcSessionExpired = 6060,
    OidcJwtInvalid,
    OidcJwkNotFound,
    OidcAudienceMismatch,
    OidcIssuerMismatch,
    PasskeyAssertionInvalid,
    PasskeySessionExpired,
    /// C1: `oidc_session_open` could not match `(iss, aud, kid)` from the JWT
    /// against any ACTIVE entry of the supplied JWK registry.
    OidcJwkInactive,
    /// C1: `recover_as_primary_oidc` — the verifier version pinned at open
    /// time does not equal the current `OIDC_VERIFIER_V1`. Block downgrade
    /// attacks across verifier upgrades.
    OidcVerifierMismatch,
    /// C1: `recover_as_primary_oidc` — `parsed.addr_seed` did not match
    /// `rule_pda.primary_slot[1..33]` (a different OIDC identity is trying
    /// to recover this dWallet).
    OidcAddrSeedMismatch,

    IkaCpiAccountMismatch = 6070,
    IkaCpiFailed,

    DelegationNotConfirmed = 6080,

    // Update 3: USD spending limit (KIND_SPENDING_USD dispatch + admin).
    /// The single-tx USD value exceeds the rule's `max_per_tx_usd`.
    SpendingPerTxExceeded = 6090,
    /// The accumulated daily USD spend would exceed `max_per_day_usd`.
    SpendingDailyExceeded,
    /// The accumulated weekly USD spend would exceed `max_per_week_usd`.
    SpendingWeeklyExceeded,
    /// The attached price feed is older than the rule's freshness window.
    SpendingPriceStale,
    /// The price feed confidence exceeds the rule's `max_confidence_bps`.
    SpendingConfidenceExceeded,
    /// `asset_index` is out of range, or the asset is not in the allowlist.
    SpendingAssetNotAllowed,
    /// amount→USD conversion overflowed u64, or the price was non-positive.
    SpendingConversionOverflow,

    /// A2 audit fix (2026-05-25): a rule sub-PDA that the dispatch must mutate
    /// in place (Velocity / Spending USD runtime counters) was not passed as
    /// writable. We reject explicitly instead of relying on the SVM runtime to
    /// fault on the raw write through `data_ptr()`.
    RuleAccountNotWritable,

    /// Review fix (2026-05-25): the per-tx `amount` of a session signature
    /// exceeded the session's `max_amount_per_tx` cap (set by the owner at
    /// `session_open`). Added at the enum tail to avoid shifting existing codes.
    SessionAmountExceeded,
}

impl From<AuthError> for PolicyEngineError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::InvalidNonce => PolicyEngineError::InvalidNonce,
            AuthError::UnsupportedScheme => PolicyEngineError::UnsupportedScheme,
            _ => PolicyEngineError::AuthFailed,
        }
    }
}

impl From<HumanMessageError> for PolicyEngineError {
    fn from(_e: HumanMessageError) -> Self {
        PolicyEngineError::ClearSigningRenderFailed
    }
}

// ── Events (mirror of ABI §5 — subset for F0.5) ─────────────────────────────

#[event(discriminator = 0)]
pub struct EngineInitialized {
    pub engine: Address,
    pub dwallet: Address,
    pub ts: i64,
}

#[event(discriminator = 1)]
pub struct EngineDelegationConfirmed {
    pub engine: Address,
    pub dwallet: Address,
    pub ts: i64,
}

#[event(discriminator = 2)]
pub struct EnginePaused {
    pub engine: Address,
    pub ts: i64,
}

#[event(discriminator = 3)]
pub struct EngineResumed {
    pub engine: Address,
    pub ts: i64,
}

// B1 audit fix (2026-05-25): the `EngineRevoked` event (disc 4) was removed —
// no handler ever emitted it (there is no engine-revoke instruction; `pause`
// covers the kill-switch need). Discriminator 4 is retired, not reused.

// Fields are promoted to u64 to keep the struct padding-free for Quasar's
// memcpy event serialization (same pattern as `SignatureRejected` in
// `contracts/shared/src/events.rs`).
#[event(discriminator = 10)]
pub struct RuleAdded {
    pub engine: Address,
    pub ts: i64,
    pub kind: u64,
    pub rule_index: u64,
    pub generation: u64,
}

#[event(discriminator = 11)]
pub struct RuleUpdated {
    pub engine: Address,
    pub ts: i64,
    pub kind: u64,
    pub rule_index: u64,
    pub generation: u64,
}

#[event(discriminator = 12)]
pub struct RuleRemoved {
    pub engine: Address,
    pub ts: i64,
    pub kind: u64,
    pub rule_index: u64,
    pub generation: u64,
}

// L2 audit convention (2026-05-16): events SHOULD be emitted *after* every
// validation has passed and *before* any state mutation. Today several
// handlers (e.g. `request_signature`, `recover_as_primary_oidc`,
// `quorum_session_finalize`) emit `SignatureRequested` near the top of the
// handler; this is intentional so off-chain consumers see "request seen"
// even for rejected attempts (debugging / metrics). Future handlers must NOT
// emit success-implying events (`SignatureApproved`, `RuleAdded`, etc.)
// before the corresponding state transition succeeds.
#[event(discriminator = 20)]
pub struct SignatureRequested {
    pub engine: Address,
    pub request_hash: Address,
    pub ts: i64,
}

#[event(discriminator = 21)]
pub struct SignatureApproved {
    pub engine: Address,
    pub request_hash: Address,
    pub ts: i64,
}

#[event(discriminator = 30)]
pub struct PrimaryRecoverInvoked {
    pub engine: Address,
    pub request_hash: Address,
    pub ts: i64,
}

#[event(discriminator = 40)]
pub struct SessionOpened {
    pub engine: Address,
    pub session_index: u64,
    pub expires_at_ts: i64,
    pub ts: i64,
}

#[event(discriminator = 41)]
pub struct SessionRevoked {
    pub engine: Address,
    pub session_index: u64,
    pub ts: i64,
}

#[event(discriminator = 42)]
pub struct SessionClosed {
    pub engine: Address,
    pub session_index: u64,
    pub ts: i64,
}

// ── State: PolicyEngine header (ABI §3.1) ───────────────────────────────────
//
// Account discriminator = 1. Total = 1698 bytes (to confirm in F0.5 build).
//
// IMPORTANT: every byte offset below is mirrored in `docs/POLICY_ENGINE_ABI_V3.md`
// §3.1. Any change here MUST be mirrored in the same commit, and updated in the
// cross-language fixtures (`fixtures/policy_engine_v3/state/`).

/// `RuleEntry` byte length (mirror of ABI §3.2). Kept as a flat byte array
/// inside `PolicyEngine` to stay compatible with Quasar zero-copy account
/// derives (which currently accept `[u8; N]` but not arrays of nested
/// non-`Pod` structs). Helpers below decode/encode entries by offset.
pub const RULE_ENTRY_BYTES: usize = 96;
pub const RULES_FLAT_BYTES: usize = MAX_RULES * RULE_ENTRY_BYTES; // 1536

#[account(discriminator = 1, set_inner)]
#[seeds(b"policy_engine", dwallet: Address, init_authority_hash: Address)]
pub struct PolicyEngine {
    pub version: u8,
    pub dwallet: Address,
    pub init_authority_slot: [u8; MEMBER_SLOT_LEN],
    pub owner_slot: [u8; MEMBER_SLOT_LEN],
    pub next_admin_nonce: u64,
    pub next_primary_recover_nonce: u64,
    pub next_quorum_session_nonce: u64,
    pub next_oidc_session_nonce: u64,
    pub next_passkey_session_nonce: u64,
    pub paused: u8,
    pub rules_count: u8,
    pub rules_generation: u32,
    pub _pad_head: [u8; 6],
    pub rules_flat: [u8; RULES_FLAT_BYTES],
    pub _pad_tail: [u8; 8],
}

/// Logical view of a single entry in `PolicyEngine.rules_flat`.
///
/// Layout (96 bytes, mirror of ABI §3.2):
/// ```text
/// 0      1   kind
/// 1      1   bump
/// 2      1   version
/// 3      1   enabled
/// 4      4   generation       u32 LE
/// 8      32  rule_pda
/// 40     32  config_hash
/// 72     24  _pad
/// ```
#[derive(Copy, Clone)]
pub struct RuleEntry {
    pub kind: u8,
    pub bump: u8,
    pub version: u8,
    pub enabled: u8,
    pub generation: u32,
    pub rule_pda: Address,
    pub config_hash: [u8; 32],
}

impl RuleEntry {
    pub const EMPTY: Self = Self {
        kind: KIND_EMPTY,
        bump: 0,
        version: 0,
        enabled: 0,
        generation: 0,
        rule_pda: Address::new_from_array([0u8; 32]),
        config_hash: [0u8; 32],
    };

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.kind == KIND_EMPTY
    }
}

#[inline]
pub fn read_rule_entry(rules_flat: &[u8; RULES_FLAT_BYTES], slot: usize) -> RuleEntry {
    debug_assert!(slot < MAX_RULES);
    let off = slot * RULE_ENTRY_BYTES;
    let mut gen_b = [0u8; 4];
    gen_b.copy_from_slice(&rules_flat[off + 4..off + 8]);
    let mut pda_b = [0u8; 32];
    pda_b.copy_from_slice(&rules_flat[off + 8..off + 40]);
    let mut hash_b = [0u8; 32];
    hash_b.copy_from_slice(&rules_flat[off + 40..off + 72]);
    RuleEntry {
        kind: rules_flat[off],
        bump: rules_flat[off + 1],
        version: rules_flat[off + 2],
        enabled: rules_flat[off + 3],
        generation: u32::from_le_bytes(gen_b),
        rule_pda: Address::from(pda_b),
        config_hash: hash_b,
    }
}

#[inline]
pub fn write_rule_entry(rules_flat: &mut [u8; RULES_FLAT_BYTES], slot: usize, entry: &RuleEntry) {
    debug_assert!(slot < MAX_RULES);
    let off = slot * RULE_ENTRY_BYTES;
    rules_flat[off] = entry.kind;
    rules_flat[off + 1] = entry.bump;
    rules_flat[off + 2] = entry.version;
    rules_flat[off + 3] = entry.enabled;
    rules_flat[off + 4..off + 8].copy_from_slice(&entry.generation.to_le_bytes());
    rules_flat[off + 8..off + 40].copy_from_slice(entry.rule_pda.as_array().as_slice());
    rules_flat[off + 40..off + 72].copy_from_slice(&entry.config_hash);
    // Tail padding (24 bytes) intentionally left untouched on overwrite to
    // surface zeroed-out drift via the on-chain header check.
    for b in rules_flat[off + 72..off + RULE_ENTRY_BYTES].iter_mut() {
        *b = 0;
    }
}

#[inline]
pub fn init_authority_hash_from_slot(slot: &[u8; MEMBER_SLOT_LEN]) -> Address {
    Address::from(hashv(&[slot]))
}

// ── State: RuleHeader (ABI §3.4) ─────────────────────────────────────────────
//
// First 96 bytes of every rule sub-PDA. Account discriminator = 2.
// Each `<Kind>Rule` account below extends this with its config payload.

#[account(discriminator = 2, set_inner)]
#[seeds(b"rule_allowlist", engine: Address, rule_index: u8)]
pub struct AllowlistRule {
    pub kind: u8,
    pub index: u8,
    pub enabled: u8,
    pub _pad0: u8,
    pub generation: u32,
    pub config_version: u32,
    pub _pad1: [u8; 4],
    pub engine: Address,
    pub next_admin_nonce: u64,
    pub config_hash: [u8; 32],
    pub _pad_header_tail: [u8; 8],
    // ─── config payload (ABI §3.5.1) ──
    pub config_applies_to: u8,
    pub destinations_count: u8,
    pub _pad_cfg0: [u8; 6],
    pub destinations_flat: [u8; 32 * 32], // 1024 bytes — 32 destinations × 32
}

// ─── VelocityRule (ABI §3.5.2 — count-based rate limit, F3) ───────────────
//
// F3 scope: count-based rate limit (cap = N requests per window). Each window
// tracks `current_count` and `window_start_ts`. Sum-based limits (cap by
// lamports per window) live in `_reserved_sum` and ship in F3b once
// request_signature gains an `amount` field.
#[account(discriminator = 2, set_inner)]
#[seeds(b"rule_velocity", engine: Address, rule_index: u8)]
pub struct VelocityRule {
    pub kind: u8,
    pub index: u8,
    pub enabled: u8,
    pub _pad0: u8,
    pub generation: u32,
    pub config_version: u32,
    pub _pad1: [u8; 4],
    pub engine: Address,
    pub next_admin_nonce: u64,
    pub config_hash: [u8; 32],
    pub _pad_header_tail: [u8; 8],
    // ─── config payload (ABI §3.5.2) ──
    pub config_applies_to: u8,
    pub windows_count: u8,
    pub _pad_cfg0: [u8; 6],
    // 4 × VelocityWindow (48 bytes each):
    //   0   8   window_seconds u64
    //   8   8   cap u64
    //   16  8   current_count u64 (mutable)
    //   24  8   _reserved_sum u64 (F3b — sum-based limits)
    //   32  8   window_start_ts i64 (mutable)
    //   40  8   _pad
    pub windows_flat: [u8; 4 * 48],
}

pub const VELOCITY_WINDOW_BYTES: usize = 48;
pub const MAX_VELOCITY_WINDOWS: usize = 4;

// ─── TimeLockRule (ABI §3.5.3, F4) ─────────────────────────────────────────
//
// mode = 0 → absolute unlock at `unlock_ts`
// mode = 1 → delay window: unlocked when current_ts >= created_at_ts + delay_seconds
#[account(discriminator = 2, set_inner)]
#[seeds(b"rule_time_lock", engine: Address, rule_index: u8)]
pub struct TimeLockRule {
    pub kind: u8,
    pub index: u8,
    pub enabled: u8,
    pub _pad0: u8,
    pub generation: u32,
    pub config_version: u32,
    pub _pad1: [u8; 4],
    pub engine: Address,
    pub next_admin_nonce: u64,
    pub config_hash: [u8; 32],
    pub _pad_header_tail: [u8; 8],
    // ─── config payload (ABI §3.5.3, 32 bytes) ──
    pub config_applies_to: u8,
    pub mode: u8, // 0 = absolute unlock_ts, 1 = delay_seconds
    pub _pad_cfg0: [u8; 6],
    pub unlock_ts: i64,
    pub delay_seconds: u64,
    pub created_at_ts: i64,
}

pub const TIME_LOCK_MODE_ABSOLUTE: u8 = 0;
pub const TIME_LOCK_MODE_DELAY: u8 = 1;

// ─── OracleRule (ABI §3.5.4, F5 — storage-only) ────────────────────────────
#[account(discriminator = 2, set_inner)]
#[seeds(b"rule_oracle", engine: Address, rule_index: u8)]
pub struct OracleRule {
    pub kind: u8,
    pub index: u8,
    pub enabled: u8,
    pub _pad0: u8,
    pub generation: u32,
    pub config_version: u32,
    pub _pad1: [u8; 4],
    pub engine: Address,
    pub next_admin_nonce: u64,
    pub config_hash: [u8; 32],
    pub _pad_header_tail: [u8; 8],
    // ─── config payload (ABI §3.5.4, 328 bytes) ──
    pub config_applies_to: u8,
    pub feeds_count: u8,
    pub freshness_seconds_div16: u8,
    pub min_confidence_bps_div4: u8,
    pub _pad_cfg0: [u8; 4],
    // 4 × OracleFeed (80 bytes each: feed_account 32 + feed_owner 32 + min_q64 i64 + max_q64 i64)
    pub feeds_flat: [u8; 4 * 80],
}

pub const ORACLE_FEED_BYTES: usize = 80;
pub const MAX_ORACLE_FEEDS: usize = 4;

// ─── PasskeyRule (ABI §3.5.5, F6 — storage-only) ───────────────────────────
#[account(discriminator = 2, set_inner)]
#[seeds(b"rule_passkey", engine: Address, rule_index: u8)]
pub struct PasskeyRule {
    pub kind: u8,
    pub index: u8,
    pub enabled: u8,
    pub _pad0: u8,
    pub generation: u32,
    pub config_version: u32,
    pub _pad1: [u8; 4],
    pub engine: Address,
    pub next_admin_nonce: u64,
    pub config_hash: [u8; 32],
    pub _pad_header_tail: [u8; 8],
    // ─── config payload (ABI §3.5.5, 520 bytes) ──
    pub config_applies_to: u8,
    pub credentials_count: u8,
    pub _pad_cfg0: [u8; 6],
    // 4 × PasskeyCredential (128 bytes each: pubkey 33 + _pad 31 + rp_id_hash 32 + credential_id_hash 32)
    pub credentials_flat: [u8; 4 * 128],
}

pub const PASSKEY_CREDENTIAL_BYTES: usize = 128;
pub const MAX_PASSKEY_CREDENTIALS: usize = 4;

// ─── FheGatedRule (ABI §3.5.6, F7 — storage-only) ──────────────────────────
#[account(discriminator = 2, set_inner)]
#[seeds(b"rule_fhe_gated", engine: Address, rule_index: u8)]
pub struct FheGatedRule {
    pub kind: u8,
    pub index: u8,
    pub enabled: u8,
    pub _pad0: u8,
    pub generation: u32,
    pub config_version: u32,
    pub _pad1: [u8; 4],
    pub engine: Address,
    pub next_admin_nonce: u64,
    pub config_hash: [u8; 32],
    pub _pad_header_tail: [u8; 8],
    // ─── config payload (ABI §3.5.6, 136 bytes) ──
    pub config_applies_to: u8,
    pub authorities_count: u8,
    pub freshness_seconds_div16: u8,
    pub _pad_cfg0: [u8; 5],
    // 4 × FHE authority Address (32 bytes each)
    pub authorities_flat: [u8; 4 * 32],
}

pub const MAX_FHE_AUTHORITIES: usize = 4;

// ─── SpendingUsdRule (Update 3 — KIND_SPENDING_USD, tag 9) ─────────────────
//
// USD-denominated spending cap: per-tx / per-day / per-week ceilings enforced
// on-chain by converting `amount` (asset base units) → USD via the Pyth
// adapter `FeedCache` price (canonical 1e8). Up to 16 assets per rule; exactly
// ONE feed (the moved asset) is attached + verified per signature, so the CU
// cost is constant regardless of allowlist size. Day/week accumulators live in
// the sub-PDA and are mutated at dispatch (same data_mut_ptr pattern as
// `KIND_VELOCITY`). Account-relative offsets (1-based after the disc byte):
//   sub_data[97]        config_applies_to       u8
//   sub_data[98]        feeds_count             u8   (0..=16)
//   sub_data[99]        freshness_seconds_div16 u8
//   sub_data[100]       max_confidence_bps_div4 u8   (0 disables)
//   sub_data[101..105]  _pad_cfg0               [u8;4]
//   sub_data[105..113]  max_per_tx_usd          u64 LE   (0 = window off)
//   sub_data[113..121]  max_per_day_usd         u64 LE
//   sub_data[121..129]  max_per_week_usd        u64 LE
//   sub_data[129..137]  current_day_unix        i64 LE   (floor(ts/86400)*86400)
//   sub_data[137..145]  current_day_sum_usd     u64 LE
//   sub_data[145..153]  current_week_unix       i64 LE   (floor(ts/604800)*604800)
//   sub_data[153..161]  current_week_sum_usd    u64 LE
//   sub_data[161..689]  feeds_flat              [u8; 16*33]
//     each SpendingUsdFeed (33 B): [..32] feed_cache_account, [32] decimals
#[account(discriminator = 2, set_inner)]
#[seeds(b"rule_spending_usd", engine: Address, rule_index: u8)]
pub struct SpendingUsdRule {
    pub kind: u8,
    pub index: u8,
    pub enabled: u8,
    pub _pad0: u8,
    pub generation: u32,
    pub config_version: u32,
    pub _pad1: [u8; 4],
    pub engine: Address,
    pub next_admin_nonce: u64,
    pub config_hash: [u8; 32],
    pub _pad_header_tail: [u8; 8],
    // ─── config payload (592 bytes) ──
    pub config_applies_to: u8,
    pub feeds_count: u8,
    pub freshness_seconds_div16: u8,
    pub max_confidence_bps_div4: u8,
    pub _pad_cfg0: [u8; 4],
    pub max_per_tx_usd: u64,
    pub max_per_day_usd: u64,
    pub max_per_week_usd: u64,
    pub current_day_unix: i64,
    pub current_day_sum_usd: u64,
    pub current_week_unix: i64,
    pub current_week_sum_usd: u64,
    // 16 × SpendingUsdFeed (33 bytes each: feed_cache_account 32 + decimals 1)
    pub feeds_flat: [u8; 16 * 33],
}

pub const SPENDING_USD_FEED_BYTES: usize = 33;
pub const MAX_SPENDING_USD_FEEDS: usize = 16;

// ── Allowlists (H1, C2) ────────────────────────────────────────────────────
//
// Defense-in-depth lists for two trust boundaries the audit (2026-05-16)
// flagged as "trust the owner key that creates the rule":
//
// - `ALLOWED_ORACLE_OWNERS` constrains `feed_owner` values referenced from
//   `KIND_ORACLE` rules. Population SHOULD include the real Pyth Pull V2
//   program ID + any official Andromeda v1 adapter program IDs before
//   mainnet. Empty list = permissive (devnet default).
//
// - `ALLOWED_FHE_AUTHORITIES` constrains pubkeys registered in
//   `KIND_FHE_GATED.authorities_flat` via `update_rule_fhe_gated_authorities`
//   (disc 126). Empty list = permissive (devnet default).
//
// Both lists are `&[]` placeholders in devnet builds. Adding the
// `mainnet` cargo feature enforces non-empty content via a `const assert!`
// at compile time so deploys cannot accidentally ship a permissive list.
/// The Andromeda Pyth adapter program
/// (`A6xjw8jkJTFjpjHCRSFxVt1d1KbBZdh3XBNYvTfLZxP2`). It owns every `FeedCache`
/// PDA a `KIND_ORACLE` rule may reference, normalising Pyth `PriceUpdateV2`
/// into the canonical 64-byte view. Do NOT add the Pyth receiver itself
/// (`rec5EKMG…`) — its `PriceUpdateV2` layout ≠ the canonical view, so the
/// dispatch would read corrupt price/conf/publish_time offsets.
pub const PYTH_ADAPTER_PROGRAM_ID: Address = Address::new_from_array([
    135, 64, 28, 176, 14, 200, 192, 16, 202, 65, 97, 239, 13, 84, 132, 89, 56, 19, 27, 2, 163, 5,
    112, 210, 201, 183, 192, 117, 23, 36, 210, 169,
]);

pub const ALLOWED_ORACLE_OWNERS: &[Address] = &[PYTH_ADAPTER_PROGRAM_ID];
pub const ALLOWED_FHE_AUTHORITIES: &[Address] = &[];

#[cfg(feature = "mainnet")]
const _: () = assert!(
    !ALLOWED_ORACLE_OWNERS.is_empty(),
    "ALLOWED_ORACLE_OWNERS must be populated for mainnet builds"
);

#[cfg(feature = "mainnet")]
const _: () = assert!(
    !ALLOWED_FHE_AUTHORITIES.is_empty(),
    "ALLOWED_FHE_AUTHORITIES must be populated for mainnet builds"
);

#[inline]
fn is_oracle_owner_allowed(owner: &[u8; 32]) -> bool {
    if ALLOWED_ORACLE_OWNERS.is_empty() {
        return true;
    }
    for allowed in ALLOWED_ORACLE_OWNERS {
        if allowed.as_array() == owner {
            return true;
        }
    }
    false
}

#[inline]
fn is_fhe_authority_allowed(authority: &[u8; 32]) -> bool {
    if ALLOWED_FHE_AUTHORITIES.is_empty() {
        return true;
    }
    for allowed in ALLOWED_FHE_AUTHORITIES {
        if allowed.as_array() == authority {
            return true;
        }
    }
    false
}

// ─── SessionKeyRule (ABI §3.5.7, F8b — storage layer) ───────────────────────
//
// The SessionKeyRule slot is the engine's per-dWallet *policy surface* for
// ephemeral signing sessions. It does NOT itself authorise signing — sessions
// are opened on demand via `session_open` (disc 100) and authorise signing via
// `request_signature_via_session` (disc 101), which routes through a separate
// entrypoint and bypasses the normal `request_signature` dispatch loop.
//
// `applies_to` MUST equal `APPLIES_SESSION` (no PATH_NORMAL) — sessions are a
// separate signing path; a session rule that also applied to normal signing
// would silently delegate every normal-path tx to the session keypair, which
// is the opposite of what we want.
#[account(discriminator = 2, set_inner)]
#[seeds(b"rule_session_key", engine: Address, rule_index: u8)]
pub struct SessionKeyRule {
    // Header (96 bytes — mirror of RuleHeader, ABI §3.4).
    pub kind: u8,
    pub index: u8,
    pub enabled: u8,
    pub _pad0: u8,
    pub generation: u32,
    pub config_version: u32,
    pub _pad1: [u8; 4],
    pub engine: Address,
    pub next_admin_nonce: u64,
    pub config_hash: [u8; 32],
    pub _pad_header_tail: [u8; 8],
    // ─── config payload (40 bytes, F8b minimal) ──
    pub config_applies_to: u8, // MUST equal APPLIES_SESSION (=4).
    pub max_sessions: u8,      // 1..16 — upper bound on session_index.
    pub _pad_cfg0: [u8; 6],
    pub default_ttl_seconds: u64, // upper bound for session expires_at - created_at.
    pub default_max_uses: u32,    // upper bound for session.max_uses.
    pub _pad_cfg1: u32,
    pub session_max_amount_per_tx: u64, // per-session per-tx amount cap.
}

pub const MAX_SESSIONS_PER_ENGINE: u8 = 16;
pub const SESSION_KEY_RULE_CONFIG_BYTES: usize = 40;

// ─── Session (F8b — ephemeral PDA, not in engine.rules_flat index) ─────────
//
// One Session PDA per active session, addressed by `(engine, session_index)`.
// Created by `session_open`, consumed by `request_signature_via_session`,
// closed by `session_revoke`/`session_close` (owner challenge) or
// `close_expired_session` (permissionless post-expiry — F8c). The Session
// keypair signs natively — Andromeda never custodies it.
#[account(discriminator = 3, set_inner)]
#[seeds(b"session", engine: Address, session_index: u32)]
pub struct Session {
    pub engine: Address,
    pub session_signer: Address,
    pub session_index: u32,
    pub _pad0: u32,
    pub created_at_ts: i64,
    pub expires_at_ts: i64,
    pub used_count: u32,
    pub max_uses: u32,
    pub next_signature_nonce: u64,
    pub max_amount_per_tx: u64,
    pub next_admin_nonce: u64,
    // F8c: optional per-session destination allowlist. `destinations_count == 0`
    // means unrestricted (any destination); `> 0` enforces the whitelist in
    // `request_signature_via_session`. Updated via discs 105/106.
    pub destinations_count: u8,
    pub _pad_cfg: [u8; 7],
    pub destinations_flat: [u8; SESSION_MAX_DESTINATIONS * 32],
}

pub const SESSION_MAX_DESTINATIONS: usize = 8;
pub const SESSION_BYTES: usize = 112 + SESSION_MAX_DESTINATIONS * 32;

// ─── QuorumSession (F9b — ephemeral M-of-N recovery staging) ──────────────
//
// One QuorumSession PDA per in-flight quorum recovery, addressed by
// `(engine, session_nonce_u64)`. Opened by `quorum_session_open` (primary
// authorizes), filled in by N × `quorum_session_contribute` (one tx per
// member), finalized by anyone (`quorum_session_finalize` → CPI Ika), and
// closed after finalize or expiry (`quorum_session_close`). Snapshots the
// member roster + threshold at open time so concurrent admin changes don't
// affect this in-flight recovery (rules-policy legacy invariant).
#[account(discriminator = 4, set_inner)]
#[seeds(b"quorum_session", engine: Address, session_nonce: u64)]
pub struct QuorumSession {
    pub engine: Address,
    pub rule_pda: Address,
    pub payer_for_close: Address,
    pub session_nonce: u64,
    pub message_digest: [u8; 32],
    pub metadata_digest: [u8; 32],
    pub user_pubkey: [u8; 32],
    pub destination: [u8; 32],
    pub amount: u64,
    pub expires_at: i64,
    pub created_at: i64,
    pub finalized_at: i64,
    pub signature_scheme: u16,
    pub member_count_snapshot: u8,
    pub threshold_snapshot: u8,
    pub message_approval_bump: u8,
    pub contributions_count: u8,
    pub contributions_bitmap: u16,
    // F9b: explicit flag rather than relying on `finalized_at != 0` — quasar-svm
    // tests run with `Clock.unix_timestamp == 0`, so the i64 timestamp alone
    // cannot distinguish "open at ts=0" from "never finalized".
    pub is_finalized: u8,
    pub _pad: [u8; 3],
    pub members_snapshot: [u8; 16 * MEMBER_SLOT_LEN],
}

pub const MAX_QUORUM_SESSION_TTL_SECONDS: i64 = 7 * 24 * 3600;

// ─── PasskeySession (F9d — passkey-recovery ephemeral session) ─────────────
//
// One PasskeySession PDA per in-flight passkey recovery, addressed by
// `(engine, passkey_session_nonce_u64)`. Opened by `passkey_session_open`
// (WebAuthn assertion via Secp256r1 precompile authenticates the passkey
// primary off-chain → ephemeral Ed25519 key recorded), consumed by
// `recover_as_primary_passkey_session` (ephemeral key signs use challenges
// → CPI Ika), closed after expiry.
#[account(discriminator = 5, set_inner)]
#[seeds(b"passkey_session", engine: Address, passkey_session_nonce: u64)]
pub struct PasskeySession {
    pub engine: Address,
    pub rule_pda: Address,
    pub payer_for_close: Address,
    /// `sha256(credentialId)` pinned at open. A different passkey under the
    /// same primary slot (same pubkey, different credential ID) cannot reuse
    /// this session.
    pub credential_id_hash: [u8; 32],
    /// 33-byte compressed Secp256r1 pubkey of the passkey credential (mirror
    /// of `RecoveryRule.primary_slot[1..34]` at open time). Re-checked on
    /// every use — a primary rotation kills the session immediately.
    pub credential_pubkey: [u8; 33],
    pub _credential_pad: u8,
    /// User's ephemeral Ed25519 public key — every use authorized by a fresh
    /// Ed25519 precompile signature from this key.
    pub eph_pk: [u8; 32],
    pub session_nonce: u64,
    pub next_use_nonce: u64,
    pub not_after_unix_ts: u64,
    pub expires_at: i64,
    pub created_at: i64,
    /// F9d quirk (mirrors F9b): explicit u8 flag rather than relying on
    /// `closed_at != 0`, since `Clock.unix_timestamp == 0` in quasar-svm.
    pub is_closed: u8,
    pub _pad: [u8; 7],
}

pub const PASSKEY_SESSION_TTL_SECONDS: i64 = 600;
pub const WEBAUTHN_AUTH_DATA_MAX: usize = 192;
pub const WEBAUTHN_CLIENT_DATA_JSON_MAX: usize = 192;

// ─── OidcSession (C1 — Login Social on-chain) ──────────────────────────────
//
// One OidcSession PDA per in-flight OIDC recovery, addressed by
// `(engine, oidc_session_nonce_u64)`. Opened by `oidc_session_open` (OIDC
// JWT verified via the `oidc-verifier` library — Google/Apple JWT proves
// the user's identity, off-chain → on-chain), consumed by
// `recover_as_primary_oidc` (ephemeral Ed25519 key signs use challenges →
// CPI Ika), closed after expiry.
//
// Mirrors the PasskeySession layout to keep the gateway/dashboard code
// paths parallel between passkey and OIDC recovery.
#[account(discriminator = 6, set_inner)]
#[seeds(b"oidc_session", engine: Address, oidc_session_nonce: u64)]
pub struct OidcSession {
    pub engine: Address,
    pub rule_pda: Address,
    pub payer_for_close: Address,
    /// `addr_seed = sha256("andromeda::oidc::addr::v1" || lp(iss) || lp(aud)
    /// || lp(sub))` derived from the JWT at open time. Re-checked against
    /// `rule_pda.primary_slot[1..33]` on every use — a primary rotation
    /// (different OIDC identity) kills the session.
    pub addr_seed: [u8; 32],
    /// `sha256(header.payload)` of the JWT used at open time — diagnostic
    /// only (audit trail). The signature verify already happened.
    pub jwt_digest: [u8; 32],
    /// User's ephemeral Ed25519 public key — every use authorized by a fresh
    /// Ed25519 precompile signature from this key.
    pub eph_pk: [u8; 32],
    pub session_nonce: u64,
    pub next_use_nonce: u64,
    pub not_after_unix_ts: u64,
    pub expires_at: i64,
    pub created_at: i64,
    /// `OIDC_VERIFIER_V1` snapshot at open time; pinned so a verifier
    /// upgrade doesn't silently widen the trust surface of an open session.
    pub verifier_version: u32,
    /// Mirror of `PasskeySession.is_closed` — explicit flag because
    /// `Clock.unix_timestamp == 0` in quasar-svm tests.
    pub is_closed: u8,
    pub _pad: [u8; 3],
}

pub const OIDC_SESSION_TTL_SECONDS: i64 = 600;
/// Hard cap on the JWT byte length the engine accepts in a single ix data
/// blob. Solana single-tx ix data ≈ 1232 bytes total; minus disc + fixed
/// args (~150 bytes) leaves ~1000 bytes for the JWT. Google/Apple `openid`
/// id_tokens are ~700–900 bytes, fitting comfortably.
pub const MAX_OIDC_JWT_BYTES: usize = 1024;

// ── Allowed OIDC issuers / audiences (C1 placeholder, mainnet-gated) ──────
//
// On devnet pre-alpha these lists are empty so any (iss, aud) parsed from
// a JWT bypasses the allowlist (the `oidc-verifier` itself rejects empty
// lists with `BadConfig`, so we route empties through a permissive
// fallback). For mainnet the `mainnet` cargo feature enforces non-empty
// content via a `const assert!` — deploying without proper allowlists
// fails to compile.
pub const ALLOWED_OIDC_ISSUERS: &[&[u8]] = &[];
pub const ALLOWED_OIDC_AUDIENCES: &[&[u8]] = &[];

#[cfg(feature = "mainnet")]
const _: () = assert!(
    !ALLOWED_OIDC_ISSUERS.is_empty(),
    "ALLOWED_OIDC_ISSUERS must be populated for mainnet builds"
);

#[cfg(feature = "mainnet")]
const _: () = assert!(
    !ALLOWED_OIDC_AUDIENCES.is_empty(),
    "ALLOWED_OIDC_AUDIENCES must be populated for mainnet builds"
);

/// Devnet fallback set so `oidc-verifier` doesn't reject with `BadConfig`
/// when the production allowlist is empty (placeholder). Mainnet builds
/// always have non-empty `ALLOWED_OIDC_ISSUERS`/`ALLOWED_OIDC_AUDIENCES`
/// (compile-time enforced) and never hit this path.
#[cfg(not(feature = "mainnet"))]
const DEVNET_FALLBACK_ISSUERS: &[&[u8]] =
    &[b"https://accounts.google.com", b"https://appleid.apple.com"];
#[cfg(not(feature = "mainnet"))]
const DEVNET_FALLBACK_AUDIENCES: &[&[u8]] = &[b"andromeda-devnet"];

// ── JwkRegistry layout mirrors (see contracts/jwk-registry/src/lib.rs) ────
//
// Used by `oidc_session_open` to extract the active JWK material from an
// `UncheckedAccount` without depending on the `andromeda_jwk_registry`
// crate (would pull a heavy import for a 256-byte read).

/// Canonical `andromeda_jwk_registry` program ID
/// (`8xL2mrQ2amDpinQMHJPaEELbgEXWRVGn4PQ7kzDm7vNM`). Mirrors the
/// `declare_id!` in `contracts/jwk-registry/src/lib.rs`. Used by C1 audit
/// fix to defend `oidc_session_open` against accounts whose layout matches
/// `JwkRegistry` but are owned by a different program.
pub const JWK_REGISTRY_PROGRAM_ID: Address = Address::new_from_array([
    0x76, 0x2e, 0x45, 0x5b, 0x2c, 0xb1, 0x1c, 0x44, 0x7a, 0x39, 0xdf, 0x49, 0xbd, 0x8f, 0x10, 0xae,
    0x25, 0x41, 0x96, 0xad, 0xb4, 0x5c, 0xd6, 0x59, 0x84, 0x6e, 0x39, 0x84, 0x59, 0xbe, 0x80, 0x3a,
]);

pub const JWK_REGISTRY_MAX_ENTRIES: usize = 8;
pub const JWK_ENTRY_LEN: usize = 400;
/// 1 disc + 1 version + 1 entry_count + 6 reserved + 32×4 (roles) + 8×5
/// (timelock + grace + grace_post_revoke + 2 rotation_ready_at) = 162.
pub const JWK_HEADER_LEN: usize = 1 + 1 + 1 + 6 + 32 * 4 + 8 * 5;
const JWK_ACCOUNT_DISCRIMINATOR: u8 = 1;
const JWK_STATUS_ACTIVE: u8 = 2;

// Per-entry offsets (mirror of `EO_*` in jwk-registry/src/lib.rs).
const JWK_EO_STATUS: usize = 0;
const JWK_EO_ISSUER_HASH: usize = 8;
const JWK_EO_AUDIENCE_HASH: usize = 40;
const JWK_EO_KID_HASH: usize = 72;
const JWK_EO_MODULUS: usize = 104;
const JWK_EO_EXPONENT: usize = 360;

/// Read one JWK entry from a `JwkRegistry` account's raw data, validating
/// the entry status is `ACTIVE`. Returns `(modulus_n_256B, exponent_e,
/// issuer_hash, audience_hash, kid_hash)`.
#[allow(clippy::type_complexity)]
fn read_jwk_entry(
    data: &[u8],
    entry_idx: usize,
) -> Result<([u8; 256], u32, [u8; 32], [u8; 32], [u8; 32]), ProgramError> {
    if data.is_empty() || data[0] != JWK_ACCOUNT_DISCRIMINATOR {
        return Err(PolicyEngineError::OidcJwkNotFound.into());
    }
    let entry_base = JWK_HEADER_LEN + entry_idx * JWK_ENTRY_LEN;
    if entry_base + JWK_ENTRY_LEN > data.len() {
        return Err(PolicyEngineError::OidcJwkNotFound.into());
    }
    let entry = &data[entry_base..entry_base + JWK_ENTRY_LEN];
    if entry[JWK_EO_STATUS] != JWK_STATUS_ACTIVE {
        return Err(PolicyEngineError::OidcJwkInactive.into());
    }
    let mut modulus = [0u8; 256];
    modulus.copy_from_slice(&entry[JWK_EO_MODULUS..JWK_EO_MODULUS + 256]);
    let exponent = u32::from_le_bytes(
        entry[JWK_EO_EXPONENT..JWK_EO_EXPONENT + 4]
            .try_into()
            .map_err(|_| PolicyEngineError::OidcJwkNotFound)?,
    );
    let mut iss = [0u8; 32];
    iss.copy_from_slice(&entry[JWK_EO_ISSUER_HASH..JWK_EO_ISSUER_HASH + 32]);
    let mut aud = [0u8; 32];
    aud.copy_from_slice(&entry[JWK_EO_AUDIENCE_HASH..JWK_EO_AUDIENCE_HASH + 32]);
    let mut kid = [0u8; 32];
    kid.copy_from_slice(&entry[JWK_EO_KID_HASH..JWK_EO_KID_HASH + 32]);
    Ok((modulus, exponent, iss, aud, kid))
}

#[account(discriminator = 2, set_inner)]
#[seeds(b"rule_recovery", engine: Address, rule_index: u8)]
pub struct RecoveryRule {
    pub kind: u8,
    pub index: u8,
    pub enabled: u8,
    pub _pad0: u8,
    pub generation: u32,
    pub config_version: u32,
    pub _pad1: [u8; 4],
    pub engine: Address,
    pub next_admin_nonce: u64,
    pub config_hash: [u8; 32],
    pub _pad_header_tail: [u8; 8],
    // ─── config payload (ABI §3.5.8) ──
    pub config_applies_to: u8,
    pub primary_present: u8,
    pub members_count: u8,
    pub quorum_threshold: u8,
    pub daily_limit_present: u8,
    pub destinations_count: u8,
    pub pending_change_kind: u8,
    pub _pad_cfg0: u8,
    pub primary_slot: [u8; MEMBER_SLOT_LEN],
    pub _pad_cfg1: [u8; 6],
    pub daily_limit: u64,
    pub cooldown_seconds: u64,
    pub current_day_unix: i64,
    pub current_day_sum: u64,
    // F9d: repurposed from `pending_change_value` — passkey-session nonce
    // counter, bumped by `passkey_session_open`. The field name retains the
    // same bit layout to keep the on-chain account size stable.
    pub next_passkey_session_nonce: u64,
    pub pending_change_at_ts: i64,
    pub members: [u8; 16 * MEMBER_SLOT_LEN],
    pub destinations: [u8; 16 * 32],
    pub oidc_iss_hash: [u8; 16],
    pub oidc_aud_hash: [u8; 16],
    pub jwk_registry_addr: Address,
    // F9b: monotonic counter handed to `QuorumSession` PDAs as the seed
    // component. Bumped on every `quorum_session_open` so concurrent sessions
    // get distinct PDAs.
    pub next_session_nonce: u64,
    pub _pad_cfg_tail: [u8; 8],
}

// ── Challenges (mirror of `docs/POLICY_ENGINE_ABI_V3.md` §6) ────────────────
//
// Off-chain mirrors (Go, TS) live at `gateway/internal/policy/challenges.go`
// and `ika-backend/src/clients/policyEngine/challenges.ts` (to be created).
// Cross-language fixtures in `fixtures/policy_engine_v3/challenges/`.

#[inline(always)]
fn human_len_le(human: &[u8]) -> [u8; 2] {
    debug_assert!(human.len() <= MAX_HUMAN_MESSAGE_BYTES);
    (human.len() as u16).to_le_bytes()
}

#[inline]
pub fn policy_engine_init_challenge(
    dwallet: &Address,
    init_authority_slot: &[u8; MEMBER_SLOT_LEN],
    owner_slot: &[u8; MEMBER_SLOT_LEN],
    default_recovery_present: u8,
    default_recovery_hash: &[u8; 32],
) -> [u8; 32] {
    let op_tag: &[u8] = if default_recovery_present == 1 {
        OP_INIT_WITH_RECOVERY
    } else {
        OP_INIT
    };
    let present = [default_recovery_present];
    hashv(&[
        DOMAIN_INIT_V1,
        op_tag,
        dwallet.as_array().as_slice(),
        init_authority_slot,
        owner_slot,
        &present,
        default_recovery_hash,
    ])
}

/// Maximum extras the admin challenge format accepts (mirrored off-chain).
pub const ADMIN_CHALLENGE_MAX_EXTRAS: usize = 12;

/// Canonical admin challenge for `policy-engine v3` (clear-signing v2,
/// ABI §6.2). Used by `add_rule_*`, `update_rule_*`, `remove_rule`, `pause`,
/// `resume`, `revoke`.
///
/// M2 audit fix (2026-05-16): each `extras[i]` is prefixed with a `u16 LE`
/// length tag so two variable-length extras can never be concatenated into
/// an ambiguous byte string. Off-chain mirrors (Go gateway, TS ika-backend)
/// MUST emit the same wire format — cross-language fixtures under
/// `fixtures/policy_engine_v3/challenges/admin/` exist to catch drift.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn admin_challenge(
    op_tag: &[u8],
    human: &[u8],
    engine: &Address,
    dwallet: &Address,
    rule_kind: u8,
    rule_index: u8,
    rule_generation: u32,
    expected_nonce: u64,
    config_hash: &[u8; 32],
    owner_slot: &[u8; MEMBER_SLOT_LEN],
    extras: &[&[u8]],
) -> [u8; 32] {
    let h_len = human_len_le(human);
    let kind_b = [rule_kind];
    let index_b = [rule_index];
    let gen_le = rule_generation.to_le_bytes();
    let nonce_le = expected_nonce.to_le_bytes();
    // M2: each extra ships as (u16_le_len, bytes). 12 fixed parts + up to
    // 12 extras × 2 (length + payload) = 36 slots.
    let mut parts: [&[u8]; 36] = [&[]; 36];
    let mut extra_lens: [[u8; 2]; ADMIN_CHALLENGE_MAX_EXTRAS] =
        [[0u8; 2]; ADMIN_CHALLENGE_MAX_EXTRAS];
    parts[0] = DOMAIN_V3;
    parts[1] = op_tag;
    parts[2] = &h_len;
    parts[3] = human;
    parts[4] = engine.as_array().as_slice();
    parts[5] = dwallet.as_array().as_slice();
    parts[6] = &kind_b;
    parts[7] = &index_b;
    parts[8] = &gen_le;
    parts[9] = &nonce_le;
    parts[10] = config_hash;
    parts[11] = owner_slot;
    let mut n = 12usize;
    // First pass: write all the u16 LE lengths into the local backing
    // array. We must do this BEFORE binding `parts[*]` references so the
    // borrow checker can see the backing array is stable for the rest of
    // the function.
    let extra_count = extras.len().min(ADMIN_CHALLENGE_MAX_EXTRAS);
    for i in 0..extra_count {
        // Truncates to u16 — extras above 65 535 bytes are rejected upstream
        // (every existing caller passes ≤ 1232 bytes).
        extra_lens[i] = (extras[i].len() as u16).to_le_bytes();
    }
    for i in 0..extra_count {
        if n + 1 >= parts.len() {
            break;
        }
        parts[n] = &extra_lens[i];
        parts[n + 1] = extras[i];
        n += 2;
    }
    hashv(&parts[..n])
}

/// Runtime request_metadata_digest (ABI §6.4, V2). Not human-signed — gateway
/// computes canonically and the program recomputes & compares.
///
/// Update 3: V2 appends `amount` (asset base units) + `asset_index` (index in
/// the `KIND_SPENDING_USD` allowlist) and bumps the domain to
/// `DOMAIN_REQUEST_V2`. The normal signing path (disc 1) passes the real
/// values; paths that do not carry a value (session) pass `0, 0`.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn request_metadata_digest(
    engine: &Address,
    dwallet: &Address,
    message_digest: &[u8; 32],
    destination: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    path: u8,
    rules_generation: u32,
    amount: u64,
    asset_index: u8,
) -> [u8; 32] {
    let scheme_le = signature_scheme.to_le_bytes();
    let path_b = [path];
    let gen_le = rules_generation.to_le_bytes();
    let amount_le = amount.to_le_bytes();
    let asset_b = [asset_index];
    hashv(&[
        DOMAIN_REQUEST_V2,
        b"request-signature",
        engine.as_array().as_slice(),
        dwallet.as_array().as_slice(),
        message_digest,
        destination,
        user_pubkey,
        &scheme_le,
        &path_b,
        &gen_le,
        &amount_le,
        &asset_b,
    ])
}

/// Fase 1 (A1, 2026-05-25): owner-authorization challenge for the NORMAL
/// signing path (disc 1). The dWallet `owner_slot` signs this off-chain and the
/// gateway relays the precompile invocation. Binds the rendered human message,
/// the engine/dWallet identity, and the full request via `metadata_digest`
/// (destination, amount, message, scheme, generation, asset_index are all folded
/// in) — so the gateway cannot alter any request field. Anti-replay is the Ika
/// MessageApproval PDA (unique per message_digest), so no extra nonce is needed.
#[inline]
pub fn normal_use_challenge(
    human: &[u8],
    engine: &Address,
    dwallet: &Address,
    metadata_digest: &[u8; 32],
    owner_slot: &[u8; MEMBER_SLOT_LEN],
) -> [u8; 32] {
    let h_len = human_len_le(human);
    hashv(&[
        DOMAIN_V3,
        OP_NORMAL_SIGN,
        &h_len,
        human,
        engine.as_array().as_slice(),
        dwallet.as_array().as_slice(),
        metadata_digest,
        owner_slot,
    ])
}

#[inline]
fn check_sysvar_addr(addr: &Address) -> Result<(), ProgramError> {
    check_sysvar_address(addr).map_err(|_| PolicyEngineError::AuthFailed.into())
}

// ── F7b — FHE-Gated sysvar walker ────────────────────────────────────────────
//
// Minimal Instructions-sysvar reader used by the `KIND_FHE_GATED` dispatch.
// Mirrors the layout the runtime serialises:
//   [0..2]  num_instructions u16 LE
//   [2..2 + 2 * N] per-ix offset table (u16 LE pointing into the body table)
// Each ix body:
//   [0..2]  accounts_count u16 LE
//   [2..2 + 33 * accounts_count] AccountMeta entries
//   [next..+32] program_id (Pubkey)
//   [next..+2] data_len u16 LE
//   [next..+data_len] ix data
//
// `andromeda_auth::precompile` already exposes a higher-level matcher
// (`verify_ed25519`) that searches for `(pubkey, message)` equality, but
// FHE-Gated needs to *parse* the matched message to check the embedded
// timestamp + authorize byte. We therefore walk the sysvar locally.

#[inline]
fn read_u16_le_local(buf: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    if end > buf.len() {
        return None;
    }
    Some(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
}

/// Returns `(program_id_slice, ix_data_slice)` for the `i`-th instruction in
/// the sysvar, or `None` when `i` is past the end. Returns `Err` on a
/// malformed sysvar.
#[allow(clippy::type_complexity)]
fn read_ix_body_for_fhe(sysvar_data: &[u8], i: usize) -> Result<Option<(&[u8], &[u8])>, ()> {
    const ACCOUNT_META_LEN: usize = 33;
    const PROGRAM_ID_LEN: usize = 32;

    if sysvar_data.len() < 2 {
        return Err(());
    }
    let num_instructions = read_u16_le_local(sysvar_data, 0).ok_or(())? as usize;
    if i >= num_instructions {
        return Ok(None);
    }
    let table_start: usize = 2;
    let off_ptr = table_start
        .checked_add(i.checked_mul(2).ok_or(())?)
        .ok_or(())?;
    let ix_offset = read_u16_le_local(sysvar_data, off_ptr).ok_or(())? as usize;
    let accounts_count = read_u16_le_local(sysvar_data, ix_offset).ok_or(())? as usize;
    let accounts_size = accounts_count.checked_mul(ACCOUNT_META_LEN).ok_or(())?;
    let program_id_off = ix_offset
        .checked_add(2)
        .and_then(|x| x.checked_add(accounts_size))
        .ok_or(())?;
    if program_id_off.checked_add(PROGRAM_ID_LEN).ok_or(())? > sysvar_data.len() {
        return Err(());
    }
    let program_id = &sysvar_data[program_id_off..program_id_off + PROGRAM_ID_LEN];
    let data_len_off = program_id_off + PROGRAM_ID_LEN;
    let data_len = read_u16_le_local(sysvar_data, data_len_off).ok_or(())? as usize;
    let data_off = data_len_off + 2;
    if data_off.checked_add(data_len).ok_or(())? > sysvar_data.len() {
        return Err(());
    }
    Ok(Some((
        program_id,
        &sysvar_data[data_off..data_off + data_len],
    )))
}

/// Parses a long-record (Ed25519 / Secp256r1) precompile ix data buffer and
/// returns `(pubkey_slice, message_slice)` for the first record whose offsets
/// are self-references (`0xFFFF`). Cross-instruction references are rejected
/// (`policy-engine` never emits them and the long-record dispatch wouldn't
/// know how to follow them). Returns `None` on malformed data.
fn first_ed25519_record_self(ix_data: &[u8]) -> Option<(&[u8], &[u8])> {
    const HEADER_LEN: usize = 2;
    const LONG_OFFSETS_LEN: usize = 14;
    const SELF_INDEX: u16 = 0xFFFF;
    const SIG_LEN: usize = 64;
    const PK_LEN: usize = 32;

    if ix_data.len() < HEADER_LEN + LONG_OFFSETS_LEN {
        return None;
    }
    let n = ix_data[0] as usize;
    if n == 0 {
        return None;
    }
    let r = HEADER_LEN;
    let sig_off = read_u16_le_local(ix_data, r)? as usize;
    let sig_ix = read_u16_le_local(ix_data, r + 2)?;
    let pk_off = read_u16_le_local(ix_data, r + 4)? as usize;
    let pk_ix = read_u16_le_local(ix_data, r + 6)?;
    let msg_off = read_u16_le_local(ix_data, r + 8)? as usize;
    let msg_size = read_u16_le_local(ix_data, r + 10)? as usize;
    let msg_ix = read_u16_le_local(ix_data, r + 12)?;
    if sig_ix != SELF_INDEX || pk_ix != SELF_INDEX || msg_ix != SELF_INDEX {
        return None;
    }
    if sig_off.checked_add(SIG_LEN)? > ix_data.len() {
        return None;
    }
    let pk_end = pk_off.checked_add(PK_LEN)?;
    if pk_end > ix_data.len() {
        return None;
    }
    let msg_end = msg_off.checked_add(msg_size)?;
    if msg_end > ix_data.len() {
        return None;
    }
    Some((&ix_data[pk_off..pk_end], &ix_data[msg_off..msg_end]))
}

// ── Program entrypoints ──────────────────────────────────────────────────────

/// Shared rule-dispatch loop for every signing path (Fase 2, 2026-05-25).
///
/// Extracted verbatim from `request_signature` (disc 1) so the session
/// (disc 101) and OIDC-session (disc 107) signing paths enforce the SAME
/// rule set. The caller attaches exactly one remaining account per ENABLED
/// rule slot (ascending) plus any per-kind aux accounts, then passes the
/// iterator here. `path` selects which rules are ENFORCED: a rule runs only
/// when `applies_to & path != 0`; rules on other paths are still
/// header-validated (drift check) but skipped. `skip_slot` excludes exactly
/// one slot entirely. Behaviour for PATH_NORMAL (`skip_slot = None`) is
/// byte-for-byte identical to the previous inline loop.
#[allow(clippy::too_many_arguments)]
fn dispatch_active_rules<I>(
    rules_flat: &[u8; RULES_FLAT_BYTES],
    rem_iter: &mut I,
    sysvar_view: &AccountView,
    current_ts: i64,
    dwallet_addr: &Address,
    destination: &[u8; 32],
    amount: u64,
    asset_index: u8,
    metadata_digest: &[u8; 32],
    path: u8,
    // `skip_slot` lets a caller exclude exactly ONE enabled slot from the
    // dispatch — used by `request_signature_via_oidc_session` for the recovery
    // rule that backs the OIDC session: it is already validated as the named
    // `rule_pda` account, so re-reading it here as a trailing remaining_account
    // would duplicate the account (shared borrow_state) and is unnecessary
    // (recovery rules are APPLIES_RECOVERY — never a session gate). disc 1/101
    // pass `None`.
    skip_slot: Option<usize>,
) -> Result<(), ProgramError>
where
    I: Iterator<Item = Result<AccountView, ProgramError>>,
{
    for slot in 0..MAX_RULES {
        let entry = read_rule_entry(rules_flat, slot);
        if entry.kind == KIND_EMPTY || entry.enabled != 1 {
            continue;
        }
        // Excluded slot (e.g. the OIDC recovery rule): not pulled from
        // remaining_accounts and not re-validated here.
        if skip_slot == Some(slot) {
            continue;
        }

        // Pull the matching sub-PDA from the remaining accounts.
        let sub_view = rem_iter
            .next()
            .ok_or(PolicyEngineError::InvalidRuleHeader)?
            .map_err(|_| PolicyEngineError::InvalidRuleHeader)?;

        // Address binding: account passed in MUST be the recorded sub-PDA.
        require!(
            *sub_view.address() == entry.rule_pda,
            PolicyEngineError::InvalidRuleHeader
        );
        // Ownership: sub-PDA must be owned by this program.
        require!(
            sub_view.owner() == &ID,
            PolicyEngineError::InvalidRuleHeader
        );

        // Borrow the sub-PDA bytes and validate header drift.
        let sub_data = sub_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::InvalidRuleHeader)?;
        require!(
            sub_data.len() >= RULE_HEADER_BYTES + 1,
            PolicyEngineError::InvalidRuleHeader
        );
        // sub_data[0] = account discriminator (= 2 for rules). Offsets
        // below are 1-based relative to the start of the account data.
        // (Mirror of ABI §3.4 RuleHeader layout.)
        //
        // M1 audit fix (2026-05-16): defense-in-depth — the address binding
        // + owner check above already constrain this to a sub-PDA written
        // by `add_rule_*`, but explicitly checking the discriminator
        // hardens the loop against any future refactor that changes how
        // rule PDAs are derived or owned.
        require!(sub_data[0] == 2, PolicyEngineError::InvalidRuleHeader);
        let header_kind = sub_data[1];
        let header_index = sub_data[2];
        let header_enabled = sub_data[3];
        let mut gen_b = [0u8; 4];
        gen_b.copy_from_slice(&sub_data[5..9]);
        let header_gen = u32::from_le_bytes(gen_b);
        let header_config_hash = &sub_data[57..89]; // offset 56 + 1 (disc)

        require!(
            header_kind == entry.kind
                && header_index == slot as u8
                && header_enabled == 1
                && header_gen == entry.generation
                && header_config_hash == entry.config_hash,
            PolicyEngineError::InvalidRuleHeader
        );

        // Applies_to gate: rules whose mask excludes `path` are
        // header-validated above (drift check) but skip enforcement here.
        let applies_to = sub_data[97];
        if (applies_to & path) == 0 {
            continue;
        }

        // Per-kind dispatch (only when applies_to includes `path`).
        match entry.kind {
            KIND_ALLOWLIST => {
                // AllowlistConfig payload starts at offset 96 + 1 (disc) = 97:
                //   97  applies_to u8
                //   98  destinations_count u8
                //   99..105 _pad
                //   105..1129 destinations_flat (32 destinations × 32)
                let count = sub_data[98] as usize;
                require!(count <= 32, PolicyEngineError::InvalidRuleHeader);
                let mut allowed = false;
                for i in 0..count {
                    let off = 105 + i * 32;
                    if &sub_data[off..off + 32] == destination.as_slice() {
                        allowed = true;
                        break;
                    }
                }
                require!(allowed, PolicyEngineError::AllowlistDestinationNotAllowed);
            }
            KIND_VELOCITY => {
                // F3b: count-based rate limit with real mutation via
                // unsafe data_mut_ptr (same pattern Quasar uses
                // internally for `set_lamports` / `resize` / `realloc`).
                // sub-PDA layout mirror of ABI §3.5.2:
                //   sub_data[97]   applies_to u8
                //   sub_data[98]   windows_count u8
                //   sub_data[99..105]  _pad
                //   sub_data[105..297] windows_flat (4 × 48 bytes)
                let count = sub_data[98] as usize;
                require!(count <= 4, PolicyEngineError::InvalidRuleHeader);

                // Pass 1: read + validate, collect (next_count, next_start)
                // for each window.
                let mut to_apply = [(0u64, 0i64); 4];
                for i in 0..count {
                    let base = 105 + i * 48;
                    let window_seconds = u64::from_le_bytes(
                        sub_data[base..base + 8]
                            .try_into()
                            .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                    );
                    let cap = u64::from_le_bytes(
                        sub_data[base + 8..base + 16]
                            .try_into()
                            .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                    );
                    let current_count = u64::from_le_bytes(
                        sub_data[base + 16..base + 24]
                            .try_into()
                            .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                    );
                    let window_start = i64::from_le_bytes(
                        sub_data[base + 32..base + 40]
                            .try_into()
                            .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                    );
                    require!(
                        window_seconds > 0 && cap > 0,
                        PolicyEngineError::InvalidRuleHeader
                    );
                    let elapsed = current_ts >= window_start.saturating_add(window_seconds as i64);
                    let (next_count, next_start) = if elapsed {
                        (1u64, current_ts)
                    } else {
                        (current_count.saturating_add(1), window_start)
                    };
                    require!(next_count <= cap, PolicyEngineError::VelocityCapExceeded);
                    to_apply[i] = (next_count, next_start);
                }
                let data_len = sub_data.len();
                drop(sub_data);

                // Pass 2: write back the new counters via Quasar's
                // unsafe data_mut_ptr API.
                //
                // A2 audit fix (2026-05-25): fail closed if the caller did
                // not pass the sub-PDA as writable, rather than depending on
                // the SVM runtime to fault on the raw write below.
                require!(
                    sub_view.is_writable(),
                    PolicyEngineError::RuleAccountNotWritable
                );
                // SAFETY: the remaining-account sub_view is declared
                // writable (checked above), the immutable borrow above was
                // released, and no other alias exists. We only touch bytes
                // inside the existing data buffer; we do not resize. This is
                // the same pattern Quasar uses internally for cross-account
                // mutations (cf. `set_lamports` in quasar-lang).
                let data_mut: &mut [u8] = unsafe {
                    core::slice::from_raw_parts_mut(sub_view.data_ptr() as *mut u8, data_len)
                };
                for i in 0..count {
                    let (next_count, next_start) = to_apply[i];
                    let base = 105 + i * 48;
                    data_mut[base + 16..base + 24].copy_from_slice(&next_count.to_le_bytes());
                    data_mut[base + 32..base + 40].copy_from_slice(&next_start.to_le_bytes());
                }
            }
            KIND_TIME_LOCK => {
                // F4: read-only dispatch (no mutation). Layout:
                //   sub_data[97]   applies_to u8
                //   sub_data[98]   mode u8 (0=absolute, 1=delay)
                //   sub_data[99..105]  _pad
                //   sub_data[105..113] unlock_ts i64
                //   sub_data[113..121] delay_seconds u64
                //   sub_data[121..129] created_at_ts i64
                let mode = sub_data[98];
                let unlock_ts = i64::from_le_bytes(
                    sub_data[105..113]
                        .try_into()
                        .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                );
                let delay_seconds = u64::from_le_bytes(
                    sub_data[113..121]
                        .try_into()
                        .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                );
                let created_at_ts = i64::from_le_bytes(
                    sub_data[121..129]
                        .try_into()
                        .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                );
                let effective_unlock = match mode {
                    TIME_LOCK_MODE_ABSOLUTE => unlock_ts,
                    TIME_LOCK_MODE_DELAY => created_at_ts.saturating_add(delay_seconds as i64),
                    _ => return Err(PolicyEngineError::InvalidRuleHeader.into()),
                };
                require!(
                    current_ts >= effective_unlock,
                    PolicyEngineError::TimeLocked
                );
            }
            KIND_ORACLE => {
                // F5b — Oracle dispatch.
                //
                // Layout (mirror of ABI §3.5.4):
                //   sub_data[97]   config_applies_to u8
                //   sub_data[98]   feeds_count u8
                //   sub_data[99]   freshness_seconds_div16 u8
                //   sub_data[100]  min_confidence_bps_div4 u8
                //   sub_data[101..105] _pad_cfg0
                //   sub_data[105..105 + 80*N] feeds_flat
                //     each OracleFeed (80 B):
                //       [..32] feed_account Address
                //       [32..64] feed_owner Address
                //       [64..72] min_q64 i64 LE
                //       [72..80] max_q64 i64 LE
                //
                // For each feed, the caller must attach one trailing
                // aux account in `remaining_accounts` (after the sub-PDA)
                // whose `address` matches `feed_account` and whose `owner`
                // matches `feed_owner`. The aux account's data MUST start
                // with the canonical price layout (Andromeda v1):
                //   [0..32]  feed_id (opaque, not checked here)
                //   [32..40] price i64 LE
                //   [40..48] confidence u64 LE
                //   [48..56] _reserved
                //   [56..64] publish_time i64 LE
                //
                // Real Pyth `PriceUpdateV2` accounts ship the same three
                // critical fields (price / confidence / publish_time) but
                // at provider-defined offsets — an adapter layer on the
                // off-chain side normalises them into this canonical
                // 64-byte view before the tx is signed. Keeps the on-chain
                // dispatch cheap and protocol-agnostic.
                let count = sub_data[98] as usize;
                require!(
                    count <= MAX_ORACLE_FEEDS,
                    PolicyEngineError::InvalidRuleHeader
                );
                let freshness_secs = (sub_data[99] as i64).saturating_mul(16);
                // H3 fix: the rule's `min_confidence_bps_div4` (legacy name)
                // is an UPPER bound on accepted price uncertainty. A value
                // of 0 disables the check (back-compat for rules created
                // before H3 landed). max_confidence_bps fits in u64 even
                // for u8::MAX * 4 = 1020 bps.
                let max_confidence_bps_div4 = sub_data[100] as u64;
                // Collect feed metadata into a local buffer because we
                // need to drop the immutable sub_data borrow before
                // pulling aux accounts (some sub_data references can
                // still be live across the loop).
                let mut feeds: [([u8; 32], [u8; 32], i64, i64); MAX_ORACLE_FEEDS] =
                    [([0u8; 32], [0u8; 32], 0i64, 0i64); MAX_ORACLE_FEEDS];
                for i in 0..count {
                    let base = 105 + i * ORACLE_FEED_BYTES;
                    let mut feed_acct = [0u8; 32];
                    feed_acct.copy_from_slice(&sub_data[base..base + 32]);
                    let mut feed_owner = [0u8; 32];
                    feed_owner.copy_from_slice(&sub_data[base + 32..base + 64]);
                    let min_q64 = i64::from_le_bytes(
                        sub_data[base + 64..base + 72]
                            .try_into()
                            .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                    );
                    let max_q64 = i64::from_le_bytes(
                        sub_data[base + 72..base + 80]
                            .try_into()
                            .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                    );
                    feeds[i] = (feed_acct, feed_owner, min_q64, max_q64);
                }
                drop(sub_data);

                let max_confidence_bps = max_confidence_bps_div4.saturating_mul(4);
                for i in 0..count {
                    let (expected_acct, expected_owner, min_q64, max_q64) = feeds[i];
                    // H1 fix: defense-in-depth allowlist. A rule whose
                    // feed_owner is outside the allowed set is rejected
                    // even if the rule itself was created by a legit
                    // owner (which lowers the blast radius of a
                    // gateway/owner-key compromise that registers a
                    // malicious feed_owner).
                    require!(
                        is_oracle_owner_allowed(&expected_owner),
                        PolicyEngineError::OracleOwnerMismatch
                    );
                    let aux_view = rem_iter
                        .next()
                        .ok_or(PolicyEngineError::InvalidRuleHeader)?
                        .map_err(|_| PolicyEngineError::InvalidRuleHeader)?;
                    require!(
                        aux_view.address().as_array() == &expected_acct,
                        PolicyEngineError::InvalidRuleHeader
                    );
                    require!(
                        aux_view.owner().as_array() == &expected_owner,
                        PolicyEngineError::OracleOwnerMismatch
                    );
                    let aux_data = aux_view
                        .try_borrow()
                        .map_err(|_| PolicyEngineError::InvalidRuleHeader)?;
                    require!(aux_data.len() >= 64, PolicyEngineError::InvalidRuleHeader);
                    let price = i64::from_le_bytes(
                        aux_data[32..40]
                            .try_into()
                            .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                    );
                    let confidence = u64::from_le_bytes(
                        aux_data[40..48]
                            .try_into()
                            .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                    );
                    let publish_time = i64::from_le_bytes(
                        aux_data[56..64]
                            .try_into()
                            .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                    );
                    require!(
                        publish_time.saturating_add(freshness_secs) >= current_ts,
                        PolicyEngineError::OracleStale
                    );
                    require!(
                        price >= min_q64 && price <= max_q64,
                        PolicyEngineError::OracleOutOfBand
                    );
                    // H3: confidence_bps = confidence * 10_000 / |price|.
                    // Skipped when the rule sets `max_confidence_bps_div4 = 0`.
                    if max_confidence_bps > 0 {
                        let abs_price = if price < 0 {
                            (price as i128).unsigned_abs() as u64
                        } else {
                            price as u64
                        };
                        // price == 0 with confidence > 0 means infinite
                        // uncertainty — reject unconditionally. price == 0
                        // with confidence == 0 is degenerate but not the
                        // adversarial case we care about (oracle would
                        // already fail OracleOutOfBand for any non-trivial
                        // band).
                        if abs_price == 0 {
                            require!(confidence == 0, PolicyEngineError::OracleConfidenceExceeded);
                        } else {
                            let confidence_bps = confidence.saturating_mul(10_000) / abs_price;
                            require!(
                                confidence_bps <= max_confidence_bps,
                                PolicyEngineError::OracleConfidenceExceeded
                            );
                        }
                    }
                }
            }
            KIND_SPENDING_USD => {
                // Update 3 — USD spending-limit dispatch.
                //
                // Fase 2 (2026-05-25): SPENDING_USD needs a TRUSTED per-tx
                // `amount`, which only the normal path carries (bound into
                // metadata_digest + owner signature). The session / OIDC
                // paths don't plumb a per-tx amount, so enforcing here with
                // amount = 0 would silently pass every spend — a forbidden
                // silent bypass of a spending limit. Fail closed instead:
                // owners must keep SPENDING_USD on the normal path only.
                require!(path == PATH_NORMAL, PolicyEngineError::InvalidRuleKind);
                //
                // Reads ONE feed (the moved asset, `asset_index`) from the
                // allowlist, converts `amount` (asset base units) → USD 1e8
                // via the Pyth adapter FeedCache price, and enforces the
                // per-tx / per-day / per-week ceilings. Day/week accumulators
                // are mutated in place (KIND_VELOCITY data_mut_ptr pattern).
                // Layout mirror: see `SpendingUsdRule`.
                //
                // Defense-in-depth: the address binding + header drift checks
                // above already constrain this to a full sub-PDA written by
                // add_rule_spending_usd (always 689 bytes), but assert the
                // exact size so any future refactor or undersized account
                // fails closed instead of panicking on the offset reads below.
                require!(
                    sub_data.len() >= 1 + RULE_HEADER_BYTES + SPENDING_USD_CONFIG_BYTES,
                    PolicyEngineError::InvalidRuleHeader
                );
                let feeds_count = sub_data[98] as usize;
                require!(
                    feeds_count <= MAX_SPENDING_USD_FEEDS,
                    PolicyEngineError::InvalidRuleHeader
                );
                let aidx = asset_index as usize;
                require!(
                    aidx < feeds_count,
                    PolicyEngineError::SpendingAssetNotAllowed
                );

                let freshness_secs = (sub_data[99] as i64).saturating_mul(16);
                let max_confidence_bps = (sub_data[100] as u64).saturating_mul(4);
                let max_per_tx = u64::from_le_bytes(
                    sub_data[105..113]
                        .try_into()
                        .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                );
                let max_per_day = u64::from_le_bytes(
                    sub_data[113..121]
                        .try_into()
                        .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                );
                let max_per_week = u64::from_le_bytes(
                    sub_data[121..129]
                        .try_into()
                        .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                );
                let cur_day_unix = i64::from_le_bytes(
                    sub_data[129..137]
                        .try_into()
                        .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                );
                let cur_day_sum = u64::from_le_bytes(
                    sub_data[137..145]
                        .try_into()
                        .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                );
                let cur_week_unix = i64::from_le_bytes(
                    sub_data[145..153]
                        .try_into()
                        .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                );
                let cur_week_sum = u64::from_le_bytes(
                    sub_data[153..161]
                        .try_into()
                        .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                );
                // Read only the moved asset's feed entry (stack budget: never
                // load all 16 — read just `asset_index` straight from data).
                let fbase = 161 + aidx * SPENDING_USD_FEED_BYTES;
                let mut feed_cache_account = [0u8; 32];
                feed_cache_account.copy_from_slice(&sub_data[fbase..fbase + 32]);
                let decimals = sub_data[fbase + 32];
                let data_len = sub_data.len();
                drop(sub_data);

                // Pull the single aux FeedCache account for the moved asset.
                let aux_view = rem_iter
                    .next()
                    .ok_or(PolicyEngineError::InvalidRuleHeader)?
                    .map_err(|_| PolicyEngineError::InvalidRuleHeader)?;
                require!(
                    aux_view.address().as_array() == &feed_cache_account,
                    PolicyEngineError::SpendingAssetNotAllowed
                );
                require!(
                    is_oracle_owner_allowed(aux_view.owner().as_array()),
                    PolicyEngineError::OracleOwnerMismatch
                );
                let aux_data = aux_view
                    .try_borrow()
                    .map_err(|_| PolicyEngineError::InvalidRuleHeader)?;
                require!(aux_data.len() >= 64, PolicyEngineError::InvalidRuleHeader);
                let price = i64::from_le_bytes(
                    aux_data[32..40]
                        .try_into()
                        .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                );
                let confidence = u64::from_le_bytes(
                    aux_data[40..48]
                        .try_into()
                        .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                );
                let publish_time = i64::from_le_bytes(
                    aux_data[56..64]
                        .try_into()
                        .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
                );
                drop(aux_data);

                // Frescor fail-closed: an old price is never assumed valid.
                require!(
                    publish_time.saturating_add(freshness_secs) >= current_ts,
                    PolicyEngineError::SpendingPriceStale
                );
                // A non-positive price cannot value a spend — reject.
                require!(price > 0, PolicyEngineError::SpendingConversionOverflow);
                // Optional confidence ceiling (same maths as KIND_ORACLE).
                if max_confidence_bps > 0 {
                    let abs_price = price as u64; // price > 0 guaranteed above
                    let confidence_bps = confidence.saturating_mul(10_000) / abs_price;
                    require!(
                        confidence_bps <= max_confidence_bps,
                        PolicyEngineError::SpendingConfidenceExceeded
                    );
                }

                // Convert: amount_usd_1e8 = amount * price / 10^decimals.
                // u128 intermediate; price already USD 1e8; dividing by the
                // asset's base-unit scale brings it back to USD 1e8.
                let pow10 = 10u128
                    .checked_pow(decimals as u32)
                    .ok_or(PolicyEngineError::SpendingConversionOverflow)?;
                let numer = (amount as u128)
                    .checked_mul(price as u128)
                    .ok_or(PolicyEngineError::SpendingConversionOverflow)?;
                let amount_usd_1e8: u64 = (numer / pow10)
                    .try_into()
                    .map_err(|_| PolicyEngineError::SpendingConversionOverflow)?;

                // Per-tx ceiling.
                if max_per_tx > 0 {
                    require!(
                        amount_usd_1e8 <= max_per_tx,
                        PolicyEngineError::SpendingPerTxExceeded
                    );
                }

                // Daily bucket: floor(ts/86400)*86400. Reset on a new bucket.
                let day_bucket = (current_ts / 86_400).saturating_mul(86_400);
                let next_day_sum = if day_bucket != cur_day_unix {
                    amount_usd_1e8
                } else {
                    cur_day_sum.saturating_add(amount_usd_1e8)
                };
                if max_per_day > 0 {
                    require!(
                        next_day_sum <= max_per_day,
                        PolicyEngineError::SpendingDailyExceeded
                    );
                }

                // Weekly bucket: floor(ts/604800)*604800.
                let week_bucket = (current_ts / 604_800).saturating_mul(604_800);
                let next_week_sum = if week_bucket != cur_week_unix {
                    amount_usd_1e8
                } else {
                    cur_week_sum.saturating_add(amount_usd_1e8)
                };
                if max_per_week > 0 {
                    require!(
                        next_week_sum <= max_per_week,
                        PolicyEngineError::SpendingWeeklyExceeded
                    );
                }

                // Write back the accumulators.
                //
                // A2 audit fix (2026-05-25): fail closed if the caller did
                // not pass the sub-PDA as writable.
                require!(
                    sub_view.is_writable(),
                    PolicyEngineError::RuleAccountNotWritable
                );
                // SAFETY: the sub_view is declared writable (checked above),
                // the immutable borrow above was dropped, and no other alias
                // exists. We only touch existing bytes (no resize). Same
                // pattern as KIND_VELOCITY.
                let data_mut: &mut [u8] = unsafe {
                    core::slice::from_raw_parts_mut(sub_view.data_ptr() as *mut u8, data_len)
                };
                data_mut[129..137].copy_from_slice(&day_bucket.to_le_bytes());
                data_mut[137..145].copy_from_slice(&next_day_sum.to_le_bytes());
                data_mut[145..153].copy_from_slice(&week_bucket.to_le_bytes());
                data_mut[153..161].copy_from_slice(&next_week_sum.to_le_bytes());
            }
            KIND_PASSKEY => {
                // F6b — Passkey dispatch.
                //
                // Layout (ABI §3.5.5):
                //   sub_data[97]  config_applies_to u8
                //   sub_data[98]  credentials_count u8
                //   sub_data[99..105] _pad_cfg0
                //   sub_data[105..105 + 128 * N] credentials_flat
                //     each PasskeyCredential (128 B):
                //       [..33]  pubkey (33 B compressed P-256)
                //       [33..64] _pad
                //       [64..96]  rp_id_hash
                //       [96..128] credential_id_hash
                //
                // The user signs the canonical `metadata_digest` via
                // WebAuthn — the caller attaches a Secp256r1 precompile
                // invocation in the same tx whose `(pubkey, message)` is
                // `(credential.pubkey, auth_data || sha256(cdj))`. The
                // clientDataJSON.challenge field MUST embed the
                // base64url-no-pad form of `metadata_digest`. The
                // dispatch routes through `andromeda_auth::verify_signature`
                // scheme=WEBAUTHN, which already handles the anchor check
                // + reconstruction + sysvar lookup.
                //
                // The caller attaches two trailing aux accounts per
                // passkey slot in `remaining_accounts`:
                //   aux[0].data = raw `authenticatorData` bytes
                //   aux[1].data = raw `clientDataJSON` bytes
                // The aux addresses are opaque (any pubkey); only the
                // data content matters. This avoids bloating the ix data
                // with two 192-byte fields on every `request_signature`.
                let count = sub_data[98] as usize;
                require!(
                    count > 0 && count <= MAX_PASSKEY_CREDENTIALS,
                    PolicyEngineError::InvalidRuleHeader
                );
                // Snapshot credential pubkeys (we need them after dropping
                // `sub_data`).
                let mut credentials: [[u8; 33]; MAX_PASSKEY_CREDENTIALS] =
                    [[0u8; 33]; MAX_PASSKEY_CREDENTIALS];
                for i in 0..count {
                    let base = 105 + i * PASSKEY_CREDENTIAL_BYTES;
                    credentials[i].copy_from_slice(&sub_data[base..base + 33]);
                }
                drop(sub_data);

                // Pull aux accounts: auth_data first, then cdj.
                let auth_view = rem_iter
                    .next()
                    .ok_or(PolicyEngineError::PasskeyAssertionInvalid)?
                    .map_err(|_| PolicyEngineError::PasskeyAssertionInvalid)?;
                let cdj_view = rem_iter
                    .next()
                    .ok_or(PolicyEngineError::PasskeyAssertionInvalid)?
                    .map_err(|_| PolicyEngineError::PasskeyAssertionInvalid)?;
                let auth_data_ref = auth_view
                    .try_borrow()
                    .map_err(|_| PolicyEngineError::PasskeyAssertionInvalid)?;
                let cdj_ref = cdj_view
                    .try_borrow()
                    .map_err(|_| PolicyEngineError::PasskeyAssertionInvalid)?;

                // Verify the WebAuthn assertion using the metadata digest
                // as the canonical challenge.
                check_sysvar_addr(sysvar_view.address())?;
                let sysvar_data_ref = sysvar_view
                    .try_borrow()
                    .map_err(|_| PolicyEngineError::AuthFailed)?;

                // Walk the registered credentials and accept the first one
                // whose pubkey matches a Secp256r1 precompile invocation
                // signing `(auth_data || sha256(cdj))`. `verify_signature`
                // also enforces the cdj anchor check on `metadata_digest`.
                let mut accepted = false;
                for i in 0..count {
                    let mut slot = [0u8; MEMBER_SLOT_LEN];
                    slot[0] = SCHEME_WEBAUTHN;
                    slot[1..34].copy_from_slice(&credentials[i]);
                    if verify_signature(VerifyInput {
                        member_slot: &slot,
                        challenge: metadata_digest,
                        instructions_sysvar_data: &sysvar_data_ref,
                        webauthn_auth_data: &auth_data_ref,
                        webauthn_client_data_json: &cdj_ref,
                    })
                    .is_ok()
                    {
                        accepted = true;
                        break;
                    }
                }
                drop(sysvar_data_ref);
                drop(cdj_ref);
                drop(auth_data_ref);
                require!(accepted, PolicyEngineError::PasskeyAssertionInvalid);
            }
            KIND_FHE_GATED => {
                // F7b — FHE-Gated dispatch.
                //
                // Layout (ABI §3.5.6):
                //   sub_data[97]  config_applies_to u8
                //   sub_data[98]  authorities_count u8
                //   sub_data[99]  freshness_seconds_div16 u8
                //   sub_data[100..105] _pad_cfg0
                //   sub_data[105..105 + 32 * N] authorities_flat
                //     each authority = 32-byte Ed25519 pubkey.
                //
                // The on-chain check looks for an Ed25519 precompile
                // invocation in the same tx whose `(pubkey, message)`
                // matches one of the configured authorities and a
                // canonical decision body of:
                //   `andromeda::fhe-decision::v1`
                //   || dwallet (32)
                //   || metadata_digest (32)
                //   || decision_timestamp (8 LE i64)
                //   || authorize (1 byte; MUST be 1)
                //
                // Total decision body = 27 + 32 + 32 + 8 + 1 = 100 bytes.
                let count = sub_data[98] as usize;
                require!(
                    count > 0 && count <= MAX_FHE_AUTHORITIES,
                    PolicyEngineError::InvalidRuleHeader
                );
                let freshness_secs = (sub_data[99] as i64).saturating_mul(16);
                let mut authorities: [[u8; 32]; MAX_FHE_AUTHORITIES] =
                    [[0u8; 32]; MAX_FHE_AUTHORITIES];
                for i in 0..count {
                    let base = 105 + i * 32;
                    authorities[i].copy_from_slice(&sub_data[base..base + 32]);
                }
                drop(sub_data);

                check_sysvar_addr(sysvar_view.address())?;
                let sysvar_data_ref = sysvar_view
                    .try_borrow()
                    .map_err(|_| PolicyEngineError::AuthFailed)?;

                const FHE_DECISION_DOMAIN: &[u8] = b"andromeda::fhe-decision::v1";
                const FHE_DECISION_LEN: usize = FHE_DECISION_DOMAIN.len() + 32 + 32 + 8 + 1;
                // Try every authority. For the matched authority, the
                // precompile lookup also enforces message-byte equality,
                // so we rebuild the canonical decision body for each
                // candidate timestamp range… actually the message has the
                // timestamp embedded, which we don't know up-front. We
                // therefore rely on `precompile::verify_ed25519` returning
                // `NoMatchingInvocation` when (pubkey, prefix) don't match
                // and parse the matched message ourselves once it does.
                //
                // Strategy: walk the Ed25519 precompile invocations in the
                // sysvar, parse each `(pubkey, message)`, and accept if
                // (a) pubkey ∈ authorities, (b) message length == 100,
                // (c) prefix == DOMAIN || dwallet || metadata_digest,
                // (d) authorize == 1, (e) age within freshness window.
                let dwallet_bytes = *dwallet_addr.as_array();
                let mut accepted = false;
                let mut idx = 0usize;
                while let Some((program_id, ix_data)) = read_ix_body_for_fhe(&sysvar_data_ref, idx)
                    .map_err(|_| PolicyEngineError::FheDecisionInvalid)?
                {
                    idx += 1;
                    if program_id != ED25519_PRECOMPILE_ID.as_array().as_slice() {
                        continue;
                    }
                    // Walk every record in this Ed25519 precompile ix
                    // looking for a match. Records use the long-record
                    // 14-byte offsets format documented in
                    // `andromeda_auth::precompile`.
                    if let Some((pk, msg)) = first_ed25519_record_self(ix_data) {
                        if msg.len() != FHE_DECISION_LEN {
                            continue;
                        }
                        // Match pubkey ∈ authorities.
                        let mut found_authority = false;
                        for a in authorities.iter().take(count) {
                            if pk == a.as_slice() {
                                found_authority = true;
                                break;
                            }
                        }
                        if !found_authority {
                            continue;
                        }
                        if &msg[..FHE_DECISION_DOMAIN.len()] != FHE_DECISION_DOMAIN {
                            continue;
                        }
                        let mut off = FHE_DECISION_DOMAIN.len();
                        if &msg[off..off + 32] != &dwallet_bytes[..] {
                            continue;
                        }
                        off += 32;
                        if &msg[off..off + 32] != &metadata_digest[..] {
                            continue;
                        }
                        off += 32;
                        let ts_bytes: [u8; 8] = msg[off..off + 8]
                            .try_into()
                            .map_err(|_| PolicyEngineError::FheDecisionInvalid)?;
                        let decision_ts = i64::from_le_bytes(ts_bytes);
                        off += 8;
                        let authorize = msg[off];
                        if authorize != 1 {
                            continue;
                        }
                        if decision_ts.saturating_add(freshness_secs) < current_ts {
                            continue;
                        }
                        accepted = true;
                        break;
                    }
                }
                drop(sysvar_data_ref);
                require!(accepted, PolicyEngineError::FheDecisionMissing);
            }
            KIND_SESSION_KEY => {
                // The SessionKey rule authenticates the session itself —
                // it is created by `session_open` (disc 100) and enforced
                // by the session entrypoints, never re-run as a dispatch
                // rule. In the NORMAL path a SessionKey rule must never
                // carry APPLIES_NORMAL, so reaching this arm means it was
                // misconfigured -> reject. In the SESSION path it is the
                // expected self-rule (already authenticated by the session
                // signer / OIDC primary) and is skipped here.
                require!(path == PATH_SESSION, PolicyEngineError::InvalidRuleKind);
            }
            KIND_RECOVERY => {
                // Recovery rules belong exclusively to the recovery
                // entrypoints (disc 80/81/87); never enforced here.
                return Err(PolicyEngineError::InvalidRuleKind.into());
            }
            _ => {
                return Err(PolicyEngineError::InvalidRuleKind.into());
            }
        }
        // `sub_data` (if still alive) is dropped here on scope exit.
    }

    // Reject extra trailing accounts: caller must attach exactly one
    // sub-PDA per active rule, no more.
    require!(
        rem_iter.next().is_none(),
        PolicyEngineError::InvalidRuleHeader
    );
    Ok(())
}

#[program]
mod policy_engine_program {
    use super::*;

    /// Disc 0 — bootstrap a `PolicyEngine` PDA.
    ///
    /// Spec: `docs/POLICY_ENGINE_ABI_V3.md` §7.1.
    /// ADRs: PE-003 (default_recovery opt-in), PE-008 (delegation atomicity).
    ///
    /// F0.5 scope: this handler is fully functional EXCEPT that
    /// `default_recovery_present == 1` currently asserts the recovery sub-PDA
    /// passed in is initialized to zeros — full RecoveryConfig population will
    /// land in F9. The challenge already covers the future hash.
    #[instruction(discriminator = 0)]
    pub fn init_engine(
        ctx: Ctx<InitEngine>,
        init_authority_slot: [u8; MEMBER_SLOT_LEN],
        init_authority_hash: Address,
        owner_slot: [u8; MEMBER_SLOT_LEN],
        default_recovery_present: u8,
        default_recovery_hash: [u8; 32],
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();

        // Audit: hash<->slot consistency (PE-008 / ABI §7.1).
        let computed = init_authority_hash_from_slot(&init_authority_slot);
        require!(
            computed == init_authority_hash,
            PolicyEngineError::InvalidInitAuthoritySlot
        );
        validate_slot(&init_authority_slot)
            .map_err(|_| PolicyEngineError::InvalidInitAuthoritySlot)?;
        require!(
            init_authority_slot[0] != SCHEME_WEBAUTHN && init_authority_slot[0] != SCHEME_OIDC_JWT,
            PolicyEngineError::UnsupportedScheme
        );

        validate_slot(&owner_slot).map_err(|_| PolicyEngineError::InvalidOwnerSlot)?;
        require!(
            owner_slot[0] != SCHEME_WEBAUTHN,
            PolicyEngineError::UnsupportedScheme
        );

        // Verify init_authority precompile signature over the canonical
        // init challenge.
        let challenge = policy_engine_init_challenge(
            &dwallet_addr,
            &init_authority_slot,
            &owner_slot,
            default_recovery_present,
            &default_recovery_hash,
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        verify_signature(VerifyInput {
            member_slot: &init_authority_slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &[],
            webauthn_client_data_json: &[],
        })
        .map_err(|_| PolicyEngineError::AuthFailed)?;
        drop(sysvar_data_ref);

        ctx.accounts.engine.set_inner(PolicyEngineInner {
            version: ENGINE_LAYOUT_V1,
            dwallet: dwallet_addr,
            init_authority_slot,
            owner_slot,
            next_admin_nonce: 0,
            next_primary_recover_nonce: 0,
            next_quorum_session_nonce: 0,
            next_oidc_session_nonce: 0,
            next_passkey_session_nonce: 0,
            paused: 0,
            rules_count: 0,
            rules_generation: 0,
            _pad_head: [0u8; 6],
            rules_flat: [0u8; RULES_FLAT_BYTES],
            _pad_tail: [0u8; 8],
        });

        ctx.accounts.program.emit_event(
            &EngineInitialized {
                engine: engine_addr,
                dwallet: dwallet_addr,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 1 — normal signing path.
    ///
    /// F8a: dispatches every active rule (up to `MAX_RULES`). Sub-PDAs travel
    /// as trailing `remaining_accounts` in ascending slot order — one account
    /// per active slot (kind != EMPTY && enabled == 1). Account convention:
    ///
    /// ```text
    /// declared_accounts[0..12]  // dwallet, engine, coordinator, message_approval,
    ///                           // payer, cpi_auth, caller_program, dwallet_program,
    ///                           // clock, system_program, event_authority, program
    /// remaining_accounts[..]    // sub-PDA per active rule, ascending by slot index
    /// ```
    ///
    /// Each remaining account must be `writable`: kinds with runtime counters
    /// (Velocity, SessionKey, Recovery) mutate via `data_ptr()`; read-only
    /// kinds (Allowlist, TimeLock, Oracle/Passkey/FheGated) simply don't write.
    ///
    /// Rules whose `applies_to` mask excludes `PATH_NORMAL` are header-validated
    /// (drift check) but NOT enforced — so e.g. a Recovery rule (applies_to =
    /// RECOVERY only) does not block normal signing, but is still verified to
    /// be the authentic sub-PDA recorded in `engine.rules_flat[slot]`.
    #[instruction(discriminator = 1)]
    #[allow(clippy::too_many_arguments)]
    pub fn request_signature(
        ctx: CtxWithRemaining<RequestSignature>,
        _init_authority_hash: Address,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
        destination: [u8; 32],
        rules_generation_seen: u32,
        // Update 3 (ABI V2): the asset amount (base units) and the index of the
        // asset in the active KIND_SPENDING_USD allowlist. Bound into the
        // metadata_digest below. Ignored by every other rule kind; pass 0/0 when
        // no spending rule is active.
        amount: u64,
        asset_index: u8,
        // Update 6 (ABI V3): the Ika `message_metadata_digest` forwarded to
        // `approve_message`. Opaque 32 bytes — the program does NOT interpret it
        // (Zcash BLAKE2b personal, future sr25519 context, etc. all live
        // off-chain). `[0u8; 32]` (the default for every chain without signing
        // metadata) reproduces the prior behaviour. NOT bound to the Andromeda
        // `metadata_digest` above — they are independent bindings.
        ika_msg_metadata_digest: [u8; 32],
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let request_hash = Address::from(message_digest);

        ctx.accounts.program.emit_event(
            &SignatureRequested {
                engine: engine_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;

        require!(
            ctx.accounts.engine.paused == 0,
            PolicyEngineError::EnginePaused
        );

        let on_chain_gen: u32 = ctx.accounts.engine.rules_generation.into();
        require!(
            on_chain_gen == rules_generation_seen,
            PolicyEngineError::InvalidRuleHeader
        );

        // Validate metadata_digest against canonical computation.
        let expected_md = request_metadata_digest(
            &engine_addr,
            &dwallet_addr,
            &message_digest,
            &destination,
            &user_pubkey,
            signature_scheme,
            PATH_NORMAL,
            on_chain_gen,
            amount,
            asset_index,
        );
        require!(
            metadata_digest == expected_md,
            PolicyEngineError::AuthFailed
        );

        // Fase 1 (A1, 2026-05-25): zero-trust owner authorization. The gateway
        // can never relay a normal-path signature without the dWallet owner's
        // consent — the `owner_slot` must sign the `normal_use_challenge` (which
        // binds `metadata_digest` = the full request) via a precompile in THIS
        // transaction. There is no per-request nonce in the challenge by design:
        // anti-replay is the Ika MessageApproval PDA (derived from
        // `message_digest`, so re-approving the same message fails) plus the
        // destination-chain tx's own nonce/blockhash. WebAuthn/passkey primaries authorize
        // via the KIND_PASSKEY rule (step-up) or a session, not here — same
        // exclusion `verify_owner_admin` applies to the admin path.
        let owner_slot = ctx.accounts.engine.owner_slot;
        require!(
            owner_slot[0] != SCHEME_WEBAUTHN,
            PolicyEngineError::UnsupportedScheme
        );
        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len = human_message::normal_sign_message(
            &mut human_buf,
            &dwallet_addr,
            &destination,
            amount,
            signature_scheme,
        )
        .map_err(PolicyEngineError::from)?;
        let auth_challenge = normal_use_challenge(
            &human_buf[..human_len],
            &engine_addr,
            &dwallet_addr,
            &metadata_digest,
            &owner_slot,
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        verify_signature(VerifyInput {
            member_slot: &owner_slot,
            challenge: &auth_challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &[],
            webauthn_client_data_json: &[],
        })
        .map_err(|_| PolicyEngineError::AuthFailed)?;
        drop(sysvar_data_ref);

        // Local CPI defense (mirror of allowlist-destinations).
        require!(
            validate_ika_cpi_accounts(
                &ctx.accounts.dwallet_program.to_account_view(),
                &ctx.accounts.dwallet_account.to_account_view(),
            ),
            PolicyEngineError::IkaCpiAccountMismatch
        );

        // F8a: dispatch loop factored into `dispatch_active_rules` so the
        // session (disc 101) and OIDC-session (disc 107) paths enforce the
        // same rules (Fase 2). The caller attaches exactly one remaining
        // account per active slot in ascending order; PATH_NORMAL enforces
        // rules whose `applies_to` mask includes the normal path.
        let remaining = ctx.remaining_accounts();
        let mut rem_iter = remaining.iter();
        dispatch_active_rules(
            &ctx.accounts.engine.rules_flat,
            &mut rem_iter,
            &sysvar_view,
            current_ts,
            &dwallet_addr,
            &destination,
            amount,
            asset_index,
            &metadata_digest,
            PATH_NORMAL,
            None,
        )?;

        // CPI Ika approve_message — the last side-effect of the instruction.
        // Anti-replay of this normal-path authorization is the Ika MessageApproval
        // PDA (derived from message_digest): re-approving the same message fails
        // because the PDA already exists. The owner authorization above binds the
        // full request via metadata_digest, so the gateway cannot alter any field.
        invoke_ika_approve_message(
            &ctx.accounts.dwallet_program.to_account_view(),
            &ctx.accounts.cpi_authority.to_account_view(),
            // F9-COORD: the Ika caller_program must be THIS program's id — Ika
            // derives the signing authority as PDA(["__ika_cpi_authority"],
            // caller_program) and requires it to sign. Use the `program`
            // account (= policy-engine id, executable). The separate
            // `caller_program` slot stays in the context (now unused) so the
            // instruction account layout is unchanged.
            &ctx.accounts.program.to_account_view(),
            cpi_authority_bump,
            &ctx.accounts.coordinator.to_account_view(),
            &ctx.accounts.message_approval.to_account_view(),
            &ctx.accounts.dwallet_account.to_account_view(),
            &ctx.accounts.payer.to_account_view(),
            &ctx.accounts.system_program.to_account_view(),
            message_digest,
            // Update 6 (ABI V3): forward the caller-supplied Ika
            // message_metadata_digest. `[0u8; 32]` (the default for every chain
            // without signing metadata) keeps the prior F9-SIGN behaviour — the
            // network derives the MessageApproval WITHOUT a metadata seed. For
            // Zcash (and future sr25519) it is non-zero, and the gateway derived
            // the MessageApproval PDA with the matching metadata seed. This is
            // independent of the Andromeda policy `metadata_digest` enforced above.
            ika_msg_metadata_digest,
            user_pubkey,
            signature_scheme,
            message_approval_bump,
        )?;

        ctx.accounts.program.emit_event(
            &SignatureApproved {
                engine: engine_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 10 — `add_rule_allowlist`.
    ///
    /// PE-011: this initialises the rule with `destinations_count = 0`. The
    /// owner adds destinations one-by-one via `update_rule_allowlist_add_destination`
    /// (disc 120). This keeps the tx well under the 1232-byte Solana limit
    /// (F0.5 discovery).
    #[instruction(discriminator = 10)]
    pub fn add_rule_allowlist(
        ctx: Ctx<AddRuleAllowlist>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        rule_index: u8,
        config_applies_to: u8,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        require!(
            (rule_index as usize) < MAX_RULES,
            PolicyEngineError::TooManyRules
        );
        require!(
            (config_applies_to & !APPLIES_ALL) == 0 && config_applies_to != 0,
            PolicyEngineError::RuleNotApplicable
        );

        // Singleton kind enforcement (ADR PE-002).
        for s in 0..MAX_RULES {
            let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, s);
            if entry.kind == KIND_ALLOWLIST && entry.enabled == 1 {
                return Err(PolicyEngineError::RuleAlreadyActive.into());
            }
        }
        let slot = rule_index as usize;
        let existing = read_rule_entry(&ctx.accounts.engine.rules_flat, slot);
        require!(existing.is_empty(), PolicyEngineError::RuleSlotInUse);

        // Canonical empty config_hash (no destinations yet).
        let applies_b = [config_applies_to];
        let zero_count = [0u8];
        let empty_destinations = [0u8; 1024];
        let config_hash = hashv(&[
            b"allowlist-config-v1",
            &applies_b,
            &zero_count,
            &empty_destinations,
        ]);
        let new_generation = existing.generation.saturating_add(1);

        // Human-readable message (clear-signing v2).
        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];

        let gen_le = new_generation.to_le_bytes();
        let challenge = admin_challenge(
            OP_ADD_ALLOWLIST,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_ALLOWLIST,
            rule_index,
            new_generation,
            on_chain_nonce,
            &config_hash,
            &owner_slot,
            &[&applies_b, &gen_le],
        );

        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        // Initialize the sub-PDA with empty allowlist.
        let rule_addr = *ctx.accounts.rule_pda.address();
        ctx.accounts.rule_pda.set_inner(AllowlistRuleInner {
            kind: KIND_ALLOWLIST,
            index: rule_index,
            enabled: 1,
            _pad0: 0,
            generation: new_generation,
            config_version: 1,
            _pad1: [0u8; 4],
            engine: engine_addr,
            next_admin_nonce: 0,
            config_hash,
            _pad_header_tail: [0u8; 8],
            config_applies_to,
            destinations_count: 0,
            _pad_cfg0: [0u8; 6],
            destinations_flat: empty_destinations,
        });

        // Update engine header.
        let new_entry = RuleEntry {
            kind: KIND_ALLOWLIST,
            bump: 0, // Quasar resolves bumps via #[seeds] at validation time.
            version: RULE_HEADER_V1,
            enabled: 1,
            generation: new_generation,
            rule_pda: rule_addr,
            config_hash,
        };
        write_rule_entry(&mut ctx.accounts.engine.rules_flat, slot, &new_entry);
        let cur_count: u8 = ctx.accounts.engine.rules_count;
        // M1 audit fix: counters bounded by `MAX_RULES` and engine slot limit
        // (RuleSlotInUse) so overflow is unreachable, but `checked_add` makes
        // the invariant explicit and prevents drift if bounds change.
        ctx.accounts.engine.rules_count = cur_count
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?;
        let cur_gen: u32 = ctx.accounts.engine.rules_generation.into();
        ctx.accounts.engine.rules_generation = cur_gen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();

        ctx.accounts.program.emit_event(
            &RuleAdded {
                engine: engine_addr,
                ts: current_ts,
                kind: KIND_ALLOWLIST as u64,
                rule_index: rule_index as u64,
                generation: new_generation as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 17 — `add_rule_recovery`.
    ///
    /// Disc 11 — `add_rule_velocity` (F3).
    ///
    /// Count-based rate limit: up to 4 windows × {window_seconds, cap}. The
    /// runtime mutable counters (`current_count`, `window_start_ts`) are
    /// initialized to zero and advance on every `request_signature`.
    #[instruction(discriminator = 11)]
    #[allow(clippy::too_many_arguments)]
    pub fn add_rule_velocity(
        ctx: Ctx<AddRuleVelocity>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        rule_index: u8,
        config_applies_to: u8,
        windows_count: u8,
        // 4 × VelocityWindowConfig (16 bytes each: window_seconds u64 + cap u64).
        windows_config: [u8; 4 * 16],
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        require!(
            (rule_index as usize) < MAX_RULES,
            PolicyEngineError::TooManyRules
        );
        require!(
            (config_applies_to & !APPLIES_ALL) == 0 && config_applies_to != 0,
            PolicyEngineError::RuleNotApplicable
        );
        require!(
            windows_count >= 1 && (windows_count as usize) <= MAX_VELOCITY_WINDOWS,
            PolicyEngineError::InvalidRuleHeader
        );

        // Singleton kind enforcement (PE-002).
        for s in 0..MAX_RULES {
            let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, s);
            if entry.kind == KIND_VELOCITY && entry.enabled == 1 {
                return Err(PolicyEngineError::RuleAlreadyActive.into());
            }
        }
        let slot = rule_index as usize;
        let existing = read_rule_entry(&ctx.accounts.engine.rules_flat, slot);
        require!(existing.is_empty(), PolicyEngineError::RuleSlotInUse);

        // Validate window_seconds > 0 and cap > 0 for each declared window.
        for i in 0..(windows_count as usize) {
            let base = i * 16;
            let window_seconds = u64::from_le_bytes(
                windows_config[base..base + 8]
                    .try_into()
                    .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
            );
            let cap = u64::from_le_bytes(
                windows_config[base + 8..base + 16]
                    .try_into()
                    .map_err(|_| PolicyEngineError::InvalidRuleHeader)?,
            );
            require!(
                window_seconds > 0 && cap > 0,
                PolicyEngineError::InvalidRuleHeader
            );
        }

        // Build the canonical `windows_flat` payload (48 bytes per window:
        // [window_seconds || cap || current_count=0 || _reserved_sum=0 ||
        // window_start_ts=0 || _pad]).
        let mut windows_flat = [0u8; 4 * 48];
        for i in 0..(windows_count as usize) {
            let src = i * 16;
            let dst = i * 48;
            windows_flat[dst..dst + 16].copy_from_slice(&windows_config[src..src + 16]);
            // current_count / _reserved_sum / window_start_ts / _pad already 0.
        }

        let applies_b = [config_applies_to];
        let count_b = [windows_count];
        let config_hash = hashv(&[b"velocity-config-v1", &applies_b, &count_b, &windows_flat]);
        let new_generation = existing.generation.saturating_add(1);

        // Reuse the allowlist_pause renderer for now (TODO F3: dedicated
        // velocity_add_rule renderer in `andromeda_auth::human_message`).
        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];

        let gen_le = new_generation.to_le_bytes();
        let challenge = admin_challenge(
            OP_ADD_VELOCITY,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_VELOCITY,
            rule_index,
            new_generation,
            on_chain_nonce,
            &config_hash,
            &owner_slot,
            &[&applies_b, &count_b, &gen_le, &windows_flat],
        );

        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        let rule_addr = *ctx.accounts.rule_pda.address();
        ctx.accounts.rule_pda.set_inner(VelocityRuleInner {
            kind: KIND_VELOCITY,
            index: rule_index,
            enabled: 1,
            _pad0: 0,
            generation: new_generation,
            config_version: 1,
            _pad1: [0u8; 4],
            engine: engine_addr,
            next_admin_nonce: 0,
            config_hash,
            _pad_header_tail: [0u8; 8],
            config_applies_to,
            windows_count,
            _pad_cfg0: [0u8; 6],
            windows_flat,
        });

        let new_entry = RuleEntry {
            kind: KIND_VELOCITY,
            bump: 0,
            version: RULE_HEADER_V1,
            enabled: 1,
            generation: new_generation,
            rule_pda: rule_addr,
            config_hash,
        };
        write_rule_entry(&mut ctx.accounts.engine.rules_flat, slot, &new_entry);
        let cur_count: u8 = ctx.accounts.engine.rules_count;
        // M1 audit fix: counters bounded by `MAX_RULES` and engine slot limit
        // (RuleSlotInUse) so overflow is unreachable, but `checked_add` makes
        // the invariant explicit and prevents drift if bounds change.
        ctx.accounts.engine.rules_count = cur_count
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?;
        let cur_gen: u32 = ctx.accounts.engine.rules_generation.into();
        ctx.accounts.engine.rules_generation = cur_gen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();

        ctx.accounts.program.emit_event(
            &RuleAdded {
                engine: engine_addr,
                ts: current_ts,
                kind: KIND_VELOCITY as u64,
                rule_index: rule_index as u64,
                generation: new_generation as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 12 — `add_rule_time_lock` (F4).
    ///
    /// mode = 0 (absolute): unlocks when `current_ts >= unlock_ts`.
    /// mode = 1 (delay):    unlocks when `current_ts >= created_at_ts + delay_seconds`.
    #[instruction(discriminator = 12)]
    #[allow(clippy::too_many_arguments)]
    pub fn add_rule_time_lock(
        ctx: Ctx<AddRuleTimeLock>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        rule_index: u8,
        config_applies_to: u8,
        mode: u8,
        unlock_ts: i64,
        delay_seconds: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        require!(
            (rule_index as usize) < MAX_RULES,
            PolicyEngineError::TooManyRules
        );
        require!(
            (config_applies_to & !APPLIES_ALL) == 0 && config_applies_to != 0,
            PolicyEngineError::RuleNotApplicable
        );
        require!(
            mode == TIME_LOCK_MODE_ABSOLUTE || mode == TIME_LOCK_MODE_DELAY,
            PolicyEngineError::InvalidRuleHeader
        );

        for s in 0..MAX_RULES {
            let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, s);
            if entry.kind == KIND_TIME_LOCK && entry.enabled == 1 {
                return Err(PolicyEngineError::RuleAlreadyActive.into());
            }
        }
        let slot = rule_index as usize;
        let existing = read_rule_entry(&ctx.accounts.engine.rules_flat, slot);
        require!(existing.is_empty(), PolicyEngineError::RuleSlotInUse);

        let applies_b = [config_applies_to];
        let mode_b = [mode];
        let unlock_le = unlock_ts.to_le_bytes();
        let delay_le = delay_seconds.to_le_bytes();
        // created_at_ts is runtime state (clock-derived at creation), NOT
        // part of the canonical config_hash — otherwise client and program
        // would never agree on the challenge bytes.
        let config_hash = hashv(&[
            b"time-lock-config-v1",
            &applies_b,
            &mode_b,
            &unlock_le,
            &delay_le,
        ]);
        let new_generation = existing.generation.saturating_add(1);

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];

        let gen_le = new_generation.to_le_bytes();
        let challenge = admin_challenge(
            OP_ADD_TIME_LOCK,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_TIME_LOCK,
            rule_index,
            new_generation,
            on_chain_nonce,
            &config_hash,
            &owner_slot,
            &[&applies_b, &mode_b, &unlock_le, &delay_le, &gen_le],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        let rule_addr = *ctx.accounts.rule_pda.address();
        ctx.accounts.rule_pda.set_inner(TimeLockRuleInner {
            kind: KIND_TIME_LOCK,
            index: rule_index,
            enabled: 1,
            _pad0: 0,
            generation: new_generation,
            config_version: 1,
            _pad1: [0u8; 4],
            engine: engine_addr,
            next_admin_nonce: 0,
            config_hash,
            _pad_header_tail: [0u8; 8],
            config_applies_to,
            mode,
            _pad_cfg0: [0u8; 6],
            unlock_ts,
            delay_seconds,
            created_at_ts: current_ts,
        });
        let new_entry = RuleEntry {
            kind: KIND_TIME_LOCK,
            bump: 0,
            version: RULE_HEADER_V1,
            enabled: 1,
            generation: new_generation,
            rule_pda: rule_addr,
            config_hash,
        };
        write_rule_entry(&mut ctx.accounts.engine.rules_flat, slot, &new_entry);
        let cur_count: u8 = ctx.accounts.engine.rules_count;
        // M1 audit fix: counters bounded by `MAX_RULES` and engine slot limit
        // (RuleSlotInUse) so overflow is unreachable, but `checked_add` makes
        // the invariant explicit and prevents drift if bounds change.
        ctx.accounts.engine.rules_count = cur_count
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?;
        let cur_gen: u32 = ctx.accounts.engine.rules_generation.into();
        ctx.accounts.engine.rules_generation = cur_gen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();

        ctx.accounts.program.emit_event(
            &RuleAdded {
                engine: engine_addr,
                ts: current_ts,
                kind: KIND_TIME_LOCK as u64,
                rule_index: rule_index as u64,
                generation: new_generation as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 13 — `add_rule_oracle` (F5 storage; feeds added via disc 122 in F5c).
    #[instruction(discriminator = 13)]
    #[allow(clippy::too_many_arguments)]
    pub fn add_rule_oracle(
        ctx: Ctx<AddRuleOracle>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        rule_index: u8,
        config_applies_to: u8,
        freshness_seconds_div16: u8,
        min_confidence_bps_div4: u8,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        require!(
            (rule_index as usize) < MAX_RULES,
            PolicyEngineError::TooManyRules
        );
        require!(
            (config_applies_to & !APPLIES_ALL) == 0 && config_applies_to != 0,
            PolicyEngineError::RuleNotApplicable
        );
        // B4 audit fix (2026-05-25): freshness == 0 makes the dispatch require
        // `publish_time >= now`, which rejects every real (past-timestamped)
        // price — a silent fail-closed footgun. Reject at creation time.
        require!(
            freshness_seconds_div16 > 0,
            PolicyEngineError::InvalidRuleHeader
        );
        for s in 0..MAX_RULES {
            let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, s);
            if entry.kind == KIND_ORACLE && entry.enabled == 1 {
                return Err(PolicyEngineError::RuleAlreadyActive.into());
            }
        }
        let slot = rule_index as usize;
        let existing = read_rule_entry(&ctx.accounts.engine.rules_flat, slot);
        require!(existing.is_empty(), PolicyEngineError::RuleSlotInUse);

        let empty_feeds = [0u8; 4 * 80];
        let applies_b = [config_applies_to];
        let fresh_b = [freshness_seconds_div16];
        let conf_b = [min_confidence_bps_div4];
        let zero_count = [0u8];
        let config_hash = hashv(&[
            b"oracle-config-v1",
            &applies_b,
            &zero_count,
            &fresh_b,
            &conf_b,
            &empty_feeds,
        ]);
        let new_generation = existing.generation.saturating_add(1);

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];

        let gen_le = new_generation.to_le_bytes();
        let challenge = admin_challenge(
            OP_ADD_ORACLE,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_ORACLE,
            rule_index,
            new_generation,
            on_chain_nonce,
            &config_hash,
            &owner_slot,
            &[&applies_b, &fresh_b, &conf_b, &gen_le],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        let rule_addr = *ctx.accounts.rule_pda.address();
        ctx.accounts.rule_pda.set_inner(OracleRuleInner {
            kind: KIND_ORACLE,
            index: rule_index,
            enabled: 1,
            _pad0: 0,
            generation: new_generation,
            config_version: 1,
            _pad1: [0u8; 4],
            engine: engine_addr,
            next_admin_nonce: 0,
            config_hash,
            _pad_header_tail: [0u8; 8],
            config_applies_to,
            feeds_count: 0,
            freshness_seconds_div16,
            min_confidence_bps_div4,
            _pad_cfg0: [0u8; 4],
            feeds_flat: empty_feeds,
        });
        let new_entry = RuleEntry {
            kind: KIND_ORACLE,
            bump: 0,
            version: RULE_HEADER_V1,
            enabled: 1,
            generation: new_generation,
            rule_pda: rule_addr,
            config_hash,
        };
        write_rule_entry(&mut ctx.accounts.engine.rules_flat, slot, &new_entry);
        let cur_count: u8 = ctx.accounts.engine.rules_count;
        // M1 audit fix: counters bounded by `MAX_RULES` and engine slot limit
        // (RuleSlotInUse) so overflow is unreachable, but `checked_add` makes
        // the invariant explicit and prevents drift if bounds change.
        ctx.accounts.engine.rules_count = cur_count
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?;
        let cur_gen: u32 = ctx.accounts.engine.rules_generation.into();
        ctx.accounts.engine.rules_generation = cur_gen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();

        ctx.accounts.program.emit_event(
            &RuleAdded {
                engine: engine_addr,
                ts: current_ts,
                kind: KIND_ORACLE as u64,
                rule_index: rule_index as u64,
                generation: new_generation as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 18 — `add_rule_spending_usd` (Update 3 — KIND_SPENDING_USD storage).
    ///
    /// Creates a USD spending-limit rule with `feeds_count = 0` and the
    /// per-tx / per-day / per-week USD ceilings (canonical 1e8, 0 = window
    /// disabled). Assets are added one-by-one via
    /// `update_rule_spending_usd_add_feed` (disc 19) — a rule with zero feeds
    /// enforces nothing. Accumulators start zeroed. Owner-signed
    /// `OP_ADD_SPENDING_USD` admin challenge (clear-signing on the caps).
    #[instruction(discriminator = 18)]
    #[allow(clippy::too_many_arguments)]
    pub fn add_rule_spending_usd(
        ctx: Ctx<AddRuleSpendingUsd>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        rule_index: u8,
        config_applies_to: u8,
        freshness_seconds_div16: u8,
        max_confidence_bps_div4: u8,
        max_per_tx_usd: u64,
        max_per_day_usd: u64,
        max_per_week_usd: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        require!(
            (rule_index as usize) < MAX_RULES,
            PolicyEngineError::TooManyRules
        );
        // Review fix (2026-05-25): SPENDING_USD can only be ENFORCED on the
        // NORMAL path — it needs a trusted per-tx `amount` (bound into
        // metadata_digest + owner signature), which the session / OIDC paths do
        // not carry. Restrict the mask to exactly APPLIES_NORMAL so a
        // misconfigured rule fails HERE with a clear error instead of silently
        // bricking session signing later (the dispatch's `path == PATH_NORMAL`
        // guard remains as runtime defense-in-depth). Subsumes the generic
        // `(applies_to & !APPLIES_ALL) == 0 && != 0` validity check.
        require!(
            config_applies_to == APPLIES_NORMAL,
            PolicyEngineError::RuleNotApplicable
        );
        // B4 audit fix (2026-05-25): freshness == 0 would make the spending
        // dispatch require `publish_time >= now`, rejecting every real price.
        require!(
            freshness_seconds_div16 > 0,
            PolicyEngineError::InvalidRuleHeader
        );
        for s in 0..MAX_RULES {
            let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, s);
            if entry.kind == KIND_SPENDING_USD && entry.enabled == 1 {
                return Err(PolicyEngineError::RuleAlreadyActive.into());
            }
        }
        let slot = rule_index as usize;
        let existing = read_rule_entry(&ctx.accounts.engine.rules_flat, slot);
        require!(existing.is_empty(), PolicyEngineError::RuleSlotInUse);

        let empty_feeds = [0u8; MAX_SPENDING_USD_FEEDS * SPENDING_USD_FEED_BYTES];
        let applies_b = [config_applies_to];
        let fresh_b = [freshness_seconds_div16];
        let conf_b = [max_confidence_bps_div4];
        let zero_count = [0u8];
        // Caps travel as one 24-byte LE block in both the config_hash and the
        // admin challenge so the approver signs over the exact ceilings.
        let mut caps = [0u8; 24];
        caps[0..8].copy_from_slice(&max_per_tx_usd.to_le_bytes());
        caps[8..16].copy_from_slice(&max_per_day_usd.to_le_bytes());
        caps[16..24].copy_from_slice(&max_per_week_usd.to_le_bytes());
        let config_hash = hashv(&[
            b"spending-usd-config-v1",
            &applies_b,
            &zero_count,
            &fresh_b,
            &conf_b,
            &caps,
            &empty_feeds,
        ]);
        let new_generation = existing.generation.saturating_add(1);

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len = human_message::spending_usd_add_message(
            &mut human_buf,
            max_per_tx_usd,
            max_per_day_usd,
            max_per_week_usd,
            &engine_addr,
            &dwallet_addr,
        )
        .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];

        let gen_le = new_generation.to_le_bytes();
        let challenge = admin_challenge(
            OP_ADD_SPENDING_USD,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_SPENDING_USD,
            rule_index,
            new_generation,
            on_chain_nonce,
            &config_hash,
            &owner_slot,
            &[&applies_b, &fresh_b, &conf_b, &caps, &gen_le],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        let rule_addr = *ctx.accounts.rule_pda.address();
        ctx.accounts.rule_pda.set_inner(SpendingUsdRuleInner {
            kind: KIND_SPENDING_USD,
            index: rule_index,
            enabled: 1,
            _pad0: 0,
            generation: new_generation,
            config_version: 1,
            _pad1: [0u8; 4],
            engine: engine_addr,
            next_admin_nonce: 0,
            config_hash,
            _pad_header_tail: [0u8; 8],
            config_applies_to,
            feeds_count: 0,
            freshness_seconds_div16,
            max_confidence_bps_div4,
            _pad_cfg0: [0u8; 4],
            max_per_tx_usd,
            max_per_day_usd,
            max_per_week_usd,
            current_day_unix: 0,
            current_day_sum_usd: 0,
            current_week_unix: 0,
            current_week_sum_usd: 0,
            feeds_flat: empty_feeds,
        });
        let new_entry = RuleEntry {
            kind: KIND_SPENDING_USD,
            bump: 0,
            version: RULE_HEADER_V1,
            enabled: 1,
            generation: new_generation,
            rule_pda: rule_addr,
            config_hash,
        };
        write_rule_entry(&mut ctx.accounts.engine.rules_flat, slot, &new_entry);
        let cur_count: u8 = ctx.accounts.engine.rules_count;
        ctx.accounts.engine.rules_count = cur_count
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?;
        let cur_gen: u32 = ctx.accounts.engine.rules_generation.into();
        ctx.accounts.engine.rules_generation = cur_gen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();

        ctx.accounts.program.emit_event(
            &RuleAdded {
                engine: engine_addr,
                ts: current_ts,
                kind: KIND_SPENDING_USD as u64,
                rule_index: rule_index as u64,
                generation: new_generation as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 14 — `add_rule_passkey` (F6 storage; credentials added via disc 124 in F6c).
    #[instruction(discriminator = 14)]
    pub fn add_rule_passkey(
        ctx: Ctx<AddRulePasskey>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        rule_index: u8,
        config_applies_to: u8,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        require!(
            (rule_index as usize) < MAX_RULES,
            PolicyEngineError::TooManyRules
        );
        require!(
            (config_applies_to & !APPLIES_ALL) == 0 && config_applies_to != 0,
            PolicyEngineError::RuleNotApplicable
        );
        for s in 0..MAX_RULES {
            let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, s);
            if entry.kind == KIND_PASSKEY && entry.enabled == 1 {
                return Err(PolicyEngineError::RuleAlreadyActive.into());
            }
        }
        let slot = rule_index as usize;
        let existing = read_rule_entry(&ctx.accounts.engine.rules_flat, slot);
        require!(existing.is_empty(), PolicyEngineError::RuleSlotInUse);

        let empty_creds = [0u8; 4 * 128];
        let applies_b = [config_applies_to];
        let zero_count = [0u8];
        let config_hash = hashv(&[b"passkey-config-v1", &applies_b, &zero_count, &empty_creds]);
        let new_generation = existing.generation.saturating_add(1);

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];

        let gen_le = new_generation.to_le_bytes();
        let challenge = admin_challenge(
            OP_ADD_PASSKEY,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_PASSKEY,
            rule_index,
            new_generation,
            on_chain_nonce,
            &config_hash,
            &owner_slot,
            &[&applies_b, &gen_le],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        let rule_addr = *ctx.accounts.rule_pda.address();
        ctx.accounts.rule_pda.set_inner(PasskeyRuleInner {
            kind: KIND_PASSKEY,
            index: rule_index,
            enabled: 1,
            _pad0: 0,
            generation: new_generation,
            config_version: 1,
            _pad1: [0u8; 4],
            engine: engine_addr,
            next_admin_nonce: 0,
            config_hash,
            _pad_header_tail: [0u8; 8],
            config_applies_to,
            credentials_count: 0,
            _pad_cfg0: [0u8; 6],
            credentials_flat: empty_creds,
        });
        let new_entry = RuleEntry {
            kind: KIND_PASSKEY,
            bump: 0,
            version: RULE_HEADER_V1,
            enabled: 1,
            generation: new_generation,
            rule_pda: rule_addr,
            config_hash,
        };
        write_rule_entry(&mut ctx.accounts.engine.rules_flat, slot, &new_entry);
        let cur_count: u8 = ctx.accounts.engine.rules_count;
        // M1 audit fix: counters bounded by `MAX_RULES` and engine slot limit
        // (RuleSlotInUse) so overflow is unreachable, but `checked_add` makes
        // the invariant explicit and prevents drift if bounds change.
        ctx.accounts.engine.rules_count = cur_count
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?;
        let cur_gen: u32 = ctx.accounts.engine.rules_generation.into();
        ctx.accounts.engine.rules_generation = cur_gen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();

        ctx.accounts.program.emit_event(
            &RuleAdded {
                engine: engine_addr,
                ts: current_ts,
                kind: KIND_PASSKEY as u64,
                rule_index: rule_index as u64,
                generation: new_generation as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 15 — `add_rule_fhe_gated` (F7 storage; authorities added via disc 126 in F7c).
    #[instruction(discriminator = 15)]
    pub fn add_rule_fhe_gated(
        ctx: Ctx<AddRuleFheGated>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        rule_index: u8,
        config_applies_to: u8,
        freshness_seconds_div16: u8,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        require!(
            (rule_index as usize) < MAX_RULES,
            PolicyEngineError::TooManyRules
        );
        require!(
            (config_applies_to & !APPLIES_ALL) == 0 && config_applies_to != 0,
            PolicyEngineError::RuleNotApplicable
        );
        for s in 0..MAX_RULES {
            let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, s);
            if entry.kind == KIND_FHE_GATED && entry.enabled == 1 {
                return Err(PolicyEngineError::RuleAlreadyActive.into());
            }
        }
        let slot = rule_index as usize;
        let existing = read_rule_entry(&ctx.accounts.engine.rules_flat, slot);
        require!(existing.is_empty(), PolicyEngineError::RuleSlotInUse);

        let empty_auth = [0u8; 4 * 32];
        let applies_b = [config_applies_to];
        let fresh_b = [freshness_seconds_div16];
        let zero_count = [0u8];
        let config_hash = hashv(&[
            b"fhe-gated-config-v1",
            &applies_b,
            &zero_count,
            &fresh_b,
            &empty_auth,
        ]);
        let new_generation = existing.generation.saturating_add(1);

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];

        let gen_le = new_generation.to_le_bytes();
        let challenge = admin_challenge(
            OP_ADD_FHE_GATED,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_FHE_GATED,
            rule_index,
            new_generation,
            on_chain_nonce,
            &config_hash,
            &owner_slot,
            &[&applies_b, &fresh_b, &gen_le],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        let rule_addr = *ctx.accounts.rule_pda.address();
        ctx.accounts.rule_pda.set_inner(FheGatedRuleInner {
            kind: KIND_FHE_GATED,
            index: rule_index,
            enabled: 1,
            _pad0: 0,
            generation: new_generation,
            config_version: 1,
            _pad1: [0u8; 4],
            engine: engine_addr,
            next_admin_nonce: 0,
            config_hash,
            _pad_header_tail: [0u8; 8],
            config_applies_to,
            authorities_count: 0,
            freshness_seconds_div16,
            _pad_cfg0: [0u8; 5],
            authorities_flat: empty_auth,
        });
        let new_entry = RuleEntry {
            kind: KIND_FHE_GATED,
            bump: 0,
            version: RULE_HEADER_V1,
            enabled: 1,
            generation: new_generation,
            rule_pda: rule_addr,
            config_hash,
        };
        write_rule_entry(&mut ctx.accounts.engine.rules_flat, slot, &new_entry);
        let cur_count: u8 = ctx.accounts.engine.rules_count;
        // M1 audit fix: counters bounded by `MAX_RULES` and engine slot limit
        // (RuleSlotInUse) so overflow is unreachable, but `checked_add` makes
        // the invariant explicit and prevents drift if bounds change.
        ctx.accounts.engine.rules_count = cur_count
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?;
        let cur_gen: u32 = ctx.accounts.engine.rules_generation.into();
        ctx.accounts.engine.rules_generation = cur_gen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();

        ctx.accounts.program.emit_event(
            &RuleAdded {
                engine: engine_addr,
                ts: current_ts,
                kind: KIND_FHE_GATED as u64,
                rule_index: rule_index as u64,
                generation: new_generation as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 16 — `add_rule_session_key` (F8b).
    ///
    /// Registers the SessionKey rule slot for this engine. The rule is a
    /// *policy surface*: it bounds how many concurrent sessions are allowed
    /// (`max_sessions`), the maximum TTL (`default_ttl_seconds`), the maximum
    /// uses per session (`default_max_uses`), and the per-tx amount cap
    /// (`session_max_amount_per_tx`). Actual sessions live in ephemeral
    /// Session PDAs created by `session_open` (disc 100).
    ///
    /// `config_applies_to` MUST equal `APPLIES_SESSION`. Sessions never apply
    /// to the normal signing path (they have their own entrypoint, disc 101).
    #[instruction(discriminator = 16)]
    #[allow(clippy::too_many_arguments)]
    pub fn add_rule_session_key(
        ctx: Ctx<AddRuleSessionKey>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        rule_index: u8,
        config_applies_to: u8,
        max_sessions: u8,
        default_ttl_seconds: u64,
        default_max_uses: u32,
        session_max_amount_per_tx: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        require!(
            (rule_index as usize) < MAX_RULES,
            PolicyEngineError::TooManyRules
        );
        // SessionKey rule MUST be APPLIES_SESSION only — normal signing uses a
        // separate dispatch and would otherwise silently delegate to the
        // session keypair.
        require!(
            config_applies_to == APPLIES_SESSION,
            PolicyEngineError::RuleNotApplicable
        );
        require!(
            max_sessions >= 1 && max_sessions <= MAX_SESSIONS_PER_ENGINE,
            PolicyEngineError::InvalidRuleHeader
        );
        require!(
            default_ttl_seconds > 0 && default_max_uses > 0 && session_max_amount_per_tx > 0,
            PolicyEngineError::InvalidRuleHeader
        );

        // Singleton enforcement (ADR PE-002).
        for s in 0..MAX_RULES {
            let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, s);
            if entry.kind == KIND_SESSION_KEY && entry.enabled == 1 {
                return Err(PolicyEngineError::RuleAlreadyActive.into());
            }
        }
        let slot = rule_index as usize;
        let existing = read_rule_entry(&ctx.accounts.engine.rules_flat, slot);
        require!(existing.is_empty(), PolicyEngineError::RuleSlotInUse);

        let applies_b = [config_applies_to];
        let max_b = [max_sessions];
        let ttl_le = default_ttl_seconds.to_le_bytes();
        let uses_le = default_max_uses.to_le_bytes();
        let amount_le = session_max_amount_per_tx.to_le_bytes();
        let config_hash = hashv(&[
            b"session-key-config-v1",
            &applies_b,
            &max_b,
            &ttl_le,
            &uses_le,
            &amount_le,
        ]);
        let new_generation = existing.generation.saturating_add(1);

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];

        let gen_le = new_generation.to_le_bytes();
        let challenge = admin_challenge(
            OP_ADD_SESSION_KEY,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_SESSION_KEY,
            rule_index,
            new_generation,
            on_chain_nonce,
            &config_hash,
            &owner_slot,
            &[&applies_b, &max_b, &ttl_le, &uses_le, &amount_le, &gen_le],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        let rule_addr = *ctx.accounts.rule_pda.address();
        ctx.accounts.rule_pda.set_inner(SessionKeyRuleInner {
            kind: KIND_SESSION_KEY,
            index: rule_index,
            enabled: 1,
            _pad0: 0,
            generation: new_generation,
            config_version: 1,
            _pad1: [0u8; 4],
            engine: engine_addr,
            next_admin_nonce: 0,
            config_hash,
            _pad_header_tail: [0u8; 8],
            config_applies_to,
            max_sessions,
            _pad_cfg0: [0u8; 6],
            default_ttl_seconds,
            default_max_uses,
            _pad_cfg1: 0,
            session_max_amount_per_tx,
        });
        let new_entry = RuleEntry {
            kind: KIND_SESSION_KEY,
            bump: 0,
            version: RULE_HEADER_V1,
            enabled: 1,
            generation: new_generation,
            rule_pda: rule_addr,
            config_hash,
        };
        write_rule_entry(&mut ctx.accounts.engine.rules_flat, slot, &new_entry);
        let cur_count: u8 = ctx.accounts.engine.rules_count;
        // M1 audit fix: counters bounded by `MAX_RULES` and engine slot limit
        // (RuleSlotInUse) so overflow is unreachable, but `checked_add` makes
        // the invariant explicit and prevents drift if bounds change.
        ctx.accounts.engine.rules_count = cur_count
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?;
        let cur_gen: u32 = ctx.accounts.engine.rules_generation.into();
        ctx.accounts.engine.rules_generation = cur_gen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();

        ctx.accounts.program.emit_event(
            &RuleAdded {
                engine: engine_addr,
                ts: current_ts,
                kind: KIND_SESSION_KEY as u64,
                rule_index: rule_index as u64,
                generation: new_generation as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 17 — `add_rule_recovery` (F9a: production wiring).
    ///
    /// PE-011: initialises the recovery rule with `members_count = 0` and
    /// `destinations_count = 0`. Members are added via disc 130
    /// (`update_rule_recovery_add_member`) and destinations via disc 132
    /// (`update_rule_recovery_add_destination`). Keeps the tx well under
    /// 1232 bytes. F9a delivers: owner-authenticated init, primary signing
    /// path (`recover_as_primary` disc 80), daily limit enforcement, member
    /// roster updates. Quorum/OIDC/passkey paths land in F9b/c/d.
    #[instruction(discriminator = 17)]
    #[allow(clippy::too_many_arguments)]
    pub fn add_rule_recovery(
        ctx: Ctx<AddRuleRecovery>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        rule_index: u8,
        config_applies_to: u8,
        primary_present: u8,
        primary_slot: [u8; MEMBER_SLOT_LEN],
        quorum_threshold: u8,
        daily_limit_present: u8,
        daily_limit: u64,
        cooldown_seconds: u64,
        oidc_iss_hash: [u8; 16],
        oidc_aud_hash: [u8; 16],
        jwk_registry_addr: Address,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        require!(
            (rule_index as usize) < MAX_RULES,
            PolicyEngineError::TooManyRules
        );
        require!(
            config_applies_to == APPLIES_RECOVERY,
            PolicyEngineError::RuleNotApplicable
        );
        require!(
            cooldown_seconds >= MIN_COOLDOWN_SECONDS && cooldown_seconds <= MAX_COOLDOWN_SECONDS,
            PolicyEngineError::GenericError
        );
        // quorum_threshold validated against members_count at finalize time
        // (after enough members are added). Cap by MAX_RECOVERY_MEMBERS.
        require!(
            quorum_threshold <= MAX_RECOVERY_MEMBERS as u8,
            PolicyEngineError::GenericError
        );
        if primary_present == 1 {
            // H0 audit fix (2026-05-16): OIDC primary slots use `[scheme, addr_seed(32), 0]`
            // (see `validate_oidc_slot`); the legacy `validate_slot` rejects scheme=4 by
            // design. Branch so each scheme is validated by its own layout helper.
            require!(
                primary_slot[0] == SCHEME_ED25519
                    || primary_slot[0] == SCHEME_SECP256K1
                    || primary_slot[0] == SCHEME_SECP256R1
                    || primary_slot[0] == SCHEME_WEBAUTHN
                    || primary_slot[0] == SCHEME_OIDC_JWT,
                PolicyEngineError::UnsupportedScheme
            );
            if primary_slot[0] == SCHEME_OIDC_JWT {
                validate_oidc_slot(&primary_slot)
                    .map_err(|_| PolicyEngineError::InvalidOwnerSlot)?;
            } else {
                validate_slot(&primary_slot).map_err(|_| PolicyEngineError::InvalidOwnerSlot)?;
            }
        }

        // Singleton enforcement.
        for s in 0..MAX_RULES {
            let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, s);
            if entry.kind == KIND_RECOVERY && entry.enabled == 1 {
                return Err(PolicyEngineError::RuleAlreadyActive.into());
            }
        }
        let slot = rule_index as usize;
        let existing = read_rule_entry(&ctx.accounts.engine.rules_flat, slot);
        require!(existing.is_empty(), PolicyEngineError::RuleSlotInUse);

        let new_generation = existing.generation.saturating_add(1);

        // Canonical config_hash — binds every immutable param so any drift
        // (e.g. a malicious update path) is detectable at signing time. Lists
        // (members, destinations) start empty and are appended via incremental
        // update instructions; their zero buffers come from .rodata statics
        // so we do NOT spill 1056 bytes onto the SBF stack here.
        let applies_b = [config_applies_to];
        let primary_present_b = [primary_present];
        let quorum_b = [quorum_threshold];
        let daily_present_b = [daily_limit_present];
        let daily_limit_le = daily_limit.to_le_bytes();
        let cooldown_le = cooldown_seconds.to_le_bytes();
        let config_hash = hashv(&[
            b"recovery-config-v1",
            &applies_b,
            &primary_present_b,
            &primary_slot,
            &quorum_b,
            &daily_present_b,
            &daily_limit_le,
            &cooldown_le,
            &ZERO_RECOVERY_MEMBERS,
            &ZERO_RECOVERY_DESTINATIONS,
            &oidc_iss_hash,
            &oidc_aud_hash,
            jwk_registry_addr.as_array().as_slice(),
        ]);

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];
        let gen_le = new_generation.to_le_bytes();
        let challenge = admin_challenge(
            OP_ADD_RECOVERY,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_RECOVERY,
            rule_index,
            new_generation,
            on_chain_nonce,
            &config_hash,
            &owner_slot,
            &[
                &applies_b,
                &primary_present_b,
                &primary_slot,
                &quorum_b,
                &daily_present_b,
                &daily_limit_le,
                &cooldown_le,
                &oidc_iss_hash,
                &oidc_aud_hash,
                jwk_registry_addr.as_array().as_slice(),
                &gen_le,
            ],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        // Field-by-field assignment instead of `set_inner` to avoid building
        // the 1232-byte RecoveryRuleInner literal on the SBF stack. The
        // account is already zeroed at init (Quasar `init` guarantees this),
        // so members/destinations/pending_change_* implicitly stay zero.
        let rule_addr = *ctx.accounts.rule_pda.address();
        ctx.accounts.rule_pda.kind = KIND_RECOVERY;
        ctx.accounts.rule_pda.index = rule_index;
        ctx.accounts.rule_pda.enabled = 1;
        ctx.accounts.rule_pda.generation = new_generation.into();
        ctx.accounts.rule_pda.config_version = 1u32.into();
        ctx.accounts.rule_pda.engine = engine_addr;
        ctx.accounts.rule_pda.next_admin_nonce = 0u64.into();
        ctx.accounts.rule_pda.config_hash = config_hash;
        ctx.accounts.rule_pda.config_applies_to = config_applies_to;
        ctx.accounts.rule_pda.primary_present = primary_present;
        ctx.accounts.rule_pda.quorum_threshold = quorum_threshold;
        ctx.accounts.rule_pda.daily_limit_present = daily_limit_present;
        ctx.accounts.rule_pda.primary_slot = primary_slot;
        ctx.accounts.rule_pda.daily_limit = daily_limit.into();
        ctx.accounts.rule_pda.cooldown_seconds = cooldown_seconds.into();
        ctx.accounts.rule_pda.oidc_iss_hash = oidc_iss_hash;
        ctx.accounts.rule_pda.oidc_aud_hash = oidc_aud_hash;
        ctx.accounts.rule_pda.jwk_registry_addr = jwk_registry_addr;
        ctx.accounts.rule_pda.next_session_nonce = 0u64.into();

        let new_entry = RuleEntry {
            kind: KIND_RECOVERY,
            bump: 0,
            version: RULE_HEADER_V1,
            enabled: 1,
            generation: new_generation,
            rule_pda: rule_addr,
            config_hash,
        };
        write_rule_entry(&mut ctx.accounts.engine.rules_flat, slot, &new_entry);
        let cur_count: u8 = ctx.accounts.engine.rules_count;
        // M1 audit fix: counters bounded by `MAX_RULES` and engine slot limit
        // (RuleSlotInUse) so overflow is unreachable, but `checked_add` makes
        // the invariant explicit and prevents drift if bounds change.
        ctx.accounts.engine.rules_count = cur_count
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?;
        let cur_gen: u32 = ctx.accounts.engine.rules_generation.into();
        ctx.accounts.engine.rules_generation = cur_gen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();

        ctx.accounts.program.emit_event(
            &RuleAdded {
                engine: engine_addr,
                ts: current_ts,
                kind: KIND_RECOVERY as u64,
                rule_index: rule_index as u64,
                generation: new_generation as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 60 — `pause` the engine globally (ADR PE-005).
    #[instruction(discriminator = 60)]
    pub fn pause(
        ctx: Ctx<EngineAdmin>,
        _init_authority_hash: Address,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let challenge = admin_challenge(
            OP_PAUSE,
            &human_buf[..len],
            &engine_addr,
            &dwallet_addr,
            KIND_EMPTY,
            0xFF,
            0,
            on_chain_nonce,
            &[0u8; 32],
            &owner_slot,
            &[],
        );

        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        ctx.accounts.engine.paused = 1;
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();

        ctx.accounts.program.emit_event(
            &EnginePaused {
                engine: engine_addr,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 61 — `resume` the engine.
    #[instruction(discriminator = 61)]
    pub fn resume(
        ctx: Ctx<EngineAdmin>,
        _init_authority_hash: Address,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let len =
            human_message::allowlist_resume_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let challenge = admin_challenge(
            OP_RESUME,
            &human_buf[..len],
            &engine_addr,
            &dwallet_addr,
            KIND_EMPTY,
            0xFF,
            0,
            on_chain_nonce,
            &[0u8; 32],
            &owner_slot,
            &[],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        ctx.accounts.engine.paused = 0;
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();

        ctx.accounts.program.emit_event(
            &EngineResumed {
                engine: engine_addr,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 110 — `remove_rule` (B1 audit fix, 2026-05-25).
    ///
    /// Owner-authenticated removal of an active rule of ANY kind. Closes the
    /// rule sub-PDA (rent → recipient bound in the challenge), clears the
    /// `RuleEntry` slot in `engine.rules_flat`, decrements `rules_count`, and
    /// bumps `rules_generation`. This frees the slot so the same `(kind,
    /// rule_index)` can be recreated (the singleton-per-kind guard reads the
    /// live `rules_flat`, so a removed rule no longer blocks re-adding its kind).
    ///
    /// The `rule_pda` is an `UncheckedAccount` because the kind (and thus the
    /// concrete account type and seeds) is only known at runtime; it is
    /// validated manually against the recorded `RuleEntry` (address + owner +
    /// discriminator + header drift) exactly like the `request_signature`
    /// dispatch loop does, before being closed.
    #[instruction(discriminator = 110)]
    pub fn remove_rule(
        ctx: Ctx<RemoveRule>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        rule_index: u8,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();
        let recipient_addr = *ctx.accounts.recipient.address();

        let slot = rule_index as usize;
        require!(slot < MAX_RULES, PolicyEngineError::TooManyRules);
        let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, slot);
        require!(!entry.is_empty(), PolicyEngineError::RuleNotFound);

        // Validate the rule sub-PDA against the recorded RuleEntry (mirror of the
        // request_signature dispatch checks). Borrow is scoped + dropped before
        // the close below.
        let rule_addr = *ctx.accounts.rule_pda.address();
        require!(
            rule_addr == entry.rule_pda,
            PolicyEngineError::InvalidRuleHeader
        );
        {
            let rule_view = ctx.accounts.rule_pda.to_account_view();
            require!(
                rule_view.owner() == &ID,
                PolicyEngineError::InvalidRuleHeader
            );
            let rule_data = rule_view
                .try_borrow()
                .map_err(|_| PolicyEngineError::InvalidRuleHeader)?;
            require!(
                rule_data.len() >= RULE_HEADER_BYTES + 1,
                PolicyEngineError::InvalidRuleHeader
            );
            require!(rule_data[0] == 2, PolicyEngineError::InvalidRuleHeader);
            require!(
                rule_data[1] == entry.kind,
                PolicyEngineError::InvalidRuleHeader
            );
            require!(
                rule_data[2] == slot as u8,
                PolicyEngineError::InvalidRuleHeader
            );
            let mut gen_b = [0u8; 4];
            gen_b.copy_from_slice(&rule_data[5..9]);
            require!(
                u32::from_le_bytes(gen_b) == entry.generation,
                PolicyEngineError::InvalidRuleHeader
            );
            require!(
                rule_data[57..89] == entry.config_hash,
                PolicyEngineError::InvalidRuleHeader
            );
        }

        // Owner challenge (clear-signing). Binds the recipient so a stolen
        // signature cannot redirect the reclaimed rent.
        let new_generation = entry.generation.saturating_add(1);
        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];
        let gen_le = new_generation.to_le_bytes();
        let challenge = admin_challenge(
            OP_REMOVE_RULE,
            human,
            &engine_addr,
            &dwallet_addr,
            entry.kind,
            rule_index,
            new_generation,
            on_chain_nonce,
            &entry.config_hash,
            &owner_slot,
            &[recipient_addr.as_array().as_slice(), &gen_le],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        // Close the rule sub-PDA, routing reclaimed rent to the recipient.
        // disc_len = 1 (rule accounts use a 1-byte discriminator).
        {
            let recipient_view = ctx.accounts.recipient.to_account_view();
            // SAFETY: rule_pda is the instruction's own (mut) account; this is
            // the sole mutable view taken in scope, and recipient_view is a view
            // of a different account (recipient), so no aliasing occurs.
            let rule_view_mut = unsafe { ctx.accounts.rule_pda.to_account_view_mut() };
            quasar_lang::ops::close::close_account(rule_view_mut, recipient_view, 1)?;
        }

        // Clear the slot, decrement count, bump generation, advance nonce.
        write_rule_entry(&mut ctx.accounts.engine.rules_flat, slot, &RuleEntry::EMPTY);
        let cur_count: u8 = ctx.accounts.engine.rules_count;
        ctx.accounts.engine.rules_count = cur_count.saturating_sub(1);
        let cur_gen: u32 = ctx.accounts.engine.rules_generation.into();
        ctx.accounts.engine.rules_generation = cur_gen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();

        ctx.accounts.program.emit_event(
            &RuleRemoved {
                engine: engine_addr,
                ts: current_ts,
                kind: entry.kind as u64,
                rule_index: rule_index as u64,
                generation: new_generation as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 120 — `update_rule_allowlist_add_destination`.
    ///
    /// PE-011: 1 destination per tx (32 bytes payload). Owner signs a
    /// per-destination challenge; gateway chains submissions to add N items.
    #[instruction(discriminator = 120)]
    pub fn update_rule_allowlist_add_destination(
        ctx: Ctx<UpdateRuleAllowlist>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        _rule_index: u8,
        destination: [u8; 32],
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        // Validate rule header is consistent with engine's RuleEntry snapshot.
        let header_kind = ctx.accounts.rule_pda.kind;
        let header_index = ctx.accounts.rule_pda.index;
        let header_enabled = ctx.accounts.rule_pda.enabled;
        let header_gen: u32 = ctx.accounts.rule_pda.generation.into();
        require!(
            header_kind == KIND_ALLOWLIST,
            PolicyEngineError::InvalidRuleKind
        );
        require!(header_enabled == 1, PolicyEngineError::RuleDisabled);
        let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, header_index as usize);
        require!(
            entry.kind == header_kind && entry.generation == header_gen,
            PolicyEngineError::InvalidRuleHeader
        );

        let count: u8 = ctx.accounts.rule_pda.destinations_count;
        require!(
            count < 32,
            PolicyEngineError::AllowlistDestinationNotAllowed
        );

        // Idempotent: if destination already present, succeed without bumping.
        for i in 0..(count as usize) {
            let off = i * 32;
            if ctx.accounts.rule_pda.destinations_flat[off..off + 32] == destination {
                return Ok(());
            }
        }

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len = human_message::allowlist_add_destination_message(
            &mut human_buf,
            &destination,
            &engine_addr,
            &dwallet_addr,
        )
        .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];

        let new_gen = header_gen.saturating_add(1);
        let gen_le = new_gen.to_le_bytes();
        let challenge = admin_challenge(
            OP_ALLOWLIST_ADD_DEST,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_ALLOWLIST,
            header_index,
            new_gen,
            on_chain_nonce,
            &[0u8; 32], // recomputed config_hash carried via extras for visibility.
            &owner_slot,
            &[&destination, &gen_le],
        );

        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        // Append destination.
        let off = (count as usize) * 32;
        ctx.accounts.rule_pda.destinations_flat[off..off + 32].copy_from_slice(&destination);
        ctx.accounts.rule_pda.destinations_count = count + 1;
        ctx.accounts.rule_pda.generation = new_gen.into();

        // Recompute config_hash to mirror the new state.
        let applies_b = [ctx.accounts.rule_pda.config_applies_to];
        let new_count = [count + 1];
        let new_hash = hashv(&[
            b"allowlist-config-v1",
            &applies_b,
            &new_count,
            &ctx.accounts.rule_pda.destinations_flat,
        ]);
        ctx.accounts.rule_pda.config_hash = new_hash;

        // Mirror into RuleEntry.
        let mut entry = entry;
        entry.generation = new_gen;
        entry.config_hash = new_hash;
        write_rule_entry(
            &mut ctx.accounts.engine.rules_flat,
            header_index as usize,
            &entry,
        );
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();
        let cur_egen: u32 = ctx.accounts.engine.rules_generation.into();
        // M1 audit fix: rules_generation is u32; ~4B updates before overflow.
        ctx.accounts.engine.rules_generation = cur_egen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();

        ctx.accounts.program.emit_event(
            &RuleUpdated {
                engine: engine_addr,
                ts: current_ts,
                kind: KIND_ALLOWLIST as u64,
                rule_index: header_index as u64,
                generation: new_gen as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 121 — `update_rule_allowlist_remove_destination`.
    #[instruction(discriminator = 121)]
    pub fn update_rule_allowlist_remove_destination(
        ctx: Ctx<UpdateRuleAllowlist>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        _rule_index: u8,
        destination: [u8; 32],
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        let header_kind = ctx.accounts.rule_pda.kind;
        let header_index = ctx.accounts.rule_pda.index;
        let header_gen: u32 = ctx.accounts.rule_pda.generation.into();
        require!(
            header_kind == KIND_ALLOWLIST,
            PolicyEngineError::InvalidRuleKind
        );
        let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, header_index as usize);
        require!(
            entry.kind == header_kind && entry.generation == header_gen,
            PolicyEngineError::InvalidRuleHeader
        );

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len = human_message::allowlist_remove_destination_message(
            &mut human_buf,
            &destination,
            &engine_addr,
            &dwallet_addr,
        )
        .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];

        let new_gen = header_gen.saturating_add(1);
        let gen_le = new_gen.to_le_bytes();
        let challenge = admin_challenge(
            OP_ALLOWLIST_REMOVE_DEST,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_ALLOWLIST,
            header_index,
            new_gen,
            on_chain_nonce,
            &[0u8; 32],
            &owner_slot,
            &[&destination, &gen_le],
        );

        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        // Find and remove (swap-with-last). Idempotent if not present.
        let count = ctx.accounts.rule_pda.destinations_count as usize;
        for i in 0..count {
            let off = i * 32;
            if ctx.accounts.rule_pda.destinations_flat[off..off + 32] == destination {
                let last = (count - 1) * 32;
                if i != count - 1 {
                    let mut tail = [0u8; 32];
                    tail.copy_from_slice(&ctx.accounts.rule_pda.destinations_flat[last..last + 32]);
                    ctx.accounts.rule_pda.destinations_flat[off..off + 32].copy_from_slice(&tail);
                }
                ctx.accounts.rule_pda.destinations_flat[last..last + 32]
                    .copy_from_slice(&[0u8; 32]);
                ctx.accounts.rule_pda.destinations_count = (count as u8) - 1;
                break;
            }
        }

        let applies_b = [ctx.accounts.rule_pda.config_applies_to];
        let new_count_b = [ctx.accounts.rule_pda.destinations_count];
        let new_hash = hashv(&[
            b"allowlist-config-v1",
            &applies_b,
            &new_count_b,
            &ctx.accounts.rule_pda.destinations_flat,
        ]);
        ctx.accounts.rule_pda.config_hash = new_hash;
        ctx.accounts.rule_pda.generation = new_gen.into();

        let mut entry = entry;
        entry.generation = new_gen;
        entry.config_hash = new_hash;
        write_rule_entry(
            &mut ctx.accounts.engine.rules_flat,
            header_index as usize,
            &entry,
        );
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();
        let cur_egen: u32 = ctx.accounts.engine.rules_generation.into();
        // M1 audit fix: rules_generation is u32; ~4B updates before overflow.
        ctx.accounts.engine.rules_generation = cur_egen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();

        ctx.accounts.program.emit_event(
            &RuleUpdated {
                engine: engine_addr,
                ts: current_ts,
                kind: KIND_ALLOWLIST as u64,
                rule_index: header_index as u64,
                generation: new_gen as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 122 — `update_rule_oracle_add_feed` (F5c).
    ///
    /// Appends one Pyth feed to an existing `KIND_ORACLE` rule:
    ///   `feed_account` — the adapter `FeedCache` PDA (`[b"feed_cache", feed_id]`)
    ///   `feed_owner`   — the Pyth adapter program id (must be in
    ///                    `ALLOWED_ORACLE_OWNERS`, mirrors the H1 dispatch check)
    ///   `min_q64`/`max_q64` — canonical 1e8 price band (`min <= max`).
    ///
    /// Owner-signed `OP_ORACLE_ADD_FEED` challenge; structurally identical to
    /// disc 120 (allowlist add-destination). Idempotent on `feed_account`. The
    /// `add_rule_oracle` (disc 13) creates the rule with `feeds_count = 0`; a
    /// rule with zero feeds enforces nothing, so this is the instruction that
    /// makes a `KIND_ORACLE` rule actually gate signing.
    #[instruction(discriminator = 122)]
    #[allow(clippy::too_many_arguments)]
    pub fn update_rule_oracle_add_feed(
        ctx: Ctx<UpdateRuleOracle>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        _rule_index: u8,
        feed_account: [u8; 32],
        feed_owner: [u8; 32],
        min_q64: i64,
        max_q64: i64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        // Validate rule header is consistent with engine's RuleEntry snapshot.
        let header_kind = ctx.accounts.rule_pda.kind;
        let header_index = ctx.accounts.rule_pda.index;
        let header_enabled = ctx.accounts.rule_pda.enabled;
        let header_gen: u32 = ctx.accounts.rule_pda.generation.into();
        require!(
            header_kind == KIND_ORACLE,
            PolicyEngineError::InvalidRuleKind
        );
        require!(header_enabled == 1, PolicyEngineError::RuleDisabled);
        let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, header_index as usize);
        require!(
            entry.kind == header_kind && entry.generation == header_gen,
            PolicyEngineError::InvalidRuleHeader
        );

        // Band sanity — an inverted band would reject every price (footgun).
        require!(min_q64 <= max_q64, PolicyEngineError::OracleOutOfBand);

        // H1 defense-in-depth: only platform adapter owners may back a feed.
        // Mirrors the dispatch-time `is_oracle_owner_allowed` check so a feed
        // that would always fail at signing time cannot even be registered.
        require!(
            is_oracle_owner_allowed(&feed_owner),
            PolicyEngineError::OracleOwnerMismatch
        );

        let count: u8 = ctx.accounts.rule_pda.feeds_count;
        require!(
            (count as usize) < MAX_ORACLE_FEEDS,
            PolicyEngineError::TooManyRules
        );

        // Idempotent: if feed_account already present, succeed without bumping.
        for i in 0..(count as usize) {
            let off = i * ORACLE_FEED_BYTES;
            if ctx.accounts.rule_pda.feeds_flat[off..off + 32] == feed_account {
                return Ok(());
            }
        }

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len = human_message::oracle_add_feed_message(
            &mut human_buf,
            &feed_account,
            &feed_owner,
            min_q64,
            max_q64,
            &engine_addr,
            &dwallet_addr,
        )
        .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];

        let new_gen = header_gen.saturating_add(1);
        let gen_le = new_gen.to_le_bytes();
        let min_le = min_q64.to_le_bytes();
        let max_le = max_q64.to_le_bytes();
        let challenge = admin_challenge(
            OP_ORACLE_ADD_FEED,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_ORACLE,
            header_index,
            new_gen,
            on_chain_nonce,
            &[0u8; 32], // recomputed config_hash carried via extras for visibility.
            &owner_slot,
            &[&feed_account, &feed_owner, &min_le, &max_le, &gen_le],
        );

        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        // Append feed.
        let off = (count as usize) * ORACLE_FEED_BYTES;
        ctx.accounts.rule_pda.feeds_flat[off..off + 32].copy_from_slice(&feed_account);
        ctx.accounts.rule_pda.feeds_flat[off + 32..off + 64].copy_from_slice(&feed_owner);
        ctx.accounts.rule_pda.feeds_flat[off + 64..off + 72].copy_from_slice(&min_le);
        ctx.accounts.rule_pda.feeds_flat[off + 72..off + 80].copy_from_slice(&max_le);
        ctx.accounts.rule_pda.feeds_count = count + 1;
        ctx.accounts.rule_pda.generation = new_gen.into();

        // Recompute config_hash to mirror the new state.
        let applies_b = [ctx.accounts.rule_pda.config_applies_to];
        let new_count = [count + 1];
        let fresh_b = [ctx.accounts.rule_pda.freshness_seconds_div16];
        let conf_b = [ctx.accounts.rule_pda.min_confidence_bps_div4];
        let new_hash = hashv(&[
            b"oracle-config-v1",
            &applies_b,
            &new_count,
            &fresh_b,
            &conf_b,
            &ctx.accounts.rule_pda.feeds_flat,
        ]);
        ctx.accounts.rule_pda.config_hash = new_hash;

        // Mirror into RuleEntry.
        let mut entry = entry;
        entry.generation = new_gen;
        entry.config_hash = new_hash;
        write_rule_entry(
            &mut ctx.accounts.engine.rules_flat,
            header_index as usize,
            &entry,
        );
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();
        let cur_egen: u32 = ctx.accounts.engine.rules_generation.into();
        ctx.accounts.engine.rules_generation = cur_egen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();

        ctx.accounts.program.emit_event(
            &RuleUpdated {
                engine: engine_addr,
                ts: current_ts,
                kind: KIND_ORACLE as u64,
                rule_index: header_index as u64,
                generation: new_gen as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 19 — `update_rule_spending_usd_add_feed` (Update 3).
    ///
    /// Appends one asset to an existing `KIND_SPENDING_USD` rule:
    ///   `feed_cache_account` — the Pyth adapter `FeedCache` PDA
    ///   `decimals`           — the asset's base-unit decimals (SOL=9, USDC=6…)
    ///
    /// Owner-signed `OP_SPENDING_USD_ADD_FEED` challenge. Idempotent on
    /// `feed_cache_account`. `add_rule_spending_usd` (disc 18) creates the rule
    /// with `feeds_count = 0`; a rule with zero feeds enforces nothing, so this
    /// is the instruction that makes the spending limit actually gate signing.
    ///
    /// Defense-in-depth: the `feed_cache` account is passed in and its `owner`
    /// is checked against `ALLOWED_ORACLE_OWNERS` (the Pyth adapter) — a feed
    /// that would always fail at dispatch cannot even be registered.
    #[instruction(discriminator = 19)]
    #[allow(clippy::too_many_arguments)]
    pub fn update_rule_spending_usd_add_feed(
        ctx: Ctx<UpdateRuleSpendingUsd>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        _rule_index: u8,
        feed_cache_account: [u8; 32],
        decimals: u8,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        // Validate rule header is consistent with engine's RuleEntry snapshot.
        let header_kind = ctx.accounts.rule_pda.kind;
        let header_index = ctx.accounts.rule_pda.index;
        let header_enabled = ctx.accounts.rule_pda.enabled;
        let header_gen: u32 = ctx.accounts.rule_pda.generation.into();
        require!(
            header_kind == KIND_SPENDING_USD,
            PolicyEngineError::InvalidRuleKind
        );
        require!(header_enabled == 1, PolicyEngineError::RuleDisabled);
        let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, header_index as usize);
        require!(
            entry.kind == header_kind && entry.generation == header_gen,
            PolicyEngineError::InvalidRuleHeader
        );

        // Decimals sanity — bounds 10^decimals so the dispatch conversion can
        // never overflow u128 (and rejects an obviously bogus asset config).
        require!(decimals <= 24, PolicyEngineError::SpendingAssetNotAllowed);

        // Defense-in-depth: the feed cache must be owned by the Pyth adapter
        // (mirrors the dispatch-time owner gate). Passing a wrong/non-existent
        // account is rejected here instead of silently failing every sign.
        let fc_view = ctx.accounts.feed_cache.to_account_view();
        require!(
            fc_view.address().as_array() == &feed_cache_account,
            PolicyEngineError::SpendingAssetNotAllowed
        );
        require!(
            is_oracle_owner_allowed(fc_view.owner().as_array()),
            PolicyEngineError::OracleOwnerMismatch
        );

        let count: u8 = ctx.accounts.rule_pda.feeds_count;
        require!(
            (count as usize) < MAX_SPENDING_USD_FEEDS,
            PolicyEngineError::TooManyRules
        );

        // Idempotent: if feed_cache_account already present, succeed without bumping.
        for i in 0..(count as usize) {
            let off = i * SPENDING_USD_FEED_BYTES;
            if ctx.accounts.rule_pda.feeds_flat[off..off + 32] == feed_cache_account {
                return Ok(());
            }
        }

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len = human_message::spending_usd_add_feed_message(
            &mut human_buf,
            &feed_cache_account,
            decimals,
            &engine_addr,
            &dwallet_addr,
        )
        .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];

        let new_gen = header_gen.saturating_add(1);
        let gen_le = new_gen.to_le_bytes();
        let dec_b = [decimals];
        let challenge = admin_challenge(
            OP_SPENDING_USD_ADD_FEED,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_SPENDING_USD,
            header_index,
            new_gen,
            on_chain_nonce,
            &[0u8; 32], // recomputed config_hash carried via extras for visibility.
            &owner_slot,
            &[&feed_cache_account, &dec_b, &gen_le],
        );

        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        // Append feed entry (33 bytes: account 32 + decimals 1).
        let off = (count as usize) * SPENDING_USD_FEED_BYTES;
        ctx.accounts.rule_pda.feeds_flat[off..off + 32].copy_from_slice(&feed_cache_account);
        ctx.accounts.rule_pda.feeds_flat[off + 32] = decimals;
        ctx.accounts.rule_pda.feeds_count = count + 1;
        ctx.accounts.rule_pda.generation = new_gen.into();

        // Recompute config_hash to mirror the new state (caps unchanged).
        let applies_b = [ctx.accounts.rule_pda.config_applies_to];
        let new_count = [count + 1];
        let fresh_b = [ctx.accounts.rule_pda.freshness_seconds_div16];
        let conf_b = [ctx.accounts.rule_pda.max_confidence_bps_div4];
        let max_per_tx: u64 = ctx.accounts.rule_pda.max_per_tx_usd.into();
        let max_per_day: u64 = ctx.accounts.rule_pda.max_per_day_usd.into();
        let max_per_week: u64 = ctx.accounts.rule_pda.max_per_week_usd.into();
        let mut caps = [0u8; 24];
        caps[0..8].copy_from_slice(&max_per_tx.to_le_bytes());
        caps[8..16].copy_from_slice(&max_per_day.to_le_bytes());
        caps[16..24].copy_from_slice(&max_per_week.to_le_bytes());
        let new_hash = hashv(&[
            b"spending-usd-config-v1",
            &applies_b,
            &new_count,
            &fresh_b,
            &conf_b,
            &caps,
            &ctx.accounts.rule_pda.feeds_flat,
        ]);
        ctx.accounts.rule_pda.config_hash = new_hash;

        // Mirror into RuleEntry.
        let mut entry = entry;
        entry.generation = new_gen;
        entry.config_hash = new_hash;
        write_rule_entry(
            &mut ctx.accounts.engine.rules_flat,
            header_index as usize,
            &entry,
        );
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();
        let cur_egen: u32 = ctx.accounts.engine.rules_generation.into();
        ctx.accounts.engine.rules_generation = cur_egen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();

        ctx.accounts.program.emit_event(
            &RuleUpdated {
                engine: engine_addr,
                ts: current_ts,
                kind: KIND_SPENDING_USD as u64,
                rule_index: header_index as u64,
                generation: new_gen as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 126 — `update_rule_fhe_gated_authorities` (C2 audit fix).
    ///
    /// Replaces the FHE authority list of a `KIND_FHE_GATED` rule in one
    /// shot. Owner signs an `OP_UPDATE_FHE_AUTH` challenge binding the new
    /// (count, flat_bytes) tuple. `new_count == 0` is rejected — an active
    /// FHE-Gated rule must have at least one authority (the F7b dispatch
    /// already fail-closes on count==0).
    ///
    /// Each pubkey is validated against `ALLOWED_FHE_AUTHORITIES` when that
    /// list is non-empty (devnet placeholder = permissive).
    #[instruction(discriminator = 126)]
    #[allow(clippy::too_many_arguments)]
    pub fn update_rule_fhe_gated_authorities(
        ctx: Ctx<UpdateRuleFheGated>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        _rule_index: u8,
        new_count: u8,
        new_authorities: [u8; MAX_FHE_AUTHORITIES * 32],
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        let header_kind = ctx.accounts.rule_pda.kind;
        let header_index = ctx.accounts.rule_pda.index;
        let header_enabled = ctx.accounts.rule_pda.enabled;
        let header_gen: u32 = ctx.accounts.rule_pda.generation.into();
        let applies_to = ctx.accounts.rule_pda.config_applies_to;
        let freshness = ctx.accounts.rule_pda.freshness_seconds_div16;
        require!(
            header_kind == KIND_FHE_GATED,
            PolicyEngineError::InvalidRuleKind
        );
        require!(header_enabled == 1, PolicyEngineError::RuleDisabled);
        let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, header_index as usize);
        require!(
            entry.kind == header_kind && entry.generation == header_gen,
            PolicyEngineError::InvalidRuleHeader
        );

        require!(
            new_count as usize > 0 && (new_count as usize) <= MAX_FHE_AUTHORITIES,
            PolicyEngineError::InvalidRuleHeader
        );
        let count = new_count as usize;
        for i in 0..count {
            let off = i * 32;
            let mut auth = [0u8; 32];
            auth.copy_from_slice(&new_authorities[off..off + 32]);
            // Zero pubkey is never a valid Ed25519 public key.
            require!(auth != [0u8; 32], PolicyEngineError::InvalidRuleHeader);
            require!(
                is_fhe_authority_allowed(&auth),
                PolicyEngineError::AuthFailed
            );
        }
        // Canonical flat: payload bytes + zero-padding for unused slots.
        let mut canon = [0u8; MAX_FHE_AUTHORITIES * 32];
        canon[..count * 32].copy_from_slice(&new_authorities[..count * 32]);

        let applies_b = [applies_to];
        let count_b = [new_count];
        let fresh_b = [freshness];
        let new_hash = hashv(&[
            b"fhe-gated-config-v1",
            &applies_b,
            &count_b,
            &fresh_b,
            &canon,
        ]);
        let new_gen = header_gen.saturating_add(1);
        let gen_le = new_gen.to_le_bytes();

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];

        let challenge = admin_challenge(
            OP_UPDATE_FHE_AUTH,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_FHE_GATED,
            header_index,
            new_gen,
            on_chain_nonce,
            &new_hash,
            &owner_slot,
            &[&count_b, &canon, &gen_le],
        );

        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        ctx.accounts.rule_pda.authorities_count = new_count;
        ctx.accounts
            .rule_pda
            .authorities_flat
            .copy_from_slice(&canon);
        ctx.accounts.rule_pda.generation = new_gen.into();
        ctx.accounts.rule_pda.config_hash = new_hash;

        let mut entry = entry;
        entry.generation = new_gen;
        entry.config_hash = new_hash;
        write_rule_entry(
            &mut ctx.accounts.engine.rules_flat,
            header_index as usize,
            &entry,
        );
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();
        let cur_egen: u32 = ctx.accounts.engine.rules_generation.into();
        // M1 audit fix: rules_generation is u32; ~4B updates before overflow.
        ctx.accounts.engine.rules_generation = cur_egen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();

        ctx.accounts.program.emit_event(
            &RuleUpdated {
                engine: engine_addr,
                ts: current_ts,
                kind: KIND_FHE_GATED as u64,
                rule_index: header_index as u64,
                generation: new_gen as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 87 — `oidc_session_open` (C1 — Login Social on-chain).
    ///
    /// Verifies an OIDC JWT (Google/Apple) and opens an `OidcSession` PDA
    /// bound to a user-supplied ephemeral Ed25519 key. Subsequent
    /// recoveries (`recover_as_primary_oidc`) are signed by `eph_pk` for
    /// the duration of the session — the JWT is NOT consumed per signature.
    ///
    /// Flow (mirrors `passkey_session_open`):
    ///   1. JWT bytes arrive in the ix data (≤ `MAX_OIDC_JWT_BYTES = 1024`).
    ///   2. Caller picks a JWK entry index in the supplied `jwk_registry`
    ///      account; we validate the entry is ACTIVE and extract
    ///      `(issuer_hash, audience_hash, kid_hash, modulus, exponent)`.
    ///   3. We call `oidc_verifier::verify` — with `oidc-rsa` feature OFF
    ///      (devnet pre-alpha), this always fails at the RSA step. Wiring
    ///      stays correct so the post-syscall redeploy is a feature-flag
    ///      flip, not a rewrite.
    ///   4. Cross-check `parsed.{issuer,audience,kid}_hash` against the JWK
    ///      entry the caller pointed at — defends against feeding a JWT
    ///      from one (iss, aud, kid) while pointing at another's modulus.
    ///   5. Compare `parsed.addr_seed` byte-for-byte with
    ///      `rule_pda.primary_slot[1..33]` (which carries the addr_seed for
    ///      `scheme = SCHEME_OIDC_JWT`).
    ///   6. Verify the user-supplied ephemeral key signed the
    ///      `oidc_session_open_challenge` (Ed25519 precompile).
    ///   7. Populate the `OidcSession` PDA + bump the engine's
    ///      `next_oidc_session_nonce`.
    #[instruction(discriminator = 87)]
    #[allow(clippy::too_many_arguments)]
    pub fn oidc_session_open(
        ctx: Ctx<OidcSessionOpenAccts>,
        _init_authority_hash: Address,
        _rule_index: u8,
        _oidc_session_nonce: u64,
        eph_pk: [u8; 32],
        not_after_unix_ts: u64,
        nonce_randomness: [u8; 32],
        expected_oidc_session_nonce: u64,
        jwk_entry_index: u8,
        jwt_len: u16,
        jwt_bytes: [u8; MAX_OIDC_JWT_BYTES],
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let rule_addr = *ctx.accounts.rule_pda.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let payer_addr = *ctx.accounts.payer.address();
        let jwk_registry_addr = *ctx.accounts.jwk_registry.address();

        // M6 audit fix (2026-05-16): block session creation while paused.
        require!(
            ctx.accounts.engine.paused == 0,
            PolicyEngineError::EnginePaused
        );

        // C1 audit fix (2026-05-16): the JWK registry that backs this session
        // MUST be the one pinned in the RecoveryRule at init time. Without this
        // anyone could craft a forged registry with a controlled RSA modulus and
        // open a session against any OIDC primary.
        require!(
            jwk_registry_addr == ctx.accounts.rule_pda.jwk_registry_addr,
            PolicyEngineError::OidcJwkNotFound
        );
        // Defense-in-depth: the account must be owned by the canonical
        // `andromeda_jwk_registry` program. Layout coincidence with another
        // program would otherwise still pass `read_jwk_entry`.
        require!(
            ctx.accounts.jwk_registry.to_account_view().owner() == &JWK_REGISTRY_PROGRAM_ID,
            PolicyEngineError::OidcJwkNotFound
        );

        // 0. nonce reject-fast.
        let on_chain_nonce: u64 = ctx.accounts.engine.next_oidc_session_nonce.into();
        require!(
            expected_oidc_session_nonce == on_chain_nonce,
            PolicyEngineError::InvalidNonce
        );

        // 1. primary must be an OIDC slot.
        require!(
            ctx.accounts.rule_pda.primary_present == 1,
            PolicyEngineError::RuleNotApplicable
        );
        let primary_slot = ctx.accounts.rule_pda.primary_slot;
        require!(
            primary_slot[0] == SCHEME_OIDC_JWT,
            PolicyEngineError::UnsupportedScheme
        );
        // H0 audit fix (2026-05-16): OIDC slot has its own layout
        // (`[4, addr_seed(32), 0]`); the legacy `validate_slot` rejects it.
        validate_oidc_slot(&primary_slot).map_err(|_| PolicyEngineError::InvalidOwnerSlot)?;

        // 2. JWT length bounds.
        let jl = jwt_len as usize;
        require!(
            jl > 0 && jl <= MAX_OIDC_JWT_BYTES,
            PolicyEngineError::OidcJwtInvalid
        );

        // 3. effective expiry — capped at now + OIDC_SESSION_TTL_SECONDS.
        //
        // L1 audit fix (2026-05-16): `not_after_unix_ts` is a HARD UPPER
        // BOUND, not a default. Effective expiry is
        // `min(not_after_unix_ts, now + OIDC_SESSION_TTL_SECONDS)`. A caller
        // passing a value smaller than `now + TTL` shortens the session;
        // larger values are silently clamped by the TTL. Documented in
        // GitBook (Login Social section).
        let not_after_i = if not_after_unix_ts <= i64::MAX as u64 {
            not_after_unix_ts as i64
        } else {
            i64::MAX
        };
        let expires_at = current_ts
            .saturating_add(OIDC_SESSION_TTL_SECONDS)
            .min(not_after_i);
        require!(
            expires_at > current_ts,
            PolicyEngineError::OidcSessionExpired
        );

        // 4. JWK registry lookup. The caller supplies `jwk_entry_index` —
        // we don't scan the whole registry on-chain (CU expensive); we
        // just validate the selected entry is ACTIVE and that
        // `(iss_hash, aud_hash, kid_hash)` cross-checks against the JWT.
        require!(
            (jwk_entry_index as usize) < JWK_REGISTRY_MAX_ENTRIES,
            PolicyEngineError::OidcJwkNotFound
        );
        let registry_data = ctx
            .accounts
            .jwk_registry
            .to_account_view()
            .try_borrow()
            .map_err(|_| PolicyEngineError::OidcJwkNotFound)?;
        let (modulus_n, exponent_e, reg_iss_hash, reg_aud_hash, reg_kid_hash) =
            read_jwk_entry(&registry_data, jwk_entry_index as usize)?;
        // jwt_digest is computed by the verifier; we capture it via ParsedOidc.

        // 5. Build issuer/audience allowlist (devnet placeholder fallback
        // when consts empty — see ALLOWED_OIDC_ISSUERS docs).
        #[cfg(not(feature = "mainnet"))]
        let (issuers, audiences): (&[&[u8]], &[&[u8]]) = (
            if ALLOWED_OIDC_ISSUERS.is_empty() {
                DEVNET_FALLBACK_ISSUERS
            } else {
                ALLOWED_OIDC_ISSUERS
            },
            if ALLOWED_OIDC_AUDIENCES.is_empty() {
                DEVNET_FALLBACK_AUDIENCES
            } else {
                ALLOWED_OIDC_AUDIENCES
            },
        );
        #[cfg(feature = "mainnet")]
        let (issuers, audiences): (&[&[u8]], &[&[u8]]) =
            (ALLOWED_OIDC_ISSUERS, ALLOWED_OIDC_AUDIENCES);

        // 6. Verify the JWT. This call:
        //    - parses header + claims (strict),
        //    - checks iss/aud allowlists,
        //    - verifies RSA-2048 (sol_big_mod_exp; stubs to 0xFF on
        //      `oidc-rsa` OFF builds, blocking devnet pre-alpha),
        //    - re-derives addr_seed + the three hashes,
        //    - recomputes oidc_nonce and matches the JWT's `nonce` claim.
        let parsed = oidc_verifier::verify(oidc_verifier::VerifyOidcInput {
            jwt: &jwt_bytes[..jl],
            modulus_n: &modulus_n,
            exponent_e,
            allowed_issuers: issuers,
            allowed_audiences: audiences,
            eph_pk: &eph_pk,
            not_after_unix_ts,
            nonce_randomness: &nonce_randomness,
            now_unix_ts: current_ts,
        })
        .map_err(|_| PolicyEngineError::OidcJwtInvalid)?;
        drop(registry_data);

        // 7. Cross-check the JWK entry vs the JWT-derived hashes. Without
        // this, a compromised registry entry could be paired with a JWT
        // whose (iss, aud, kid) don't actually match.
        require!(
            parsed.issuer_hash == reg_iss_hash,
            PolicyEngineError::OidcIssuerMismatch
        );
        require!(
            parsed.audience_hash == reg_aud_hash,
            PolicyEngineError::OidcAudienceMismatch
        );
        require!(
            parsed.kid_hash == reg_kid_hash,
            PolicyEngineError::OidcJwkInactive
        );

        // M8 audit fix (2026-05-16): the RecoveryRule pins a 16-byte prefix of
        // `(sha256(iss), sha256(aud))` independently of the registry. Defense
        // in depth: even if a pinning bypass on the registry slipped past in a
        // future refactor, the (iss, aud) must still match what the dWallet
        // owner authorised when the rule was added.
        require!(
            parsed.issuer_hash[..16] == ctx.accounts.rule_pda.oidc_iss_hash,
            PolicyEngineError::OidcIssuerMismatch
        );
        require!(
            parsed.audience_hash[..16] == ctx.accounts.rule_pda.oidc_aud_hash,
            PolicyEngineError::OidcAudienceMismatch
        );

        // 8. Identity match — the JWT's user MUST be the OIDC primary of
        // this dWallet. primary_slot[1..33] holds the addr_seed for
        // scheme = SCHEME_OIDC_JWT.
        require!(
            primary_slot[1..33] == parsed.addr_seed,
            PolicyEngineError::OidcAddrSeedMismatch
        );

        // 9. Verify the ephemeral key signed the open challenge.
        let challenge = oidc_session_open_challenge(
            &dwallet_addr,
            &primary_slot,
            &eph_pk,
            not_after_unix_ts,
            &parsed.jwt_digest,
            &jwk_registry_addr,
            oidc_verifier::OIDC_VERIFIER_V1,
            on_chain_nonce,
        )
        .map_err(PolicyEngineError::from)?;
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let mut eph_slot = [0u8; MEMBER_SLOT_LEN];
        eph_slot[0] = SCHEME_ED25519;
        eph_slot[1..33].copy_from_slice(&eph_pk);
        verify_signature(VerifyInput {
            member_slot: &eph_slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &[],
            webauthn_client_data_json: &[],
        })
        .map_err(|_| PolicyEngineError::AuthFailed)?;
        drop(sysvar_data_ref);

        // 10. Populate the session PDA.
        ctx.accounts.session.engine = engine_addr;
        ctx.accounts.session.rule_pda = rule_addr;
        ctx.accounts.session.payer_for_close = payer_addr;
        ctx.accounts.session.addr_seed = parsed.addr_seed;
        ctx.accounts.session.jwt_digest = parsed.jwt_digest;
        ctx.accounts.session.eph_pk = eph_pk;
        ctx.accounts.session.session_nonce = on_chain_nonce.into();
        ctx.accounts.session.next_use_nonce = 0u64.into();
        ctx.accounts.session.not_after_unix_ts = not_after_unix_ts.into();
        ctx.accounts.session.expires_at = expires_at.into();
        ctx.accounts.session.created_at = current_ts.into();
        ctx.accounts.session.verifier_version = oidc_verifier::OIDC_VERIFIER_V1.into();
        ctx.accounts.session.is_closed = 0;

        // M1 audit fix.
        ctx.accounts.engine.next_oidc_session_nonce = on_chain_nonce
            .checked_add(1)
            .ok_or(PolicyEngineError::InvalidNonce)?
            .into();
        Ok(())
    }

    /// Disc 81 — `recover_as_primary_oidc` (C1 audit — implemented).
    ///
    /// Consumes an open `OidcSession` to authorize one Ika `approve_message`
    /// CPI. The session's ephemeral Ed25519 key signs a per-use challenge;
    /// we re-validate session liveness, addr_seed equality against the
    /// current OIDC primary (so a rotation kills active sessions), verifier
    /// version pin (downgrade guard), then CPI Ika.
    #[instruction(discriminator = 81)]
    #[allow(clippy::too_many_arguments)]
    pub fn recover_as_primary_oidc(
        ctx: Ctx<RecoverAsPrimaryOidcAccts>,
        _init_authority_hash: Address,
        _rule_index: u8,
        _oidc_session_nonce: u64,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
        expected_use_nonce: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let request_hash = Address::from(message_digest);
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let session_addr = *ctx.accounts.session.address();
        let rule_addr = *ctx.accounts.rule_pda.address();
        let message_approval_addr = *ctx.accounts.message_approval.address();

        ctx.accounts.program.emit_event(
            &SignatureRequested {
                engine: engine_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;

        require!(
            ctx.accounts.engine.paused == 0,
            PolicyEngineError::EnginePaused
        );

        // Session must reference this rule_pda (defense in depth in case
        // the rule_index in seeds drifted).
        require!(
            ctx.accounts.session.rule_pda == rule_addr,
            PolicyEngineError::InvalidRuleHeader
        );

        // 1. session open + not expired.
        require!(
            ctx.accounts.session.is_closed == 0,
            PolicyEngineError::OidcSessionExpired
        );
        let expires_at: i64 = ctx.accounts.session.expires_at.into();
        require!(
            current_ts < expires_at,
            PolicyEngineError::OidcSessionExpired
        );

        // 2. verifier version pin — downgrade guard.
        let pinned_ver: u32 = ctx.accounts.session.verifier_version.into();
        require!(
            pinned_ver == oidc_verifier::OIDC_VERIFIER_V1,
            PolicyEngineError::OidcVerifierMismatch
        );

        // 3. use-nonce.
        let use_nonce: u64 = ctx.accounts.session.next_use_nonce.into();
        require!(
            expected_use_nonce == use_nonce,
            PolicyEngineError::InvalidNonce
        );

        // 4. policy primary must still match the bound addr_seed.
        let bound_addr_seed = ctx.accounts.session.addr_seed;
        let mut expected_primary = [0u8; MEMBER_SLOT_LEN];
        expected_primary[0] = SCHEME_OIDC_JWT;
        expected_primary[1..33].copy_from_slice(&bound_addr_seed);
        let primary_slot = ctx.accounts.rule_pda.primary_slot;
        require!(
            primary_slot == expected_primary,
            PolicyEngineError::OidcAddrSeedMismatch
        );

        // 5. Ed25519 precompile over per-use challenge with the session's eph_pk.
        let eph_pk = ctx.accounts.session.eph_pk;
        let challenge = oidc_primary_use_challenge(
            &session_addr,
            &dwallet_addr,
            &message_approval_addr,
            &message_digest,
            &metadata_digest,
            &user_pubkey,
            signature_scheme,
            message_approval_bump,
            use_nonce,
            &expected_primary,
        )
        .map_err(PolicyEngineError::from)?;
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let mut eph_slot = [0u8; MEMBER_SLOT_LEN];
        eph_slot[0] = SCHEME_ED25519;
        eph_slot[1..33].copy_from_slice(&eph_pk);
        verify_signature(VerifyInput {
            member_slot: &eph_slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &[],
            webauthn_client_data_json: &[],
        })
        .map_err(|_| PolicyEngineError::AuthFailed)?;
        drop(sysvar_data_ref);

        // 6. consume use-nonce BEFORE CPI.
        ctx.accounts.session.next_use_nonce = use_nonce
            .checked_add(1)
            .ok_or(PolicyEngineError::InvalidNonce)?
            .into();

        // 7. CPI Ika defense + approve.
        require!(
            validate_ika_cpi_accounts(
                &ctx.accounts.dwallet_program.to_account_view(),
                &ctx.accounts.dwallet_account.to_account_view(),
            ),
            PolicyEngineError::IkaCpiAccountMismatch
        );
        invoke_ika_approve_message(
            &ctx.accounts.dwallet_program.to_account_view(),
            &ctx.accounts.cpi_authority.to_account_view(),
            // F9-COORD: the Ika caller_program must be THIS program's id — Ika
            // derives the signing authority as PDA(["__ika_cpi_authority"],
            // caller_program) and requires it to sign. Use the `program`
            // account (= policy-engine id, executable). The separate
            // `caller_program` slot stays in the context (now unused) so the
            // instruction account layout is unchanged.
            &ctx.accounts.program.to_account_view(),
            cpi_authority_bump,
            &ctx.accounts.coordinator.to_account_view(),
            &ctx.accounts.message_approval.to_account_view(),
            &ctx.accounts.dwallet_account.to_account_view(),
            &ctx.accounts.payer.to_account_view(),
            &ctx.accounts.system_program.to_account_view(),
            message_digest,
            // F9-SIGN: Ika message_metadata_digest = 0 (the signed message carries
            // no Ika metadata). The Andromeda policy challenge (metadata_digest) is
            // already enforced above via the request_metadata_digest match, so
            // binding it into the Ika MessageApproval here is both redundant and
            // breaks the Ika Sign step (the network derives the approval with empty
            // metadata → otherwise "MessageApproval PDA not found").
            [0u8; 32],
            user_pubkey,
            signature_scheme,
            message_approval_bump,
        )?;

        ctx.accounts.program.emit_event(
            &SignatureApproved {
                engine: engine_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 88 — `oidc_session_close` (C1 — Login Social on-chain).
    ///
    /// Permissionless close once `current_ts >= expires_at`. Recipient signs
    /// the tx and receives the rent; MUST equal `session.payer_for_close`.
    #[instruction(discriminator = 88)]
    pub fn oidc_session_close(
        ctx: Ctx<OidcSessionCloseAccts>,
        _init_authority_hash: Address,
        _oidc_session_nonce: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let expires_at: i64 = ctx.accounts.session.expires_at.into();
        require!(
            current_ts >= expires_at,
            PolicyEngineError::OidcSessionExpired
        );
        let recipient_addr = *ctx.accounts.recipient.address();
        require!(
            ctx.accounts.session.payer_for_close == recipient_addr,
            PolicyEngineError::AuthFailed
        );
        let recipient_view = ctx.accounts.recipient.to_account_view();
        ctx.accounts.session.close(recipient_view)?;
        Ok(())
    }

    /// Disc 100 — `session_open` (F8b).
    ///
    /// Owner authorises (challenge) the creation of a new Session PDA bound
    /// to a session keypair (`session_signer`). Caller-supplied bounds
    /// (`expires_at_ts`, `max_uses`, `max_amount_per_tx`) must be within the
    /// SessionKey rule's policy limits. Once open, the session signs natively
    /// via `request_signature_via_session` (disc 101) without further owner
    /// involvement until expiry, max_uses, or explicit revoke (F8c).
    #[instruction(discriminator = 100)]
    #[allow(clippy::too_many_arguments)]
    pub fn session_open(
        ctx: Ctx<SessionOpen>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        rule_index: u8,
        session_index: u32,
        session_signer: Address,
        expires_at_ts: i64,
        max_uses: u32,
        max_amount_per_tx: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        // M6 audit fix (2026-05-16): block session creation while paused.
        require!(
            ctx.accounts.engine.paused == 0,
            PolicyEngineError::EnginePaused
        );

        // Validate the SessionKey rule exists at the declared slot.
        let slot = rule_index as usize;
        require!(slot < MAX_RULES, PolicyEngineError::TooManyRules);
        let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, slot);
        require!(
            entry.kind == KIND_SESSION_KEY && entry.enabled == 1,
            PolicyEngineError::RuleNotFound
        );
        // Rule PDA address binding.
        require!(
            *ctx.accounts.rule_pda.address() == entry.rule_pda,
            PolicyEngineError::InvalidRuleHeader
        );
        let rule = &ctx.accounts.rule_pda;
        let max_sessions: u8 = rule.max_sessions;
        let default_ttl: u64 = rule.default_ttl_seconds.into();
        let default_max_uses: u32 = rule.default_max_uses.into();
        let amount_cap: u64 = rule.session_max_amount_per_tx.into();

        require!(
            (session_index as u8) < max_sessions,
            PolicyEngineError::InvalidRuleHeader
        );
        require!(
            expires_at_ts > current_ts,
            PolicyEngineError::SessionExpired
        );
        let ttl_actual = (expires_at_ts - current_ts) as u64;
        require!(
            ttl_actual <= default_ttl,
            PolicyEngineError::InvalidRuleHeader
        );
        require!(
            max_uses > 0 && max_uses <= default_max_uses,
            PolicyEngineError::InvalidRuleHeader
        );
        require!(
            max_amount_per_tx > 0 && max_amount_per_tx <= amount_cap,
            PolicyEngineError::InvalidRuleHeader
        );

        // Build the canonical challenge. The session_signer + bounds are
        // bound so a stolen signature cannot redirect to another keypair or
        // extend lifetime.
        let session_signer_bytes = *session_signer.as_array();
        let session_idx_le = session_index.to_le_bytes();
        let expires_le = expires_at_ts.to_le_bytes();
        let uses_le = max_uses.to_le_bytes();
        let amount_le = max_amount_per_tx.to_le_bytes();
        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];
        let challenge = admin_challenge(
            OP_SESSION_OPEN,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_SESSION_KEY,
            rule_index,
            entry.generation,
            on_chain_nonce,
            &entry.config_hash,
            &owner_slot,
            &[
                &session_idx_le,
                session_signer_bytes.as_slice(),
                &expires_le,
                &uses_le,
                &amount_le,
            ],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        ctx.accounts.session.set_inner(SessionInner {
            engine: engine_addr,
            session_signer,
            session_index,
            _pad0: 0,
            created_at_ts: current_ts,
            expires_at_ts,
            used_count: 0,
            max_uses,
            next_signature_nonce: 0,
            max_amount_per_tx,
            next_admin_nonce: 0,
            destinations_count: 0,
            _pad_cfg: [0u8; 7],
            destinations_flat: [0u8; SESSION_MAX_DESTINATIONS * 32],
        });

        ctx.accounts.engine.next_admin_nonce = new_nonce.into();

        ctx.accounts.program.emit_event(
            &SessionOpened {
                engine: engine_addr,
                session_index: session_index as u64,
                expires_at_ts,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 101 — `request_signature_via_session` (F8b).
    ///
    /// Session keypair signs natively; this entrypoint validates the session
    /// (expiry, max_uses, nonce monotonicity), recomputes the canonical
    /// metadata_digest with `PATH_SESSION`, increments counters, and CPIs
    /// `Ika::approve_message`. Bypasses the normal `request_signature`
    /// dispatch loop — sessions are their own gate (see ADR PE-006a, F8b).
    #[instruction(discriminator = 101)]
    #[allow(clippy::too_many_arguments)]
    pub fn request_signature_via_session(
        ctx: CtxWithRemaining<RequestSignatureViaSession>,
        _init_authority_hash: Address,
        _session_index: u32,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
        destination: [u8; 32],
        expected_signature_nonce: u64,
        // Review fix (2026-05-25): per-tx transfer amount (base units), enforced
        // against the session's `max_amount_per_tx` cap below. Authorized by the
        // session signer's native tx signature (the session key signs the whole
        // tx, including this param). Off-chain Risk Layer verifies amount↔tx.
        amount: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let request_hash = Address::from(message_digest);

        ctx.accounts.program.emit_event(
            &SignatureRequested {
                engine: engine_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;

        require!(
            ctx.accounts.engine.paused == 0,
            PolicyEngineError::EnginePaused
        );

        // Session signer must match the bound keypair.
        require!(
            ctx.accounts.session_signer.address() == &ctx.accounts.session.session_signer,
            PolicyEngineError::AuthFailed
        );

        // Atomic monotonic nonce — single-use per session signature.
        let on_chain_nonce: u64 = ctx.accounts.session.next_signature_nonce.into();
        require!(
            expected_signature_nonce == on_chain_nonce,
            PolicyEngineError::InvalidNonce
        );

        // Expiry.
        let expires: i64 = ctx.accounts.session.expires_at_ts.into();
        require!(current_ts < expires, PolicyEngineError::SessionExpired);

        // Usage cap.
        let used: u32 = ctx.accounts.session.used_count.into();
        let cap: u32 = ctx.accounts.session.max_uses.into();
        require!(used < cap, PolicyEngineError::SessionCapExceeded);

        // Per-tx amount cap (set by the owner at session_open, always > 0).
        // Review fix (2026-05-25): previously the cap was stored but never
        // enforced because this entrypoint carried no `amount`. The session
        // signer's tx signature authorizes `amount`; on-chain we cap it here.
        let max_amount: u64 = ctx.accounts.session.max_amount_per_tx.into();
        require!(
            amount <= max_amount,
            PolicyEngineError::SessionAmountExceeded
        );

        // F8c: optional per-session destination whitelist. `destinations_count
        // == 0` means unrestricted (any destination allowed). When > 0, the
        // requested destination MUST appear in the list, byte-for-byte.
        let dest_count = ctx.accounts.session.destinations_count as usize;
        if dest_count > 0 {
            require!(
                dest_count <= SESSION_MAX_DESTINATIONS,
                PolicyEngineError::InvalidRuleHeader
            );
            let mut allowed = false;
            for i in 0..dest_count {
                let off = i * 32;
                if &ctx.accounts.session.destinations_flat[off..off + 32] == destination.as_slice()
                {
                    allowed = true;
                    break;
                }
            }
            require!(allowed, PolicyEngineError::SessionDestinationNotAllowed);
        }

        // metadata_digest binding — PATH_SESSION ensures a session-bound
        // signature can't be replayed onto the normal-signing path.
        let rules_generation: u32 = ctx.accounts.engine.rules_generation.into();
        let expected_md = request_metadata_digest(
            &engine_addr,
            &dwallet_addr,
            &message_digest,
            &destination,
            &user_pubkey,
            signature_scheme,
            PATH_SESSION,
            rules_generation,
            // Session path carries its amount in the session challenge, not in
            // the metadata digest — pass 0/0 for the V2 binding.
            0,
            0,
        );
        require!(
            metadata_digest == expected_md,
            PolicyEngineError::AuthFailed
        );

        // Local CPI defense.
        require!(
            validate_ika_cpi_accounts(
                &ctx.accounts.dwallet_program.to_account_view(),
                &ctx.accounts.dwallet_account.to_account_view(),
            ),
            PolicyEngineError::IkaCpiAccountMismatch
        );

        // Fase 2 (2026-05-25): enforce the engine's APPLIES_SESSION rules on the
        // session signing path too. The caller attaches one remaining account
        // per ENABLED slot (ascending order); only rules whose `applies_to` mask
        // includes PATH_SESSION are enforced. The SessionKey rule that
        // authenticates this session is header-validated and then skipped (it is
        // already enforced by `session_signer` above). SPENDING_USD fails closed
        // (no trusted per-tx amount on the session path). Scoped in a block so
        // the immutable `remaining_accounts` borrow ends before the mutable
        // session counter writes below.
        {
            let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
            let remaining = ctx.remaining_accounts();
            let mut rem_iter = remaining.iter();
            dispatch_active_rules(
                &ctx.accounts.engine.rules_flat,
                &mut rem_iter,
                &sysvar_view,
                current_ts,
                &dwallet_addr,
                &destination,
                0,
                0,
                &metadata_digest,
                PATH_SESSION,
                None,
            )?;
        }

        // Atomic counter bumps before CPI.
        // M1 audit fix: monotonic counters with explicit overflow guards.
        ctx.accounts.session.next_signature_nonce = on_chain_nonce
            .checked_add(1)
            .ok_or(PolicyEngineError::InvalidNonce)?
            .into();
        ctx.accounts.session.used_count = used
            .checked_add(1)
            .ok_or(PolicyEngineError::SessionCapExceeded)?
            .into();

        invoke_ika_approve_message(
            &ctx.accounts.dwallet_program.to_account_view(),
            &ctx.accounts.cpi_authority.to_account_view(),
            // F9-COORD: the Ika caller_program must be THIS program's id — Ika
            // derives the signing authority as PDA(["__ika_cpi_authority"],
            // caller_program) and requires it to sign. Use the `program`
            // account (= policy-engine id, executable). The separate
            // `caller_program` slot stays in the context (now unused) so the
            // instruction account layout is unchanged.
            &ctx.accounts.program.to_account_view(),
            cpi_authority_bump,
            &ctx.accounts.coordinator.to_account_view(),
            &ctx.accounts.message_approval.to_account_view(),
            &ctx.accounts.dwallet_account.to_account_view(),
            &ctx.accounts.payer.to_account_view(),
            &ctx.accounts.system_program.to_account_view(),
            message_digest,
            // F9-SIGN: Ika message_metadata_digest = 0 (the signed message carries
            // no Ika metadata). The Andromeda policy challenge (metadata_digest) is
            // already enforced above via the request_metadata_digest match, so
            // binding it into the Ika MessageApproval here is both redundant and
            // breaks the Ika Sign step (the network derives the approval with empty
            // metadata → otherwise "MessageApproval PDA not found").
            [0u8; 32],
            user_pubkey,
            signature_scheme,
            message_approval_bump,
        )?;

        ctx.accounts.program.emit_event(
            &SignatureApproved {
                engine: engine_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 107 — `request_signature_via_oidc_session` (Fase 2, 2026-05-25).
    ///
    /// OIDC-session NORMAL signing with the engine's `APPLIES_SESSION` rules
    /// enforced. Mirrors `recover_as_primary_oidc` (disc 81) for the OIDC
    /// session validation (open / not-expired / verifier pin / use-nonce /
    /// addr_seed == rule primary), but binds the `destination` into the
    /// canonical `metadata_digest` (PATH_SESSION) and runs the shared
    /// `dispatch_active_rules` over every active slot BEFORE the CPI — so an
    /// OIDC session is gated by the same Allowlist / Velocity / TimeLock /
    /// Oracle rules a session signer would be. SPENDING_USD fails closed
    /// (no trusted per-tx amount on the session path).
    ///
    /// The recovery rule that backs the session occupies a rules_flat slot but
    /// is EXCLUDED from the dispatch (`skip_slot = rule_index`): it is validated
    /// as the named `rule_pda` and is APPLIES_RECOVERY (never a session gate).
    ///
    /// Unlike `oidc_session_open` (JWT verify, RSA-gated), this entrypoint only
    /// checks the already-open `OidcSession` state + an Ed25519 precompile from
    /// the session's `eph_pk`, so it works on clusters without `sol_big_mod_exp`.
    #[instruction(discriminator = 107)]
    #[allow(clippy::too_many_arguments)]
    pub fn request_signature_via_oidc_session(
        ctx: CtxWithRemaining<RequestSignatureViaOidcSessionAccts>,
        _init_authority_hash: Address,
        rule_index: u8,
        _oidc_session_nonce: u64,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
        expected_use_nonce: u64,
        destination: [u8; 32],
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let request_hash = Address::from(message_digest);
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let session_addr = *ctx.accounts.session.address();
        let rule_addr = *ctx.accounts.rule_pda.address();
        let message_approval_addr = *ctx.accounts.message_approval.address();

        ctx.accounts.program.emit_event(
            &SignatureRequested {
                engine: engine_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;

        require!(
            ctx.accounts.engine.paused == 0,
            PolicyEngineError::EnginePaused
        );

        // Session must reference this rule_pda (defense in depth).
        require!(
            ctx.accounts.session.rule_pda == rule_addr,
            PolicyEngineError::InvalidRuleHeader
        );

        // 1. session open + not expired.
        require!(
            ctx.accounts.session.is_closed == 0,
            PolicyEngineError::OidcSessionExpired
        );
        let expires_at: i64 = ctx.accounts.session.expires_at.into();
        require!(
            current_ts < expires_at,
            PolicyEngineError::OidcSessionExpired
        );

        // 2. verifier version pin — downgrade guard.
        let pinned_ver: u32 = ctx.accounts.session.verifier_version.into();
        require!(
            pinned_ver == oidc_verifier::OIDC_VERIFIER_V1,
            PolicyEngineError::OidcVerifierMismatch
        );

        // 3. use-nonce.
        let use_nonce: u64 = ctx.accounts.session.next_use_nonce.into();
        require!(
            expected_use_nonce == use_nonce,
            PolicyEngineError::InvalidNonce
        );

        // 4. policy primary must still match the bound addr_seed. `rule_pda` is
        // an UncheckedAccount (it is re-read by the dispatch as a trailing
        // remaining_account, so a typed `Account<T>` would deadlock the shared
        // borrow). Read `primary_slot` under a scoped borrow released here.
        let bound_addr_seed = ctx.accounts.session.addr_seed;
        let mut expected_primary = [0u8; MEMBER_SLOT_LEN];
        expected_primary[0] = SCHEME_OIDC_JWT;
        expected_primary[1..33].copy_from_slice(&bound_addr_seed);
        let rule_view = ctx.accounts.rule_pda.to_account_view();
        require!(
            rule_view.owner() == &ID,
            PolicyEngineError::InvalidRuleHeader
        );
        let primary_slot = {
            let rule_data = rule_view
                .try_borrow()
                .map_err(|_| PolicyEngineError::InvalidRuleHeader)?;
            // RecoveryRule: disc(1) + header(96) + 8 config bytes
            // (config_applies_to, primary_present, members_count,
            // quorum_threshold, daily_limit_present, destinations_count,
            // pending_change_kind, _pad_cfg0) + primary_slot(34).
            const PRIMARY_SLOT_OFF: usize = 1 + RULE_HEADER_BYTES + 8;
            require!(
                rule_data.len() >= PRIMARY_SLOT_OFF + MEMBER_SLOT_LEN,
                PolicyEngineError::InvalidRuleHeader
            );
            require!(rule_data[0] == 2, PolicyEngineError::InvalidRuleHeader);
            require!(
                rule_data[1] == KIND_RECOVERY,
                PolicyEngineError::InvalidRuleKind
            );
            let mut ps = [0u8; MEMBER_SLOT_LEN];
            ps.copy_from_slice(&rule_data[PRIMARY_SLOT_OFF..PRIMARY_SLOT_OFF + MEMBER_SLOT_LEN]);
            ps
        };
        require!(
            primary_slot == expected_primary,
            PolicyEngineError::OidcAddrSeedMismatch
        );

        // 5. metadata_digest canonical binding — PATH_SESSION + destination, so
        // the eph_pk authorization below covers the exact spend and the digest
        // can't be replayed onto the normal path. Amount carried by the rules,
        // not here (0/0 for the V2 binding; SPENDING_USD fails closed below).
        let rules_generation: u32 = ctx.accounts.engine.rules_generation.into();
        let expected_md = request_metadata_digest(
            &engine_addr,
            &dwallet_addr,
            &message_digest,
            &destination,
            &user_pubkey,
            signature_scheme,
            PATH_SESSION,
            rules_generation,
            0,
            0,
        );
        require!(
            metadata_digest == expected_md,
            PolicyEngineError::AuthFailed
        );

        // 6. Ed25519 precompile over the per-use challenge with the session eph_pk.
        let eph_pk = ctx.accounts.session.eph_pk;
        let challenge = oidc_primary_use_challenge(
            &session_addr,
            &dwallet_addr,
            &message_approval_addr,
            &message_digest,
            &metadata_digest,
            &user_pubkey,
            signature_scheme,
            message_approval_bump,
            use_nonce,
            &expected_primary,
        )
        .map_err(PolicyEngineError::from)?;
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let mut eph_slot = [0u8; MEMBER_SLOT_LEN];
        eph_slot[0] = SCHEME_ED25519;
        eph_slot[1..33].copy_from_slice(&eph_pk);
        verify_signature(VerifyInput {
            member_slot: &eph_slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &[],
            webauthn_client_data_json: &[],
        })
        .map_err(|_| PolicyEngineError::AuthFailed)?;
        drop(sysvar_data_ref);

        // 7. consume use-nonce BEFORE CPI (single-use per signature).
        ctx.accounts.session.next_use_nonce = use_nonce
            .checked_add(1)
            .ok_or(PolicyEngineError::InvalidNonce)?
            .into();

        // 8. CPI Ika defense.
        require!(
            validate_ika_cpi_accounts(
                &ctx.accounts.dwallet_program.to_account_view(),
                &ctx.accounts.dwallet_account.to_account_view(),
            ),
            PolicyEngineError::IkaCpiAccountMismatch
        );

        // 9. Fase 2: enforce the engine's APPLIES_SESSION rules (same shared
        // dispatch as disc 1 / disc 101). The caller attaches one remaining
        // account per ENABLED slot (ascending) plus per-kind aux. The recovery
        // rule that backs this OIDC session is EXCLUDED from the dispatch
        // (`skip_slot = rule_index`): it was already validated as the named
        // `rule_pda` above and is APPLIES_RECOVERY (never a session gate), so
        // the caller does NOT attach it as a remaining account.
        //
        // SECURITY INVARIANT: `skip_slot = rule_index` cannot be abused to skip
        // a different (session-gating) rule. The `#[account(address =
        // RecoveryRule::seeds(engine, rule_index))]` constraint on `rule_pda` is
        // enforced by Quasar at parse time, so `rule_index` is bound to the
        // recovery rule's PDA; `session.rule_pda == rule_addr` (checked above)
        // binds it to THIS session's recovery rule. So slot `rule_index` is
        // provably the recovery slot, never an allowlist/velocity/etc. slot.
        //
        // Scoped so the immutable remaining-accounts borrow ends before the CPI.
        {
            let remaining = ctx.remaining_accounts();
            let mut rem_iter = remaining.iter();
            dispatch_active_rules(
                &ctx.accounts.engine.rules_flat,
                &mut rem_iter,
                &sysvar_view,
                current_ts,
                &dwallet_addr,
                &destination,
                0,
                0,
                &metadata_digest,
                PATH_SESSION,
                Some(rule_index as usize),
            )?;
        }

        // 10. CPI Ika approve_message (F9-SIGN: ika message_metadata_digest = 0).
        invoke_ika_approve_message(
            &ctx.accounts.dwallet_program.to_account_view(),
            &ctx.accounts.cpi_authority.to_account_view(),
            &ctx.accounts.program.to_account_view(),
            cpi_authority_bump,
            &ctx.accounts.coordinator.to_account_view(),
            &ctx.accounts.message_approval.to_account_view(),
            &ctx.accounts.dwallet_account.to_account_view(),
            &ctx.accounts.payer.to_account_view(),
            &ctx.accounts.system_program.to_account_view(),
            message_digest,
            [0u8; 32],
            user_pubkey,
            signature_scheme,
            message_approval_bump,
        )?;

        ctx.accounts.program.emit_event(
            &SignatureApproved {
                engine: engine_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 102 — `session_revoke` (F8c).
    ///
    /// Owner force-expires a session by setting `expires_at_ts = 0`. The
    /// session keypair can no longer sign, but the PDA is NOT closed (rent
    /// stays). Use `session_close` (disc 103) to also reclaim rent. Splitting
    /// the two lets the owner audit-trail a revoke without losing the on-chain
    /// record of who/when/why the session was killed.
    #[instruction(discriminator = 102)]
    pub fn session_revoke(
        ctx: Ctx<SessionAdminAction>,
        _init_authority_hash: Address,
        _session_index: u32,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.session.next_admin_nonce.into();
        let session_addr = *ctx.accounts.session.address();
        let session_idx: u32 = ctx.accounts.session.session_index.into();

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];
        let idx_le = session_idx.to_le_bytes();
        let challenge = admin_challenge(
            OP_SESSION_REVOKE,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_SESSION_KEY,
            0,
            0,
            on_chain_nonce,
            &[0u8; 32],
            &owner_slot,
            &[session_addr.as_array().as_slice(), &idx_le],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        ctx.accounts.session.expires_at_ts = 0i64.into();
        ctx.accounts.session.next_admin_nonce = new_nonce.into();

        ctx.accounts.program.emit_event(
            &SessionRevoked {
                engine: engine_addr,
                session_index: session_idx as u64,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 103 — `session_close` (F8c).
    ///
    /// Owner closes the Session PDA and routes rent to a recipient bound into
    /// the challenge (so a stolen signature cannot redirect rent). After
    /// close, the seed slot is free for reuse by the next `session_open`.
    #[instruction(discriminator = 103)]
    pub fn session_close(
        ctx: Ctx<SessionCloseAction>,
        _init_authority_hash: Address,
        _session_index: u32,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.session.next_admin_nonce.into();
        let session_addr = *ctx.accounts.session.address();
        let session_idx: u32 = ctx.accounts.session.session_index.into();
        let recipient_addr = *ctx.accounts.recipient.address();

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];
        let idx_le = session_idx.to_le_bytes();
        let challenge = admin_challenge(
            OP_SESSION_CLOSE,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_SESSION_KEY,
            0,
            0,
            on_chain_nonce,
            &[0u8; 32],
            &owner_slot,
            &[
                session_addr.as_array().as_slice(),
                &idx_le,
                recipient_addr.as_array().as_slice(),
            ],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let _new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        // Close the PDA (transfers lamports to recipient and zeros data).
        let recipient_view = ctx.accounts.recipient.to_account_view();
        ctx.accounts.session.close(recipient_view)?;

        ctx.accounts.program.emit_event(
            &SessionClosed {
                engine: engine_addr,
                session_index: session_idx as u64,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 104 — `close_expired_session` (F8c, permissionless).
    ///
    /// Anyone may close a Session PDA once `current_ts >= expires_at_ts`. Rent
    /// is routed to the caller-chosen `recipient` (typically the gas sponsor
    /// that submits this cleanup tx). No challenge needed — the runtime
    /// expiry is the gate.
    #[instruction(discriminator = 104)]
    pub fn close_expired_session(
        ctx: Ctx<SessionCloseAction>,
        _init_authority_hash: Address,
        _session_index: u32,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let expires: i64 = ctx.accounts.session.expires_at_ts.into();
        require!(current_ts >= expires, PolicyEngineError::SessionExpired);
        // Note: `SessionExpired` is reused intentionally — semantics here are
        // "expired, so cleanup is allowed". The session is over; this is the
        // happy path. If you want a tighter check distinguishing "still
        // active" from "already expired", split the error in F17 (audit).

        let engine_addr = *ctx.accounts.engine.address();
        let session_idx: u32 = ctx.accounts.session.session_index.into();
        let recipient_view = ctx.accounts.recipient.to_account_view();
        ctx.accounts.session.close(recipient_view)?;

        ctx.accounts.program.emit_event(
            &SessionClosed {
                engine: engine_addr,
                session_index: session_idx as u64,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 105 — `session_add_destination` (F8c).
    ///
    /// Owner appends a destination to the session's per-tx allowlist. Cap is
    /// `SESSION_MAX_DESTINATIONS = 8`. Idempotent — re-adding an existing
    /// destination is a no-op.
    #[instruction(discriminator = 105)]
    pub fn session_add_destination(
        ctx: Ctx<SessionAdminAction>,
        _init_authority_hash: Address,
        _session_index: u32,
        expected_nonce: u64,
        destination: [u8; 32],
    ) -> Result<(), ProgramError> {
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.session.next_admin_nonce.into();
        let session_addr = *ctx.accounts.session.address();
        let session_idx: u32 = ctx.accounts.session.session_index.into();

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];
        let idx_le = session_idx.to_le_bytes();
        let challenge = admin_challenge(
            OP_SESSION_ADD_DEST,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_SESSION_KEY,
            0,
            0,
            on_chain_nonce,
            &[0u8; 32],
            &owner_slot,
            &[session_addr.as_array().as_slice(), &idx_le, &destination],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        let count = ctx.accounts.session.destinations_count as usize;
        // Idempotent: if already present, just bump the nonce and exit.
        for i in 0..count {
            let off = i * 32;
            if ctx.accounts.session.destinations_flat[off..off + 32] == destination {
                ctx.accounts.session.next_admin_nonce = new_nonce.into();
                return Ok(());
            }
        }
        require!(
            count < SESSION_MAX_DESTINATIONS,
            PolicyEngineError::SessionCapExceeded
        );
        let off = count * 32;
        ctx.accounts.session.destinations_flat[off..off + 32].copy_from_slice(&destination);
        ctx.accounts.session.destinations_count = (count as u8) + 1;
        ctx.accounts.session.next_admin_nonce = new_nonce.into();
        Ok(())
    }

    /// Disc 106 — `session_remove_destination` (F8c).
    ///
    /// Owner removes a destination from the session's allowlist. Tail entry
    /// is swapped into the vacated slot; remaining bytes zeroed. No-op if the
    /// destination is not present (nonce still advances to prevent replay).
    #[instruction(discriminator = 106)]
    pub fn session_remove_destination(
        ctx: Ctx<SessionAdminAction>,
        _init_authority_hash: Address,
        _session_index: u32,
        expected_nonce: u64,
        destination: [u8; 32],
    ) -> Result<(), ProgramError> {
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.session.next_admin_nonce.into();
        let session_addr = *ctx.accounts.session.address();
        let session_idx: u32 = ctx.accounts.session.session_index.into();

        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];
        let idx_le = session_idx.to_le_bytes();
        let challenge = admin_challenge(
            OP_SESSION_REMOVE_DEST,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_SESSION_KEY,
            0,
            0,
            on_chain_nonce,
            &[0u8; 32],
            &owner_slot,
            &[session_addr.as_array().as_slice(), &idx_le, &destination],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        let count = ctx.accounts.session.destinations_count as usize;
        for i in 0..count {
            let off = i * 32;
            if ctx.accounts.session.destinations_flat[off..off + 32] == destination {
                let last = (count - 1) * 32;
                if i != count - 1 {
                    let mut tail = [0u8; 32];
                    tail.copy_from_slice(&ctx.accounts.session.destinations_flat[last..last + 32]);
                    ctx.accounts.session.destinations_flat[off..off + 32].copy_from_slice(&tail);
                }
                ctx.accounts.session.destinations_flat[last..last + 32].copy_from_slice(&[0u8; 32]);
                ctx.accounts.session.destinations_count = (count - 1) as u8;
                ctx.accounts.session.next_admin_nonce = new_nonce.into();
                return Ok(());
            }
        }
        // Not found — still advance the nonce so a stolen signature is
        // single-use.
        ctx.accounts.session.next_admin_nonce = new_nonce.into();
        Ok(())
    }

    /// Disc 130 — `update_rule_recovery_add_member` (F9a, PE-011).
    ///
    /// Owner appends one member slot to `RecoveryRule.members`. Idempotent —
    /// adding an already-present slot is a no-op (nonce still advances). Cap
    /// is `MAX_RECOVERY_MEMBERS = 16`.
    #[instruction(discriminator = 130)]
    pub fn update_rule_recovery_add_member(
        ctx: Ctx<UpdateRuleRecovery>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        rule_index: u8,
        member_slot: [u8; MEMBER_SLOT_LEN],
    ) -> Result<(), ProgramError> {
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        validate_slot(&member_slot).map_err(|_| PolicyEngineError::InvalidOwnerSlot)?;
        require!(
            member_slot[0] == SCHEME_ED25519
                || member_slot[0] == SCHEME_SECP256K1
                || member_slot[0] == SCHEME_SECP256R1
                || member_slot[0] == SCHEME_WEBAUTHN,
            PolicyEngineError::UnsupportedScheme
        );

        // Validate rule slot exists and is enabled Recovery.
        let slot = rule_index as usize;
        let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, slot);
        require!(
            entry.kind == KIND_RECOVERY && entry.enabled == 1,
            PolicyEngineError::RuleNotFound
        );
        require!(
            *ctx.accounts.rule_pda.address() == entry.rule_pda,
            PolicyEngineError::InvalidRuleHeader
        );

        let new_generation = entry.generation.saturating_add(1);
        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];
        let gen_le = new_generation.to_le_bytes();
        let challenge = admin_challenge(
            OP_RECOVERY_ADD_MEMBER,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_RECOVERY,
            rule_index,
            new_generation,
            on_chain_nonce,
            &entry.config_hash,
            &owner_slot,
            &[&member_slot, &gen_le],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        let count = ctx.accounts.rule_pda.members_count as usize;
        for i in 0..count {
            let off = i * MEMBER_SLOT_LEN;
            if ctx.accounts.rule_pda.members[off..off + MEMBER_SLOT_LEN] == member_slot {
                // Idempotent — nonce still advances.
                ctx.accounts.engine.next_admin_nonce = new_nonce.into();
                return Ok(());
            }
        }
        require!(
            count < MAX_RECOVERY_MEMBERS,
            PolicyEngineError::TooManyRules
        );
        let off = count * MEMBER_SLOT_LEN;
        ctx.accounts.rule_pda.members[off..off + MEMBER_SLOT_LEN].copy_from_slice(&member_slot);
        ctx.accounts.rule_pda.members_count = (count as u8) + 1;
        ctx.accounts.rule_pda.generation = new_generation.into();
        // config_hash is intentionally NOT recomputed here — members are a
        // dynamic roster managed by the owner and orthogonal to the immutable
        // config payload (primary/quorum_threshold/daily/cooldown/oidc/jwk).
        // The engine RuleEntry.config_hash stays the same; only `generation`
        // advances on the sub-PDA header. (Mirror of rules-policy legacy.)
        let mut new_entry = entry;
        new_entry.generation = new_generation;
        write_rule_entry(&mut ctx.accounts.engine.rules_flat, slot, &new_entry);
        let cur_gen: u32 = ctx.accounts.engine.rules_generation.into();
        ctx.accounts.engine.rules_generation = cur_gen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();
        Ok(())
    }

    /// Disc 131 — `update_rule_recovery_remove_member` (F9a, PE-011).
    ///
    /// Owner removes one member slot. Tail entry swapped into the freed slot;
    /// trailing bytes zeroed. No-op if the slot is not present (nonce still
    /// advances so a stolen signature is single-use).
    #[instruction(discriminator = 131)]
    pub fn update_rule_recovery_remove_member(
        ctx: Ctx<UpdateRuleRecovery>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        rule_index: u8,
        member_slot: [u8; MEMBER_SLOT_LEN],
    ) -> Result<(), ProgramError> {
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        let slot = rule_index as usize;
        let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, slot);
        require!(
            entry.kind == KIND_RECOVERY && entry.enabled == 1,
            PolicyEngineError::RuleNotFound
        );
        require!(
            *ctx.accounts.rule_pda.address() == entry.rule_pda,
            PolicyEngineError::InvalidRuleHeader
        );

        let new_generation = entry.generation.saturating_add(1);
        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];
        let gen_le = new_generation.to_le_bytes();
        let challenge = admin_challenge(
            OP_RECOVERY_REMOVE_MEMBER,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_RECOVERY,
            rule_index,
            new_generation,
            on_chain_nonce,
            &entry.config_hash,
            &owner_slot,
            &[&member_slot, &gen_le],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        let count = ctx.accounts.rule_pda.members_count as usize;
        for i in 0..count {
            let off = i * MEMBER_SLOT_LEN;
            if ctx.accounts.rule_pda.members[off..off + MEMBER_SLOT_LEN] == member_slot {
                let last = (count - 1) * MEMBER_SLOT_LEN;
                if i != count - 1 {
                    let mut tail = [0u8; MEMBER_SLOT_LEN];
                    tail.copy_from_slice(
                        &ctx.accounts.rule_pda.members[last..last + MEMBER_SLOT_LEN],
                    );
                    ctx.accounts.rule_pda.members[off..off + MEMBER_SLOT_LEN]
                        .copy_from_slice(&tail);
                }
                ctx.accounts.rule_pda.members[last..last + MEMBER_SLOT_LEN]
                    .copy_from_slice(&[0u8; MEMBER_SLOT_LEN]);
                ctx.accounts.rule_pda.members_count = (count - 1) as u8;
                break;
            }
        }
        ctx.accounts.rule_pda.generation = new_generation.into();
        let mut new_entry = entry;
        new_entry.generation = new_generation;
        write_rule_entry(&mut ctx.accounts.engine.rules_flat, slot, &new_entry);
        let cur_gen: u32 = ctx.accounts.engine.rules_generation.into();
        ctx.accounts.engine.rules_generation = cur_gen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();
        Ok(())
    }

    /// Disc 132 — `update_rule_recovery_add_destination` (F9a, PE-011).
    ///
    /// Owner appends one allowed destination (32 bytes) to the recovery
    /// destinations whitelist. Idempotent. Cap `MAX_RECOVERY_DESTINATIONS = 16`.
    #[instruction(discriminator = 132)]
    pub fn update_rule_recovery_add_destination(
        ctx: Ctx<UpdateRuleRecovery>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        rule_index: u8,
        destination: [u8; 32],
    ) -> Result<(), ProgramError> {
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        let slot = rule_index as usize;
        let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, slot);
        require!(
            entry.kind == KIND_RECOVERY && entry.enabled == 1,
            PolicyEngineError::RuleNotFound
        );
        require!(
            *ctx.accounts.rule_pda.address() == entry.rule_pda,
            PolicyEngineError::InvalidRuleHeader
        );

        let new_generation = entry.generation.saturating_add(1);
        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];
        let gen_le = new_generation.to_le_bytes();
        let challenge = admin_challenge(
            OP_RECOVERY_ADD_DEST,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_RECOVERY,
            rule_index,
            new_generation,
            on_chain_nonce,
            &entry.config_hash,
            &owner_slot,
            &[&destination, &gen_le],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        let count = ctx.accounts.rule_pda.destinations_count as usize;
        for i in 0..count {
            let off = i * 32;
            if ctx.accounts.rule_pda.destinations[off..off + 32] == destination {
                ctx.accounts.engine.next_admin_nonce = new_nonce.into();
                return Ok(());
            }
        }
        require!(
            count < MAX_RECOVERY_DESTINATIONS,
            PolicyEngineError::TooManyRules
        );
        let off = count * 32;
        ctx.accounts.rule_pda.destinations[off..off + 32].copy_from_slice(&destination);
        ctx.accounts.rule_pda.destinations_count = (count as u8) + 1;
        ctx.accounts.rule_pda.generation = new_generation.into();
        let mut new_entry = entry;
        new_entry.generation = new_generation;
        write_rule_entry(&mut ctx.accounts.engine.rules_flat, slot, &new_entry);
        let cur_gen: u32 = ctx.accounts.engine.rules_generation.into();
        ctx.accounts.engine.rules_generation = cur_gen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();
        Ok(())
    }

    /// Disc 133 — `update_rule_recovery_remove_destination` (F9a, PE-011).
    #[instruction(discriminator = 133)]
    pub fn update_rule_recovery_remove_destination(
        ctx: Ctx<UpdateRuleRecovery>,
        _init_authority_hash: Address,
        expected_nonce: u64,
        rule_index: u8,
        destination: [u8; 32],
    ) -> Result<(), ProgramError> {
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let owner_slot = ctx.accounts.engine.owner_slot;
        let on_chain_nonce: u64 = ctx.accounts.engine.next_admin_nonce.into();

        let slot = rule_index as usize;
        let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, slot);
        require!(
            entry.kind == KIND_RECOVERY && entry.enabled == 1,
            PolicyEngineError::RuleNotFound
        );
        require!(
            *ctx.accounts.rule_pda.address() == entry.rule_pda,
            PolicyEngineError::InvalidRuleHeader
        );

        let new_generation = entry.generation.saturating_add(1);
        let mut human_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
        let human_len =
            human_message::allowlist_pause_message(&mut human_buf, &engine_addr, &dwallet_addr)
                .map_err(PolicyEngineError::from)?;
        let human = &human_buf[..human_len];
        let gen_le = new_generation.to_le_bytes();
        let challenge = admin_challenge(
            OP_RECOVERY_REMOVE_DEST,
            human,
            &engine_addr,
            &dwallet_addr,
            KIND_RECOVERY,
            rule_index,
            new_generation,
            on_chain_nonce,
            &entry.config_hash,
            &owner_slot,
            &[&destination, &gen_le],
        );
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(PolicyEngineError::from)?;
        drop(sysvar_data_ref);

        let count = ctx.accounts.rule_pda.destinations_count as usize;
        for i in 0..count {
            let off = i * 32;
            if ctx.accounts.rule_pda.destinations[off..off + 32] == destination {
                let last = (count - 1) * 32;
                if i != count - 1 {
                    let mut tail = [0u8; 32];
                    tail.copy_from_slice(&ctx.accounts.rule_pda.destinations[last..last + 32]);
                    ctx.accounts.rule_pda.destinations[off..off + 32].copy_from_slice(&tail);
                }
                ctx.accounts.rule_pda.destinations[last..last + 32].copy_from_slice(&[0u8; 32]);
                ctx.accounts.rule_pda.destinations_count = (count - 1) as u8;
                break;
            }
        }
        ctx.accounts.rule_pda.generation = new_generation.into();
        let mut new_entry = entry;
        new_entry.generation = new_generation;
        write_rule_entry(&mut ctx.accounts.engine.rules_flat, slot, &new_entry);
        let cur_gen: u32 = ctx.accounts.engine.rules_generation.into();
        ctx.accounts.engine.rules_generation = cur_gen
            .checked_add(1)
            .ok_or(PolicyEngineError::TooManyRules)?
            .into();
        ctx.accounts.engine.next_admin_nonce = new_nonce.into();
        Ok(())
    }

    /// Disc 80 — `recover_as_primary` (F9a).
    ///
    /// Primary keypair signs an Ika `approve_message` directly, bypassing the
    /// normal owner_slot signing path. The recovery "owns" the dWallet by
    /// virtue of being on the same authority program (policy-engine) — we
    /// don't rotate `engine.owner_slot`; instead each recovery is a one-off
    /// signature whose nonce is tracked in `RecoveryRule.next_admin_nonce`.
    ///
    /// Daily limit + destinations whitelist are enforced when present. Mirrors
    /// `rules-policy::recover_as_primary` legacy semantics line-for-line, but
    /// reads policy fields from the Recovery sub-PDA instead of a dedicated
    /// policy account. Cooldown / pending_change enforcement lands in F9b.
    #[instruction(discriminator = 80)]
    #[allow(clippy::too_many_arguments)]
    pub fn recover_as_primary(
        ctx: Ctx<RecoverAsPrimary>,
        _init_authority_hash: Address,
        rule_index: u8,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
        destination: [u8; 32],
        expected_nonce: u64,
        amount: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let request_hash = Address::from(message_digest);

        ctx.accounts.program.emit_event(
            &SignatureRequested {
                engine: engine_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;

        require!(
            ctx.accounts.engine.paused == 0,
            PolicyEngineError::EnginePaused
        );

        // Validate rule slot and PDA binding.
        let slot = rule_index as usize;
        let entry = read_rule_entry(&ctx.accounts.engine.rules_flat, slot);
        require!(
            entry.kind == KIND_RECOVERY && entry.enabled == 1,
            PolicyEngineError::RuleNotFound
        );
        require!(
            *ctx.accounts.rule_pda.address() == entry.rule_pda,
            PolicyEngineError::InvalidRuleHeader
        );

        // Primary must be present.
        require!(
            ctx.accounts.rule_pda.primary_present == 1,
            PolicyEngineError::RuleNotApplicable
        );
        let primary_slot = ctx.accounts.rule_pda.primary_slot;

        // Atomic nonce check.
        let policy_nonce: u64 = ctx.accounts.rule_pda.next_admin_nonce.into();
        require!(
            expected_nonce == policy_nonce,
            PolicyEngineError::InvalidNonce
        );

        // Destination whitelist (when set).
        let dest_count = ctx.accounts.rule_pda.destinations_count as usize;
        if dest_count > 0 {
            require!(
                dest_count <= MAX_RECOVERY_DESTINATIONS,
                PolicyEngineError::InvalidRuleHeader
            );
            let mut allowed = false;
            for i in 0..dest_count {
                let off = i * 32;
                if &ctx.accounts.rule_pda.destinations[off..off + 32] == destination.as_slice() {
                    allowed = true;
                    break;
                }
            }
            require!(allowed, PolicyEngineError::RecoveryDestinationNotAllowed);
        }

        // Daily-limit enforcement (when set).
        if ctx.accounts.rule_pda.daily_limit_present == 1 {
            let limit: u64 = ctx.accounts.rule_pda.daily_limit.into();
            let current_day_unix: i64 = ctx.accounts.rule_pda.current_day_unix.into();
            let current_day_sum: u64 = ctx.accounts.rule_pda.current_day_sum.into();
            // Day bucket: floor(current_ts / 86400) * 86400. Reset when
            // crossing a day boundary.
            let day = (current_ts / 86_400) * 86_400;
            let (next_day, next_sum) = if day != current_day_unix {
                (day, amount)
            } else {
                (day, current_day_sum.saturating_add(amount))
            };
            require!(
                next_sum <= limit,
                PolicyEngineError::RecoveryDailyLimitExceeded
            );
            ctx.accounts.rule_pda.current_day_unix = next_day.into();
            ctx.accounts.rule_pda.current_day_sum = next_sum.into();
        }

        // Re-validate the recompute of `metadata_digest` is the caller's
        // responsibility — primary_recover_challenge below binds it. Local
        // CPI defense.
        require!(
            validate_ika_cpi_accounts(
                &ctx.accounts.dwallet_program.to_account_view(),
                &ctx.accounts.dwallet_account.to_account_view(),
            ),
            PolicyEngineError::IkaCpiAccountMismatch
        );

        // Recompute the canonical challenge that the primary keypair signed
        // off-chain (mirror of `rules-policy::recover_as_primary`).
        let message_approval_addr = *ctx.accounts.message_approval.address();
        let challenge = primary_recover_challenge(
            &dwallet_addr,
            &message_approval_addr,
            &message_digest,
            &metadata_digest,
            &user_pubkey,
            signature_scheme,
            message_approval_bump,
            policy_nonce,
            &primary_slot,
        )
        .map_err(PolicyEngineError::from)?;

        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let scheme = primary_slot[0];
        require!(
            scheme == SCHEME_ED25519 || scheme == SCHEME_SECP256K1 || scheme == SCHEME_SECP256R1,
            PolicyEngineError::UnsupportedScheme
        );
        verify_signature(VerifyInput {
            member_slot: &primary_slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &[],
            webauthn_client_data_json: &[],
        })
        .map_err(|_| PolicyEngineError::AuthFailed)?;
        drop(sysvar_data_ref);

        // Atomic nonce bump BEFORE CPI.
        // M1 audit fix.
        ctx.accounts.rule_pda.next_admin_nonce = policy_nonce
            .checked_add(1)
            .ok_or(PolicyEngineError::InvalidNonce)?
            .into();

        invoke_ika_approve_message(
            &ctx.accounts.dwallet_program.to_account_view(),
            &ctx.accounts.cpi_authority.to_account_view(),
            // F9-COORD: the Ika caller_program must be THIS program's id — Ika
            // derives the signing authority as PDA(["__ika_cpi_authority"],
            // caller_program) and requires it to sign. Use the `program`
            // account (= policy-engine id, executable). The separate
            // `caller_program` slot stays in the context (now unused) so the
            // instruction account layout is unchanged.
            &ctx.accounts.program.to_account_view(),
            cpi_authority_bump,
            &ctx.accounts.coordinator.to_account_view(),
            &ctx.accounts.message_approval.to_account_view(),
            &ctx.accounts.dwallet_account.to_account_view(),
            &ctx.accounts.payer.to_account_view(),
            &ctx.accounts.system_program.to_account_view(),
            message_digest,
            // F9-SIGN: Ika message_metadata_digest = 0 (the signed message carries
            // no Ika metadata). The Andromeda policy challenge (metadata_digest) is
            // already enforced above via the request_metadata_digest match, so
            // binding it into the Ika MessageApproval here is both redundant and
            // breaks the Ika Sign step (the network derives the approval with empty
            // metadata → otherwise "MessageApproval PDA not found").
            [0u8; 32],
            user_pubkey,
            signature_scheme,
            message_approval_bump,
        )?;

        ctx.accounts.program.emit_event(
            &PrimaryRecoverInvoked {
                engine: engine_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        ctx.accounts.program.emit_event(
            &SignatureApproved {
                engine: engine_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 82 — `quorum_session_open` (F9b).
    ///
    /// Primary keypair authorizes a quorum session bound to a specific
    /// `(message, amount, destination, expiry)`. Snapshots the current member
    /// roster + threshold so concurrent admin updates (disc 130/131) cannot
    /// affect in-flight recoveries. Caller pays rent; the same caller is
    /// recorded in `payer_for_close` so `quorum_session_close` can refund.
    #[instruction(discriminator = 82)]
    #[allow(clippy::too_many_arguments)]
    pub fn quorum_session_open(
        ctx: Ctx<QuorumSessionOpenAccts>,
        _init_authority_hash: Address,
        _rule_index: u8,
        _session_nonce: u64,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        amount: u64,
        destination: [u8; 32],
        expires_at: i64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let engine_addr = *ctx.accounts.engine.address();
        let rule_addr = *ctx.accounts.rule_pda.address();
        let payer_addr = *ctx.accounts.payer.address();

        // M6 audit fix (2026-05-16): block session creation while paused.
        require!(
            ctx.accounts.engine.paused == 0,
            PolicyEngineError::EnginePaused
        );

        let ttl = expires_at.saturating_sub(current_ts);
        require!(
            ttl > 0 && ttl <= MAX_QUORUM_SESSION_TTL_SECONDS,
            PolicyEngineError::GenericError
        );

        // Recovery rule must exist + primary present.
        require!(
            ctx.accounts.rule_pda.primary_present == 1,
            PolicyEngineError::RuleNotApplicable
        );
        let primary_slot = ctx.accounts.rule_pda.primary_slot;
        let threshold = ctx.accounts.rule_pda.quorum_threshold;
        let member_count = ctx.accounts.rule_pda.members_count;
        require!(
            threshold >= 1 && member_count >= threshold,
            PolicyEngineError::GenericError
        );

        let session_nonce_on_chain: u64 = ctx.accounts.rule_pda.next_session_nonce.into();

        // Primary signs the canonical open challenge.
        let challenge = quorum_session_open_challenge(
            &dwallet_addr,
            &message_digest,
            &metadata_digest,
            &user_pubkey,
            signature_scheme,
            message_approval_bump,
            amount,
            &destination,
            expires_at,
            session_nonce_on_chain,
            &primary_slot,
        )
        .map_err(PolicyEngineError::from)?;
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let scheme = primary_slot[0];
        require!(
            scheme == SCHEME_ED25519 || scheme == SCHEME_SECP256K1 || scheme == SCHEME_SECP256R1,
            PolicyEngineError::UnsupportedScheme
        );
        verify_signature(VerifyInput {
            member_slot: &primary_slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &[],
            webauthn_client_data_json: &[],
        })
        .map_err(|_| PolicyEngineError::AuthFailed)?;
        drop(sysvar_data_ref);

        // Snapshot the member roster (field-by-field — set_inner literal would
        // build 544+ bytes of locals on the SBF stack, like the recovery
        // add_rule incident).
        ctx.accounts.session.engine = engine_addr;
        ctx.accounts.session.rule_pda = rule_addr;
        ctx.accounts.session.payer_for_close = payer_addr;
        ctx.accounts.session.session_nonce = session_nonce_on_chain.into();
        ctx.accounts.session.message_digest = message_digest;
        ctx.accounts.session.metadata_digest = metadata_digest;
        ctx.accounts.session.user_pubkey = user_pubkey;
        ctx.accounts.session.destination = destination;
        ctx.accounts.session.amount = amount.into();
        ctx.accounts.session.expires_at = expires_at.into();
        ctx.accounts.session.created_at = current_ts.into();
        ctx.accounts.session.finalized_at = 0i64.into();
        ctx.accounts.session.is_finalized = 0;
        ctx.accounts.session.signature_scheme = signature_scheme.into();
        ctx.accounts.session.member_count_snapshot = member_count;
        ctx.accounts.session.threshold_snapshot = threshold;
        ctx.accounts.session.message_approval_bump = message_approval_bump;
        ctx.accounts.session.contributions_count = 0;
        ctx.accounts.session.contributions_bitmap = 0u16.into();
        ctx.accounts
            .session
            .members_snapshot
            .copy_from_slice(&ctx.accounts.rule_pda.members);

        // M1 audit fix.
        ctx.accounts.rule_pda.next_session_nonce = session_nonce_on_chain
            .checked_add(1)
            .ok_or(PolicyEngineError::InvalidNonce)?
            .into();
        Ok(())
    }

    /// Disc 83 — `quorum_session_contribute` (F9b, Ed25519/Secp256k1/Secp256r1).
    ///
    /// One member contribution per tx. Member signs the canonical
    /// `quorum_contribute_challenge` off-chain; we validate via precompile.
    /// Bitmap entry prevents double-contribution by the same member index.
    /// WebAuthn-Secp256r1 contributions are deferred to disc 84 (F9b-webauthn).
    #[instruction(discriminator = 83)]
    pub fn quorum_session_contribute(
        ctx: Ctx<QuorumSessionContributeAccts>,
        _init_authority_hash: Address,
        _session_nonce: u64,
        member_index: u8,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        require!(
            ctx.accounts.session.is_finalized == 0,
            PolicyEngineError::GenericError
        );
        let expires_at: i64 = ctx.accounts.session.expires_at.into();
        require!(current_ts < expires_at, PolicyEngineError::SessionExpired);

        let mc = ctx.accounts.session.member_count_snapshot;
        require!(
            member_index < mc,
            PolicyEngineError::RecoveryMemberNotInQuorum
        );

        let bit = 1u16 << (member_index as u16);
        let bitmap: u16 = ctx.accounts.session.contributions_bitmap.into();
        require!((bitmap & bit) == 0, PolicyEngineError::GenericError);

        let off = (member_index as usize) * MEMBER_SLOT_LEN;
        let mut slot = [0u8; MEMBER_SLOT_LEN];
        slot.copy_from_slice(&ctx.accounts.session.members_snapshot[off..off + MEMBER_SLOT_LEN]);
        validate_slot(&slot).map_err(|_| PolicyEngineError::InvalidOwnerSlot)?;

        let session_addr = *ctx.accounts.session.address();
        let amount: u64 = ctx.accounts.session.amount.into();
        let signature_scheme: u16 = ctx.accounts.session.signature_scheme.into();
        let expires_at_i64: i64 = ctx.accounts.session.expires_at.into();
        let dwallet_addr_ref = *ctx.accounts.dwallet_account.address();
        let destination_arr = ctx.accounts.session.destination;
        let message_digest_arr = ctx.accounts.session.message_digest;
        let metadata_digest_arr = ctx.accounts.session.metadata_digest;
        let user_pubkey_arr = ctx.accounts.session.user_pubkey;
        let bump_u8 = ctx.accounts.session.message_approval_bump;
        let challenge = quorum_contribute_challenge(
            &session_addr,
            &slot,
            &dwallet_addr_ref,
            amount,
            &destination_arr,
            &message_digest_arr,
            &metadata_digest_arr,
            &user_pubkey_arr,
            signature_scheme,
            bump_u8,
            expires_at_i64,
        )
        .map_err(PolicyEngineError::from)?;

        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        let scheme = slot[0];
        require!(
            scheme == SCHEME_ED25519 || scheme == SCHEME_SECP256K1 || scheme == SCHEME_SECP256R1,
            PolicyEngineError::UnsupportedScheme
        );
        verify_signature(VerifyInput {
            member_slot: &slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &[],
            webauthn_client_data_json: &[],
        })
        .map_err(|_| PolicyEngineError::AuthFailed)?;
        drop(sysvar_data_ref);

        let new_bitmap = bitmap | bit;
        let new_count = ctx.accounts.session.contributions_count + 1;
        ctx.accounts.session.contributions_bitmap = new_bitmap.into();
        ctx.accounts.session.contributions_count = new_count;
        Ok(())
    }

    /// Disc 84 — `quorum_session_contribute_webauthn` (F9b-webauthn).
    ///
    /// Same semantics as disc 83 (single member contribution per tx,
    /// bitmap-protected against double-contribution, session must be live)
    /// but for the `SCHEME_WEBAUTHN` slot variant. The member signs the same
    /// canonical `quorum_contribute_challenge` via a WebAuthn assertion:
    /// the on-chain handler reconstructs `auth_data || sha256(cdj)` and
    /// matches it against a Secp256r1 precompile invocation in the same tx,
    /// while also enforcing the `clientDataJSON.challenge` anchor check.
    #[instruction(discriminator = 84)]
    #[allow(clippy::too_many_arguments)]
    pub fn quorum_session_contribute_webauthn(
        ctx: Ctx<QuorumSessionContributeAccts>,
        _init_authority_hash: Address,
        _session_nonce: u64,
        member_index: u8,
        webauthn_auth_data_len: u16,
        webauthn_auth_data: [u8; WEBAUTHN_AUTH_DATA_MAX],
        webauthn_cdj_len: u16,
        webauthn_cdj: [u8; WEBAUTHN_CLIENT_DATA_JSON_MAX],
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        require!(
            ctx.accounts.session.is_finalized == 0,
            PolicyEngineError::GenericError
        );
        let expires_at: i64 = ctx.accounts.session.expires_at.into();
        require!(current_ts < expires_at, PolicyEngineError::SessionExpired);

        let mc = ctx.accounts.session.member_count_snapshot;
        require!(
            member_index < mc,
            PolicyEngineError::RecoveryMemberNotInQuorum
        );

        let bit = 1u16 << (member_index as u16);
        let bitmap: u16 = ctx.accounts.session.contributions_bitmap.into();
        require!((bitmap & bit) == 0, PolicyEngineError::GenericError);

        let off = (member_index as usize) * MEMBER_SLOT_LEN;
        let mut slot = [0u8; MEMBER_SLOT_LEN];
        slot.copy_from_slice(&ctx.accounts.session.members_snapshot[off..off + MEMBER_SLOT_LEN]);
        validate_slot(&slot).map_err(|_| PolicyEngineError::InvalidOwnerSlot)?;
        require!(
            slot[0] == SCHEME_WEBAUTHN,
            PolicyEngineError::UnsupportedScheme
        );

        // WebAuthn payload bounds.
        let auth_len = webauthn_auth_data_len as usize;
        let cdj_len = webauthn_cdj_len as usize;
        require!(
            auth_len > 0
                && auth_len <= WEBAUTHN_AUTH_DATA_MAX
                && cdj_len > 0
                && cdj_len <= WEBAUTHN_CLIENT_DATA_JSON_MAX,
            PolicyEngineError::PasskeyStepUpInvalid
        );

        let session_addr = *ctx.accounts.session.address();
        let amount: u64 = ctx.accounts.session.amount.into();
        let signature_scheme: u16 = ctx.accounts.session.signature_scheme.into();
        let expires_at_i64: i64 = ctx.accounts.session.expires_at.into();
        let dwallet_addr_ref = *ctx.accounts.dwallet_account.address();
        let destination_arr = ctx.accounts.session.destination;
        let message_digest_arr = ctx.accounts.session.message_digest;
        let metadata_digest_arr = ctx.accounts.session.metadata_digest;
        let user_pubkey_arr = ctx.accounts.session.user_pubkey;
        let bump_u8 = ctx.accounts.session.message_approval_bump;
        let challenge = quorum_contribute_challenge(
            &session_addr,
            &slot,
            &dwallet_addr_ref,
            amount,
            &destination_arr,
            &message_digest_arr,
            &metadata_digest_arr,
            &user_pubkey_arr,
            signature_scheme,
            bump_u8,
            expires_at_i64,
        )
        .map_err(PolicyEngineError::from)?;

        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        verify_signature(VerifyInput {
            member_slot: &slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &webauthn_auth_data[..auth_len],
            webauthn_client_data_json: &webauthn_cdj[..cdj_len],
        })
        .map_err(|_| PolicyEngineError::PasskeyAssertionInvalid)?;
        drop(sysvar_data_ref);

        let new_bitmap = bitmap | bit;
        let new_count = ctx.accounts.session.contributions_count + 1;
        ctx.accounts.session.contributions_bitmap = new_bitmap.into();
        ctx.accounts.session.contributions_count = new_count;
        Ok(())
    }

    /// Disc 85 — `quorum_session_finalize` (F9b).
    ///
    /// Permissionless: anyone may call once `contributions_count >=
    /// threshold_snapshot`. Enforces daily_limit + destination whitelist on
    /// the RecoveryRule (state shared across sessions). CPIs Ika
    /// `approve_message`. Marks `finalized_at` so the session cannot be
    /// finalized twice or used after expiry.
    #[instruction(discriminator = 85)]
    #[allow(clippy::too_many_arguments)]
    pub fn quorum_session_finalize(
        ctx: Ctx<QuorumSessionFinalizeAccts>,
        _init_authority_hash: Address,
        _rule_index: u8,
        _session_nonce: u64,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let rule_addr = *ctx.accounts.rule_pda.address();
        let request_hash = Address::from(ctx.accounts.session.message_digest);

        // H2 audit fix (2026-05-16): the session pinned its `rule_pda` at open
        // time. Even with `rule_index` parametrized in the accounts struct,
        // require the runtime equality so the dispatched policy is exactly the
        // one the quorum signed off on.
        require!(
            ctx.accounts.session.rule_pda == rule_addr,
            PolicyEngineError::InvalidRuleHeader
        );

        ctx.accounts.program.emit_event(
            &SignatureRequested {
                engine: engine_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;

        require!(
            ctx.accounts.engine.paused == 0,
            PolicyEngineError::EnginePaused
        );

        let finalized_at: i64 = ctx.accounts.session.finalized_at.into();
        require!(finalized_at == 0, PolicyEngineError::GenericError);
        let expires_at: i64 = ctx.accounts.session.expires_at.into();
        require!(current_ts < expires_at, PolicyEngineError::SessionExpired);
        require!(
            ctx.accounts.session.contributions_count >= ctx.accounts.session.threshold_snapshot,
            PolicyEngineError::RecoveryQuorumNotReached
        );

        // Snapshot fields needed below before we borrow rule_pda mutably.
        // (F9-SIGN: session.metadata_digest is no longer snapshotted — the Ika
        // approve_message now uses a zero message_metadata_digest; the session's
        // own challenge binding stays enforced via open/contribute.)
        let message_digest = ctx.accounts.session.message_digest;
        let user_pubkey = ctx.accounts.session.user_pubkey;
        let signature_scheme: u16 = ctx.accounts.session.signature_scheme.into();
        let message_approval_bump = ctx.accounts.session.message_approval_bump;
        let destination = ctx.accounts.session.destination;
        let amount: u64 = ctx.accounts.session.amount.into();

        // Destination whitelist (when set).
        let dest_count = ctx.accounts.rule_pda.destinations_count as usize;
        if dest_count > 0 {
            require!(
                dest_count <= MAX_RECOVERY_DESTINATIONS,
                PolicyEngineError::InvalidRuleHeader
            );
            let mut allowed = false;
            for i in 0..dest_count {
                let off = i * 32;
                if &ctx.accounts.rule_pda.destinations[off..off + 32] == destination.as_slice() {
                    allowed = true;
                    break;
                }
            }
            require!(allowed, PolicyEngineError::RecoveryDestinationNotAllowed);
        }

        // Daily-limit (state on RecoveryRule, shared across sessions).
        //
        // L3 audit fix (2026-05-16): the daily window is bucketed by the UTC
        // midnight boundary (`current_ts / 86_400 * 86_400`). For users in
        // other timezones "daily" does NOT correspond to local calendar days.
        // This is intentional — on-chain time is UTC and a per-tenant TZ
        // would add state without buying real security. Documented in
        // GitBook (Recovery section).
        //
        // M7 audit note (2026-05-16): the TOCTOU race that would let two
        // concurrent finalizes overshoot the daily limit is mitigated by the
        // Solana runtime: `rule_pda` is `mut` in `QuorumSessionFinalizeAccts`,
        // so two txs that touch the same `rule_pda` cannot execute in
        // parallel — the runtime serializes them. The off-chain gateway also
        // pre-checks the limit before dispatch as a primary guard. The race
        // re-appears only if a future ABI change moves the daily state out of
        // `RecoveryRule` (e.g. into a sibling read-only PDA); that change MUST
        // re-introduce nonce-based ordering at the same time.
        if ctx.accounts.rule_pda.daily_limit_present == 1 {
            let limit: u64 = ctx.accounts.rule_pda.daily_limit.into();
            let current_day_unix: i64 = ctx.accounts.rule_pda.current_day_unix.into();
            let current_day_sum: u64 = ctx.accounts.rule_pda.current_day_sum.into();
            let day = (current_ts / 86_400) * 86_400;
            let (next_day, next_sum) = if day != current_day_unix {
                (day, amount)
            } else {
                (day, current_day_sum.saturating_add(amount))
            };
            require!(
                next_sum <= limit,
                PolicyEngineError::RecoveryDailyLimitExceeded
            );
            ctx.accounts.rule_pda.current_day_unix = next_day.into();
            ctx.accounts.rule_pda.current_day_sum = next_sum.into();
        }

        // CPI Ika defense.
        require!(
            validate_ika_cpi_accounts(
                &ctx.accounts.dwallet_program.to_account_view(),
                &ctx.accounts.dwallet_account.to_account_view(),
            ),
            PolicyEngineError::IkaCpiAccountMismatch
        );

        // Mark finalized BEFORE CPI (anti-replay on re-entrancy).
        ctx.accounts.session.finalized_at = current_ts.into();
        ctx.accounts.session.is_finalized = 1;

        invoke_ika_approve_message(
            &ctx.accounts.dwallet_program.to_account_view(),
            &ctx.accounts.cpi_authority.to_account_view(),
            // F9-COORD: the Ika caller_program must be THIS program's id — Ika
            // derives the signing authority as PDA(["__ika_cpi_authority"],
            // caller_program) and requires it to sign. Use the `program`
            // account (= policy-engine id, executable). The separate
            // `caller_program` slot stays in the context (now unused) so the
            // instruction account layout is unchanged.
            &ctx.accounts.program.to_account_view(),
            cpi_authority_bump,
            &ctx.accounts.coordinator.to_account_view(),
            &ctx.accounts.message_approval.to_account_view(),
            &ctx.accounts.dwallet_account.to_account_view(),
            &ctx.accounts.payer.to_account_view(),
            &ctx.accounts.system_program.to_account_view(),
            message_digest,
            // F9-SIGN: Ika message_metadata_digest = 0 (the signed message carries
            // no Ika metadata). The Andromeda policy challenge (metadata_digest) is
            // already enforced above via the request_metadata_digest match, so
            // binding it into the Ika MessageApproval here is both redundant and
            // breaks the Ika Sign step (the network derives the approval with empty
            // metadata → otherwise "MessageApproval PDA not found").
            [0u8; 32],
            user_pubkey,
            signature_scheme,
            message_approval_bump,
        )?;

        ctx.accounts.program.emit_event(
            &SignatureApproved {
                engine: engine_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 86 — `quorum_session_close` (F9b).
    ///
    /// Closes the session PDA after finalize OR after expiry. Lamports go to
    /// `recipient`, which MUST equal `session.payer_for_close` (locked in at
    /// open time). Permissionless after expiry; before finalize+expiry, only
    /// the original payer can close.
    #[instruction(discriminator = 86)]
    pub fn quorum_session_close(
        ctx: Ctx<QuorumSessionCloseAccts>,
        _init_authority_hash: Address,
        _session_nonce: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let expires_at: i64 = ctx.accounts.session.expires_at.into();
        require!(
            ctx.accounts.session.is_finalized == 1 || current_ts >= expires_at,
            PolicyEngineError::GenericError
        );

        let stored = ctx.accounts.session.payer_for_close;
        let dest_addr = *ctx.accounts.recipient.address();
        require!(dest_addr == stored, PolicyEngineError::AuthFailed);

        let recipient_view = ctx.accounts.recipient.to_account_view();
        ctx.accounts.session.close(recipient_view)?;
        Ok(())
    }

    /// Disc 89 — `passkey_session_open` (F9d).
    ///
    /// Authenticates the dWallet's passkey primary (Secp256r1 + WebAuthn
    /// assertion) and opens a short-lived PasskeySession bound to an
    /// ephemeral Ed25519 key. The user signs `passkey_session_open_challenge`
    /// inside `clientDataJSON.challenge`; `verify_signature` (scheme =
    /// WEBAUTHN) checks the Secp256r1 precompile signature over
    /// `(auth_data || sha256(clientDataJSON))` AND that the canonical
    /// challenge bytes appear base64url-no-pad inside the JSON.
    #[instruction(discriminator = 89)]
    #[allow(clippy::too_many_arguments)]
    pub fn passkey_session_open(
        ctx: Ctx<PasskeySessionOpenAccts>,
        _init_authority_hash: Address,
        _rule_index: u8,
        _passkey_session_nonce: u64,
        eph_pk: [u8; 32],
        not_after_unix_ts: u64,
        credential_id_hash: [u8; 32],
        expected_passkey_session_nonce: u64,
        webauthn_auth_data_len: u16,
        webauthn_auth_data: [u8; WEBAUTHN_AUTH_DATA_MAX],
        webauthn_cdj_len: u16,
        webauthn_cdj: [u8; WEBAUTHN_CLIENT_DATA_JSON_MAX],
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let rule_addr = *ctx.accounts.rule_pda.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let payer_addr = *ctx.accounts.payer.address();

        // M6 audit fix (2026-05-16): block session creation while paused.
        require!(
            ctx.accounts.engine.paused == 0,
            PolicyEngineError::EnginePaused
        );

        // 0. nonce reject-fast.
        let on_chain_nonce: u64 = ctx.accounts.rule_pda.next_passkey_session_nonce.into();
        require!(
            expected_passkey_session_nonce == on_chain_nonce,
            PolicyEngineError::InvalidNonce
        );

        // 1. primary must be a passkey slot.
        require!(
            ctx.accounts.rule_pda.primary_present == 1,
            PolicyEngineError::RuleNotApplicable
        );
        let primary_slot = ctx.accounts.rule_pda.primary_slot;
        require!(
            primary_slot[0] == SCHEME_WEBAUTHN,
            PolicyEngineError::UnsupportedScheme
        );
        validate_slot(&primary_slot).map_err(|_| PolicyEngineError::InvalidOwnerSlot)?;

        // 2. WebAuthn payload bounds.
        let auth_len = webauthn_auth_data_len as usize;
        let cdj_len = webauthn_cdj_len as usize;
        require!(
            auth_len > 0
                && auth_len <= WEBAUTHN_AUTH_DATA_MAX
                && cdj_len > 0
                && cdj_len <= WEBAUTHN_CLIENT_DATA_JSON_MAX,
            PolicyEngineError::PasskeyStepUpInvalid
        );

        // 3. effective expiry — capped at now + PASSKEY_SESSION_TTL_SECONDS.
        let not_after_i = if not_after_unix_ts <= i64::MAX as u64 {
            not_after_unix_ts as i64
        } else {
            i64::MAX
        };
        let expires_at = current_ts
            .saturating_add(PASSKEY_SESSION_TTL_SECONDS)
            .min(not_after_i);
        require!(
            expires_at > current_ts,
            PolicyEngineError::PasskeyStepUpInvalid
        );

        // 4. derive open challenge and verify the WebAuthn assertion.
        let challenge = passkey_session_open_challenge(
            &dwallet_addr,
            &primary_slot,
            &eph_pk,
            not_after_unix_ts,
            &credential_id_hash,
            on_chain_nonce,
        )
        .map_err(PolicyEngineError::from)?;
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        verify_signature(VerifyInput {
            member_slot: &primary_slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &webauthn_auth_data[..auth_len],
            webauthn_client_data_json: &webauthn_cdj[..cdj_len],
        })
        .map_err(|_| PolicyEngineError::PasskeyAssertionInvalid)?;
        drop(sysvar_data_ref);

        // 5. pin credential pubkey.
        let mut credential_pubkey = [0u8; 33];
        credential_pubkey.copy_from_slice(&primary_slot[1..34]);

        // 6. populate the session (field-by-field; PasskeySession is small but
        // we stay consistent with the F8c/F9b stack pattern).
        ctx.accounts.session.engine = engine_addr;
        ctx.accounts.session.rule_pda = rule_addr;
        ctx.accounts.session.payer_for_close = payer_addr;
        ctx.accounts.session.credential_id_hash = credential_id_hash;
        ctx.accounts.session.credential_pubkey = credential_pubkey;
        ctx.accounts.session._credential_pad = 0;
        ctx.accounts.session.eph_pk = eph_pk;
        ctx.accounts.session.session_nonce = on_chain_nonce.into();
        ctx.accounts.session.next_use_nonce = 0u64.into();
        ctx.accounts.session.not_after_unix_ts = not_after_unix_ts.into();
        ctx.accounts.session.expires_at = expires_at.into();
        ctx.accounts.session.created_at = current_ts.into();
        ctx.accounts.session.is_closed = 0;

        // M1 audit fix.
        ctx.accounts.rule_pda.next_passkey_session_nonce = on_chain_nonce
            .checked_add(1)
            .ok_or(PolicyEngineError::InvalidNonce)?
            .into();
        Ok(())
    }

    /// Disc 90 — `recover_as_primary_passkey_session` (F9d).
    ///
    /// Ephemeral Ed25519 key (recorded at open time) signs the per-use
    /// challenge; on-chain we re-validate session liveness, primary equality,
    /// and the Ed25519 precompile, then CPI Ika `approve_message`.
    #[instruction(discriminator = 90)]
    #[allow(clippy::too_many_arguments)]
    pub fn recover_as_primary_passkey_session(
        ctx: Ctx<RecoverAsPrimaryPasskeySessionAccts>,
        _init_authority_hash: Address,
        _rule_index: u8,
        _passkey_session_nonce: u64,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
        expected_use_nonce: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let engine_addr = *ctx.accounts.engine.address();
        let request_hash = Address::from(message_digest);
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let session_addr = *ctx.accounts.session.address();
        let message_approval_addr = *ctx.accounts.message_approval.address();
        let rule_addr = *ctx.accounts.rule_pda.address();

        // H2 fix: session must reference the same RecoveryRule slot we're
        // dispatching against. PDA derivation alone is not sufficient — the
        // session pinned a specific rule_pda at open time and that binding
        // must hold across the session lifetime.
        require!(
            ctx.accounts.session.rule_pda == rule_addr,
            PolicyEngineError::InvalidRuleHeader
        );

        ctx.accounts.program.emit_event(
            &SignatureRequested {
                engine: engine_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;

        require!(
            ctx.accounts.engine.paused == 0,
            PolicyEngineError::EnginePaused
        );

        // 1. session open + not expired.
        require!(
            ctx.accounts.session.is_closed == 0,
            PolicyEngineError::PasskeySessionExpired
        );
        let expires_at: i64 = ctx.accounts.session.expires_at.into();
        require!(
            current_ts < expires_at,
            PolicyEngineError::PasskeySessionExpired
        );

        // 2. use-nonce.
        let use_nonce: u64 = ctx.accounts.session.next_use_nonce.into();
        require!(
            expected_use_nonce == use_nonce,
            PolicyEngineError::InvalidNonce
        );

        // 2b. policy primary must still be the bound passkey credential.
        let credential_pubkey = ctx.accounts.session.credential_pubkey;
        let mut expected_primary = [0u8; MEMBER_SLOT_LEN];
        expected_primary[0] = SCHEME_WEBAUTHN;
        expected_primary[1..34].copy_from_slice(&credential_pubkey);
        let primary_slot = ctx.accounts.rule_pda.primary_slot;
        require!(
            primary_slot == expected_primary,
            PolicyEngineError::PasskeyStepUpRequired
        );

        // 3. Ed25519 precompile over per-use challenge with the session's eph_pk.
        let eph_pk = ctx.accounts.session.eph_pk;
        let challenge = passkey_primary_use_challenge(
            &session_addr,
            &dwallet_addr,
            &message_approval_addr,
            &message_digest,
            &metadata_digest,
            &user_pubkey,
            signature_scheme,
            message_approval_bump,
            use_nonce,
            &expected_primary,
        )
        .map_err(PolicyEngineError::from)?;
        check_sysvar_addr(ctx.accounts.instructions_sysvar.address())?;
        let sysvar_view = ctx.accounts.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PolicyEngineError::AuthFailed)?;
        // Build a minimal Ed25519 slot for the ephemeral key.
        let mut eph_slot = [0u8; MEMBER_SLOT_LEN];
        eph_slot[0] = SCHEME_ED25519;
        eph_slot[1..33].copy_from_slice(&eph_pk);
        verify_signature(VerifyInput {
            member_slot: &eph_slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &[],
            webauthn_client_data_json: &[],
        })
        .map_err(|_| PolicyEngineError::AuthFailed)?;
        drop(sysvar_data_ref);

        // 4. consume use-nonce BEFORE CPI.
        // M1 audit fix.
        ctx.accounts.session.next_use_nonce = use_nonce
            .checked_add(1)
            .ok_or(PolicyEngineError::InvalidNonce)?
            .into();

        // 5. CPI Ika defense + approve.
        require!(
            validate_ika_cpi_accounts(
                &ctx.accounts.dwallet_program.to_account_view(),
                &ctx.accounts.dwallet_account.to_account_view(),
            ),
            PolicyEngineError::IkaCpiAccountMismatch
        );
        invoke_ika_approve_message(
            &ctx.accounts.dwallet_program.to_account_view(),
            &ctx.accounts.cpi_authority.to_account_view(),
            // F9-COORD: the Ika caller_program must be THIS program's id — Ika
            // derives the signing authority as PDA(["__ika_cpi_authority"],
            // caller_program) and requires it to sign. Use the `program`
            // account (= policy-engine id, executable). The separate
            // `caller_program` slot stays in the context (now unused) so the
            // instruction account layout is unchanged.
            &ctx.accounts.program.to_account_view(),
            cpi_authority_bump,
            &ctx.accounts.coordinator.to_account_view(),
            &ctx.accounts.message_approval.to_account_view(),
            &ctx.accounts.dwallet_account.to_account_view(),
            &ctx.accounts.payer.to_account_view(),
            &ctx.accounts.system_program.to_account_view(),
            message_digest,
            // F9-SIGN: Ika message_metadata_digest = 0 (the signed message carries
            // no Ika metadata). The Andromeda policy challenge (metadata_digest) is
            // already enforced above via the request_metadata_digest match, so
            // binding it into the Ika MessageApproval here is both redundant and
            // breaks the Ika Sign step (the network derives the approval with empty
            // metadata → otherwise "MessageApproval PDA not found").
            [0u8; 32],
            user_pubkey,
            signature_scheme,
            message_approval_bump,
        )?;

        ctx.accounts.program.emit_event(
            &SignatureApproved {
                engine: engine_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// Disc 91 — `passkey_session_close` (F9d).
    ///
    /// Permissionless close once `current_ts >= expires_at`. Recipient signs
    /// the tx and receives the rent; MUST equal `session.payer_for_close`
    /// (locked in at open time).
    #[instruction(discriminator = 91)]
    pub fn passkey_session_close(
        ctx: Ctx<PasskeySessionCloseAccts>,
        _init_authority_hash: Address,
        _passkey_session_nonce: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let expires_at: i64 = ctx.accounts.session.expires_at.into();
        require!(
            ctx.accounts.session.is_closed == 1 || current_ts >= expires_at,
            PolicyEngineError::GenericError
        );

        let stored = ctx.accounts.session.payer_for_close;
        let recipient_addr = *ctx.accounts.recipient.address();
        require!(recipient_addr == stored, PolicyEngineError::AuthFailed);
        let recipient_view = ctx.accounts.recipient.to_account_view();
        ctx.accounts.session.close(recipient_view)?;
        Ok(())
    }
}

// ── Account contexts ─────────────────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_slot: [u8; 34], init_authority_hash: Address)]
pub struct InitEngine {
    pub dwallet_account: UncheckedAccount,

    #[account(init, payer = payer, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>, // generated by #[program] mod policy_engine_program
}

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct RequestSignature {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    pub coordinator: UncheckedAccount,

    #[account(mut)]
    pub message_approval: UncheckedAccount,

    #[account(mut)]
    pub payer: Signer,

    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub dwallet_program: UncheckedAccount,
    // F6b/F7b: dispatch loop for `KIND_PASSKEY` and `KIND_FHE_GATED` reads the
    // sysvar to locate the corresponding precompile invocation that signed the
    // metadata digest / FHE decision. Older callers that only use Allowlist /
    // Velocity / TimeLock / Oracle slots may attach the all-ones sentinel,
    // but the slot must always be present in the accounts list.
    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>, // generated by #[program] mod policy_engine_program
                                               // F8a: sub-PDAs for active rules travel as trailing `remaining_accounts`
                                               // (read via `CtxWithRemaining::remaining_accounts()`). One account per
                                               // active slot, in ascending `rule_index` order. Each account must be
                                               // writable so kinds with runtime counters (Velocity, SessionKey, Recovery)
                                               // can write back through `data_ptr()`. Read-only kinds (Allowlist, Oracle,
                                               // TimeLock) simply don't mutate.
}

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct EngineAdmin {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,

    #[account(mut)]
    pub payer: Signer,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>, // generated by #[program] mod policy_engine_program
}

// ── B1 — RemoveRule (disc 110) ─────────────────────────────────────────────
//
// `rule_pda` is an `UncheckedAccount` because the kind (and thus the concrete
// account type + seeds) is only known at runtime; the handler validates it
// against the engine's recorded `RuleEntry` before closing it.
#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct RemoveRule {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut)]
    pub rule_pda: UncheckedAccount,

    /// Receives the reclaimed rent. MUST equal the address bound into the owner
    /// challenge.
    #[account(mut)]
    pub recipient: UncheckedAccount,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,

    #[account(mut)]
    pub payer: Signer,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, _expected_nonce: u64, rule_index: u8)]
pub struct AddRuleAllowlist {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(init, payer = payer, address = AllowlistRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<AllowlistRule>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>, // generated by #[program] mod policy_engine_program
}

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, _expected_nonce: u64, rule_index: u8)]
pub struct UpdateRuleAllowlist {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut, address = AllowlistRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<AllowlistRule>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>, // generated by #[program] mod policy_engine_program
}

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, _expected_nonce: u64, rule_index: u8)]
pub struct UpdateRuleFheGated {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut, address = FheGatedRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<FheGatedRule>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, _expected_nonce: u64, rule_index: u8)]
pub struct UpdateRuleOracle {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut, address = OracleRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<OracleRule>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, _expected_nonce: u64, rule_index: u8)]
pub struct UpdateRuleSpendingUsd {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut, address = SpendingUsdRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<SpendingUsdRule>,

    /// The Pyth adapter `FeedCache` PDA being registered. Read-only; only its
    /// address + owner are checked (defense-in-depth, see disc 19).
    pub feed_cache: UncheckedAccount,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, _expected_nonce: u64, rule_index: u8)]
pub struct AddRuleVelocity {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(init, payer = payer, address = VelocityRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<VelocityRule>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

// rustfmt does not converge on attribute-macro args inside macro_rules! bodies
// (it would reindent the `#[account(...)]` PDA-seed args on every --check pass).
// Skip it so the crate stays rustfmt-clean / hook-safe; the body is hand-aligned.
#[rustfmt::skip]
macro_rules! add_rule_accounts {
    ($name:ident, $rule_ty:ident) => {
        #[derive(Accounts)]
        #[instruction(init_authority_hash: Address, _expected_nonce: u64, rule_index: u8)]
        pub struct $name {
            pub dwallet_account: UncheckedAccount,
            #[account(mut, address = PolicyEngine::seeds(
                                dwallet_account.address(),
                                &init_authority_hash
                            ))]
            pub engine: Account<PolicyEngine>,
            #[account(init, payer = payer, address = $rule_ty::seeds(
                                engine.address(),
                                rule_index
                            ))]
            pub rule_pda: Account<$rule_ty>,
            #[account(mut)]
            pub payer: Signer,
            pub instructions_sysvar: UncheckedAccount,
            pub clock: Sysvar<Clock>,
            pub rent: Sysvar<Rent>,
            pub system_program: Program<SystemProgram>,
            pub event_authority: EventAuthority,
            pub program: Program<PolicyEngineProgram>,
        }
    };
}

// F4 debug: replace AddRuleTimeLock macro expansion with an explicit
// struct identical to AddRuleAllowlist's shape (rule out macro hygiene).
#[derive(Accounts)]
#[instruction(init_authority_hash: Address, _expected_nonce: u64, rule_index: u8)]
pub struct AddRuleTimeLock {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(init, payer = payer, address = TimeLockRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<TimeLockRule>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

add_rule_accounts!(AddRuleOracle, OracleRule);
add_rule_accounts!(AddRulePasskey, PasskeyRule);
add_rule_accounts!(AddRuleFheGated, FheGatedRule);
add_rule_accounts!(AddRuleSessionKey, SessionKeyRule);
add_rule_accounts!(AddRuleSpendingUsd, SpendingUsdRule);

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, _expected_nonce: u64, rule_index: u8)]
pub struct AddRuleRecovery {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(init, payer = payer, address = RecoveryRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<RecoveryRule>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>, // generated by #[program] mod policy_engine_program
}

// ── F8b — SessionOpen accounts ──────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(
    init_authority_hash: Address,
    _expected_nonce: u64,
    rule_index: u8,
    session_index: u32
)]
pub struct SessionOpen {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(address = SessionKeyRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<SessionKeyRule>,

    #[account(init, payer = payer, address = Session::seeds(
        engine.address(),
        session_index
    ))]
    pub session: Account<Session>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

// ── F8b — RequestSignatureViaSession accounts ──────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, session_index: u32)]
pub struct RequestSignatureViaSession {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut, address = Session::seeds(
        engine.address(),
        session_index
    ))]
    pub session: Account<Session>,

    /// Session keypair signs natively. Andromeda never holds this key — the
    /// dev's app generates it client-side at session_open time and uses it
    /// here. Even if the gateway is compromised, an attacker without this
    /// keypair cannot replay signatures.
    pub session_signer: Signer,

    pub coordinator: UncheckedAccount,

    #[account(mut)]
    pub message_approval: UncheckedAccount,

    #[account(mut)]
    pub payer: Signer,

    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub dwallet_program: UncheckedAccount,
    // Fase 2: the session dispatch loop reads the sysvar for `KIND_PASSKEY` /
    // `KIND_FHE_GATED` session rules with APPLIES_SESSION (to locate the
    // precompile invocation that signed the metadata digest / FHE decision).
    // Sessions using only Allowlist / Velocity / TimeLock / Oracle slots still
    // must attach the slot (all-ones sentinel ok) — it is just not read.
    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
    // Fase 2: sub-PDAs for active rules travel as trailing `remaining_accounts`
    // (read via `CtxWithRemaining::remaining_accounts()`), one per active slot
    // in ascending `rule_index` order — identical convention to disc 1.
}

// ── F8c — SessionAdminAction (revoke / add_destination / remove_destination)

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, session_index: u32)]
pub struct SessionAdminAction {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut, address = Session::seeds(
        engine.address(),
        session_index
    ))]
    pub session: Account<Session>,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,

    #[account(mut)]
    pub payer: Signer,

    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

// ── F8c — SessionCloseAction (close / close_expired) ───────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, session_index: u32)]
pub struct SessionCloseAction {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut, address = Session::seeds(
        engine.address(),
        session_index
    ))]
    pub session: Account<Session>,

    /// Where the reclaimed rent lamports go. For `session_close` (disc 103)
    /// the recipient is bound into the owner challenge. For
    /// `close_expired_session` (disc 104) the caller picks freely.
    #[account(mut)]
    pub recipient: UncheckedAccount,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,

    #[account(mut)]
    pub payer: Signer,

    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

// ── F9a — UpdateRuleRecovery (130/131/132/133 share the same accounts) ────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, _expected_nonce: u64, rule_index: u8)]
pub struct UpdateRuleRecovery {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut, address = RecoveryRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<RecoveryRule>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

// ── F9a — RecoverAsPrimary (disc 80) ──────────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, rule_index: u8)]
pub struct RecoverAsPrimary {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut, address = RecoveryRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<RecoveryRule>,

    pub coordinator: UncheckedAccount,

    #[account(mut)]
    pub message_approval: UncheckedAccount,

    #[account(mut)]
    pub payer: Signer,

    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub dwallet_program: UncheckedAccount,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

// ── F9b — QuorumSession accounts ──────────────────────────────────────────

#[derive(Accounts)]
#[instruction(
    init_authority_hash: Address,
    rule_index: u8,
    session_nonce: u64
)]
pub struct QuorumSessionOpenAccts {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut, address = RecoveryRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<RecoveryRule>,

    #[account(init, payer = payer, address = QuorumSession::seeds(
        engine.address(),
        session_nonce
    ))]
    pub session: Account<QuorumSession>,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,

    #[account(mut)]
    pub payer: Signer,

    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, session_nonce: u64)]
pub struct QuorumSessionContributeAccts {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut, address = QuorumSession::seeds(
        engine.address(),
        session_nonce
    ))]
    pub session: Account<QuorumSession>,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,

    #[account(mut)]
    pub payer: Signer,

    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, rule_index: u8, session_nonce: u64)]
pub struct QuorumSessionFinalizeAccts {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    // H1 audit fix (2026-05-16): `rule_index` was hardcoded to `0u8`, which both
    // broke multi-rule recovery (DoS) and let a permissive rule_0 bypass a
    // restrictive rule_N when the session opened against rule_N. Now passed in
    // as an instruction parameter so the PDA derivation matches the rule that
    // owns the session. Cross-check `session.rule_pda == *rule_pda.address()`
    // is enforced in the handler (H2).
    #[account(mut, address = RecoveryRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<RecoveryRule>,

    #[account(mut, address = QuorumSession::seeds(
        engine.address(),
        session_nonce
    ))]
    pub session: Account<QuorumSession>,

    pub coordinator: UncheckedAccount,

    #[account(mut)]
    pub message_approval: UncheckedAccount,

    #[account(mut)]
    pub payer: Signer,

    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub dwallet_program: UncheckedAccount,

    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, session_nonce: u64)]
pub struct QuorumSessionCloseAccts {
    pub dwallet_account: UncheckedAccount,

    #[account(address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut, address = QuorumSession::seeds(
        engine.address(),
        session_nonce
    ))]
    pub session: Account<QuorumSession>,

    /// Receives the rent refund AND signs the tx. MUST equal
    /// `session.payer_for_close`. Bakes the legacy rules-policy invariant
    /// "only the original payer can reclaim rent" into account validation
    /// and avoids Solana's "same writable account twice" rejection that a
    /// separate `payer: Signer` slot would trigger.
    #[account(mut)]
    pub recipient: Signer,

    pub clock: Sysvar<Clock>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

// ── F9d — Passkey session accounts ────────────────────────────────────────

#[derive(Accounts)]
#[instruction(
    init_authority_hash: Address,
    rule_index: u8,
    passkey_session_nonce: u64
)]
pub struct PasskeySessionOpenAccts {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut, address = RecoveryRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<RecoveryRule>,

    #[account(init, payer = payer, address = PasskeySession::seeds(
        engine.address(),
        passkey_session_nonce
    ))]
    pub session: Account<PasskeySession>,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,

    #[account(mut)]
    pub payer: Signer,

    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, rule_index: u8, passkey_session_nonce: u64)]
pub struct RecoverAsPrimaryPasskeySessionAccts {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(address = RecoveryRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<RecoveryRule>,

    #[account(mut, address = PasskeySession::seeds(
        engine.address(),
        passkey_session_nonce
    ))]
    pub session: Account<PasskeySession>,

    pub coordinator: UncheckedAccount,

    #[account(mut)]
    pub message_approval: UncheckedAccount,

    #[account(mut)]
    pub payer: Signer,

    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub dwallet_program: UncheckedAccount,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, passkey_session_nonce: u64)]
pub struct PasskeySessionCloseAccts {
    pub dwallet_account: UncheckedAccount,

    #[account(address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut, address = PasskeySession::seeds(
        engine.address(),
        passkey_session_nonce
    ))]
    pub session: Account<PasskeySession>,

    /// Receives rent + signs tx. MUST equal `session.payer_for_close`.
    #[account(mut)]
    pub recipient: Signer,

    pub clock: Sysvar<Clock>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

// ── C1 — OIDC session accounts ─────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(
    init_authority_hash: Address,
    rule_index: u8,
    oidc_session_nonce: u64
)]
pub struct OidcSessionOpenAccts {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut, address = RecoveryRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<RecoveryRule>,

    #[account(init, payer = payer, address = OidcSession::seeds(
        engine.address(),
        oidc_session_nonce
    ))]
    pub session: Account<OidcSession>,

    /// `JwkRegistry` account holding the ACTIVE JWK for the (iss, aud, kid)
    /// triple inside the JWT. Read-only.
    pub jwk_registry: UncheckedAccount,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,

    #[account(mut)]
    pub payer: Signer,

    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

#[derive(Accounts)]
#[instruction(
    init_authority_hash: Address,
    rule_index: u8,
    oidc_session_nonce: u64
)]
pub struct RecoverAsPrimaryOidcAccts {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(address = RecoveryRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: Account<RecoveryRule>,

    #[account(mut, address = OidcSession::seeds(
        engine.address(),
        oidc_session_nonce
    ))]
    pub session: Account<OidcSession>,

    pub coordinator: UncheckedAccount,

    #[account(mut)]
    pub message_approval: UncheckedAccount,

    #[account(mut)]
    pub payer: Signer,

    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub dwallet_program: UncheckedAccount,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

// Fase 2 (2026-05-25) — accounts for `request_signature_via_oidc_session`
// (disc 107). Identical to `RecoverAsPrimaryOidcAccts` EXCEPT `rule_pda` is an
// `UncheckedAccount` (not `Account<RecoveryRule>`): the recovery rule occupies a
// rules_flat slot, and a typed `Account<T>` holds a persistent data borrow for
// the whole instruction. We read `primary_slot` under a scoped borrow that is
// released before the shared dispatch runs (the dispatch excludes this slot via
// `skip_slot`, so the recovery rule is NOT re-passed as a remaining account).
#[derive(Accounts)]
#[instruction(
    init_authority_hash: Address,
    rule_index: u8,
    oidc_session_nonce: u64
)]
pub struct RequestSignatureViaOidcSessionAccts {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(address = RecoveryRule::seeds(
        engine.address(),
        rule_index
    ))]
    pub rule_pda: UncheckedAccount,

    #[account(mut, address = OidcSession::seeds(
        engine.address(),
        oidc_session_nonce
    ))]
    pub session: Account<OidcSession>,

    pub coordinator: UncheckedAccount,

    #[account(mut)]
    pub message_approval: UncheckedAccount,

    #[account(mut)]
    pub payer: Signer,

    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub dwallet_program: UncheckedAccount,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}

#[derive(Accounts)]
#[instruction(init_authority_hash: Address, oidc_session_nonce: u64)]
pub struct OidcSessionCloseAccts {
    pub dwallet_account: UncheckedAccount,

    #[account(address = PolicyEngine::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub engine: Account<PolicyEngine>,

    #[account(mut, address = OidcSession::seeds(
        engine.address(),
        oidc_session_nonce
    ))]
    pub session: Account<OidcSession>,

    /// Receives rent + signs tx. MUST equal `session.payer_for_close`.
    #[account(mut)]
    pub recipient: Signer,

    pub clock: Sysvar<Clock>,
    pub event_authority: EventAuthority,
    pub program: Program<PolicyEngineProgram>,
}
