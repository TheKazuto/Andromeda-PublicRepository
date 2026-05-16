//! Andromeda — JWK Registry (Quasar master API).
//!
//! On-chain trust root for the OIDC RSA signing keys (Google / Apple) used by
//! the Login Social feature (`loginsocial.md`, Caminho A). The `rules-policy`
//! program — when opening an `OidcSession` (`scheme = 4 = OidcJwt`) — looks up
//! the modulus `n` / exponent `e` of the provider key here and requires the
//! entry to be `ACTIVE` and within its validity window (+ grace). It also
//! re-checks the entry's status on every signature use, so an emergency revoke
//! kills already-open sessions.
//!
//! Trust model (see `loginsocial.md` §4.1, §8):
//!  * `authority` (devnet: a single ops key; later: an M-of-N multisig) can
//!    `propose_jwk` → wait `timelock_seconds` → `activate_jwk`, plus
//!    `expire_jwk`, and rotate either role. It can never bypass the timelock
//!    for an `ACTIVE` key — only `bootstrap_jwk`, which is allowed only when
//!    the registry has zero entries (genesis), skips it.
//!  * `emergency_revoker` (a SEPARATE key) can only `revoke_jwk` — immediate,
//!    ignores the grace period, kills open sessions.
//!  * the off-chain watcher (`jwk-rotator/`) fetches the providers'
//!    JWKS, compares with the on-chain state, and `propose_jwk`s new keys —
//!    it never activates anything.
//!
//! Both privileged roles are real Solana transaction signers (this program is
//! ops-facing, not user-facing — there is no challenge/precompile flow here).
//!
//! Entries are stored in a fixed-size flat byte array (`entries_flat`), 400
//! bytes per entry, `MAX_JWKS` slots — same flat-array style as
//! `rules-policy`'s `members_flat` / `allowed_destinations_flat`. A
//! `REVOKED` or `EXPIRED` slot may be recycled by a future `propose_jwk`
//! (which abruptly invalidates any session that still referenced the old
//! `(issuer, audience, kid)` triple — by design).

#![no_std]
#![allow(dead_code)]

use quasar_lang::prelude::*;
use solana_address::Address;

declare_id!("8xL2mrQ2amDpinQMHJPaEELbgEXWRVGn4PQ7kzDm7vNM");

// ── Constants ──────────────────────────────────────────────────

/// Number of JWK slots. Google typically publishes 2–3 keys at a time and
/// Apple 2–4; with one audience each (the auth-broker `client_id`) plus a
/// couple of slots awaiting recycling, 8 covers the MVP. Kept deliberately
/// small so the `set_inner` temporary in `init_registry` stays well under
/// the 4 KB BPF stack frame (`8 * 400 = 3200` bytes for `entries_flat`). On
/// devnet pre-alpha the account can be re-created larger if it ever gets
/// tight (the watcher alerts on `RegistryFull`).
pub const MAX_JWKS: usize = 8;

/// Bytes per entry. Laid out 8-aligned with no internal padding (see the
/// `EO_*` offsets below).
pub const JWK_ENTRY_LEN: usize = 400;

/// Total bytes of the flat entry array.
pub const ENTRIES_BYTES: usize = MAX_JWKS * JWK_ENTRY_LEN;

// Entry status values.
pub const STATUS_EMPTY: u8 = 0;
pub const STATUS_PENDING: u8 = 1;
pub const STATUS_ACTIVE: u8 = 2;
pub const STATUS_REVOKED: u8 = 3;
pub const STATUS_EXPIRED: u8 = 4;

// Signature algorithm tag (MVP supports only RS256).
pub const ALG_RS256: u8 = 1;

// Privileged role tags (used by `rotate_role` / events).
pub const ROLE_AUTHORITY: u8 = 0;
pub const ROLE_EMERGENCY_REVOKER: u8 = 1;

/// RSA-2048 modulus length in bytes (big-endian).
pub const MODULUS_LEN: usize = 256;
/// The only RSA public exponent accepted in the MVP (`0x010001`).
pub const RSA_EXPONENT: u32 = 65_537;

// Sanity caps on configuration. Devnet uses a 1h timelock and 7d grace; prod
// will use 24–72h for both. 30 days is an absolute upper bound that catches
// gross misconfiguration without constraining legitimate ops.
pub const MAX_TIMELOCK_SECONDS: u64 = 30 * 24 * 3_600;
pub const MIN_TIMELOCK_SECONDS: u64 = 3_600;
pub const MAX_GRACE_SECONDS: u64 = 30 * 24 * 3_600;
/// Upper bound on `valid_until_ts - now` at activation. The runbook computes
/// `valid_until_ts ≈ last_seen_in_jwks + max_provider_token_ttl + grace`,
/// which is on the order of days — never months.
pub const MAX_VALIDITY_SECONDS: i64 = 30 * 24 * 3_600;

// Per-entry field offsets within a 400-byte slot.
const EO_STATUS: usize = 0; // 1
const EO_ALG: usize = 1; // 1
const EO_RESERVED0: usize = 2; // 6  (pad to 8)
const EO_ISSUER_HASH: usize = 8; // 32  sha256(iss)
const EO_AUDIENCE_HASH: usize = 40; // 32  sha256(aud)
const EO_KID_HASH: usize = 72; // 32  sha256(kid)
const EO_MODULUS: usize = 104; // 256 RSA modulus (BE)
const EO_EXPONENT: usize = 360; // 4   u32 LE
const EO_RESERVED1: usize = 364; // 4   (pad to 8)
const EO_PROPOSED_AT: usize = 368; // 8   i64 LE
const EO_VALID_FROM: usize = 376; // 8   i64 LE
const EO_VALID_UNTIL: usize = 384; // 8   i64 LE
const EO_REVOKED_AT: usize = 392; // 8   i64 LE
// 392 + 8 = 400 == JWK_ENTRY_LEN

const ZERO_ADDRESS: Address = Address::new_from_array([0u8; 32]);

// ── Program ────────────────────────────────────────────────────

#[program]
mod andromeda_jwk_registry {
    use super::*;

    /// 0 — Create the registry. Canonical registry uses the all-zero `registry_seed`;
    /// other values are for parallel registries (e.g. test harnesses). The
    /// `authority` must co-sign so a front-runner cannot squat the PDA with a
    /// key it does not control. The `emergency_revoker` is passed as a plain
    /// pubkey (lower privilege; a squatter could not pair it with a real
    /// `authority` signature anyway).
    #[instruction(discriminator = 0)]
    #[allow(clippy::too_many_arguments)]
    pub fn init_registry(
        ctx: Ctx<InitRegistry>,
        registry_seed: Address,
        authority_addr: Address,
        emergency_revoker: Address,
        timelock_seconds: u64,
        grace_period_seconds: u64,
        grace_period_post_revoke_seconds: u64,
    ) -> Result<(), ProgramError> {
        // `registry_seed` is consumed by the PDA derivation in the Accounts macro.
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts.create(
            authority_addr,
            emergency_revoker,
            timelock_seconds,
            grace_period_seconds,
            grace_period_post_revoke_seconds,
        )?;
        let registry = *ctx.accounts.registry.address();
        ctx.accounts.program.emit_event(
            &RegistryInitialized {
                registry,
                authority: authority_addr,
                emergency_revoker,
                timelock_seconds,
                grace_period_seconds,
                grace_period_post_revoke_seconds,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// 1 — Propose a new JWK (status PENDING). The off-chain watcher calls
    /// this when it sees a new `kid` in the provider's JWKS. Activation is a
    /// separate, time-locked step.
    #[instruction(discriminator = 1)]
    #[allow(clippy::too_many_arguments)]
    pub fn propose_jwk(
        ctx: Ctx<AuthorityAction>,
        registry_seed: Address,
        issuer_hash: Address,
        audience_hash: Address,
        kid_hash: Address,
        alg: u8,
        modulus_n: [u8; MODULUS_LEN],
        exponent_e: u32,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts.propose(
            &issuer_hash,
            &audience_hash,
            &kid_hash,
            alg,
            &modulus_n,
            exponent_e,
            current_ts,
        )?;
        let registry = *ctx.accounts.registry.address();
        ctx.accounts.program.emit_event(
            &JwkProposed {
                registry,
                issuer_hash,
                audience_hash,
                kid_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// 2 — Activate a PENDING JWK once the timelock has elapsed. `valid_until_ts`
    /// is computed off-chain per the rotation runbook
    /// (`last_seen_in_jwks + max_provider_token_ttl + grace`).
    #[instruction(discriminator = 2)]
    pub fn activate_jwk(
        ctx: Ctx<AuthorityAction>,
        registry_seed: Address,
        issuer_hash: Address,
        audience_hash: Address,
        kid_hash: Address,
        valid_until_ts: i64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts
            .activate(&issuer_hash, &audience_hash, &kid_hash, valid_until_ts, current_ts)?;
        let registry = *ctx.accounts.registry.address();
        ctx.accounts.program.emit_event(
            &JwkActivated {
                registry,
                issuer_hash,
                audience_hash,
                kid_hash,
                valid_from: current_ts,
                valid_until: valid_until_ts,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// 3 — Revoke a PENDING or ACTIVE JWK immediately. Callable by `authority`
    /// OR `emergency_revoker`. Ignores the grace period. The `rules-policy`
    /// program rejects any new `oidc_session_open` and any further use of an
    /// already-open session whose JWK was revoked.
    #[instruction(discriminator = 3)]
    pub fn revoke_jwk(
        ctx: Ctx<RevokerAction>,
        registry_seed: Address,
        issuer_hash: Address,
        audience_hash: Address,
        kid_hash: Address,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts
            .revoke(&issuer_hash, &audience_hash, &kid_hash, current_ts)?;
        let registry = *ctx.accounts.registry.address();
        ctx.accounts.program.emit_event(
            &JwkRevoked {
                registry,
                issuer_hash,
                audience_hash,
                kid_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// 4 — Mark an ACTIVE JWK as EXPIRED once it is past `valid_until_ts + grace`.
    /// Permissionless cleanup (like closing an expired session). The slot
    /// becomes recyclable by a future `propose_jwk`.
    #[instruction(discriminator = 4)]
    pub fn expire_jwk(
        ctx: Ctx<PermissionlessAction>,
        registry_seed: Address,
        issuer_hash: Address,
        audience_hash: Address,
        kid_hash: Address,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts
            .expire(&issuer_hash, &audience_hash, &kid_hash, current_ts)?;
        let registry = *ctx.accounts.registry.address();
        ctx.accounts.program.emit_event(
            &JwkExpired {
                registry,
                issuer_hash,
                audience_hash,
                kid_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// 5 — Genesis-only: insert the first JWK directly as ACTIVE, skipping the
    /// timelock. Requires `authority` co-sign AND an empty registry
    /// (`entry_count == 0`), so it can only ever be used once. Production
    /// should prefer `propose_jwk` + (timelock) + `activate_jwk` even at
    /// genesis; this exists so devnet does not have to wait out the timelock
    /// for the very first key. Emits both `JwkProposed` and `JwkActivated`.
    #[instruction(discriminator = 5)]
    #[allow(clippy::too_many_arguments)]
    pub fn bootstrap_jwk(
        ctx: Ctx<AuthorityAction>,
        registry_seed: Address,
        issuer_hash: Address,
        audience_hash: Address,
        kid_hash: Address,
        alg: u8,
        modulus_n: [u8; MODULUS_LEN],
        exponent_e: u32,
        valid_until_ts: i64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts.bootstrap(
            &issuer_hash,
            &audience_hash,
            &kid_hash,
            alg,
            &modulus_n,
            exponent_e,
            valid_until_ts,
            current_ts,
        )?;
        let registry = *ctx.accounts.registry.address();
        ctx.accounts.program.emit_event(
            &JwkProposed {
                registry,
                issuer_hash,
                audience_hash,
                kid_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        ctx.accounts.program.emit_event(
            &JwkActivated {
                registry,
                issuer_hash,
                audience_hash,
                kid_hash,
                valid_from: current_ts,
                valid_until: valid_until_ts,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// 6 — Propose rotating a privileged role (`role`: 0 = authority,
    /// 1 = emergency_revoker). Only the current `authority` may do this; the
    /// change takes effect after `timelock_seconds` via `activate_role_rotation`.
    #[instruction(discriminator = 6)]
    pub fn rotate_role(
        ctx: Ctx<AuthorityAction>,
        registry_seed: Address,
        role: u8,
        new_key: Address,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let ready_at = ctx.accounts.rotate(role, new_key, current_ts)?;
        let registry = *ctx.accounts.registry.address();
        ctx.accounts.program.emit_event(
            &RoleRotationProposed {
                registry,
                new_key,
                ready_at,
                ts: current_ts,
                role: role as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// 7 — Finalize a role rotation once the timelock has elapsed.
    /// Permissionless.
    #[instruction(discriminator = 7)]
    pub fn activate_role_rotation(
        ctx: Ctx<PermissionlessAction>,
        registry_seed: Address,
        role: u8,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let new_key = ctx.accounts.activate_rotation(role, current_ts)?;
        let registry = *ctx.accounts.registry.address();
        ctx.accounts.program.emit_event(
            &RoleRotated {
                registry,
                new_key,
                ts: current_ts,
                role: role as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// 8 — Cancel a pending role rotation. Only the current `authority`.
    #[instruction(discriminator = 8)]
    pub fn cancel_role_rotation(
        ctx: Ctx<AuthorityAction>,
        registry_seed: Address,
        role: u8,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts.cancel_rotation(role)?;
        let registry = *ctx.accounts.registry.address();
        ctx.accounts.program.emit_event(
            &RoleRotationCancelled {
                registry,
                ts: current_ts,
                role: role as u64,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }
}

// ── Errors ─────────────────────────────────────────────────────

#[error_code]
pub enum JwkRegistryError {
    /// `authority` (or, for `revoke_jwk`, `authority`/`emergency_revoker`)
    /// did not sign, or signed with the wrong key.
    Unauthorized = 7000,
    /// `init_registry`: the co-signing `authority` account does not match the
    /// `authority` argument, or a role pubkey is zero, or the two roles are
    /// equal.
    InvalidRoles,
    /// Timelock / grace / validity value out of the allowed range.
    InvalidConfig,
    /// `alg` is not `RS256`.
    UnsupportedAlg,
    /// Modulus is not a well-formed RSA-2048 modulus (must be exactly 256
    /// bytes, top bit set, odd).
    InvalidModulus,
    /// Exponent is not `65537`.
    InvalidExponent,
    /// A PENDING or ACTIVE entry already exists for this `(iss, aud, kid)`.
    JwkAlreadyExists,
    /// No free or recyclable slot.
    RegistryFull,
    /// `activate_jwk`: no PENDING entry for this `(iss, aud, kid)`.
    JwkNotPending,
    /// `revoke_jwk`: no PENDING/ACTIVE entry for this `(iss, aud, kid)`.
    JwkNotRevocable,
    /// `expire_jwk`: no ACTIVE entry for this `(iss, aud, kid)`.
    JwkNotExpirable,
    /// The timelock has not elapsed yet.
    TimelockNotElapsed,
    /// `expire_jwk`: the entry is not yet past `valid_until_ts + grace`.
    NotYetExpired,
    /// `valid_until_ts` is in the past or too far in the future.
    InvalidValidity,
    /// `bootstrap_jwk` was called on a non-empty registry.
    RegistryNotEmpty,
    /// `role` is not 0 or 1.
    InvalidRole,
    /// Proposed role key is zero or would collide with the other role.
    InvalidKey,
    /// `activate_role_rotation` / `cancel_role_rotation`: nothing pending.
    NoPendingRotation,
    /// H4 fix: `propose_jwk` tried to recycle a `REVOKED` slot before
    /// `revoked_at + grace_period_post_revoke_seconds` had elapsed.
    RevokeGraceNotElapsed,
}

// ── Events (zero-copy, padding-free) ───────────────────────────

#[event(discriminator = 0)]
pub struct RegistryInitialized {
    pub registry: Address,
    pub authority: Address,
    pub emergency_revoker: Address,
    pub timelock_seconds: u64,
    pub grace_period_seconds: u64,
    pub grace_period_post_revoke_seconds: u64,
    pub ts: i64,
}

#[event(discriminator = 1)]
pub struct JwkProposed {
    pub registry: Address,
    pub issuer_hash: Address,
    pub audience_hash: Address,
    pub kid_hash: Address,
    pub ts: i64,
}

#[event(discriminator = 2)]
pub struct JwkActivated {
    pub registry: Address,
    pub issuer_hash: Address,
    pub audience_hash: Address,
    pub kid_hash: Address,
    pub valid_from: i64,
    pub valid_until: i64,
    pub ts: i64,
}

#[event(discriminator = 3)]
pub struct JwkRevoked {
    pub registry: Address,
    pub issuer_hash: Address,
    pub audience_hash: Address,
    pub kid_hash: Address,
    pub ts: i64,
}

#[event(discriminator = 4)]
pub struct JwkExpired {
    pub registry: Address,
    pub issuer_hash: Address,
    pub audience_hash: Address,
    pub kid_hash: Address,
    pub ts: i64,
}

#[event(discriminator = 5)]
pub struct RoleRotationProposed {
    pub registry: Address,
    pub new_key: Address,
    pub ready_at: i64,
    pub ts: i64,
    pub role: u64,
}

#[event(discriminator = 6)]
pub struct RoleRotated {
    pub registry: Address,
    pub new_key: Address,
    pub ts: i64,
    pub role: u64,
}

#[event(discriminator = 7)]
pub struct RoleRotationCancelled {
    pub registry: Address,
    pub ts: i64,
    pub role: u64,
}

// ── Account state ──────────────────────────────────────────────

#[account(discriminator = 1, set_inner)]
#[seeds(b"jwk_registry", registry_seed: Address)]
pub struct JwkRegistry {
    pub version: u8,
    /// Number of slots that are not `EMPTY` (0..=MAX_JWKS). Only ever grows in
    /// normal operation (recycled slots stay non-empty).
    pub entry_count: u8,
    pub reserved0: [u8; 6],
    /// May `propose`/`activate`/`expire` JWKs and rotate either role.
    pub authority: Address,
    /// Pending `authority` (zero = none).
    pub pending_authority: Address,
    /// May only `revoke` JWKs — a deliberately separate, lower-privilege role.
    pub emergency_revoker: Address,
    /// Pending `emergency_revoker` (zero = none).
    pub pending_emergency_revoker: Address,
    /// Timelock for `activate_jwk` and for role rotations (seconds).
    pub timelock_seconds: u64,
    /// Grace window after `valid_until_ts` during which readers still accept
    /// the key (covers JWTs issued just before a rotation). `revoke_jwk`
    /// ignores this.
    pub grace_period_seconds: u64,
    /// H4 fix: minimum delay between `revoke_jwk` and any `propose_jwk` that
    /// would recycle the same slot. Defends against a compromised
    /// `authority` quickly resurrecting a slot the `emergency_revoker` just
    /// killed. Devnet runbook: 7 days; mainnet: 30 days.
    pub grace_period_post_revoke_seconds: u64,
    /// When the pending `authority` becomes activatable (0 = none).
    pub authority_rotation_ready_at: i64,
    /// When the pending `emergency_revoker` becomes activatable (0 = none).
    pub emergency_revoker_rotation_ready_at: i64,
    /// `MAX_JWKS` × `JWK_ENTRY_LEN` flat entry records.
    pub entries_flat: [u8; ENTRIES_BYTES],
}

// ── Pure helpers ───────────────────────────────────────────────

#[inline]
fn read_i64(b: &[u8]) -> i64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    i64::from_le_bytes(a)
}

/// Saturating `u64 → i64` (config values are capped well below `i64::MAX`, so
/// this never actually saturates; the cast is just defensive).
#[inline]
fn u64_to_i64(v: u64) -> i64 {
    if v > i64::MAX as u64 {
        i64::MAX
    } else {
        v as i64
    }
}

#[inline]
fn entry_status(entries: &[u8; ENTRIES_BYTES], idx: usize) -> u8 {
    entries[idx * JWK_ENTRY_LEN + EO_STATUS]
}

#[inline]
fn entry_field<'a>(entries: &'a [u8; ENTRIES_BYTES], idx: usize, off: usize, len: usize) -> &'a [u8] {
    let base = idx * JWK_ENTRY_LEN;
    &entries[base + off..base + off + len]
}

#[inline]
fn triple_matches(
    entries: &[u8; ENTRIES_BYTES],
    idx: usize,
    iss: &Address,
    aud: &Address,
    kid: &Address,
) -> bool {
    entry_field(entries, idx, EO_ISSUER_HASH, 32) == iss.as_array().as_slice()
        && entry_field(entries, idx, EO_AUDIENCE_HASH, 32) == aud.as_array().as_slice()
        && entry_field(entries, idx, EO_KID_HASH, 32) == kid.as_array().as_slice()
}

/// First slot matching `(iss, aud, kid)` whose status is in `want_status`.
fn find_slot(
    entries: &[u8; ENTRIES_BYTES],
    iss: &Address,
    aud: &Address,
    kid: &Address,
    want_status: &[u8],
) -> Option<usize> {
    for i in 0..MAX_JWKS {
        let st = entry_status(entries, i);
        if want_status.contains(&st) && triple_matches(entries, i, iss, aud, kid) {
            return Some(i);
        }
    }
    None
}

/// Result of picking a slot for a new JWK entry.
enum WritableSlot {
    /// Fresh, never-used slot. Caller bumps `entry_count`.
    Empty(usize),
    /// Recycling an `EXPIRED` slot. Caller leaves `entry_count` unchanged.
    Expired(usize),
    /// Recycling a `REVOKED` slot whose post-revoke grace already elapsed.
    /// Caller leaves `entry_count` unchanged.
    Revoked(usize),
    /// No usable slot found. Either every slot is PENDING/ACTIVE
    /// (`RegistryFull`) or every recyclable slot is REVOKED-but-too-recent
    /// (`RevokeGraceNotElapsed`).
    None { revoked_blocked: bool },
}

/// Picks where a new entry goes:
///   1. first `EMPTY` slot, else
///   2. first `EXPIRED` slot, else
///   3. first `REVOKED` slot whose `revoked_at + grace_post_revoke <= now`.
///
/// EXPIRED slots are preferred over REVOKED ones so an emergency revoke
/// always blocks recycling for the full post-revoke grace, even if other
/// recyclable slots exist.
fn find_writable_slot(
    entries: &[u8; ENTRIES_BYTES],
    current_ts: i64,
    grace_post_revoke: i64,
) -> WritableSlot {
    let mut expired: Option<usize> = None;
    let mut revoked_ready: Option<usize> = None;
    let mut revoked_seen = false;
    for i in 0..MAX_JWKS {
        let st = entry_status(entries, i);
        match st {
            STATUS_EMPTY => return WritableSlot::Empty(i),
            STATUS_EXPIRED if expired.is_none() => expired = Some(i),
            STATUS_REVOKED => {
                revoked_seen = true;
                if revoked_ready.is_none() {
                    let revoked_at = read_i64(entry_field(entries, i, EO_REVOKED_AT, 8));
                    if current_ts >= revoked_at.saturating_add(grace_post_revoke) {
                        revoked_ready = Some(i);
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(i) = expired {
        return WritableSlot::Expired(i);
    }
    if let Some(i) = revoked_ready {
        return WritableSlot::Revoked(i);
    }
    WritableSlot::None {
        revoked_blocked: revoked_seen,
    }
}

#[allow(clippy::too_many_arguments)]
fn write_entry(
    entries: &mut [u8; ENTRIES_BYTES],
    idx: usize,
    status: u8,
    alg: u8,
    iss: &Address,
    aud: &Address,
    kid: &Address,
    modulus_n: &[u8; MODULUS_LEN],
    exponent_e: u32,
    proposed_at: i64,
    valid_from: i64,
    valid_until: i64,
) {
    let base = idx * JWK_ENTRY_LEN;
    let slot = &mut entries[base..base + JWK_ENTRY_LEN];
    for b in slot.iter_mut() {
        *b = 0;
    }
    slot[EO_STATUS] = status;
    slot[EO_ALG] = alg;
    slot[EO_ISSUER_HASH..EO_ISSUER_HASH + 32].copy_from_slice(iss.as_array().as_slice());
    slot[EO_AUDIENCE_HASH..EO_AUDIENCE_HASH + 32].copy_from_slice(aud.as_array().as_slice());
    slot[EO_KID_HASH..EO_KID_HASH + 32].copy_from_slice(kid.as_array().as_slice());
    slot[EO_MODULUS..EO_MODULUS + MODULUS_LEN].copy_from_slice(modulus_n);
    slot[EO_EXPONENT..EO_EXPONENT + 4].copy_from_slice(&exponent_e.to_le_bytes());
    slot[EO_PROPOSED_AT..EO_PROPOSED_AT + 8].copy_from_slice(&proposed_at.to_le_bytes());
    slot[EO_VALID_FROM..EO_VALID_FROM + 8].copy_from_slice(&valid_from.to_le_bytes());
    slot[EO_VALID_UNTIL..EO_VALID_UNTIL + 8].copy_from_slice(&valid_until.to_le_bytes());
    // EO_REVOKED_AT stays 0.
}

#[inline]
fn set_entry_status(entries: &mut [u8; ENTRIES_BYTES], idx: usize, status: u8) {
    entries[idx * JWK_ENTRY_LEN + EO_STATUS] = status;
}

#[inline]
fn set_entry_i64(entries: &mut [u8; ENTRIES_BYTES], idx: usize, off: usize, v: i64) {
    let base = idx * JWK_ENTRY_LEN;
    entries[base + off..base + off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Strict RSA-2048 / RS256 profile check (mirrored by `contracts/oidc-verifier`).
fn validate_rsa_profile(alg: u8, modulus_n: &[u8; MODULUS_LEN], exponent_e: u32) -> Result<(), ProgramError> {
    require!(alg == ALG_RS256, JwkRegistryError::UnsupportedAlg);
    // Top bit set ⇒ a full 2048-bit modulus (not a shorter number left-padded
    // with zeros); odd ⇒ a real RSA modulus.
    require!(
        modulus_n[0] & 0x80 != 0 && modulus_n[MODULUS_LEN - 1] & 1 == 1,
        JwkRegistryError::InvalidModulus
    );
    require!(exponent_e == RSA_EXPONENT, JwkRegistryError::InvalidExponent);
    Ok(())
}

fn validate_role(role: u8) -> Result<(), ProgramError> {
    require!(
        role == ROLE_AUTHORITY || role == ROLE_EMERGENCY_REVOKER,
        JwkRegistryError::InvalidRole
    );
    Ok(())
}

// ── InitRegistry ───────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(registry_seed: Address)]
pub struct InitRegistry {
    #[account(init, payer = payer, address = JwkRegistry::seeds(&registry_seed))]
    pub registry: Account<JwkRegistry>,

    /// Must equal the `authority` argument — proves the authority key consents.
    pub authority: Signer,

    #[account(mut)]
    pub payer: Signer,

    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<AndromedaJwkRegistry>,
}

impl InitRegistry {
    #[inline(always)]
    pub fn create(
        &mut self,
        authority: Address,
        emergency_revoker: Address,
        timelock_seconds: u64,
        grace_period_seconds: u64,
        grace_period_post_revoke_seconds: u64,
    ) -> Result<(), ProgramError> {
        require!(
            *self.authority.address() == authority
                && authority != ZERO_ADDRESS
                && emergency_revoker != ZERO_ADDRESS
                && authority != emergency_revoker,
            JwkRegistryError::InvalidRoles
        );
        require!(
            timelock_seconds >= MIN_TIMELOCK_SECONDS
                && timelock_seconds <= MAX_TIMELOCK_SECONDS
                && grace_period_seconds <= MAX_GRACE_SECONDS
                && grace_period_post_revoke_seconds <= MAX_GRACE_SECONDS,
            JwkRegistryError::InvalidConfig
        );
        self.registry.set_inner(JwkRegistryInner {
            version: 1,
            entry_count: 0,
            reserved0: [0u8; 6],
            authority,
            pending_authority: ZERO_ADDRESS,
            emergency_revoker,
            pending_emergency_revoker: ZERO_ADDRESS,
            timelock_seconds,
            grace_period_seconds,
            grace_period_post_revoke_seconds,
            authority_rotation_ready_at: 0,
            emergency_revoker_rotation_ready_at: 0,
            entries_flat: [0u8; ENTRIES_BYTES],
        });
        Ok(())
    }
}

// ── AuthorityAction (authority co-signs) ───────────────────────

#[derive(Accounts)]
#[instruction(registry_seed: Address)]
pub struct AuthorityAction {
    #[account(mut, address = JwkRegistry::seeds(&registry_seed))]
    pub registry: Account<JwkRegistry>,

    /// Must equal `registry.authority`.
    pub authority: Signer,

    #[account(mut)]
    pub payer: Signer,

    pub clock: Sysvar<Clock>,
    pub event_authority: EventAuthority,
    pub program: Program<AndromedaJwkRegistry>,
}

impl AuthorityAction {
    #[inline]
    fn require_authority(&self) -> Result<(), ProgramError> {
        require!(
            *self.authority.address() == self.registry.authority,
            JwkRegistryError::Unauthorized
        );
        Ok(())
    }

    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn propose(
        &mut self,
        iss: &Address,
        aud: &Address,
        kid: &Address,
        alg: u8,
        modulus_n: &[u8; MODULUS_LEN],
        exponent_e: u32,
        current_ts: i64,
    ) -> Result<(), ProgramError> {
        self.require_authority()?;
        validate_rsa_profile(alg, modulus_n, exponent_e)?;
        require!(
            find_slot(
                &self.registry.entries_flat,
                iss,
                aud,
                kid,
                &[STATUS_PENDING, STATUS_ACTIVE, STATUS_REVOKED, STATUS_EXPIRED]
            )
            .is_none(),
            JwkRegistryError::JwkAlreadyExists
        );
        let grace_post_revoke = u64_to_i64(self.registry.grace_period_post_revoke_seconds.into());
        let (idx, was_empty) = match find_writable_slot(
            &self.registry.entries_flat,
            current_ts,
            grace_post_revoke,
        ) {
            WritableSlot::Empty(i) => (i, true),
            WritableSlot::Expired(i) | WritableSlot::Revoked(i) => (i, false),
            WritableSlot::None { revoked_blocked } => {
                return Err(if revoked_blocked {
                    JwkRegistryError::RevokeGraceNotElapsed.into()
                } else {
                    JwkRegistryError::RegistryFull.into()
                });
            }
        };
        write_entry(
            &mut self.registry.entries_flat,
            idx,
            STATUS_PENDING,
            alg,
            iss,
            aud,
            kid,
            modulus_n,
            exponent_e,
            current_ts,
            0,
            0,
        );
        if was_empty {
            self.registry.entry_count = self.registry.entry_count + 1;
        }
        Ok(())
    }

    #[inline(always)]
    pub fn activate(
        &mut self,
        iss: &Address,
        aud: &Address,
        kid: &Address,
        valid_until_ts: i64,
        current_ts: i64,
    ) -> Result<(), ProgramError> {
        self.require_authority()?;
        require!(
            valid_until_ts > current_ts
                && valid_until_ts.saturating_sub(current_ts) <= MAX_VALIDITY_SECONDS,
            JwkRegistryError::InvalidValidity
        );
        let idx = find_slot(&self.registry.entries_flat, iss, aud, kid, &[STATUS_PENDING])
            .ok_or(JwkRegistryError::JwkNotPending)?;
        let proposed_at = read_i64(entry_field(&self.registry.entries_flat, idx, EO_PROPOSED_AT, 8));
        let timelock = u64_to_i64(self.registry.timelock_seconds.into());
        require!(
            current_ts >= proposed_at.saturating_add(timelock),
            JwkRegistryError::TimelockNotElapsed
        );
        set_entry_status(&mut self.registry.entries_flat, idx, STATUS_ACTIVE);
        set_entry_i64(&mut self.registry.entries_flat, idx, EO_VALID_FROM, current_ts);
        set_entry_i64(&mut self.registry.entries_flat, idx, EO_VALID_UNTIL, valid_until_ts);
        Ok(())
    }

    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn bootstrap(
        &mut self,
        iss: &Address,
        aud: &Address,
        kid: &Address,
        alg: u8,
        modulus_n: &[u8; MODULUS_LEN],
        exponent_e: u32,
        valid_until_ts: i64,
        current_ts: i64,
    ) -> Result<(), ProgramError> {
        self.require_authority()?;
        require!(self.registry.entry_count == 0, JwkRegistryError::RegistryNotEmpty);
        validate_rsa_profile(alg, modulus_n, exponent_e)?;
        require!(
            valid_until_ts > current_ts
                && valid_until_ts.saturating_sub(current_ts) <= MAX_VALIDITY_SECONDS,
            JwkRegistryError::InvalidValidity
        );
        // Registry is empty ⇒ slot 0 is EMPTY.
        write_entry(
            &mut self.registry.entries_flat,
            0,
            STATUS_ACTIVE,
            alg,
            iss,
            aud,
            kid,
            modulus_n,
            exponent_e,
            current_ts,
            current_ts,
            valid_until_ts,
        );
        self.registry.entry_count = 1;
        Ok(())
    }

    #[inline(always)]
    pub fn rotate(&mut self, role: u8, new_key: Address, current_ts: i64) -> Result<i64, ProgramError> {
        self.require_authority()?;
        validate_role(role)?;
        require!(new_key != ZERO_ADDRESS, JwkRegistryError::InvalidKey);
        let timelock = u64_to_i64(self.registry.timelock_seconds.into());
        let ready_at = current_ts.saturating_add(timelock);
        if role == ROLE_AUTHORITY {
            require!(new_key != self.registry.emergency_revoker, JwkRegistryError::InvalidKey);
            self.registry.pending_authority = new_key;
            self.registry.authority_rotation_ready_at = ready_at.into();
        } else {
            require!(new_key != self.registry.authority, JwkRegistryError::InvalidKey);
            self.registry.pending_emergency_revoker = new_key;
            self.registry.emergency_revoker_rotation_ready_at = ready_at.into();
        }
        Ok(ready_at)
    }

    #[inline(always)]
    pub fn cancel_rotation(&mut self, role: u8) -> Result<(), ProgramError> {
        self.require_authority()?;
        validate_role(role)?;
        if role == ROLE_AUTHORITY {
            require!(
                self.registry.pending_authority != ZERO_ADDRESS,
                JwkRegistryError::NoPendingRotation
            );
            self.registry.pending_authority = ZERO_ADDRESS;
            self.registry.authority_rotation_ready_at = 0i64.into();
        } else {
            require!(
                self.registry.pending_emergency_revoker != ZERO_ADDRESS,
                JwkRegistryError::NoPendingRotation
            );
            self.registry.pending_emergency_revoker = ZERO_ADDRESS;
            self.registry.emergency_revoker_rotation_ready_at = 0i64.into();
        }
        Ok(())
    }
}

// ── RevokerAction (authority OR emergency_revoker co-signs) ─────

#[derive(Accounts)]
#[instruction(registry_seed: Address)]
pub struct RevokerAction {
    #[account(mut, address = JwkRegistry::seeds(&registry_seed))]
    pub registry: Account<JwkRegistry>,

    /// Must equal `registry.authority` or `registry.emergency_revoker`.
    pub revoker: Signer,

    #[account(mut)]
    pub payer: Signer,

    pub clock: Sysvar<Clock>,
    pub event_authority: EventAuthority,
    pub program: Program<AndromedaJwkRegistry>,
}

impl RevokerAction {
    #[inline(always)]
    pub fn revoke(
        &mut self,
        iss: &Address,
        aud: &Address,
        kid: &Address,
        current_ts: i64,
    ) -> Result<(), ProgramError> {
        let signer = *self.revoker.address();
        require!(
            signer == self.registry.authority || signer == self.registry.emergency_revoker,
            JwkRegistryError::Unauthorized
        );
        let idx = find_slot(
            &self.registry.entries_flat,
            iss,
            aud,
            kid,
            &[STATUS_PENDING, STATUS_ACTIVE],
        )
        .ok_or(JwkRegistryError::JwkNotRevocable)?;
        set_entry_status(&mut self.registry.entries_flat, idx, STATUS_REVOKED);
        set_entry_i64(&mut self.registry.entries_flat, idx, EO_REVOKED_AT, current_ts);
        Ok(())
    }
}

// ── PermissionlessAction (no privileged signer) ────────────────

#[derive(Accounts)]
#[instruction(registry_seed: Address)]
pub struct PermissionlessAction {
    #[account(mut, address = JwkRegistry::seeds(&registry_seed))]
    pub registry: Account<JwkRegistry>,

    #[account(mut)]
    pub payer: Signer,

    pub clock: Sysvar<Clock>,
    pub event_authority: EventAuthority,
    pub program: Program<AndromedaJwkRegistry>,
}

impl PermissionlessAction {
    #[inline(always)]
    pub fn expire(
        &mut self,
        iss: &Address,
        aud: &Address,
        kid: &Address,
        current_ts: i64,
    ) -> Result<(), ProgramError> {
        let idx = find_slot(&self.registry.entries_flat, iss, aud, kid, &[STATUS_ACTIVE])
            .ok_or(JwkRegistryError::JwkNotExpirable)?;
        let valid_until = read_i64(entry_field(&self.registry.entries_flat, idx, EO_VALID_UNTIL, 8));
        let grace = u64_to_i64(self.registry.grace_period_seconds.into());
        require!(
            current_ts > valid_until.saturating_add(grace),
            JwkRegistryError::NotYetExpired
        );
        set_entry_status(&mut self.registry.entries_flat, idx, STATUS_EXPIRED);
        Ok(())
    }

    #[inline(always)]
    pub fn activate_rotation(&mut self, role: u8, current_ts: i64) -> Result<Address, ProgramError> {
        validate_role(role)?;
        if role == ROLE_AUTHORITY {
            let pending = self.registry.pending_authority;
            require!(pending != ZERO_ADDRESS, JwkRegistryError::NoPendingRotation);
            let ready_at: i64 = self.registry.authority_rotation_ready_at.into();
            require!(current_ts >= ready_at, JwkRegistryError::TimelockNotElapsed);
            require!(pending != self.registry.emergency_revoker, JwkRegistryError::InvalidKey);
            self.registry.authority = pending;
            self.registry.pending_authority = ZERO_ADDRESS;
            self.registry.authority_rotation_ready_at = 0i64.into();
            Ok(pending)
        } else {
            let pending = self.registry.pending_emergency_revoker;
            require!(pending != ZERO_ADDRESS, JwkRegistryError::NoPendingRotation);
            let ready_at: i64 = self.registry.emergency_revoker_rotation_ready_at.into();
            require!(current_ts >= ready_at, JwkRegistryError::TimelockNotElapsed);
            require!(pending != self.registry.authority, JwkRegistryError::InvalidKey);
            self.registry.emergency_revoker = pending;
            self.registry.pending_emergency_revoker = ZERO_ADDRESS;
            self.registry.emergency_revoker_rotation_ready_at = 0i64.into();
            Ok(pending)
        }
    }
}
