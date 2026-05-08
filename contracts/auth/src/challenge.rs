//! Domain-separated, per-operation challenges.
//!
//! Every credential signs the bytes returned by these functions off-chain.
//! The on-chain handler recomputes the same hash from the same inputs and
//! requires a matching precompile invocation in the transaction.
//!
//! Each challenge embeds:
//!  * a global `DOMAIN` tag (rules out cross-program replay)
//!  * an operation-specific tag (rules out cross-operation replay)
//!  * the dWallet identity (rules out cross-policy replay)
//!  * a single-use nonce (rules out replay across time)
//!  * the credential's own member-id (rules out signing-on-behalf-of)
//!
//! All inputs are length-prefixed by being concatenated as separate `hashv`
//! arguments (the SHA-256 absorbing each item in sequence makes the boundaries
//! unambiguous as long as no two challenge functions share the same input
//! shape — which is enforced by the unique operation tag).

use crate::hash::hashv;
use solana_address::Address;

pub const DOMAIN: &[u8] = b"andromeda::rules-policy::v1";

// Init flow tag (init_authority signs once at creation; PDA is single-shot
// per (dwallet, init_authority) pair so no nonce is needed — replay against
// the same PDA fails because the account already exists).
pub const OP_INIT: &[u8] = b"init";

// Recovery flow tags
pub const OP_PRIMARY_RECOVER: &[u8] = b"primary-recover";
pub const OP_QUORUM_SESSION_OPEN: &[u8] = b"quorum-session-open";
pub const OP_QUORUM_CONTRIBUTE: &[u8] = b"quorum-contribute";

// Admin flow tags (primary signs)
pub const OP_ADMIN_ADD_MEMBER: &[u8] = b"admin-add-member";
pub const OP_ADMIN_REMOVE_MEMBER: &[u8] = b"admin-remove-member";
pub const OP_ADMIN_ADD_DESTINATION: &[u8] = b"admin-add-destination";
pub const OP_ADMIN_REMOVE_DESTINATION: &[u8] = b"admin-remove-destination";
pub const OP_ADMIN_REVOKE: &[u8] = b"admin-revoke";
pub const OP_ADMIN_SET_PRIMARY: &[u8] = b"admin-set-primary";
pub const OP_ADMIN_SET_QUORUM_THRESHOLD_IMMEDIATE: &[u8] = b"admin-set-qt-immediate";
pub const OP_ADMIN_SET_DAILY_LIMIT_IMMEDIATE: &[u8] = b"admin-set-dl-immediate";
pub const OP_ADMIN_SET_COOLDOWN_IMMEDIATE: &[u8] = b"admin-set-cd-immediate";
pub const OP_ADMIN_PROPOSE_QUORUM_THRESHOLD: &[u8] = b"admin-propose-qt";
pub const OP_ADMIN_PROPOSE_DAILY_LIMIT: &[u8] = b"admin-propose-dl";
pub const OP_ADMIN_PROPOSE_COOLDOWN: &[u8] = b"admin-propose-cd";

// ── Init (Opção 4 — init_authority binds the PDA seed) ──────────

/// Init challenge for rules-policy. The init_authority signs this exactly
/// once when creating the policy. The PDA seed includes init_authority, so
/// each (dwallet, init_authority) pair maps to a distinct PDA — the
/// signature here proves the caller really controls init_authority and
/// commits all init parameters.
///
/// Replay protection: PDA uniqueness. The PDA is created with `init`
/// (fails if already exists), so the same signature cannot be replayed to
/// the same PDA. Cross-policy replay is blocked by DOMAIN. Cross-dwallet
/// replay is blocked because dwallet is hashed in.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn rules_policy_init_challenge(
    dwallet: &Address,
    init_authority_slot: &[u8; 34],
    primary_slot: &[u8; 34],
    quorum_threshold: u8,
    daily_limit_some: u8,
    daily_limit: u64,
    cooldown_seconds: u64,
    allowed_destinations_some: u8,
) -> [u8; 32] {
    let qt = [quorum_threshold];
    let dls = [daily_limit_some];
    let dl_le = daily_limit.to_le_bytes();
    let cd_le = cooldown_seconds.to_le_bytes();
    let ads = [allowed_destinations_some];
    hashv(&[
        DOMAIN,
        OP_INIT,
        dwallet.as_array().as_slice(),
        init_authority_slot,
        primary_slot,
        &qt,
        &dls,
        &dl_le,
        &cd_le,
        &ads,
    ])
}

// ── Recovery ────────────────────────────────────────────────────

#[inline]
pub fn primary_recover_challenge(
    dwallet: &Address,
    message_digest: &[u8; 32],
    metadata_digest: &[u8; 32],
    nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    let nonce_le = nonce.to_le_bytes();
    hashv(&[
        DOMAIN,
        OP_PRIMARY_RECOVER,
        dwallet.as_array().as_slice(),
        message_digest,
        metadata_digest,
        &nonce_le,
        primary_slot,
    ])
}

/// Primary signs this to authorize opening a new quorum session bound to a
/// specific (message, amount, destination, expiry).
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn quorum_session_open_challenge(
    dwallet: &Address,
    message_digest: &[u8; 32],
    metadata_digest: &[u8; 32],
    amount: u64,
    destination: &[u8; 32],
    expires_at: i64,
    session_nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    let amount_le = amount.to_le_bytes();
    let expires_le = expires_at.to_le_bytes();
    let nonce_le = session_nonce.to_le_bytes();
    hashv(&[
        DOMAIN,
        OP_QUORUM_SESSION_OPEN,
        dwallet.as_array().as_slice(),
        message_digest,
        metadata_digest,
        &amount_le,
        destination,
        &expires_le,
        &nonce_le,
        primary_slot,
    ])
}

/// Each member signs this to add a contribution to a session. The session
/// PDA address makes the challenge unique per-session; the member slot makes
/// it unique per-member (so member A's signature can't be replayed as B's).
#[inline]
pub fn quorum_contribute_challenge(
    session: &Address,
    member_slot: &[u8; 34],
) -> [u8; 32] {
    hashv(&[
        DOMAIN,
        OP_QUORUM_CONTRIBUTE,
        session.as_array().as_slice(),
        member_slot,
    ])
}

// ── Admin (primary signs) ───────────────────────────────────────

fn admin_hash(
    op_tag: &[u8],
    dwallet: &Address,
    nonce: u64,
    primary_slot: &[u8; 34],
    extras: &[&[u8]],
) -> [u8; 32] {
    let nonce_le = nonce.to_le_bytes();
    let mut parts: [&[u8]; 16] = [&[]; 16];
    parts[0] = DOMAIN;
    parts[1] = op_tag;
    parts[2] = dwallet.as_array().as_slice();
    parts[3] = &nonce_le;
    parts[4] = primary_slot;
    let mut n = 5usize;
    for &e in extras {
        if n >= parts.len() {
            break;
        }
        parts[n] = e;
        n += 1;
    }
    hashv(&parts[..n])
}

#[inline]
pub fn admin_add_member_challenge(
    dwallet: &Address,
    new_member_slot: &[u8; 34],
    nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    admin_hash(OP_ADMIN_ADD_MEMBER, dwallet, nonce, primary_slot, &[new_member_slot.as_slice()])
}

#[inline]
pub fn admin_remove_member_challenge(
    dwallet: &Address,
    member_slot_to_remove: &[u8; 34],
    nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    admin_hash(
        OP_ADMIN_REMOVE_MEMBER,
        dwallet,
        nonce,
        primary_slot,
        &[member_slot_to_remove.as_slice()],
    )
}

#[inline]
pub fn admin_add_destination_challenge(
    dwallet: &Address,
    destination: &[u8; 32],
    nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    admin_hash(OP_ADMIN_ADD_DESTINATION, dwallet, nonce, primary_slot, &[destination.as_slice()])
}

#[inline]
pub fn admin_remove_destination_challenge(
    dwallet: &Address,
    destination: &[u8; 32],
    nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    admin_hash(OP_ADMIN_REMOVE_DESTINATION, dwallet, nonce, primary_slot, &[destination.as_slice()])
}

#[inline]
pub fn admin_revoke_challenge(
    dwallet: &Address,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    admin_hash(OP_ADMIN_REVOKE, dwallet, nonce, primary_slot, &[])
}

#[inline]
pub fn admin_set_primary_challenge(
    dwallet: &Address,
    new_primary_slot: &[u8; 34],
    nonce: u64,
    current_primary_slot: &[u8; 34],
) -> [u8; 32] {
    admin_hash(
        OP_ADMIN_SET_PRIMARY,
        dwallet,
        nonce,
        current_primary_slot,
        &[new_primary_slot.as_slice()],
    )
}

#[inline]
pub fn admin_set_quorum_threshold_immediate_challenge(
    dwallet: &Address,
    new_threshold: u8,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    let v = [new_threshold];
    admin_hash(OP_ADMIN_SET_QUORUM_THRESHOLD_IMMEDIATE, dwallet, nonce, primary_slot, &[&v])
}

#[inline]
pub fn admin_set_daily_limit_immediate_challenge(
    dwallet: &Address,
    new_some: u8,
    new_limit: u64,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    let some = [new_some];
    let limit_le = new_limit.to_le_bytes();
    admin_hash(
        OP_ADMIN_SET_DAILY_LIMIT_IMMEDIATE,
        dwallet,
        nonce,
        primary_slot,
        &[&some, &limit_le],
    )
}

#[inline]
pub fn admin_set_cooldown_immediate_challenge(
    dwallet: &Address,
    new_cooldown_seconds: u64,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    let cd_le = new_cooldown_seconds.to_le_bytes();
    admin_hash(OP_ADMIN_SET_COOLDOWN_IMMEDIATE, dwallet, nonce, primary_slot, &[&cd_le])
}

#[inline]
pub fn admin_propose_quorum_threshold_challenge(
    dwallet: &Address,
    new_threshold: u8,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    let v = [new_threshold];
    admin_hash(OP_ADMIN_PROPOSE_QUORUM_THRESHOLD, dwallet, nonce, primary_slot, &[&v])
}

#[inline]
pub fn admin_propose_daily_limit_challenge(
    dwallet: &Address,
    new_some: u8,
    new_limit: u64,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    let some = [new_some];
    let limit_le = new_limit.to_le_bytes();
    admin_hash(OP_ADMIN_PROPOSE_DAILY_LIMIT, dwallet, nonce, primary_slot, &[&some, &limit_le])
}

#[inline]
pub fn admin_propose_cooldown_challenge(
    dwallet: &Address,
    new_cooldown_seconds: u64,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    let cd_le = new_cooldown_seconds.to_le_bytes();
    admin_hash(OP_ADMIN_PROPOSE_COOLDOWN, dwallet, nonce, primary_slot, &[&cd_le])
}
