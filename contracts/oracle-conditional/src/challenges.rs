//! Domain-separated challenges for the oracle-conditional template.
//!
//! Admin challenges follow clear-signing v2 — see
//! `docs/SPEC_CLEAR_SIGNING_FROZEN.md`. Init and runtime request-signature
//! stay at v1.

use andromeda_auth::hash::hashv;
use andromeda_auth::human_message::{self, HumanMessageError, MAX_HUMAN_MESSAGE_BYTES};
use solana_address::Address;

/// Clear-signing v2 domain for admin governance challenges.
pub const DOMAIN: &[u8] = b"andromeda::oracle-conditional::v2";

/// Init / runtime request-signature domain (v1, no clear signing).
pub const DOMAIN_INIT_V1: &[u8] = b"andromeda::oracle-conditional::v1";
pub const DOMAIN_REQUEST_SIGNATURE_V1: &[u8] = b"andromeda::oracle-conditional::v1";

pub const OP_INIT: &[u8] = b"init";
pub const OP_UPDATE_BOUNDS: &[u8] = b"update-bounds";
pub const OP_PAUSE: &[u8] = b"pause";
pub const OP_RESUME: &[u8] = b"resume";

#[inline(always)]
fn human_len_le(human: &[u8]) -> [u8; 2] {
    debug_assert!(human.len() <= MAX_HUMAN_MESSAGE_BYTES);
    (human.len() as u16).to_le_bytes()
}

#[inline]
fn admin_hash_with_human(
    op_tag: &[u8],
    human: &[u8],
    dwallet: &Address,
    policy: &Address,
    nonce: u64,
    owner_slot: &[u8; 34],
    extras: &[&[u8]],
) -> [u8; 32] {
    let h_len = human_len_le(human);
    let nonce_le = nonce.to_le_bytes();
    let mut parts: [&[u8]; 16] = [&[]; 16];
    parts[0] = DOMAIN;
    parts[1] = op_tag;
    parts[2] = &h_len;
    parts[3] = human;
    parts[4] = dwallet.as_array().as_slice();
    parts[5] = policy.as_array().as_slice();
    parts[6] = &nonce_le;
    parts[7] = owner_slot;
    let mut n = 8usize;
    for &e in extras {
        if n >= parts.len() {
            break;
        }
        parts[n] = e;
        n += 1;
    }
    hashv(&parts[..n])
}

/// Audit C2 (Opção 4) init challenge. Audit M1: includes `max_confidence_bps`.
/// Preserved at v1.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn init_policy_challenge(
    dwallet: &Address,
    init_authority_slot: &[u8; 34],
    owner_slot: &[u8; 34],
    oracle_feed: &Address,
    min_price: i64,
    max_price: i64,
    max_age_slots: u64,
    max_confidence_bps: u16,
) -> [u8; 32] {
    let min_le = min_price.to_le_bytes();
    let max_le = max_price.to_le_bytes();
    let age_le = max_age_slots.to_le_bytes();
    let bps_le = max_confidence_bps.to_le_bytes();
    hashv(&[
        DOMAIN_INIT_V1,
        OP_INIT,
        dwallet.as_array().as_slice(),
        init_authority_slot,
        owner_slot,
        oracle_feed.as_array().as_slice(),
        &min_le,
        &max_le,
        &age_le,
        &bps_le,
    ])
}

// ── Admin challenges (clear-signing v2) ─────────────────────────

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn update_bounds_challenge(
    dwallet: &Address,
    policy: &Address,
    min_price: i64,
    max_price: i64,
    max_age_slots: u64,
    max_confidence_bps: u16,
    nonce: u64,
    owner_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::oracle_update_bounds_message(
        &mut msg,
        min_price,
        max_price,
        max_age_slots,
        max_confidence_bps,
        policy,
        dwallet,
    )?;
    let min_le = min_price.to_le_bytes();
    let max_le = max_price.to_le_bytes();
    let age_le = max_age_slots.to_le_bytes();
    let bps_le = max_confidence_bps.to_le_bytes();
    Ok(admin_hash_with_human(
        OP_UPDATE_BOUNDS,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        owner_slot,
        &[&min_le, &max_le, &age_le, &bps_le],
    ))
}

#[inline]
pub fn pause_challenge(
    dwallet: &Address,
    policy: &Address,
    nonce: u64,
    owner_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::oracle_pause_message(&mut msg, policy, dwallet)?;
    Ok(admin_hash_with_human(
        OP_PAUSE,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        owner_slot,
        &[],
    ))
}

#[inline]
pub fn resume_challenge(
    dwallet: &Address,
    policy: &Address,
    nonce: u64,
    owner_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::oracle_resume_message(&mut msg, policy, dwallet)?;
    Ok(admin_hash_with_human(
        OP_RESUME,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        owner_slot,
        &[],
    ))
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn request_metadata_digest(
    policy: &Address,
    dwallet: &Address,
    message_digest: &[u8; 32],
    oracle_feed: &Address,
    current_price: i64,
    posted_slot: u64,
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
) -> [u8; 32] {
    let price_le = current_price.to_le_bytes();
    let slot_le = posted_slot.to_le_bytes();
    let scheme_le = signature_scheme.to_le_bytes();
    hashv(&[
        DOMAIN_REQUEST_SIGNATURE_V1,
        b"request-signature",
        policy.as_array().as_slice(),
        dwallet.as_array().as_slice(),
        message_digest,
        oracle_feed.as_array().as_slice(),
        &price_le,
        &slot_le,
        user_pubkey,
        &scheme_le,
    ])
}
