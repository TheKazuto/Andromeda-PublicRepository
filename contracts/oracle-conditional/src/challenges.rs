//! Domain-separated challenges for the oracle-conditional template.

use andromeda_auth::hash::hashv;
use solana_address::Address;

pub const DOMAIN: &[u8] = b"andromeda::oracle-conditional::v1";

pub const OP_INIT: &[u8] = b"init";
pub const OP_UPDATE_BOUNDS: &[u8] = b"update-bounds";
pub const OP_PAUSE: &[u8] = b"pause";
pub const OP_RESUME: &[u8] = b"resume";

/// Audit C2 (Opção 4) init challenge. Audit M1: includes `max_confidence_bps`.
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
        DOMAIN,
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

#[inline]
fn admin_hash(
    op_tag: &[u8],
    dwallet: &Address,
    policy: &Address,
    nonce: u64,
    owner_slot: &[u8; 34],
    extras: &[&[u8]],
) -> [u8; 32] {
    let nonce_le = nonce.to_le_bytes();
    let mut parts: [&[u8]; 16] = [&[]; 16];
    parts[0] = DOMAIN;
    parts[1] = op_tag;
    parts[2] = dwallet.as_array().as_slice();
    parts[3] = policy.as_array().as_slice();
    parts[4] = &nonce_le;
    parts[5] = owner_slot;
    let mut n = 6usize;
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
) -> [u8; 32] {
    let min_le = min_price.to_le_bytes();
    let max_le = max_price.to_le_bytes();
    let age_le = max_age_slots.to_le_bytes();
    let bps_le = max_confidence_bps.to_le_bytes();
    admin_hash(
        OP_UPDATE_BOUNDS,
        dwallet,
        policy,
        nonce,
        owner_slot,
        &[&min_le, &max_le, &age_le, &bps_le],
    )
}

#[inline]
pub fn pause_challenge(dwallet: &Address, policy: &Address, nonce: u64, owner_slot: &[u8; 34]) -> [u8; 32] {
    admin_hash(OP_PAUSE, dwallet, policy, nonce, owner_slot, &[])
}

#[inline]
pub fn resume_challenge(dwallet: &Address, policy: &Address, nonce: u64, owner_slot: &[u8; 34]) -> [u8; 32] {
    admin_hash(OP_RESUME, dwallet, policy, nonce, owner_slot, &[])
}

#[inline]
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
        DOMAIN,
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
