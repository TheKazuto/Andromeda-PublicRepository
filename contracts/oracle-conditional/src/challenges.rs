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
    nonce: u64,
    owner_slot: &[u8; 34],
    extras: &[&[u8]],
) -> [u8; 32] {
    let nonce_le = nonce.to_le_bytes();
    let mut parts: [&[u8]; 16] = [&[]; 16];
    parts[0] = DOMAIN;
    parts[1] = op_tag;
    parts[2] = dwallet.as_array().as_slice();
    parts[3] = &nonce_le;
    parts[4] = owner_slot;
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
#[allow(clippy::too_many_arguments)]
pub fn update_bounds_challenge(
    dwallet: &Address,
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
        nonce,
        owner_slot,
        &[&min_le, &max_le, &age_le, &bps_le],
    )
}

#[inline]
pub fn pause_challenge(dwallet: &Address, nonce: u64, owner_slot: &[u8; 34]) -> [u8; 32] {
    admin_hash(OP_PAUSE, dwallet, nonce, owner_slot, &[])
}

#[inline]
pub fn resume_challenge(dwallet: &Address, nonce: u64, owner_slot: &[u8; 34]) -> [u8; 32] {
    admin_hash(OP_RESUME, dwallet, nonce, owner_slot, &[])
}
