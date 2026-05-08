//! Domain-separated challenges for the time-lock template.

use andromeda_auth::hash::hashv;
use solana_address::Address;

pub const DOMAIN: &[u8] = b"andromeda::time-lock::v1";

pub const OP_INIT: &[u8] = b"init";
pub const OP_UPDATE_WINDOW: &[u8] = b"update-window";
pub const OP_PAUSE: &[u8] = b"pause";
pub const OP_RESUME: &[u8] = b"resume";

/// Audit C2 (Opção 4) init challenge.
#[inline]
pub fn init_policy_challenge(
    dwallet: &Address,
    init_authority_slot: &[u8; 34],
    owner_slot: &[u8; 34],
    mode: u8,
    start_slot: u64,
    end_slot: u64,
    recurring_period_slots: u64,
) -> [u8; 32] {
    let mode_b = [mode];
    let start_le = start_slot.to_le_bytes();
    let end_le = end_slot.to_le_bytes();
    let period_le = recurring_period_slots.to_le_bytes();
    hashv(&[
        DOMAIN,
        OP_INIT,
        dwallet.as_array().as_slice(),
        init_authority_slot,
        owner_slot,
        &mode_b,
        &start_le,
        &end_le,
        &period_le,
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
pub fn update_window_challenge(
    dwallet: &Address,
    mode: u8,
    start_slot: u64,
    end_slot: u64,
    recurring_period_slots: u64,
    nonce: u64,
    owner_slot: &[u8; 34],
) -> [u8; 32] {
    let mode_b = [mode];
    let start_le = start_slot.to_le_bytes();
    let end_le = end_slot.to_le_bytes();
    let period_le = recurring_period_slots.to_le_bytes();
    admin_hash(
        OP_UPDATE_WINDOW,
        dwallet,
        nonce,
        owner_slot,
        &[&mode_b, &start_le, &end_le, &period_le],
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
