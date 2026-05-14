//! Domain-separated challenges for the velocity-guard template.
//!
//! Admin (governance) challenges follow clear-signing v2 — see
//! `docs/SPEC_CLEAR_SIGNING_FROZEN.md` for the wire format. Init and
//! runtime request-signature stay at v1.

use andromeda_auth::hash::hashv;
use andromeda_auth::human_message::{self, HumanMessageError, MAX_HUMAN_MESSAGE_BYTES};
use solana_address::Address;

/// Clear-signing v2 domain for admin governance challenges.
pub const DOMAIN: &[u8] = b"andromeda::velocity-guard::v2";

/// Init / runtime-request-signature domain (v1, no clear signing).
pub const DOMAIN_INIT_V1: &[u8] = b"andromeda::velocity-guard::v1";
pub const DOMAIN_REQUEST_SIGNATURE_V1: &[u8] = b"andromeda::velocity-guard::v1";

pub const OP_INIT: &[u8] = b"init";
pub const OP_UPDATE_WINDOW: &[u8] = b"update-window";
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

/// Audit C2 (Opção 4) init challenge. Preserved at v1.
#[inline]
pub fn init_policy_challenge(
    dwallet: &Address,
    init_authority_slot: &[u8; 34],
    owner_slot: &[u8; 34],
    max_sigs_per_window: u32,
    window_slots: u64,
) -> [u8; 32] {
    let max_le = max_sigs_per_window.to_le_bytes();
    let win_le = window_slots.to_le_bytes();
    hashv(&[
        DOMAIN_INIT_V1,
        OP_INIT,
        dwallet.as_array().as_slice(),
        init_authority_slot,
        owner_slot,
        &max_le,
        &win_le,
    ])
}

// ── Admin challenges (clear-signing v2) ─────────────────────────

#[inline]
pub fn update_window_challenge(
    dwallet: &Address,
    policy: &Address,
    max_sigs_per_window: u32,
    window_slots: u64,
    nonce: u64,
    owner_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::velocity_update_window_message(
        &mut msg,
        max_sigs_per_window,
        window_slots,
        policy,
        dwallet,
    )?;
    let max_le = max_sigs_per_window.to_le_bytes();
    let win_le = window_slots.to_le_bytes();
    Ok(admin_hash_with_human(
        OP_UPDATE_WINDOW,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        owner_slot,
        &[&max_le, &win_le],
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
    let len = human_message::velocity_pause_message(&mut msg, policy, dwallet)?;
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
    let len = human_message::velocity_resume_message(&mut msg, policy, dwallet)?;
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
pub fn request_metadata_digest(
    policy: &Address,
    dwallet: &Address,
    message_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    current_slot: u64,
) -> [u8; 32] {
    let scheme_le = signature_scheme.to_le_bytes();
    let slot_le = current_slot.to_le_bytes();
    hashv(&[
        DOMAIN_REQUEST_SIGNATURE_V1,
        b"request-signature",
        policy.as_array().as_slice(),
        dwallet.as_array().as_slice(),
        message_digest,
        user_pubkey,
        &scheme_le,
        &slot_le,
    ])
}
