//! Domain-separated challenges for the session-keys template.
//!
//! Owner admin actions: `create_session`, `revoke_session`, `add_allowed_program`,
//! `remove_allowed_program`, `close_session`.
//!
//! `request_signature_via_session` is NOT challenge-based — the session
//! keypair itself signs that one as a Solana transaction signer (it's the
//! whole point of the session keypair). `close_expired_session` is
//! permissionless (`current_slot >= expires_at_slot` is the only gate).

use andromeda_auth::hash::hashv;
use solana_address::Address;

pub const DOMAIN: &[u8] = b"andromeda::session-keys::v1";

pub const OP_INIT: &[u8] = b"init";
pub const OP_CREATE_SESSION: &[u8] = b"create-session";
pub const OP_REVOKE_SESSION: &[u8] = b"revoke-session";
pub const OP_ADD_ALLOWED_PROGRAM: &[u8] = b"add-allowed-program";
pub const OP_REMOVE_ALLOWED_PROGRAM: &[u8] = b"remove-allowed-program";
pub const OP_CLOSE_SESSION: &[u8] = b"close-session";

/// Audit C2 (Opção 4) init challenge. Session_index is part of the PDA seed
/// so the challenge binds the session slot the user is consenting to create.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn init_policy_challenge(
    dwallet: &Address,
    init_authority_slot: &[u8; 34],
    session_index: u32,
    owner_slot: &[u8; 34],
    session_key: &Address,
    expires_at_slot: u64,
    max_amount_per_tx: u64,
    max_uses: u32,
) -> [u8; 32] {
    let idx_le = session_index.to_le_bytes();
    let exp_le = expires_at_slot.to_le_bytes();
    let amt_le = max_amount_per_tx.to_le_bytes();
    let uses_le = max_uses.to_le_bytes();
    hashv(&[
        DOMAIN,
        OP_INIT,
        dwallet.as_array().as_slice(),
        init_authority_slot,
        &idx_le,
        owner_slot,
        session_key.as_array().as_slice(),
        &exp_le,
        &amt_le,
        &uses_le,
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
pub fn create_session_challenge(
    dwallet: &Address,
    policy: &Address,
    session_key: &Address,
    expires_at_slot: u64,
    max_amount_per_tx: u64,
    max_uses: u32,
    nonce: u64,
    owner_slot: &[u8; 34],
) -> [u8; 32] {
    let exp_le = expires_at_slot.to_le_bytes();
    let amt_le = max_amount_per_tx.to_le_bytes();
    let uses_le = max_uses.to_le_bytes();
    admin_hash(
        OP_CREATE_SESSION,
        dwallet,
        policy,
        nonce,
        owner_slot,
        &[
            session_key.as_array().as_slice(),
            &exp_le,
            &amt_le,
            &uses_le,
        ],
    )
}

#[inline]
pub fn revoke_session_challenge(
    dwallet: &Address,
    policy: &Address,
    nonce: u64,
    owner_slot: &[u8; 34],
) -> [u8; 32] {
    admin_hash(OP_REVOKE_SESSION, dwallet, policy, nonce, owner_slot, &[])
}

#[inline]
pub fn add_allowed_program_challenge(
    dwallet: &Address,
    policy: &Address,
    program_id: &Address,
    nonce: u64,
    owner_slot: &[u8; 34],
) -> [u8; 32] {
    admin_hash(
        OP_ADD_ALLOWED_PROGRAM,
        dwallet,
        policy,
        nonce,
        owner_slot,
        &[program_id.as_array().as_slice()],
    )
}

#[inline]
pub fn remove_allowed_program_challenge(
    dwallet: &Address,
    policy: &Address,
    program_id: &Address,
    nonce: u64,
    owner_slot: &[u8; 34],
) -> [u8; 32] {
    admin_hash(
        OP_REMOVE_ALLOWED_PROGRAM,
        dwallet,
        policy,
        nonce,
        owner_slot,
        &[program_id.as_array().as_slice()],
    )
}

#[inline]
pub fn close_session_challenge(
    dwallet: &Address,
    policy: &Address,
    recipient: &Address,
    nonce: u64,
    owner_slot: &[u8; 34],
) -> [u8; 32] {
    admin_hash(
        OP_CLOSE_SESSION,
        dwallet,
        policy,
        nonce,
        owner_slot,
        &[recipient.as_array().as_slice()],
    )
}

#[inline]
pub fn request_metadata_digest(
    policy: &Address,
    dwallet: &Address,
    session_key: &Address,
    message_digest: &[u8; 32],
    amount: u64,
    destination_program: &Address,
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    signature_nonce: u64,
) -> [u8; 32] {
    let amount_le = amount.to_le_bytes();
    let scheme_le = signature_scheme.to_le_bytes();
    let nonce_le = signature_nonce.to_le_bytes();
    hashv(&[
        DOMAIN,
        b"request-signature",
        policy.as_array().as_slice(),
        dwallet.as_array().as_slice(),
        session_key.as_array().as_slice(),
        message_digest,
        &amount_le,
        destination_program.as_array().as_slice(),
        user_pubkey,
        &scheme_le,
        &nonce_le,
    ])
}
