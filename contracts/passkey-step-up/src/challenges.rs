//! Domain-separated challenges for the passkey-step-up template.
//!
//! Two flavors:
//!
//!  * **Admin challenges** (`update_policy`, `pause`, `resume`) — signed by
//!    the policy `owner` from any chain, validated by the standard
//!    `andromeda_auth::admin::verify_owner_admin` flow. Same shape as the
//!    other Andromeda templates.
//!
//!  * **Step-up challenge** — what the WebAuthn passkey signs when an
//!    above-threshold signing request happens. The challenge bytes are
//!    embedded inside `clientDataJSON.challenge` (base64url-no-pad), and the
//!    on-chain handler reconstructs `authenticator_data || sha256(cdj)` and
//!    matches it against a Secp256r1 precompile invocation in the same tx.
//!    `next_step_up_nonce` makes every step-up single-use.

use andromeda_auth::hash::hashv;
use solana_address::Address;

pub const DOMAIN: &[u8] = b"andromeda::passkey-step-up::v1";

pub const OP_INIT: &[u8] = b"init";
pub const OP_UPDATE_POLICY: &[u8] = b"update-policy";
pub const OP_PAUSE: &[u8] = b"pause";
pub const OP_RESUME: &[u8] = b"resume";
pub const OP_STEP_UP: &[u8] = b"step-up";

/// Audit C2 (Opção 4) init challenge.
#[inline]
pub fn init_policy_challenge(
    dwallet: &Address,
    init_authority_slot: &[u8; 34],
    owner_slot: &[u8; 34],
    threshold_amount: u64,
    passkey_pubkey: &[u8; 33],
) -> [u8; 32] {
    let amount_le = threshold_amount.to_le_bytes();
    hashv(&[
        DOMAIN,
        OP_INIT,
        dwallet.as_array().as_slice(),
        init_authority_slot,
        owner_slot,
        &amount_le,
        passkey_pubkey.as_slice(),
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
pub fn update_policy_challenge(
    dwallet: &Address,
    threshold_amount: u64,
    passkey_pubkey: &[u8; 33],
    nonce: u64,
    owner_slot: &[u8; 34],
) -> [u8; 32] {
    let amount_le = threshold_amount.to_le_bytes();
    admin_hash(
        OP_UPDATE_POLICY,
        dwallet,
        nonce,
        owner_slot,
        &[&amount_le, passkey_pubkey.as_slice()],
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

/// Challenge that the WebAuthn passkey must sign for an above-threshold
/// signing request. The bytes returned are what the gateway places inside
/// `clientDataJSON.challenge` (base64url-no-pad).
#[inline]
pub fn step_up_challenge(
    dwallet: &Address,
    message_digest: &[u8; 32],
    tx_amount: u64,
    nonce: u64,
    passkey_pubkey: &[u8; 33],
) -> [u8; 32] {
    let amount_le = tx_amount.to_le_bytes();
    let nonce_le = nonce.to_le_bytes();
    hashv(&[
        DOMAIN,
        OP_STEP_UP,
        dwallet.as_array().as_slice(),
        message_digest,
        &amount_le,
        &nonce_le,
        passkey_pubkey.as_slice(),
    ])
}
