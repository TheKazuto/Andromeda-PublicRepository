//! Domain-separated challenges for the passkey-step-up template.
//!
//! Three flavors:
//!
//!  * **Admin challenges** (`update_policy`, `pause`, `resume`) — clear-signing
//!    v2. Signed by the policy `owner` from any chain, validated by the
//!    standard `andromeda_auth::admin::verify_owner_admin` flow.
//!
//!  * **Step-up challenge** — what the WebAuthn passkey signs when an
//!    above-threshold signing request happens. The challenge bytes are
//!    embedded inside `clientDataJSON.challenge` (base64url-no-pad), and the
//!    on-chain handler reconstructs `authenticator_data || sha256(cdj)` and
//!    matches it against a Secp256r1 precompile invocation in the same tx.
//!    Preserved at v1 (no clear signing — WebAuthn keeps base64url-no-pad
//!    challenge in clientDataJSON for the assertion).
//!
//!  * **Runtime request-signature digest** — preserved at v1.

use andromeda_auth::hash::hashv;
use andromeda_auth::human_message::{self, HumanMessageError, MAX_HUMAN_MESSAGE_BYTES};
use solana_address::Address;

/// Clear-signing v2 domain for admin governance challenges.
pub const DOMAIN: &[u8] = b"andromeda::passkey-step-up::v2";

/// Init / step-up / runtime request-signature domain (v1, no clear signing).
pub const DOMAIN_INIT_V1: &[u8] = b"andromeda::passkey-step-up::v1";
pub const DOMAIN_STEP_UP_V1: &[u8] = b"andromeda::passkey-step-up::v1";
pub const DOMAIN_REQUEST_SIGNATURE_V1: &[u8] = b"andromeda::passkey-step-up::v1";

pub const OP_INIT: &[u8] = b"init";
pub const OP_UPDATE_POLICY: &[u8] = b"update-policy";
pub const OP_PAUSE: &[u8] = b"pause";
pub const OP_RESUME: &[u8] = b"resume";
pub const OP_STEP_UP: &[u8] = b"step-up";

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
    threshold_amount: u64,
    passkey_pubkey: &[u8; 33],
) -> [u8; 32] {
    let amount_le = threshold_amount.to_le_bytes();
    hashv(&[
        DOMAIN_INIT_V1,
        OP_INIT,
        dwallet.as_array().as_slice(),
        init_authority_slot,
        owner_slot,
        &amount_le,
        passkey_pubkey.as_slice(),
    ])
}

// ── Admin challenges (clear-signing v2) ─────────────────────────

#[inline]
pub fn update_policy_challenge(
    dwallet: &Address,
    policy: &Address,
    threshold_amount: u64,
    passkey_pubkey: &[u8; 33],
    nonce: u64,
    owner_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::passkey_update_policy_message(
        &mut msg,
        threshold_amount,
        passkey_pubkey,
        policy,
        dwallet,
    )?;
    let amount_le = threshold_amount.to_le_bytes();
    Ok(admin_hash_with_human(
        OP_UPDATE_POLICY,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        owner_slot,
        &[&amount_le, passkey_pubkey.as_slice()],
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
    let len = human_message::passkey_pause_message(&mut msg, policy, dwallet)?;
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
    let len = human_message::passkey_resume_message(&mut msg, policy, dwallet)?;
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

/// Challenge that the WebAuthn passkey must sign for an above-threshold
/// signing request. The bytes returned are what the gateway places inside
/// `clientDataJSON.challenge` (base64url-no-pad). Preserved at v1 — WebAuthn
/// approval flow does not embed clear-signing text in the assertion.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn step_up_challenge(
    dwallet: &Address,
    message_approval: &Address,
    message_digest: &[u8; 32],
    metadata_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    message_approval_bump: u8,
    tx_amount: u64,
    nonce: u64,
    passkey_pubkey: &[u8; 33],
) -> [u8; 32] {
    let scheme_le = signature_scheme.to_le_bytes();
    let bump = [message_approval_bump];
    let amount_le = tx_amount.to_le_bytes();
    let nonce_le = nonce.to_le_bytes();
    hashv(&[
        DOMAIN_STEP_UP_V1,
        OP_STEP_UP,
        dwallet.as_array().as_slice(),
        message_approval.as_array().as_slice(),
        message_digest,
        metadata_digest,
        user_pubkey,
        &scheme_le,
        &bump,
        &amount_le,
        &nonce_le,
        passkey_pubkey.as_slice(),
    ])
}

#[inline]
pub fn request_metadata_digest(
    policy: &Address,
    dwallet: &Address,
    message_digest: &[u8; 32],
    tx_amount: u64,
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    step_up_nonce: Option<u64>,
) -> [u8; 32] {
    let amount_le = tx_amount.to_le_bytes();
    let scheme_le = signature_scheme.to_le_bytes();
    let no_nonce = 0u64.to_le_bytes();
    let nonce_le = step_up_nonce.unwrap_or(0).to_le_bytes();
    let nonce_flag = [if step_up_nonce.is_some() { 1 } else { 0 }];
    hashv(&[
        DOMAIN_REQUEST_SIGNATURE_V1,
        b"request-signature",
        policy.as_array().as_slice(),
        dwallet.as_array().as_slice(),
        message_digest,
        &amount_le,
        user_pubkey,
        &scheme_le,
        &nonce_flag,
        if step_up_nonce.is_some() {
            &nonce_le
        } else {
            &no_nonce
        },
    ])
}
