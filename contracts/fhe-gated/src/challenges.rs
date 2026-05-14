//! Domain-separated challenges + canonical decision bytes for the
//! fhe-gated template.
//!
//! Three flavors:
//!
//!  * **Owner admin challenges** — `rotate_authority`, `pause`, `resume`.
//!    Clear-signing v2 (`docs/SPEC_CLEAR_SIGNING_FROZEN.md`). Signed
//!    off-chain by the owner and validated via
//!    `andromeda_auth::admin::verify_owner_admin`.
//!
//!  * **`decision_canonical_bytes`** — the bytes that the Vault Transit
//!    `andromeda-fhe` ed25519 key signs. Preserved at
//!    `DOMAIN_DECISION` v1 (no clear signing — the signer is a KMS key,
//!    not a human).
//!
//!  * **`request_metadata_digest`** — runtime, preserved at v1.

use andromeda_auth::hash::hashv;
use andromeda_auth::human_message::{self, HumanMessageError, MAX_HUMAN_MESSAGE_BYTES};
use solana_address::Address;

/// Clear-signing v2 domain for admin governance challenges.
pub const DOMAIN: &[u8] = b"andromeda::fhe-gated::v2";

/// Init / runtime request-signature domain (v1, no clear signing).
pub const DOMAIN_INIT_V1: &[u8] = b"andromeda::fhe-gated::v1";
pub const DOMAIN_REQUEST_SIGNATURE_V1: &[u8] = b"andromeda::fhe-gated::v1";

/// Vault-signed decision digest — KMS key, not a human signer.
pub const DOMAIN_DECISION: &[u8] = b"andromeda::fhe-gated::decision::v1";

pub const OP_INIT: &[u8] = b"init";
pub const OP_ROTATE_AUTHORITY: &[u8] = b"rotate-authority";
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
    fhe_authority: &Address,
    decision_max_age_slots: u64,
) -> [u8; 32] {
    let age_le = decision_max_age_slots.to_le_bytes();
    hashv(&[
        DOMAIN_INIT_V1,
        OP_INIT,
        dwallet.as_array().as_slice(),
        init_authority_slot,
        owner_slot,
        fhe_authority.as_array().as_slice(),
        &age_le,
    ])
}

// ── Admin challenges (clear-signing v2) ─────────────────────────

#[inline]
pub fn rotate_authority_challenge(
    dwallet: &Address,
    policy: &Address,
    new_fhe_authority: &Address,
    nonce: u64,
    owner_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len =
        human_message::fhe_rotate_authority_message(&mut msg, new_fhe_authority, policy, dwallet)?;
    Ok(admin_hash_with_human(
        OP_ROTATE_AUTHORITY,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        owner_slot,
        &[new_fhe_authority.as_array().as_slice()],
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
    let len = human_message::fhe_pause_message(&mut msg, policy, dwallet)?;
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
    let len = human_message::fhe_resume_message(&mut msg, policy, dwallet)?;
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
    decision_created_slot: u64,
    decision_authorize: u8,
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
) -> [u8; 32] {
    let slot_le = decision_created_slot.to_le_bytes();
    let auth = [decision_authorize];
    let scheme_le = signature_scheme.to_le_bytes();
    hashv(&[
        DOMAIN_REQUEST_SIGNATURE_V1,
        b"request-signature",
        policy.as_array().as_slice(),
        dwallet.as_array().as_slice(),
        message_digest,
        &slot_le,
        &auth,
        user_pubkey,
        &scheme_le,
    ])
}

/// Canonical 32-byte digest the Vault Transit `andromeda-fhe` key must sign
/// to authorize a request. The bytes are deterministic and the encrypt-backend
/// reconstructs them exactly when calling Vault. The on-chain handler
/// recomputes the same digest and matches it against the Ed25519 precompile
/// invocation in the same transaction. Domain preserved at v1 — KMS signer,
/// not a human, no clear signing.
#[inline]
pub fn decision_canonical_bytes(
    policy: &Address,
    message_digest: &[u8; 32],
    decision_created_slot: u64,
    decision_authorize: u8,
) -> [u8; 32] {
    let slot_le = decision_created_slot.to_le_bytes();
    let auth = [decision_authorize];
    hashv(&[
        DOMAIN_DECISION,
        policy.as_array().as_slice(),
        message_digest,
        &slot_le,
        &auth,
    ])
}
