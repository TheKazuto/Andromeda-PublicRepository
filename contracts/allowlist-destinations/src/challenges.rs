//! Domain-separated challenges for the allowlist-destinations template.
//!
//! Mirror these byte-for-byte in TypeScript / Go when invoking the template
//! from the gateway / backend. The wire format for admin (governance)
//! operations follows clear-signing v2 (`docs/SPEC_CLEAR_SIGNING_FROZEN.md`):
//!
//! ```text
//! challenge = sha256(
//!     DOMAIN
//!     || op_tag
//!     || human_message_len_u16_le
//!     || human_message_bytes
//!     || dwallet || policy || nonce_le || owner_slot
//!     || canonical_typed_params...
//! )
//! ```
//!
//! Flows preserved at v1 (no clear signing — single-shot or runtime, not a
//! governance approval):
//!   * [`init_policy_challenge`] uses [`DOMAIN_INIT_V1`] (PDA-bound init).
//!   * [`request_metadata_digest`] uses [`DOMAIN_REQUEST_SIGNATURE_V1`]
//!     (runtime — gateway-rendered metadata, not signed by a human).

use andromeda_auth::hash::hashv;
use andromeda_auth::human_message::{self, HumanMessageError, MAX_HUMAN_MESSAGE_BYTES};
use solana_address::Address;

/// Clear-signing v2 domain for admin governance challenges (Fase 2).
pub const DOMAIN: &[u8] = b"andromeda::allowlist-destinations::v2";

/// Init-flow domain. PDA-bound, single-shot, no clear signing.
pub const DOMAIN_INIT_V1: &[u8] = b"andromeda::allowlist-destinations::v1";

/// Runtime request-signature digest domain. Not signed by a human — gateway
/// renders the metadata canonically.
pub const DOMAIN_REQUEST_SIGNATURE_V1: &[u8] = b"andromeda::allowlist-destinations::v1";

pub const OP_INIT: &[u8] = b"init";
pub const OP_ADD_DESTINATION: &[u8] = b"add-destination";
pub const OP_REMOVE_DESTINATION: &[u8] = b"remove-destination";
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

/// Audit C2 (Opção 4) init challenge. The init_authority signs this once at
/// creation. Replay protection: PDA uniqueness — `init` fails if the same
/// `(dwallet, init_authority_hash)` pair is reused. Preserved at v1 (no
/// clear signing — init is single-shot and PDA-bound).
#[inline]
pub fn init_policy_challenge(
    dwallet: &Address,
    init_authority_slot: &[u8; 34],
    owner_slot: &[u8; 34],
) -> [u8; 32] {
    hashv(&[
        DOMAIN_INIT_V1,
        OP_INIT,
        dwallet.as_array().as_slice(),
        init_authority_slot,
        owner_slot,
    ])
}

// ── Admin challenges (clear-signing v2) ─────────────────────────

#[inline]
pub fn add_destination_challenge(
    dwallet: &Address,
    policy: &Address,
    destination: &[u8; 32],
    nonce: u64,
    owner_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len =
        human_message::allowlist_add_destination_message(&mut msg, destination, policy, dwallet)?;
    Ok(admin_hash_with_human(
        OP_ADD_DESTINATION,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        owner_slot,
        &[destination.as_slice()],
    ))
}

#[inline]
pub fn remove_destination_challenge(
    dwallet: &Address,
    policy: &Address,
    destination: &[u8; 32],
    nonce: u64,
    owner_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::allowlist_remove_destination_message(
        &mut msg,
        destination,
        policy,
        dwallet,
    )?;
    Ok(admin_hash_with_human(
        OP_REMOVE_DESTINATION,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        owner_slot,
        &[destination.as_slice()],
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
    let len = human_message::allowlist_pause_message(&mut msg, policy, dwallet)?;
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
    let len = human_message::allowlist_resume_message(&mut msg, policy, dwallet)?;
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

// ── Runtime request-signature digest (not human-signed) ─────────

#[inline]
pub fn request_metadata_digest(
    policy: &Address,
    dwallet: &Address,
    message_digest: &[u8; 32],
    destination: &Address,
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
) -> [u8; 32] {
    let scheme_le = signature_scheme.to_le_bytes();
    hashv(&[
        DOMAIN_REQUEST_SIGNATURE_V1,
        b"request-signature",
        policy.as_array().as_slice(),
        dwallet.as_array().as_slice(),
        message_digest,
        destination.as_array().as_slice(),
        user_pubkey,
        &scheme_le,
    ])
}
