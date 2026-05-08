//! Domain-separated challenges + canonical decision bytes for the
//! fhe-gated template.
//!
//! Two flavors:
//!
//!  * **Owner admin challenges** — `rotate_authority`, `pause`, `resume`.
//!    Same shape as the other Andromeda templates; signed off-chain by the
//!    owner and validated via `andromeda_auth::admin::verify_owner_admin`.
//!
//!  * **`decision_canonical_bytes`** — the bytes that the Vault Transit
//!    `andromeda-fhe` ed25519 key signs. The on-chain handler reconstructs
//!    these bytes from the same inputs and looks up an Ed25519 precompile
//!    invocation in the same transaction with
//!    `(fhe_authority_pubkey, decision_canonical_bytes, decision_signature)`
//!    — closing the previous "gateway as trust anchor" gap.

use andromeda_auth::hash::hashv;
use solana_address::Address;

pub const DOMAIN: &[u8] = b"andromeda::fhe-gated::v1";
pub const DOMAIN_DECISION: &[u8] = b"andromeda::fhe-gated::decision::v1";

pub const OP_INIT: &[u8] = b"init";
pub const OP_ROTATE_AUTHORITY: &[u8] = b"rotate-authority";
pub const OP_PAUSE: &[u8] = b"pause";
pub const OP_RESUME: &[u8] = b"resume";

/// Audit C2 (Opção 4) init challenge.
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
        DOMAIN,
        OP_INIT,
        dwallet.as_array().as_slice(),
        init_authority_slot,
        owner_slot,
        fhe_authority.as_array().as_slice(),
        &age_le,
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
pub fn rotate_authority_challenge(
    dwallet: &Address,
    new_fhe_authority: &Address,
    nonce: u64,
    owner_slot: &[u8; 34],
) -> [u8; 32] {
    admin_hash(
        OP_ROTATE_AUTHORITY,
        dwallet,
        nonce,
        owner_slot,
        &[new_fhe_authority.as_array().as_slice()],
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

/// Canonical 32-byte digest the Vault Transit `andromeda-fhe` key must sign
/// to authorize a request. The bytes are deterministic and the encrypt-backend
/// reconstructs them exactly when calling Vault. The on-chain handler
/// recomputes the same digest and matches it against the Ed25519 precompile
/// invocation in the same transaction.
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
