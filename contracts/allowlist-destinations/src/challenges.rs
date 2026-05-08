//! Domain-separated challenges for the allowlist-destinations template.
//!
//! Mirror these byte-for-byte in TypeScript when invoking the template
//! from the gateway / backend.

use andromeda_auth::hash::hashv;
use solana_address::Address;

pub const DOMAIN: &[u8] = b"andromeda::allowlist-destinations::v1";

pub const OP_INIT: &[u8] = b"init";
pub const OP_ADD_DESTINATION: &[u8] = b"add-destination";
pub const OP_REMOVE_DESTINATION: &[u8] = b"remove-destination";
pub const OP_PAUSE: &[u8] = b"pause";
pub const OP_RESUME: &[u8] = b"resume";

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

/// Audit C2 (Opção 4) init challenge. The init_authority signs this once at
/// creation. Replay protection: PDA uniqueness — `init` fails if the same
/// `(dwallet, init_authority_hash)` pair is reused.
#[inline]
pub fn init_policy_challenge(
    dwallet: &Address,
    init_authority_slot: &[u8; 34],
    owner_slot: &[u8; 34],
) -> [u8; 32] {
    hashv(&[
        DOMAIN,
        OP_INIT,
        dwallet.as_array().as_slice(),
        init_authority_slot,
        owner_slot,
    ])
}

#[inline]
pub fn add_destination_challenge(
    dwallet: &Address,
    destination: &[u8; 32],
    nonce: u64,
    owner_slot: &[u8; 34],
) -> [u8; 32] {
    admin_hash(OP_ADD_DESTINATION, dwallet, nonce, owner_slot, &[destination.as_slice()])
}

#[inline]
pub fn remove_destination_challenge(
    dwallet: &Address,
    destination: &[u8; 32],
    nonce: u64,
    owner_slot: &[u8; 34],
) -> [u8; 32] {
    admin_hash(OP_REMOVE_DESTINATION, dwallet, nonce, owner_slot, &[destination.as_slice()])
}

#[inline]
pub fn pause_challenge(dwallet: &Address, nonce: u64, owner_slot: &[u8; 34]) -> [u8; 32] {
    admin_hash(OP_PAUSE, dwallet, nonce, owner_slot, &[])
}

#[inline]
pub fn resume_challenge(dwallet: &Address, nonce: u64, owner_slot: &[u8; 34]) -> [u8; 32] {
    admin_hash(OP_RESUME, dwallet, nonce, owner_slot, &[])
}
