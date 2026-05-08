//! Owner-style admin authorization helper.
//!
//! Many Andromeda Quasar policy templates have a single `owner` credential
//! that authorizes config changes (init, update, pause, resume, etc).
//! `verify_owner_admin` is a one-shot gate that:
//!
//!   1. checks the caller-supplied `expected_nonce` matches the on-chain nonce,
//!   2. rejects long-lived owner credentials in `WebAuthn` scheme (passkey
//!      assertions are session-scoped — owner should be a stable Ed25519 /
//!      Secp256k1 / Secp256r1 key),
//!   3. verifies the signature off-chain → on-chain via the appropriate
//!      precompile,
//!   4. returns the next nonce (`on_chain_nonce + 1`) so the caller writes it
//!      atomically with the policy state mutation.
//!
//! Each template constructs its own `challenge: [u8; 32]` from a
//! domain-separated SHA-256 (`andromeda::<template>::v1` + op tag + dwallet +
//! nonce + owner-slot + op-specific extras). See `andromeda_auth::challenge`
//! for the exact RulesPolicy challenges and replicate the same pattern in
//! each template.

use crate::{verify_signature, AuthError, VerifyInput, MEMBER_SLOT_LEN, SCHEME_WEBAUTHN};

/// Verifies a wallet-agnostic owner admin call.
///
/// On success, returns `on_chain_nonce + 1` — the caller is expected to write
/// this back into the policy account in the same instruction so replay is
/// blocked atomically.
pub fn verify_owner_admin(
    expected_nonce: u64,
    on_chain_nonce: u64,
    owner_slot: &[u8; MEMBER_SLOT_LEN],
    challenge: &[u8; 32],
    instructions_sysvar_data: &[u8],
) -> Result<u64, AuthError> {
    if expected_nonce != on_chain_nonce {
        return Err(AuthError::InvalidNonce);
    }
    if owner_slot[0] == SCHEME_WEBAUTHN {
        return Err(AuthError::UnsupportedScheme);
    }
    verify_signature(VerifyInput {
        member_slot: owner_slot,
        challenge,
        instructions_sysvar_data,
        webauthn_auth_data: &[],
        webauthn_client_data_json: &[],
    })?;
    Ok(on_chain_nonce + 1)
}
