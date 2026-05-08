//! Shared primitives across the Andromeda policy template family.
//!
//! Currently provides the canonical CPI helper to invoke Ika's
//! `approve_message` and the standard event types every template emits.
//! Every template's `request_signature` instruction calls into this crate.

#![no_std]

use quasar_lang::prelude::*;
use ika_dwallet_quasar::DWalletContext;

pub mod events;

/// Minimum cooldown for any policy-update path (seconds).
pub const MIN_COOLDOWN_SECONDS: u64 = 3_600;

/// CPI helper — constructs a DWalletContext and invokes Ika's
/// `approve_message`. Templates call this after their constraints pass.
#[allow(clippy::too_many_arguments)]
pub fn invoke_ika_approve_message<'a>(
    dwallet_program: &'a AccountView,
    cpi_authority: &'a AccountView,
    caller_program: &'a AccountView,
    cpi_authority_bump: u8,
    coordinator: &'a AccountView,
    message_approval: &'a AccountView,
    dwallet: &'a AccountView,
    payer: &'a AccountView,
    system_program: &'a AccountView,
    message_digest: [u8; 32],
    metadata_digest: [u8; 32],
    user_pubkey: [u8; 32],
    signature_scheme: u16,
    message_approval_bump: u8,
) -> Result<(), ProgramError> {
    let ctx = DWalletContext {
        dwallet_program,
        cpi_authority,
        caller_program,
        cpi_authority_bump,
    };
    ctx.approve_message(
        coordinator,
        message_approval,
        dwallet,
        payer,
        system_program,
        message_digest,
        metadata_digest,
        user_pubkey,
        signature_scheme,
        message_approval_bump,
    )
}
