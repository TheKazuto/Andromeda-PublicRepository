//! Shared primitives across the Andromeda policy template family.
//!
//! Currently provides the canonical CPI helper to invoke Ika's
//! `approve_message` and the standard event types every template emits.
//! Every template's `request_signature` instruction calls into this crate.

#![no_std]

use quasar_lang::prelude::*;
use ika_dwallet_quasar::DWalletContext;

pub mod events;

/// Ika dWallet Solana pre-alpha program ID:
/// `87W54kGYFQ1rgWqMeu4XTPHWXWmXSQCcjm8vCTfiq1oY`.
pub const IKA_DWALLET_PROGRAM_ID: Address = Address::new_from_array([
    0x69, 0xac, 0x29, 0xb9, 0x32, 0x20, 0x9f, 0x3d, 0x15, 0x10, 0x9a, 0x4a, 0x70, 0x81, 0xda, 0x41,
    0x05, 0x68, 0x34, 0x30, 0xf0, 0x5a, 0xb2, 0x32, 0x79, 0x8c, 0xb1, 0x01, 0xd7, 0x24, 0x90, 0x5b,
]);

/// Minimum cooldown for any policy-update path (seconds).
pub const MIN_COOLDOWN_SECONDS: u64 = 3_600;

/// Local defense-in-depth before invoking Ika. Ika verifies the CPI authority
/// PDA internally, but callers must not be able to pass a fake program that
/// returns success without creating a real MessageApproval.
#[inline]
pub fn validate_ika_cpi_accounts(dwallet_program: &AccountView, dwallet: &AccountView) -> bool {
    dwallet_program.address() == &IKA_DWALLET_PROGRAM_ID && dwallet.owner() == &IKA_DWALLET_PROGRAM_ID
}

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
