//! Andromeda — Allowlist Destinations policy template (Quasar master API).
//!
//! Approves a signing request only when the caller-provided `destination`
//! matches one of the whitelisted destinations stored on-chain.
//!
//! v2 (2026-05-07): challenge-based + gas-sponsored. The owner is no longer
//! a Solana transaction signer — they sign a 32-byte off-chain challenge
//! with whatever wallet they have (EVM / Sui / Bitcoin / Cosmos / NEAR /
//! Aptos / Solana / passkey). The Andromeda gateway pays Solana fees and
//! signs the transaction.

#![no_std]
#![allow(dead_code)]

pub mod challenges;

use andromeda_auth::admin::verify_owner_admin;
use andromeda_auth::hash::hashv;
use andromeda_auth::precompile::check_sysvar_address;
use andromeda_auth::{
    validate_slot, verify_signature, AuthError, VerifyInput, MEMBER_SLOT_LEN, SCHEME_WEBAUTHN,
};
use ika_dwallet_quasar::DWalletContext;
use andromeda_policy_shared::validate_ika_cpi_accounts;
use quasar_lang::prelude::*;
use solana_address::Address;

declare_id!("91hycWu3sTbRELUDBTkqbyaEse1fVFDX3RmW9uPNQqFx");

const MAX_DESTINATIONS: usize = 32;
const DESTINATIONS_BYTES: usize = MAX_DESTINATIONS * 32;

#[program]
mod allowlist_destinations {
    use super::*;

    /// 0 — Bootstrap a policy.
    ///
    /// Audit C2 fix (Opção 4): `init_authority_slot` is a wallet credential
    /// that signs a canonical init challenge. The PDA seed is
    /// `[b"allowlist", dwallet, sha256(init_authority_slot)]`, so squat by
    /// an attacker on one PDA does not block the legitimate user.
    /// Audit C1 fix: `current_ts` from `Clock` sysvar.
    #[instruction(discriminator = 0)]
    pub fn init_policy(
        ctx: Ctx<InitPolicy>,
        init_authority_slot: [u8; MEMBER_SLOT_LEN],
        init_authority_hash: Address,
        owner_slot: [u8; MEMBER_SLOT_LEN],
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let policy_addr = *ctx.accounts.policy.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        ctx.accounts.create(init_authority_slot, init_authority_hash, owner_slot)?;
        ctx.accounts.program.emit_event(&PolicyDeployed {
            policy: policy_addr,
            dwallet: dwallet_addr,
            ts: current_ts,
        }, &ctx.accounts.event_authority, EventAuthority::BUMP)?;
        Ok(())
    }

    /// Audit C2 (Opção 4) + C1 fixes.
    #[instruction(discriminator = 1)]
    pub fn request_signature(
        ctx: Ctx<RequestSignature>,
        _init_authority_hash: Address,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
        destination: Address,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let policy_addr = *ctx.accounts.policy.address();
        let request_hash = Address::from(message_digest);
        ctx.accounts.program.emit_event(&SignatureRequested {
            policy: policy_addr,
            request_hash,
            ts: current_ts,
        }, &ctx.accounts.event_authority, EventAuthority::BUMP)?;
        ctx.accounts.request(
            message_digest,
            metadata_digest,
            user_pubkey,
            signature_scheme,
            message_approval_bump,
            cpi_authority_bump,
            destination,
        )?;
        ctx.accounts.program.emit_event(&SignatureApproved {
            policy: policy_addr,
            request_hash,
            ts: current_ts,
        }, &ctx.accounts.event_authority, EventAuthority::BUMP)?;
        Ok(())
    }

    /// 2 — Append a destination. Owner authorizes via `add_destination_challenge`.
    /// Idempotent. Audit C2 (Opção 4).
    #[instruction(discriminator = 2)]
    pub fn add_destination(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        destination: [u8; 32],
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts.add(destination, expected_nonce)
    }

    /// Audit C2 (Opção 4) + C1 fixes.
    #[instruction(discriminator = 3)]
    pub fn pause(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let policy_addr = *ctx.accounts.policy.address();
        ctx.accounts.pause(expected_nonce)?;
        ctx.accounts.program.emit_event(&PolicyPaused {
            policy: policy_addr,
            ts: current_ts,
        }, &ctx.accounts.event_authority, EventAuthority::BUMP)?;
        Ok(())
    }

    /// Audit C2 (Opção 4) + C1 fixes.
    #[instruction(discriminator = 4)]
    pub fn resume(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let policy_addr = *ctx.accounts.policy.address();
        ctx.accounts.resume(expected_nonce)?;
        ctx.accounts.program.emit_event(&PolicyResumed {
            policy: policy_addr,
            ts: current_ts,
        }, &ctx.accounts.event_authority, EventAuthority::BUMP)?;
        Ok(())
    }

    /// 5 — Remove a destination. Owner authorizes via `remove_destination_challenge`.
    /// Idempotent. Audit C2 (Opção 4).
    #[instruction(discriminator = 5)]
    pub fn remove_destination(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        destination: [u8; 32],
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts.remove(destination, expected_nonce)
    }
}

#[error_code]
pub enum AllowlistError {
    TooManyDestinations = 6000,
    DestinationNotAllowed,
    PolicyPaused,
    InvalidNonce,
    AuthFailed,
    InvalidOwnerSlot,
    UnsupportedScheme,
}

impl From<AuthError> for AllowlistError {
    fn from(_e: AuthError) -> Self {
        AllowlistError::AuthFailed
    }
}

// ── Events (zero-copy, no padding) ─────────────────────────────

#[event(discriminator = 0)]
pub struct PolicyDeployed {
    pub policy: Address,
    pub dwallet: Address,
    pub ts: i64,
}

#[event(discriminator = 1)]
pub struct SignatureRequested {
    pub policy: Address,
    pub request_hash: Address,
    pub ts: i64,
}

#[event(discriminator = 2)]
pub struct SignatureApproved {
    pub policy: Address,
    pub request_hash: Address,
    pub ts: i64,
}

#[event(discriminator = 4)]
pub struct PolicyPaused {
    pub policy: Address,
    pub ts: i64,
}

#[event(discriminator = 5)]
pub struct PolicyResumed {
    pub policy: Address,
    pub ts: i64,
}

// ── Account state ──────────────────────────────────────────────
//
// Audit C2 (Opção 4): PDA seed includes `init_authority_hash`. Each
// (dwallet, init_authority) pair maps to a distinct PDA — squat-resistant.

#[account(discriminator = 1, set_inner)]
#[seeds(b"allowlist", dwallet: Address, init_authority_hash: Address)]
pub struct AllowlistPolicy {
    pub dwallet: Address,
    pub owner_slot: [u8; MEMBER_SLOT_LEN],
    pub init_authority_slot: [u8; MEMBER_SLOT_LEN],
    pub next_admin_nonce: u64,
    pub paused: u8,
    pub destinations_count: u8,
    pub destinations_flat: [u8; DESTINATIONS_BYTES],
}

/// Audit C2 (Opção 4) helper.
#[inline]
fn init_authority_hash_from_slot(slot: &[u8; MEMBER_SLOT_LEN]) -> Address {
    Address::from(hashv(&[slot]))
}

// ── InitPolicy ─────────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_slot: [u8; 34], init_authority_hash: Address)]
pub struct InitPolicy {
    pub dwallet_account: UncheckedAccount,

    #[account(init, payer = payer, address = AllowlistPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<AllowlistPolicy>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<AllowlistDestinations>,
}

impl InitPolicy {
    #[inline(always)]
    pub fn create(
        &mut self,
        init_authority_slot: [u8; MEMBER_SLOT_LEN],
        init_authority_hash: Address,
        owner_slot: [u8; MEMBER_SLOT_LEN],
    ) -> Result<(), ProgramError> {
        // Audit C2 (Opção 4): hash<->slot consistency.
        let computed = init_authority_hash_from_slot(&init_authority_slot);
        require!(
            computed == init_authority_hash,
            AllowlistError::InvalidOwnerSlot
        );
        validate_slot(&init_authority_slot).map_err(|_| AllowlistError::InvalidOwnerSlot)?;
        require!(
            init_authority_slot[0] != SCHEME_WEBAUTHN,
            AllowlistError::UnsupportedScheme
        );

        validate_slot(&owner_slot).map_err(|_| AllowlistError::InvalidOwnerSlot)?;
        require!(
            owner_slot[0] != SCHEME_WEBAUTHN,
            AllowlistError::UnsupportedScheme
        );

        // Audit C2 (Opção 4): verify init precompile signature.
        let dwallet_addr = *self.dwallet_account.address();
        let challenge = challenges::init_policy_challenge(
            &dwallet_addr,
            &init_authority_slot,
            &owner_slot,
        );
        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| AllowlistError::AuthFailed)?;
        verify_signature(VerifyInput {
            member_slot: &init_authority_slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &[],
            webauthn_client_data_json: &[],
        })
        .map_err(|_| AllowlistError::AuthFailed)?;
        drop(sysvar_data_ref);

        self.policy.set_inner(AllowlistPolicyInner {
            dwallet: dwallet_addr,
            owner_slot,
            init_authority_slot,
            next_admin_nonce: 0,
            paused: 0,
            destinations_count: 0,
            destinations_flat: [0u8; DESTINATIONS_BYTES],
        });
        Ok(())
    }
}

// ── RequestSignature ───────────────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct RequestSignature {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = AllowlistPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<AllowlistPolicy>,

    pub coordinator: UncheckedAccount,

    #[account(mut)]
    pub message_approval: UncheckedAccount,

    #[account(mut)]
    pub payer: Signer,

    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub dwallet_program: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<AllowlistDestinations>,
}

impl RequestSignature {
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &mut self,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
        destination: Address,
    ) -> Result<(), ProgramError> {
        require!(self.policy.paused == 0, AllowlistError::PolicyPaused);

        let count = self.policy.destinations_count as usize;
        let dest_bytes = destination.as_array();
        let mut allowed = false;
        for i in 0..count {
            let offset = i * 32;
            if &self.policy.destinations_flat[offset..offset + 32] == dest_bytes.as_slice() {
                allowed = true;
                break;
            }
        }
        require!(allowed, AllowlistError::DestinationNotAllowed);
        require!(
            validate_ika_cpi_accounts(
                &self.dwallet_program.to_account_view(),
                &self.dwallet_account.to_account_view(),
            ),
            AllowlistError::AuthFailed
        );

        let dwallet_ctx = DWalletContext {
            dwallet_program: self.dwallet_program.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.caller_program.to_account_view(),
            cpi_authority_bump,
        };
        dwallet_ctx.approve_message(
            self.coordinator.to_account_view(),
            self.message_approval.to_account_view(),
            self.dwallet_account.to_account_view(),
            self.payer.to_account_view(),
            self.system_program.to_account_view(),
            message_digest,
            metadata_digest,
            user_pubkey,
            signature_scheme,
            message_approval_bump,
        )
    }
}

// ── AdminAction (challenge-based) ──────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct AdminAction {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = AllowlistPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<AllowlistPolicy>,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,

    #[account(mut)]
    pub payer: Signer,
    pub event_authority: EventAuthority,
    pub program: Program<AllowlistDestinations>,
}

impl AdminAction {
    fn run<F>(&mut self, expected_nonce: u64, build_challenge: F) -> Result<(), ProgramError>
    where
        F: FnOnce(&Address, &[u8; MEMBER_SLOT_LEN], u64) -> [u8; 32],
    {
        let dwallet_addr = *self.dwallet_account.address();
        let owner_slot = self.policy.owner_slot;
        let on_chain_nonce: u64 = self.policy.next_admin_nonce.into();
        let challenge = build_challenge(&dwallet_addr, &owner_slot, on_chain_nonce);

        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| AllowlistError::AuthFailed)?;

        let new_nonce = verify_owner_admin(
            expected_nonce,
            on_chain_nonce,
            &owner_slot,
            &challenge,
            &sysvar_data_ref,
        )
        .map_err(map_auth_err)?;
        drop(sysvar_data_ref);

        self.policy.next_admin_nonce = new_nonce.into();
        Ok(())
    }

    #[inline(always)]
    pub fn add(
        &mut self,
        destination: [u8; 32],
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, owner, n| {
            challenges::add_destination_challenge(dw, &destination, n, owner)
        })?;
        let count = self.policy.destinations_count as usize;
        for i in 0..count {
            let offset = i * 32;
            if self.policy.destinations_flat[offset..offset + 32] == destination {
                return Ok(());
            }
        }
        require!(
            count < MAX_DESTINATIONS,
            AllowlistError::TooManyDestinations
        );
        let offset = count * 32;
        self.policy.destinations_flat[offset..offset + 32].copy_from_slice(&destination);
        self.policy.destinations_count = (count as u8) + 1;
        Ok(())
    }

    #[inline(always)]
    pub fn remove(
        &mut self,
        destination: [u8; 32],
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, owner, n| {
            challenges::remove_destination_challenge(dw, &destination, n, owner)
        })?;
        let count = self.policy.destinations_count as usize;
        for i in 0..count {
            let offset = i * 32;
            if self.policy.destinations_flat[offset..offset + 32] == destination {
                let last = (count - 1) * 32;
                if i != count - 1 {
                    let mut tail = [0u8; 32];
                    tail.copy_from_slice(&self.policy.destinations_flat[last..last + 32]);
                    self.policy.destinations_flat[offset..offset + 32].copy_from_slice(&tail);
                }
                self.policy.destinations_flat[last..last + 32].copy_from_slice(&[0u8; 32]);
                self.policy.destinations_count = (count - 1) as u8;
                return Ok(());
            }
        }
        Ok(())
    }

    #[inline(always)]
    pub fn pause(&mut self, expected_nonce: u64) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, owner, n| {
            challenges::pause_challenge(dw, n, owner)
        })?;
        self.policy.paused = 1;
        Ok(())
    }

    #[inline(always)]
    pub fn resume(&mut self, expected_nonce: u64) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, owner, n| {
            challenges::resume_challenge(dw, n, owner)
        })?;
        self.policy.paused = 0;
        Ok(())
    }
}

#[inline]
fn check_sysvar_addr(addr: &Address) -> Result<(), ProgramError> {
    check_sysvar_address(addr).map_err(|_| AllowlistError::AuthFailed.into())
}

fn map_auth_err(e: AuthError) -> AllowlistError {
    match e {
        AuthError::InvalidNonce => AllowlistError::InvalidNonce,
        AuthError::UnsupportedScheme => AllowlistError::UnsupportedScheme,
        _ => AllowlistError::AuthFailed,
    }
}
