//! Andromeda — Velocity Guard policy template (Quasar master API).
//!
//! Caps the number of signatures the policy will approve inside a sliding
//! `window_slots` window. Useful as a panic switch against compromised-key
//! bursts.
//!
//! v2 (2026-05-07): challenge-based + gas-sponsored. Owner signs a 32-byte
//! off-chain challenge with any wallet; Andromeda gateway pays Solana fees.

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

declare_id!("DVAkrYe4SWzihvbh94GC6aB7ESf1h4yxiSDyetq1jkdW");

#[program]
mod velocity_guard {
    use super::*;

    /// 0 — bootstrap with a max-sigs-per-window cap.
    ///
    /// Audit C2 fix (Opção 4): `init_authority_slot` is a wallet credential
    /// signing the canonical init challenge.
    /// Audit C1 fix: `current_slot` and `current_ts` from `Clock` sysvar.
    #[instruction(discriminator = 0)]
    pub fn init_policy(
        ctx: Ctx<InitPolicy>,
        init_authority_slot: [u8; MEMBER_SLOT_LEN],
        init_authority_hash: Address,
        owner_slot: [u8; MEMBER_SLOT_LEN],
        max_sigs_per_window: u32,
        window_slots: u64,
    ) -> Result<(), ProgramError> {
        let current_slot: u64 = ctx.accounts.clock.slot.into();
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let policy_addr = *ctx.accounts.policy.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        ctx.accounts.create(
            init_authority_slot,
            init_authority_hash,
            owner_slot,
            max_sigs_per_window,
            window_slots,
            current_slot,
        )?;
        ctx.accounts.program.emit_event(&PolicyDeployed {
            policy: policy_addr,
            dwallet: dwallet_addr,
            ts: current_ts,
        }, &ctx.accounts.event_authority, EventAuthority::BUMP)?;
        Ok(())
    }

    /// Audit C2 (Opção 4) + C1 fixes.
    /// `current_slot` from `Clock` sysvar — fixes the rate-limit bypass
    /// where an attacker could pass any slot to reset the window.
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
    ) -> Result<(), ProgramError> {
        let current_slot: u64 = ctx.accounts.clock.slot.into();
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
            current_slot,
        )?;
        ctx.accounts.program.emit_event(&SignatureApproved {
            policy: policy_addr,
            request_hash,
            ts: current_ts,
        }, &ctx.accounts.event_authority, EventAuthority::BUMP)?;
        Ok(())
    }

    /// 2 — update the window/cap. Owner authorizes via challenge.
    /// Audit C2 (Opção 4).
    #[instruction(discriminator = 2)]
    pub fn update_window(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        max_sigs_per_window: u32,
        window_slots: u64,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts
            .update(max_sigs_per_window, window_slots, expected_nonce)
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
}

#[error_code]
pub enum VelocityError {
    InvalidLimit = 6000,
    InvalidWindow,
    WindowLimitExceeded,
    PolicyPaused,
    InvalidNonce,
    AuthFailed,
    InvalidOwnerSlot,
    UnsupportedScheme,
}

impl From<AuthError> for VelocityError {
    fn from(_e: AuthError) -> Self {
        VelocityError::AuthFailed
    }
}

// Audit C2 (Opção 4): PDA seed includes init_authority_hash.

#[account(discriminator = 1, set_inner)]
#[seeds(b"velocity", dwallet: Address, init_authority_hash: Address)]
pub struct VelocityPolicy {
    pub dwallet: Address,
    pub owner_slot: [u8; MEMBER_SLOT_LEN],
    pub init_authority_slot: [u8; MEMBER_SLOT_LEN],
    pub next_admin_nonce: u64,
    pub paused: u8,
    pub max_sigs_per_window: u32,
    pub window_slots: u64,
    pub current_count: u32,
    pub window_start_slot: u64,
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

    #[account(init, payer = payer, address = VelocityPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<VelocityPolicy>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<VelocityGuard>,
}

impl InitPolicy {
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &mut self,
        init_authority_slot: [u8; MEMBER_SLOT_LEN],
        init_authority_hash: Address,
        owner_slot: [u8; MEMBER_SLOT_LEN],
        max_sigs_per_window: u32,
        window_slots: u64,
        current_slot: u64,
    ) -> Result<(), ProgramError> {
        // Audit C2 (Opção 4): hash<->slot consistency.
        let computed = init_authority_hash_from_slot(&init_authority_slot);
        require!(
            computed == init_authority_hash,
            VelocityError::InvalidOwnerSlot
        );
        validate_slot(&init_authority_slot).map_err(|_| VelocityError::InvalidOwnerSlot)?;
        require!(
            init_authority_slot[0] != SCHEME_WEBAUTHN,
            VelocityError::UnsupportedScheme
        );

        validate_slot(&owner_slot).map_err(|_| VelocityError::InvalidOwnerSlot)?;
        require!(
            owner_slot[0] != SCHEME_WEBAUTHN,
            VelocityError::UnsupportedScheme
        );
        require!(max_sigs_per_window >= 1, VelocityError::InvalidLimit);
        require!(window_slots >= 1, VelocityError::InvalidWindow);

        // Audit C2 (Opção 4): verify init precompile signature.
        let dwallet_addr = *self.dwallet_account.address();
        let challenge = challenges::init_policy_challenge(
            &dwallet_addr,
            &init_authority_slot,
            &owner_slot,
            max_sigs_per_window,
            window_slots,
        );
        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| VelocityError::AuthFailed)?;
        verify_signature(VerifyInput {
            member_slot: &init_authority_slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &[],
            webauthn_client_data_json: &[],
        })
        .map_err(|_| VelocityError::AuthFailed)?;
        drop(sysvar_data_ref);

        self.policy.set_inner(VelocityPolicyInner {
            dwallet: dwallet_addr,
            owner_slot,
            init_authority_slot,
            next_admin_nonce: 0,
            paused: 0,
            max_sigs_per_window,
            window_slots,
            current_count: 0,
            window_start_slot: current_slot,
        });
        Ok(())
    }
}

// ── RequestSignature ───────────────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct RequestSignature {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = VelocityPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<VelocityPolicy>,

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
    pub program: Program<VelocityGuard>,
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
        current_slot: u64,
    ) -> Result<(), ProgramError> {
        require!(self.policy.paused == 0, VelocityError::PolicyPaused);

        let window_start: u64 = self.policy.window_start_slot.into();
        let window_slots: u64 = self.policy.window_slots.into();
        let max_sigs: u32 = self.policy.max_sigs_per_window.into();
        if current_slot.saturating_sub(window_start) >= window_slots {
            self.policy.window_start_slot = current_slot.into();
            self.policy.current_count = 0u32.into();
        }
        let count: u32 = self.policy.current_count.into();
        require!(count < max_sigs, VelocityError::WindowLimitExceeded);
        let policy_addr = *self.policy.address();
        let dwallet_addr = *self.dwallet_account.address();
        let expected_metadata_digest = challenges::request_metadata_digest(
            &policy_addr,
            &dwallet_addr,
            &message_digest,
            &user_pubkey,
            signature_scheme,
            current_slot,
        );
        require!(metadata_digest == expected_metadata_digest, VelocityError::AuthFailed);
        require!(
            validate_ika_cpi_accounts(
                &self.dwallet_program.to_account_view(),
                &self.dwallet_account.to_account_view(),
            ),
            VelocityError::AuthFailed
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
        )?;

        self.policy.current_count = count.saturating_add(1).into();
        Ok(())
    }
}

// ── AdminAction (challenge-based) ──────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct AdminAction {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = VelocityPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<VelocityPolicy>,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,

    #[account(mut)]
    pub payer: Signer,
    pub event_authority: EventAuthority,
    pub program: Program<VelocityGuard>,
}

impl AdminAction {
    fn run<F>(&mut self, expected_nonce: u64, build_challenge: F) -> Result<(), ProgramError>
    where
        F: FnOnce(&Address, &Address, &[u8; MEMBER_SLOT_LEN], u64) -> [u8; 32],
    {
        let dwallet_addr = *self.dwallet_account.address();
        let policy_addr = *self.policy.address();
        let owner_slot = self.policy.owner_slot;
        let on_chain_nonce: u64 = self.policy.next_admin_nonce.into();
        let challenge = build_challenge(&dwallet_addr, &policy_addr, &owner_slot, on_chain_nonce);

        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| VelocityError::AuthFailed)?;

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
    pub fn update(
        &mut self,
        max_sigs_per_window: u32,
        window_slots: u64,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        require!(max_sigs_per_window >= 1, VelocityError::InvalidLimit);
        require!(window_slots >= 1, VelocityError::InvalidWindow);
        self.run(expected_nonce, |dw, policy, owner, n| {
            challenges::update_window_challenge(dw, policy, max_sigs_per_window, window_slots, n, owner)
        })?;
        self.policy.max_sigs_per_window = max_sigs_per_window.into();
        self.policy.window_slots = window_slots.into();
        Ok(())
    }

    #[inline(always)]
    pub fn pause(&mut self, expected_nonce: u64) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, policy, owner, n| {
            challenges::pause_challenge(dw, policy, n, owner)
        })?;
        self.policy.paused = 1;
        Ok(())
    }

    #[inline(always)]
    pub fn resume(&mut self, expected_nonce: u64) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, policy, owner, n| {
            challenges::resume_challenge(dw, policy, n, owner)
        })?;
        self.policy.paused = 0;
        Ok(())
    }
}

#[inline]
fn check_sysvar_addr(addr: &Address) -> Result<(), ProgramError> {
    check_sysvar_address(addr).map_err(|_| VelocityError::AuthFailed.into())
}

fn map_auth_err(e: AuthError) -> VelocityError {
    match e {
        AuthError::InvalidNonce => VelocityError::InvalidNonce,
        AuthError::UnsupportedScheme => VelocityError::UnsupportedScheme,
        _ => VelocityError::AuthFailed,
    }
}

// ── Events ─────────────────────────────────────────────────────

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
