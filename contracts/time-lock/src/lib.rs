//! Andromeda — Time Lock policy template (Quasar master API).
//!
//! Mode 0 (absolute window): allows signing only when start_slot <= now < end_slot.
//! Mode 1 (recurring): allows signing when (now - start_slot) % period_slots
//! falls within the first (end_slot - start_slot) slots of each period.
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
use quasar_lang::prelude::*;
use solana_address::Address;

declare_id!("2i4bE6s7oc8kkziQETy55SGWQXxwotkpERr9XMv7Q7qs");

#[program]
mod time_lock {
    use super::*;

    /// 0 — bootstrap with the initial slot window.
    ///
    /// Audit C2 fix (Opção 4): `init_authority_slot` is a wallet credential
    /// signing the canonical init challenge.
    /// Audit C1 fix: `current_ts` from `Clock` sysvar.
    #[instruction(discriminator = 0)]
    pub fn init_policy(
        ctx: Ctx<InitPolicy>,
        init_authority_slot: [u8; MEMBER_SLOT_LEN],
        init_authority_hash: Address,
        owner_slot: [u8; MEMBER_SLOT_LEN],
        mode: u8,
        start_slot: u64,
        end_slot: u64,
        recurring_period_slots: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let policy_addr = *ctx.accounts.policy.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        ctx.accounts.create(
            init_authority_slot,
            init_authority_hash,
            owner_slot,
            mode,
            start_slot,
            end_slot,
            recurring_period_slots,
        )?;
        emit!(PolicyDeployed {
            policy: policy_addr,
            dwallet: dwallet_addr,
            ts: current_ts,
        });
        Ok(())
    }

    /// Audit C2 (Opção 4) + C1 fixes.
    /// `current_slot` from `Clock` sysvar — fixes the time-lock window
    /// bypass where a manipulated slot could approve signatures outside
    /// the legitimate unlock window.
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
        emit!(SignatureRequested {
            policy: policy_addr,
            request_hash,
            ts: current_ts,
        });
        ctx.accounts.request(
            message_digest,
            metadata_digest,
            user_pubkey,
            signature_scheme,
            message_approval_bump,
            cpi_authority_bump,
            current_slot,
        )?;
        emit!(SignatureApproved {
            policy: policy_addr,
            request_hash,
            ts: current_ts,
        });
        Ok(())
    }

    /// 2 — owner updates the slot window. Authorized via challenge.
    /// Audit C2 (Opção 4).
    #[instruction(discriminator = 2)]
    pub fn update_window(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        mode: u8,
        start_slot: u64,
        end_slot: u64,
        recurring_period_slots: u64,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts
            .update(mode, start_slot, end_slot, recurring_period_slots, expected_nonce)
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
        emit!(PolicyPaused {
            policy: policy_addr,
            ts: current_ts,
        });
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
        emit!(PolicyResumed {
            policy: policy_addr,
            ts: current_ts,
        });
        Ok(())
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

#[error_code]
pub enum TimeLockError {
    InvalidMode = 6000,
    InvalidWindow,
    OutsideWindow,
    PolicyPaused,
    InvalidNonce,
    AuthFailed,
    InvalidOwnerSlot,
    UnsupportedScheme,
}

impl From<AuthError> for TimeLockError {
    fn from(_e: AuthError) -> Self {
        TimeLockError::AuthFailed
    }
}

// Audit C2 (Opção 4): PDA seed includes init_authority_hash.
// Audit H4: `mode` and `paused` are u8 (was u64 — type confusion risk
// where state machine could be inconsistent if values != 0/1 ever stored).

#[account(discriminator = 1, set_inner)]
#[seeds(b"timelock", dwallet: Address, init_authority_hash: Address)]
pub struct TimeLockPolicy {
    pub dwallet: Address,
    pub owner_slot: [u8; MEMBER_SLOT_LEN],
    pub init_authority_slot: [u8; MEMBER_SLOT_LEN],
    pub next_admin_nonce: u64,
    pub start_slot: u64,
    pub end_slot: u64,
    pub recurring_period_slots: u64,
    pub mode: u8,
    pub paused: u8,
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

    #[account(init, payer = payer, address = TimeLockPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<TimeLockPolicy>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
}

impl InitPolicy {
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &mut self,
        init_authority_slot: [u8; MEMBER_SLOT_LEN],
        init_authority_hash: Address,
        owner_slot: [u8; MEMBER_SLOT_LEN],
        mode: u8,
        start_slot: u64,
        end_slot: u64,
        recurring_period_slots: u64,
    ) -> Result<(), ProgramError> {
        // Audit C2 (Opção 4): hash<->slot consistency.
        let computed = init_authority_hash_from_slot(&init_authority_slot);
        require!(
            computed == init_authority_hash,
            TimeLockError::InvalidOwnerSlot
        );
        validate_slot(&init_authority_slot).map_err(|_| TimeLockError::InvalidOwnerSlot)?;
        require!(
            init_authority_slot[0] != SCHEME_WEBAUTHN,
            TimeLockError::UnsupportedScheme
        );

        validate_slot(&owner_slot).map_err(|_| TimeLockError::InvalidOwnerSlot)?;
        require!(
            owner_slot[0] != SCHEME_WEBAUTHN,
            TimeLockError::UnsupportedScheme
        );
        require!(mode <= 1, TimeLockError::InvalidMode);
        require!(end_slot > start_slot, TimeLockError::InvalidWindow);
        if mode == 1 {
            require!(
                recurring_period_slots > 0,
                TimeLockError::InvalidWindow
            );
            require!(
                end_slot - start_slot <= recurring_period_slots,
                TimeLockError::InvalidWindow
            );
        }

        // Audit C2 (Opção 4): verify init precompile signature.
        let dwallet_addr = *self.dwallet_account.address();
        let challenge = challenges::init_policy_challenge(
            &dwallet_addr,
            &init_authority_slot,
            &owner_slot,
            mode,
            start_slot,
            end_slot,
            recurring_period_slots,
        );
        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| TimeLockError::AuthFailed)?;
        verify_signature(VerifyInput {
            member_slot: &init_authority_slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &[],
            webauthn_client_data_json: &[],
        })
        .map_err(|_| TimeLockError::AuthFailed)?;
        drop(sysvar_data_ref);

        self.policy.set_inner(TimeLockPolicyInner {
            dwallet: dwallet_addr,
            owner_slot,
            init_authority_slot,
            next_admin_nonce: 0,
            mode,
            paused: 0,
            start_slot,
            end_slot,
            recurring_period_slots,
        });
        Ok(())
    }
}

// ── RequestSignature ───────────────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct RequestSignature {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = TimeLockPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<TimeLockPolicy>,

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
        // Audit H4: paused now u8.
        let paused: u8 = self.policy.paused;
        require!(paused == 0, TimeLockError::PolicyPaused);

        // Audit H4: mode now u8.
        let mode: u8 = self.policy.mode;
        let start = self.policy.start_slot;
        let end = self.policy.end_slot;
        let period = self.policy.recurring_period_slots;
        let allowed = if mode == 0 {
            current_slot >= start && current_slot < end
        } else if period == 0 || current_slot < start {
            false
        } else {
            let offset = (current_slot - start) % period;
            offset < (end - start)
        };
        require!(allowed, TimeLockError::OutsideWindow);

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

    #[account(mut, address = TimeLockPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<TimeLockPolicy>,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,

    #[account(mut)]
    pub payer: Signer,
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
            .map_err(|_| TimeLockError::AuthFailed)?;

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
        mode: u8,
        start_slot: u64,
        end_slot: u64,
        recurring_period_slots: u64,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        require!(mode <= 1, TimeLockError::InvalidMode);
        require!(end_slot > start_slot, TimeLockError::InvalidWindow);
        if mode == 1 {
            require!(
                recurring_period_slots > 0,
                TimeLockError::InvalidWindow
            );
            require!(
                end_slot - start_slot <= recurring_period_slots,
                TimeLockError::InvalidWindow
            );
        }
        self.run(expected_nonce, |dw, owner, n| {
            challenges::update_window_challenge(
                dw,
                mode,
                start_slot,
                end_slot,
                recurring_period_slots,
                n,
                owner,
            )
        })?;
        // Audit H4: mode now u8.
        self.policy.mode = mode;
        self.policy.start_slot = start_slot.into();
        self.policy.end_slot = end_slot.into();
        self.policy.recurring_period_slots = recurring_period_slots.into();
        Ok(())
    }

    #[inline(always)]
    pub fn pause(&mut self, expected_nonce: u64) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, owner, n| {
            challenges::pause_challenge(dw, n, owner)
        })?;
        // Audit H4: paused now u8.
        self.policy.paused = 1;
        Ok(())
    }

    #[inline(always)]
    pub fn resume(&mut self, expected_nonce: u64) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, owner, n| {
            challenges::resume_challenge(dw, n, owner)
        })?;
        // Audit H4: paused now u8.
        self.policy.paused = 0;
        Ok(())
    }
}

#[inline]
fn check_sysvar_addr(addr: &Address) -> Result<(), ProgramError> {
    check_sysvar_address(addr).map_err(|_| TimeLockError::AuthFailed.into())
}

fn map_auth_err(e: AuthError) -> TimeLockError {
    match e {
        AuthError::InvalidNonce => TimeLockError::InvalidNonce,
        AuthError::UnsupportedScheme => TimeLockError::UnsupportedScheme,
        _ => TimeLockError::AuthFailed,
    }
}
