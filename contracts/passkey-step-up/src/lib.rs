//! Andromeda — Passkey step-up policy template.
//!
//! Approves a signing request unconditionally below `threshold_amount`.
//! Above it, the caller MUST present a fresh WebAuthn assertion from the
//! bound passkey, and the assertion is verified **end-to-end on-chain** —
//! no off-chain "carimbo do backend" / attestor, no flag-only check.
//!
//! ## How step-up works on-chain (v2, 2026-05-07)
//!
//! 1. Gateway computes `step_up_challenge(dwallet, message_digest, tx_amount,
//!    next_step_up_nonce, passkey_pubkey)` — a 32-byte canonical hash that the
//!    on-chain program will recompute from the same inputs.
//! 2. User's passkey produces a WebAuthn assertion whose
//!    `clientDataJSON.challenge` contains those 32 bytes (base64url-no-pad).
//! 3. The gateway puts a Secp256r1 precompile invocation in the transaction
//!    carrying `(passkey_pubkey, signed_message=auth_data||sha256(cdj),
//!    signature)` — the Solana runtime validates the signature
//!    cryptographically.
//! 4. `request_signature_with_step_up` reconstructs the same challenge,
//!    confirms it appears inside `clientDataJSON`, reconstructs the WebAuthn
//!    signed message, and matches it against the precompile call. Only then
//!    does it CPI into the Ika dWallet program. Nonce is incremented
//!    atomically — every step-up is single-use on-chain.
//!
//! Below-threshold requests use `request_signature` (disc 1), which never
//! requires WebAuthn. Above-threshold requests must use
//! `request_signature_with_step_up` (disc 5).
//!
//! ## Owner admin
//!
//! `init_policy`, `update_policy`, `pause`, `resume` follow the standard
//! Andromeda owner challenge pattern (`andromeda_auth::admin::verify_owner_admin`)
//! so the owner is wallet-agnostic too.

#![no_std]
#![allow(dead_code)]

pub mod challenges;

use andromeda_auth::admin::verify_owner_admin;
use andromeda_auth::hash::hashv;
use andromeda_auth::precompile::check_sysvar_address;
use andromeda_auth::{
    build_member_slot, validate_slot, verify_signature, AuthError, VerifyInput, MEMBER_SLOT_LEN,
    SCHEME_WEBAUTHN, WEBAUTHN_AUTH_DATA_MAX, WEBAUTHN_CLIENT_DATA_JSON_MAX,
};
use ika_dwallet_quasar::DWalletContext;
use andromeda_policy_shared::validate_ika_cpi_accounts;
use quasar_lang::prelude::*;
use solana_address::Address;

declare_id!("7xNwfNHtN11kf5JFNhsQTuciBskmWmZ8XcHSAeNdvorC");

#[program]
mod passkey_step_up {
    use super::*;

    /// 0 — bootstrap.
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
        threshold_amount: u64,
        passkey_pubkey: [u8; 33],
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let policy_addr = *ctx.accounts.policy.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        ctx.accounts.create(
            init_authority_slot,
            init_authority_hash,
            owner_slot,
            threshold_amount,
            passkey_pubkey,
        )?;
        ctx.accounts.program.emit_event(&PolicyDeployed {
            policy: policy_addr,
            dwallet: dwallet_addr,
            ts: current_ts,
        }, &ctx.accounts.event_authority, EventAuthority::BUMP)?;
        Ok(())
    }

    /// 1 — Below-threshold signing request. Fails if `tx_amount >= threshold`
    /// (caller must use `request_signature_with_step_up` in that case).
    /// Audit C2 (Opção 4) + C1 fixes.
    #[instruction(discriminator = 1)]
    #[allow(clippy::too_many_arguments)]
    pub fn request_signature(
        ctx: Ctx<RequestSignature>,
        _init_authority_hash: Address,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
        tx_amount: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let policy_addr = *ctx.accounts.policy.address();
        let request_hash = Address::from(message_digest);
        ctx.accounts.program.emit_event(&SignatureRequested {
            policy: policy_addr,
            request_hash,
            ts: current_ts,
        }, &ctx.accounts.event_authority, EventAuthority::BUMP)?;
        ctx.accounts.request_below_threshold(
            message_digest,
            metadata_digest,
            user_pubkey,
            signature_scheme,
            message_approval_bump,
            cpi_authority_bump,
            tx_amount,
        )?;
        ctx.accounts.program.emit_event(&SignatureApproved {
            policy: policy_addr,
            request_hash,
            ts: current_ts,
        }, &ctx.accounts.event_authority, EventAuthority::BUMP)?;
        Ok(())
    }

    /// 2 — owner updates the threshold + bound passkey pubkey. Authorized
    /// via `update_policy_challenge` signed by the owner off-chain.
    /// Audit C2 (Opção 4).
    #[instruction(discriminator = 2)]
    pub fn update_policy(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        threshold_amount: u64,
        passkey_pubkey: [u8; 33],
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts
            .update(threshold_amount, passkey_pubkey, expected_nonce)
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

    /// 5 — Above-threshold signing request with step-up.
    /// Audit C2 (Opção 4) + C1 fixes.
    #[instruction(discriminator = 5)]
    #[allow(clippy::too_many_arguments)]
    pub fn request_signature_with_step_up(
        ctx: Ctx<RequestSignatureStepUp>,
        _init_authority_hash: Address,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
        tx_amount: u64,
        expected_step_up_nonce: u64,
        webauthn_auth_data_len: u8,
        webauthn_auth_data: [u8; WEBAUTHN_AUTH_DATA_MAX],
        webauthn_cdj_len: u16,
        webauthn_cdj: [u8; WEBAUTHN_CLIENT_DATA_JSON_MAX],
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let policy_addr = *ctx.accounts.policy.address();
        let request_hash = Address::from(message_digest);
        ctx.accounts.program.emit_event(&SignatureRequested {
            policy: policy_addr,
            request_hash,
            ts: current_ts,
        }, &ctx.accounts.event_authority, EventAuthority::BUMP)?;
        ctx.accounts.request_with_step_up(
            message_digest,
            metadata_digest,
            user_pubkey,
            signature_scheme,
            message_approval_bump,
            cpi_authority_bump,
            tx_amount,
            expected_step_up_nonce,
            webauthn_auth_data_len,
            &webauthn_auth_data,
            webauthn_cdj_len,
            &webauthn_cdj,
        )?;
        ctx.accounts.program.emit_event(&SignatureApproved {
            policy: policy_addr,
            request_hash,
            ts: current_ts,
        }, &ctx.accounts.event_authority, EventAuthority::BUMP)?;
        Ok(())
    }
}

#[error_code]
pub enum PasskeyError {
    StepUpRequired = 6000,
    StepUpNotAllowed,
    PolicyPaused,
    InvalidNonce,
    AuthFailed,
    InvalidOwnerSlot,
    InvalidPasskeyLen,
    UnsupportedScheme,
    InvalidWebAuthnPayload,
}

impl From<AuthError> for PasskeyError {
    fn from(_e: AuthError) -> Self {
        PasskeyError::AuthFailed
    }
}

// Audit C2 (Opção 4): PDA seed includes init_authority_hash.

#[account(discriminator = 1, set_inner)]
#[seeds(b"passkey", dwallet: Address, init_authority_hash: Address)]
pub struct PasskeyPolicy {
    pub dwallet: Address,
    pub owner_slot: [u8; MEMBER_SLOT_LEN],
    pub init_authority_slot: [u8; MEMBER_SLOT_LEN],
    pub passkey_pubkey: [u8; 33],
    pub _pad: u8,
    pub next_admin_nonce: u64,
    pub next_step_up_nonce: u64,
    pub threshold_amount: u64,
    pub paused: u64,
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

    #[account(init, payer = payer, address = PasskeyPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<PasskeyPolicy>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PasskeyStepUp>,
}

impl InitPolicy {
    #[inline(always)]
    pub fn create(
        &mut self,
        init_authority_slot: [u8; MEMBER_SLOT_LEN],
        init_authority_hash: Address,
        owner_slot: [u8; MEMBER_SLOT_LEN],
        threshold_amount: u64,
        passkey_pubkey: [u8; 33],
    ) -> Result<(), ProgramError> {
        // Audit C2 (Opção 4): hash<->slot consistency.
        let computed = init_authority_hash_from_slot(&init_authority_slot);
        require!(
            computed == init_authority_hash,
            PasskeyError::InvalidOwnerSlot
        );
        validate_slot(&init_authority_slot).map_err(|_| PasskeyError::InvalidOwnerSlot)?;
        require!(
            init_authority_slot[0] != SCHEME_WEBAUTHN,
            PasskeyError::UnsupportedScheme
        );

        validate_slot(&owner_slot).map_err(|_| PasskeyError::InvalidOwnerSlot)?;
        require!(
            owner_slot[0] != SCHEME_WEBAUTHN,
            PasskeyError::UnsupportedScheme
        );
        require!(
            passkey_pubkey[0] == 0x02 || passkey_pubkey[0] == 0x03,
            PasskeyError::InvalidPasskeyLen
        );

        // Audit C2 (Opção 4): verify init precompile signature.
        let dwallet_addr = *self.dwallet_account.address();
        let challenge = challenges::init_policy_challenge(
            &dwallet_addr,
            &init_authority_slot,
            &owner_slot,
            threshold_amount,
            &passkey_pubkey,
        );
        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PasskeyError::AuthFailed)?;
        verify_signature(VerifyInput {
            member_slot: &init_authority_slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &[],
            webauthn_client_data_json: &[],
        })
        .map_err(|_| PasskeyError::AuthFailed)?;
        drop(sysvar_data_ref);

        self.policy.set_inner(PasskeyPolicyInner {
            dwallet: dwallet_addr,
            owner_slot,
            init_authority_slot,
            passkey_pubkey,
            _pad: 0,
            next_admin_nonce: 0,
            next_step_up_nonce: 0,
            threshold_amount,
            paused: 0,
        });
        Ok(())
    }
}

// ── RequestSignature (below-threshold path) ────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct RequestSignature {
    pub dwallet_account: UncheckedAccount,

    #[account(address = PasskeyPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<PasskeyPolicy>,

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
    pub program: Program<PasskeyStepUp>,
}

impl RequestSignature {
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn request_below_threshold(
        &mut self,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
        tx_amount: u64,
    ) -> Result<(), ProgramError> {
        let paused: u64 = self.policy.paused.into();
        require!(paused == 0, PasskeyError::PolicyPaused);

        let threshold: u64 = self.policy.threshold_amount.into();
        require!(tx_amount < threshold, PasskeyError::StepUpRequired);
        let policy_addr = *self.policy.address();
        let dwallet_addr = *self.dwallet_account.address();
        let expected_metadata_digest = challenges::request_metadata_digest(
            &policy_addr,
            &dwallet_addr,
            &message_digest,
            tx_amount,
            &user_pubkey,
            signature_scheme,
            None,
        );
        require!(metadata_digest == expected_metadata_digest, PasskeyError::AuthFailed);
        require!(
            validate_ika_cpi_accounts(
                &self.dwallet_program.to_account_view(),
                &self.dwallet_account.to_account_view(),
            ),
            PasskeyError::AuthFailed
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

// ── RequestSignatureStepUp (above-threshold path) ──────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct RequestSignatureStepUp {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = PasskeyPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<PasskeyPolicy>,

    pub coordinator: UncheckedAccount,

    #[account(mut)]
    pub message_approval: UncheckedAccount,

    #[account(mut)]
    pub payer: Signer,

    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub dwallet_program: UncheckedAccount,
    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<PasskeyStepUp>,
}

impl RequestSignatureStepUp {
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn request_with_step_up(
        &mut self,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
        tx_amount: u64,
        expected_step_up_nonce: u64,
        webauthn_auth_data_len: u8,
        webauthn_auth_data: &[u8; WEBAUTHN_AUTH_DATA_MAX],
        webauthn_cdj_len: u16,
        webauthn_cdj: &[u8; WEBAUTHN_CLIENT_DATA_JSON_MAX],
    ) -> Result<(), ProgramError> {
        let paused: u64 = self.policy.paused.into();
        require!(paused == 0, PasskeyError::PolicyPaused);

        let threshold: u64 = self.policy.threshold_amount.into();
        require!(tx_amount >= threshold, PasskeyError::StepUpNotAllowed);

        let on_chain_nonce: u64 = self.policy.next_step_up_nonce.into();
        require!(
            expected_step_up_nonce == on_chain_nonce,
            PasskeyError::InvalidNonce
        );

        // Carve out slices from the fixed-size payload buffers using the
        // caller-supplied lengths.
        let auth_len = webauthn_auth_data_len as usize;
        let cdj_len = webauthn_cdj_len as usize;
        require!(
            auth_len <= WEBAUTHN_AUTH_DATA_MAX && cdj_len <= WEBAUTHN_CLIENT_DATA_JSON_MAX,
            PasskeyError::InvalidWebAuthnPayload
        );
        let auth_slice = &webauthn_auth_data[..auth_len];
        let cdj_slice = &webauthn_cdj[..cdj_len];

        let dwallet_addr = *self.dwallet_account.address();
        let policy_addr = *self.policy.address();
        let message_approval_addr = *self.message_approval.address();
        let passkey_pubkey = self.policy.passkey_pubkey;
        let expected_metadata_digest = challenges::request_metadata_digest(
            &policy_addr,
            &dwallet_addr,
            &message_digest,
            tx_amount,
            &user_pubkey,
            signature_scheme,
            Some(on_chain_nonce),
        );
        require!(metadata_digest == expected_metadata_digest, PasskeyError::AuthFailed);
        let challenge = challenges::step_up_challenge(
            &dwallet_addr,
            &message_approval_addr,
            &message_digest,
            &metadata_digest,
            &user_pubkey,
            signature_scheme,
            message_approval_bump,
            tx_amount,
            on_chain_nonce,
            &passkey_pubkey,
        );

        // Verify the WebAuthn assertion via Secp256r1 precompile + clientDataJSON parse.
        let member_slot = build_member_slot(SCHEME_WEBAUTHN, passkey_pubkey.as_slice())
            .map_err(|_| PasskeyError::InvalidPasskeyLen)?;

        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| PasskeyError::AuthFailed)?;

        verify_signature(VerifyInput {
            member_slot: &member_slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: auth_slice,
            webauthn_client_data_json: cdj_slice,
        })
        .map_err(map_auth_err)?;
        drop(sysvar_data_ref);

        // Increment nonce *before* the CPI so a replay attempt with the same
        // assertion is blocked even if the CPI itself fails.
        self.policy.next_step_up_nonce = (on_chain_nonce + 1).into();
        require!(
            validate_ika_cpi_accounts(
                &self.dwallet_program.to_account_view(),
                &self.dwallet_account.to_account_view(),
            ),
            PasskeyError::AuthFailed
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

    #[account(mut, address = PasskeyPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<PasskeyPolicy>,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,

    #[account(mut)]
    pub payer: Signer,
    pub event_authority: EventAuthority,
    pub program: Program<PasskeyStepUp>,
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
            .map_err(|_| PasskeyError::AuthFailed)?;

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
        threshold_amount: u64,
        passkey_pubkey: [u8; 33],
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        require!(
            passkey_pubkey[0] == 0x02 || passkey_pubkey[0] == 0x03,
            PasskeyError::InvalidPasskeyLen
        );
        self.run(expected_nonce, |dw, policy, owner, n| {
            challenges::update_policy_challenge(dw, policy, threshold_amount, &passkey_pubkey, n, owner)
        })?;
        self.policy.threshold_amount = threshold_amount.into();
        self.policy.passkey_pubkey = passkey_pubkey;
        Ok(())
    }

    #[inline(always)]
    pub fn pause(&mut self, expected_nonce: u64) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, policy, owner, n| {
            challenges::pause_challenge(dw, policy, n, owner)
        })?;
        self.policy.paused = 1u64.into();
        Ok(())
    }

    #[inline(always)]
    pub fn resume(&mut self, expected_nonce: u64) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, policy, owner, n| {
            challenges::resume_challenge(dw, policy, n, owner)
        })?;
        self.policy.paused = 0u64.into();
        Ok(())
    }
}

#[inline]
fn check_sysvar_addr(addr: &Address) -> Result<(), ProgramError> {
    check_sysvar_address(addr).map_err(|_| PasskeyError::AuthFailed.into())
}

fn map_auth_err(e: AuthError) -> PasskeyError {
    match e {
        AuthError::InvalidNonce => PasskeyError::InvalidNonce,
        AuthError::UnsupportedScheme => PasskeyError::UnsupportedScheme,
        AuthError::InvalidWebAuthnPayload => PasskeyError::InvalidWebAuthnPayload,
        _ => PasskeyError::AuthFailed,
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
