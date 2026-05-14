//! Andromeda — FHE-gated policy template.
//!
//! Approves a signing request only when an `EncryptedDecision` signed by the
//! configured `fhe_authority` is supplied as evidence and **verified
//! cryptographically on-chain** via the Solana Ed25519 precompile.
//!
//! The decision signature comes from the Vault Transit `andromeda-fhe` key
//! after the encrypt-backend runs the FHE evaluation. The private key
//! material lives only inside Vault — the gateway and encrypt-backend never
//! handle it.
//!
//! ## v2 (2026-05-07): full on-chain verification
//!
//! Two gaps from v1 are closed:
//!
//! 1. **Owner admin is wallet-agnostic** — `rotate_authority`, `pause`,
//!    `resume` use the standard Andromeda owner challenge pattern from
//!    `andromeda_auth::admin::verify_owner_admin` so the owner signs
//!    off-chain with any wallet.
//!
//! 2. **Decision signature validated on-chain** — the transaction must
//!    carry an Ed25519 precompile invocation whose
//!    `(public_key, message)` matches `(fhe_authority,
//!    decision_canonical_bytes(policy, message_digest, slot, authorize))`.
//!    The Solana runtime verifies the signature cryptographically before
//!    this instruction runs; we read the precompile back from the
//!    Instructions sysvar. A compromised gateway can no longer forge a
//!    decision.

#![no_std]
#![allow(dead_code)]

pub mod challenges;

use andromeda_auth::admin::verify_owner_admin;
use andromeda_auth::hash::hashv;
use andromeda_auth::human_message::HumanMessageError;
use andromeda_auth::precompile::{check_sysvar_address, verify_ed25519};
use andromeda_auth::{
    validate_slot, verify_signature, AuthError, VerifyInput, MEMBER_SLOT_LEN, SCHEME_WEBAUTHN,
};
use andromeda_policy_shared::validate_ika_cpi_accounts;
use ika_dwallet_quasar::DWalletContext;
use quasar_lang::prelude::*;
use solana_address::Address;

declare_id!("6NhfKThEydSHH6R7gBm94reo3simopRJmb4nDzkKU7np");

/// Audit M4 fix: hardcoded allowlist of Ed25519 pubkeys allowed to act as
/// `fhe_authority`. Only keys auditadas pela Shinka Labs entram aqui — owner
/// não pode setar uma chave arbitrária via init/rotate.
///
/// Production key: `andromeda-fhe` ed25519 from HashiCorp Vault Transit
/// (consumed by encrypt-backend at /v1/encrypt/decision/sign).
/// Base64: `oQzp8fHhCD2TY9Ygn3qRI4RDne3iZlkrLTW7pMkcn+w=`
const ALLOWED_FHE_AUTHORITIES: &[Address] = &[
    // andromeda-fhe (Vault Transit ed25519)
    Address::new_from_array([
        0xa1, 0x0c, 0xe9, 0xf1, 0xf1, 0xe1, 0x08, 0x3d, 0x93, 0x63, 0xd6, 0x20, 0x9f, 0x7a, 0x91,
        0x23, 0x84, 0x43, 0x9d, 0xed, 0xe2, 0x66, 0x59, 0x2b, 0x2d, 0x35, 0xbb, 0xa4, 0xc9, 0x1c,
        0x9f, 0xec,
    ]),
];

/// Audit M4 helper: enforces the allowlist.
#[inline]
fn is_allowed_fhe_authority(addr: &Address) -> bool {
    let target = addr.as_array();
    let mut i = 0usize;
    while i < ALLOWED_FHE_AUTHORITIES.len() {
        if ALLOWED_FHE_AUTHORITIES[i].as_array() == target {
            return true;
        }
        i += 1;
    }
    false
}

#[program]
mod fhe_gated {
    use super::*;

    /// 0 — bootstrap.
    ///
    /// Audit C2 fix (Opção 4): `init_authority_slot` is a wallet credential
    /// signing the canonical init challenge.
    /// Audit C1 fix: `current_ts` from `Clock` sysvar.
    /// Audit M3 fix: `decision_max_age_slots` must be > 0.
    /// Audit M4 fix: `fhe_authority` must be in `ALLOWED_FHE_AUTHORITIES`.
    #[instruction(discriminator = 0)]
    pub fn init_policy(
        ctx: Ctx<InitPolicy>,
        init_authority_slot: [u8; MEMBER_SLOT_LEN],
        init_authority_hash: Address,
        owner_slot: [u8; MEMBER_SLOT_LEN],
        fhe_authority: Address,
        decision_max_age_slots: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let policy_addr = *ctx.accounts.policy.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        ctx.accounts.create(
            init_authority_slot,
            init_authority_hash,
            owner_slot,
            fhe_authority,
            decision_max_age_slots,
        )?;
        ctx.accounts.program.emit_event(
            &PolicyDeployed {
                policy: policy_addr,
                dwallet: dwallet_addr,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// 1 — request a signature gated by an FHE decision.
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
        decision_created_slot: u64,
        decision_authorize: u8,
    ) -> Result<(), ProgramError> {
        let current_slot: u64 = ctx.accounts.clock.slot.into();
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let policy_addr = *ctx.accounts.policy.address();
        let request_hash = Address::from(message_digest);
        ctx.accounts.program.emit_event(
            &SignatureRequested {
                policy: policy_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        ctx.accounts.request(
            message_digest,
            metadata_digest,
            user_pubkey,
            signature_scheme,
            message_approval_bump,
            cpi_authority_bump,
            decision_created_slot,
            decision_authorize,
            current_slot,
        )?;
        ctx.accounts.program.emit_event(
            &SignatureApproved {
                policy: policy_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// 2 — owner rotates the bound `fhe_authority` (challenge-based).
    /// Audit C2 (Opção 4) + M4 fixes.
    #[instruction(discriminator = 2)]
    pub fn rotate_authority(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        new_fhe_authority: Address,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts.rotate(new_fhe_authority, expected_nonce)
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
        ctx.accounts.program.emit_event(
            &PolicyPaused {
                policy: policy_addr,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
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
        ctx.accounts.program.emit_event(
            &PolicyResumed {
                policy: policy_addr,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
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
pub enum FHEError {
    DecisionRejected = 6000,
    DecisionStale,
    DecisionInvalidSignature,
    PolicyPaused,
    InvalidNonce,
    AuthFailed,
    InvalidOwnerSlot,
    UnsupportedScheme,
    InvalidFHEAuthority, // Audit M4: fhe_authority not in ALLOWED_FHE_AUTHORITIES
    InvalidMaxAge,       // Audit M3: decision_max_age_slots must be > 0
    ClearSigningRenderFailed,
}

impl From<AuthError> for FHEError {
    fn from(_e: AuthError) -> Self {
        FHEError::AuthFailed
    }
}

impl From<HumanMessageError> for FHEError {
    fn from(_e: HumanMessageError) -> Self {
        FHEError::ClearSigningRenderFailed
    }
}

// Audit C2 (Opção 4): PDA seed includes init_authority_hash.

#[account(discriminator = 1, set_inner)]
#[seeds(b"fhe_gated", dwallet: Address, init_authority_hash: Address)]
pub struct FHEGatedPolicy {
    pub dwallet: Address,
    pub owner_slot: [u8; MEMBER_SLOT_LEN],
    pub init_authority_slot: [u8; MEMBER_SLOT_LEN],
    pub fhe_authority: Address,
    pub next_admin_nonce: u64,
    pub decision_max_age_slots: u64,
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

    #[account(init, payer = payer, address = FHEGatedPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<FHEGatedPolicy>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<FheGated>,
}

impl InitPolicy {
    #[inline(always)]
    pub fn create(
        &mut self,
        init_authority_slot: [u8; MEMBER_SLOT_LEN],
        init_authority_hash: Address,
        owner_slot: [u8; MEMBER_SLOT_LEN],
        fhe_authority: Address,
        decision_max_age_slots: u64,
    ) -> Result<(), ProgramError> {
        // Audit C2 (Opção 4): hash<->slot consistency.
        let computed = init_authority_hash_from_slot(&init_authority_slot);
        require!(computed == init_authority_hash, FHEError::InvalidOwnerSlot);
        validate_slot(&init_authority_slot).map_err(|_| FHEError::InvalidOwnerSlot)?;
        require!(
            init_authority_slot[0] != SCHEME_WEBAUTHN,
            FHEError::UnsupportedScheme
        );

        validate_slot(&owner_slot).map_err(|_| FHEError::InvalidOwnerSlot)?;
        require!(
            owner_slot[0] != SCHEME_WEBAUTHN,
            FHEError::UnsupportedScheme
        );

        // Audit M3: reject zero max_age (would make all decisions
        // immediately stale → DoS).
        require!(decision_max_age_slots > 0, FHEError::InvalidMaxAge);

        // Audit M4: enforce hardcoded allowlist of fhe_authority pubkeys.
        require!(
            is_allowed_fhe_authority(&fhe_authority),
            FHEError::InvalidFHEAuthority
        );

        // Audit C2 (Opção 4): verify init precompile signature.
        let dwallet_addr = *self.dwallet_account.address();
        let challenge = challenges::init_policy_challenge(
            &dwallet_addr,
            &init_authority_slot,
            &owner_slot,
            &fhe_authority,
            decision_max_age_slots,
        );
        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view.try_borrow().map_err(|_| FHEError::AuthFailed)?;
        verify_signature(VerifyInput {
            member_slot: &init_authority_slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &[],
            webauthn_client_data_json: &[],
        })
        .map_err(|_| FHEError::AuthFailed)?;
        drop(sysvar_data_ref);

        self.policy.set_inner(FHEGatedPolicyInner {
            dwallet: dwallet_addr,
            owner_slot,
            init_authority_slot,
            fhe_authority,
            next_admin_nonce: 0,
            decision_max_age_slots,
            paused: 0,
        });
        Ok(())
    }
}

// ── RequestSignature (decision verified via Ed25519 precompile) ──

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct RequestSignature {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = FHEGatedPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<FHEGatedPolicy>,

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
    pub program: Program<FheGated>,
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
        decision_created_slot: u64,
        decision_authorize: u8,
        current_slot: u64,
    ) -> Result<(), ProgramError> {
        let paused: u64 = self.policy.paused.into();
        require!(paused == 0, FHEError::PolicyPaused);

        // Constraint 1: FHE evaluator authorised the action.
        require!(decision_authorize == 1, FHEError::DecisionRejected);

        // Constraint 2: decision freshness.
        let max_age: u64 = self.policy.decision_max_age_slots.into();
        require!(
            current_slot >= decision_created_slot,
            FHEError::DecisionStale
        );
        let age = current_slot.saturating_sub(decision_created_slot);
        require!(age <= max_age, FHEError::DecisionStale);

        // Constraint 3: Ed25519 precompile must validate the decision signature
        // against `fhe_authority` over `decision_canonical_bytes(...)`.
        let policy_addr = *self.policy.address();
        let canonical = challenges::decision_canonical_bytes(
            &policy_addr,
            &message_digest,
            decision_created_slot,
            decision_authorize,
        );
        let fhe_authority_bytes: [u8; 32] = *self.policy.fhe_authority.as_array();

        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view.try_borrow().map_err(|_| FHEError::AuthFailed)?;
        verify_ed25519(&fhe_authority_bytes, &canonical, &sysvar_data_ref)
            .map_err(|_| FHEError::DecisionInvalidSignature)?;
        drop(sysvar_data_ref);
        let dwallet_addr = *self.dwallet_account.address();
        let expected_metadata_digest = challenges::request_metadata_digest(
            &policy_addr,
            &dwallet_addr,
            &message_digest,
            decision_created_slot,
            decision_authorize,
            &user_pubkey,
            signature_scheme,
        );
        require!(
            metadata_digest == expected_metadata_digest,
            FHEError::AuthFailed
        );
        require!(
            validate_ika_cpi_accounts(
                &self.dwallet_program.to_account_view(),
                &self.dwallet_account.to_account_view(),
            ),
            FHEError::AuthFailed
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

    #[account(mut, address = FHEGatedPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<FHEGatedPolicy>,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,

    #[account(mut)]
    pub payer: Signer,
    pub event_authority: EventAuthority,
    pub program: Program<FheGated>,
}

impl AdminAction {
    fn run<F>(&mut self, expected_nonce: u64, build_challenge: F) -> Result<(), ProgramError>
    where
        F: FnOnce(
            &Address,
            &Address,
            &[u8; MEMBER_SLOT_LEN],
            u64,
        ) -> Result<[u8; 32], HumanMessageError>,
    {
        let dwallet_addr = *self.dwallet_account.address();
        let policy_addr = *self.policy.address();
        let owner_slot = self.policy.owner_slot;
        let on_chain_nonce: u64 = self.policy.next_admin_nonce.into();
        let challenge = build_challenge(&dwallet_addr, &policy_addr, &owner_slot, on_chain_nonce)
            .map_err(FHEError::from)?;

        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view.try_borrow().map_err(|_| FHEError::AuthFailed)?;

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
    pub fn rotate(
        &mut self,
        new_fhe_authority: Address,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        // Audit M4: enforce allowlist on rotate too.
        require!(
            is_allowed_fhe_authority(&new_fhe_authority),
            FHEError::InvalidFHEAuthority
        );
        self.run(expected_nonce, |dw, policy, owner, n| {
            challenges::rotate_authority_challenge(dw, policy, &new_fhe_authority, n, owner)
        })?;
        self.policy.fhe_authority = new_fhe_authority;
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
    check_sysvar_address(addr).map_err(|_| FHEError::AuthFailed.into())
}

fn map_auth_err(e: AuthError) -> FHEError {
    match e {
        AuthError::InvalidNonce => FHEError::InvalidNonce,
        AuthError::UnsupportedScheme => FHEError::UnsupportedScheme,
        _ => FHEError::AuthFailed,
    }
}
