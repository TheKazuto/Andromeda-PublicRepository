//! Andromeda — Oracle-conditional policy template (Andromeda Features Roadmap §1).
//!
//! Approves a signing request only when an oracle price feed satisfies the
//! configured predicate. The on-chain program reads the **Pyth Pull V2**
//! `PriceUpdateV2` account directly (`Full` verification level only) and
//! validates against `min_price ≤ current_price ≤ max_price` plus a freshness
//! check (`current_slot - posted_slot <= max_age_slots`).
//!
//! `min_price` / `max_price` are kept in the **same expo + units** as the
//! feed; the policy doesn't normalize. The owner is responsible for setting
//! bounds that match the feed's exponent at init / update_bounds time.
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

declare_id!("Wi6x2Y4YTYcv4aMz7AQRF2UELE36fZNKhsAoCFq2ssM");

// ── Pyth Pull V2 layout constants ──
//
// Layout (PriceUpdateV2, Anchor-encoded):
//   [0..8]   Anchor discriminator
//   [8..40]  write_authority: Pubkey
//   [40]     verification_level: enum tag (1 = Full, 0 = Partial)
//   [41..73] price_message.feed_id: [u8; 32]
//   [73..81] price_message.price: i64
//   [81..89] price_message.conf: u64
//   [89..93] price_message.exponent: i32
//   [93..101] price_message.publish_time: i64
//   [125..133] posted_slot: u64
//   total length: 134 (we read up to byte 133).
const PYTH_PULL_DISC: [u8; 8] = [34, 241, 35, 99, 157, 126, 244, 205];
const PYTH_VERIFICATION_FULL: u8 = 1;
const PYTH_PRICE_OFFSET: usize = 73;
const PYTH_CONF_OFFSET: usize = 81; // Audit M1.
const PYTH_PUBLISH_TIME_OFFSET: usize = 93;
const PYTH_POSTED_SLOT_OFFSET: usize = 125;
const PYTH_PULL_FULL_LEN: usize = 133;
const PYTH_VERIFICATION_OFFSET: usize = 40;

/// Audit H1 fix: program owner of every accepted oracle_feed account must be
/// the Pyth Pull V2 program. Same Program ID across mainnet and devnet —
/// confirm before mainnet deploy.
///
/// Stored as raw bytes (not `address!(...)`) because the base58 decoder used
/// by `Address::from_str_const` overflows the SBF const-eval budget for some
/// pubkeys ("Largest term greater than 2^32"). The 32 bytes below decode to
/// `pythWSnswVUd12oZpeFP8e9CVaEqJg25g1Vtc2biRJqh` (Pyth Pull V2 program).
const PYTH_PULL_V2_PROGRAM_ID: Address = Address::new_from_array([
    0xc8, 0xe8, 0x44, 0x34, 0x4d, 0xf2, 0x01, 0x10, 0x3d, 0xa9, 0x62, 0x66, 0xc0, 0x48, 0x7f, 0x3f,
    0xbe, 0xa8, 0x21, 0x33, 0xbc, 0x05, 0x06, 0x99, 0x70, 0x2d, 0xba, 0xdf, 0x4c, 0x0f, 0x4d, 0xbc,
]);

#[program]
mod oracle_conditional {
    use super::*;

    /// 0 — bootstrap.
    ///
    /// Audit C2 fix (Opção 4): `init_authority_slot` is a wallet credential
    /// signing the canonical init challenge.
    /// Audit C1 fix: `current_ts` from `Clock` sysvar.
    /// Audit M1 hardening: `max_confidence_bps` enforces a max relative
    /// uncertainty on the Pyth price update (`conf / |price| <= bps/10000`).
    /// `0` disables the check (back-compat for callers that don't care).
    #[instruction(discriminator = 0)]
    #[allow(clippy::too_many_arguments)]
    pub fn init_policy(
        ctx: Ctx<InitPolicy>,
        init_authority_slot: [u8; MEMBER_SLOT_LEN],
        init_authority_hash: Address,
        owner_slot: [u8; MEMBER_SLOT_LEN],
        oracle_feed: Address,
        min_price: i64,
        max_price: i64,
        max_age_slots: u64,
        max_confidence_bps: u16,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let policy_addr = *ctx.accounts.policy.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        ctx.accounts.create(
            init_authority_slot,
            init_authority_hash,
            owner_slot,
            oracle_feed,
            min_price,
            max_price,
            max_age_slots,
            max_confidence_bps,
        )?;
        ctx.accounts.program.emit_event(&PolicyDeployed {
            policy: policy_addr,
            dwallet: dwallet_addr,
            ts: current_ts,
        }, &ctx.accounts.event_authority, EventAuthority::BUMP)?;
        Ok(())
    }

    /// Audit C2 (Opção 4) + C1 fixes.
    /// `current_slot` from `Clock` — fixes the freshness bypass where an
    /// attacker could pass any slot to make stale prices look fresh.
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

    /// 2 — owner updates the bounds + max age + max confidence bps.
    /// `oracle_feed` is immutable after init (rebind requires a fresh policy).
    /// Audit C2 (Opção 4) + M1.
    #[instruction(discriminator = 2)]
    #[allow(clippy::too_many_arguments)]
    pub fn update_bounds(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        min_price: i64,
        max_price: i64,
        max_age_slots: u64,
        max_confidence_bps: u16,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts.update(
            min_price,
            max_price,
            max_age_slots,
            max_confidence_bps,
            expected_nonce,
        )
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
pub enum OracleError {
    PriceOutOfBounds = 6000,
    PriceTooStale,
    OracleFeedMismatch,
    InvalidBounds,
    PolicyPaused,
    InvalidNonce,
    AuthFailed,
    InvalidOwnerSlot,
    UnsupportedScheme,
    OracleAccountInvalid,        // discriminator / size / verification_level mismatch
    OracleVerificationPartial,   // Pull V2 partial-verified update — rejected
    PriceTooUncertain,           // Audit M1: conf/|price| > max_confidence_bps/10000
}

impl From<AuthError> for OracleError {
    fn from(_e: AuthError) -> Self {
        OracleError::AuthFailed
    }
}

// Audit C2 (Opção 4): PDA seed includes init_authority_hash.

#[account(discriminator = 1, set_inner)]
#[seeds(b"oracle", dwallet: Address, init_authority_hash: Address)]
pub struct OraclePolicy {
    pub dwallet: Address,
    pub owner_slot: [u8; MEMBER_SLOT_LEN],
    pub init_authority_slot: [u8; MEMBER_SLOT_LEN],
    pub next_admin_nonce: u64,
    pub oracle_feed: Address,
    pub min_price: i64,
    pub max_price: i64,
    pub max_age_slots: u64,
    /// Audit M1: max relative uncertainty in basis points
    /// (`conf / |price| <= bps / 10_000`). `0` disables the check.
    pub max_confidence_bps: u16,
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

    #[account(init, payer = payer, address = OraclePolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<OraclePolicy>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<OracleConditional>,
}

impl InitPolicy {
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &mut self,
        init_authority_slot: [u8; MEMBER_SLOT_LEN],
        init_authority_hash: Address,
        owner_slot: [u8; MEMBER_SLOT_LEN],
        oracle_feed: Address,
        min_price: i64,
        max_price: i64,
        max_age_slots: u64,
        max_confidence_bps: u16,
    ) -> Result<(), ProgramError> {
        // Audit C2 (Opção 4): hash<->slot consistency.
        let computed = init_authority_hash_from_slot(&init_authority_slot);
        require!(
            computed == init_authority_hash,
            OracleError::InvalidOwnerSlot
        );
        validate_slot(&init_authority_slot).map_err(|_| OracleError::InvalidOwnerSlot)?;
        require!(
            init_authority_slot[0] != SCHEME_WEBAUTHN,
            OracleError::UnsupportedScheme
        );

        validate_slot(&owner_slot).map_err(|_| OracleError::InvalidOwnerSlot)?;
        require!(
            owner_slot[0] != SCHEME_WEBAUTHN,
            OracleError::UnsupportedScheme
        );
        require!(min_price <= max_price, OracleError::InvalidBounds);

        // Audit C2 (Opção 4): verify init precompile signature.
        let dwallet_addr = *self.dwallet_account.address();
        let challenge = challenges::init_policy_challenge(
            &dwallet_addr,
            &init_authority_slot,
            &owner_slot,
            &oracle_feed,
            min_price,
            max_price,
            max_age_slots,
            max_confidence_bps,
        );
        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| OracleError::AuthFailed)?;
        verify_signature(VerifyInput {
            member_slot: &init_authority_slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &[],
            webauthn_client_data_json: &[],
        })
        .map_err(|_| OracleError::AuthFailed)?;
        drop(sysvar_data_ref);

        self.policy.set_inner(OraclePolicyInner {
            dwallet: dwallet_addr,
            owner_slot,
            init_authority_slot,
            next_admin_nonce: 0,
            oracle_feed,
            min_price,
            max_price,
            max_age_slots,
            max_confidence_bps,
            paused: 0,
        });
        Ok(())
    }
}

// ── RequestSignature ───────────────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct RequestSignature {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = OraclePolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<OraclePolicy>,

    /// Pyth Pull V2 `PriceUpdateV2` account. Must be the same pubkey
    /// registered at init; the program parses price + posted_slot directly
    /// from this account's data and rejects partial-verified updates.
    /// Audit H1: program owner is verified to be the Pyth Pull V2 program.
    pub oracle_feed: UncheckedAccount,

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
    pub program: Program<OracleConditional>,
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
        let paused: u64 = self.policy.paused.into();
        require!(paused == 0, OracleError::PolicyPaused);

        let bound_match = self.oracle_feed.address() == &self.policy.oracle_feed;
        require!(bound_match, OracleError::OracleFeedMismatch);

        // Audit H1: validate the oracle account is actually owned by Pyth.
        // Without this check, an attacker could create an arbitrary account
        // with the Pyth Pull V2 discriminator and arbitrary price/posted_slot
        // bytes, then pass it as oracle_feed.
        let oracle_view = self.oracle_feed.to_account_view();
        require!(
            oracle_view.owner() == &PYTH_PULL_V2_PROGRAM_ID,
            OracleError::OracleAccountInvalid
        );
        let data = oracle_view.try_borrow()?;
        let (current_price, conf, posted_slot) = parse_pyth_pull_v2(&data)?;
        drop(data);

        // Audit M2: explicit non-negative price check. Pyth Pull V2 should
        // never publish a negative price, but the field is i64 — defending
        // against feed bugs / future format changes.
        require!(current_price > 0, OracleError::PriceOutOfBounds);

        let min: i64 = self.policy.min_price.into();
        let max: i64 = self.policy.max_price.into();
        require!(current_price >= min, OracleError::PriceOutOfBounds);
        require!(current_price <= max, OracleError::PriceOutOfBounds);

        let max_age: u64 = self.policy.max_age_slots.into();
        require!(current_slot >= posted_slot, OracleError::PriceTooStale);
        let age = current_slot.saturating_sub(posted_slot);
        require!(age <= max_age, OracleError::PriceTooStale);

        // Audit M1: confidence interval check. Reject prices whose Pyth
        // confidence band is wider than the configured threshold relative to
        // the absolute price. Skipped when `max_confidence_bps == 0`.
        let bps: u16 = self.policy.max_confidence_bps.into();
        if bps > 0 {
            // current_price > 0 was just enforced above; abs is safe.
            let price_u128 = current_price as u128;
            let conf_u128 = conf as u128;
            let bps_u128 = bps as u128;
            // Want: conf / price <= bps / 10_000
            //   ↔   conf * 10_000 <= price * bps
            // u128 fits since price/conf are u64-bounded, bps ≤ 65535.
            require!(
                conf_u128.saturating_mul(10_000u128)
                    <= price_u128.saturating_mul(bps_u128),
                OracleError::PriceTooUncertain
            );
        }
        let policy_addr = *self.policy.address();
        let dwallet_addr = *self.dwallet_account.address();
        let oracle_feed_addr = *self.oracle_feed.address();
        let expected_metadata_digest = challenges::request_metadata_digest(
            &policy_addr,
            &dwallet_addr,
            &message_digest,
            &oracle_feed_addr,
            current_price,
            posted_slot,
            &user_pubkey,
            signature_scheme,
        );
        require!(metadata_digest == expected_metadata_digest, OracleError::AuthFailed);
        require!(
            validate_ika_cpi_accounts(
                &self.dwallet_program.to_account_view(),
                &self.dwallet_account.to_account_view(),
            ),
            OracleError::AuthFailed
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

    #[account(mut, address = OraclePolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<OraclePolicy>,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,

    #[account(mut)]
    pub payer: Signer,
    pub event_authority: EventAuthority,
    pub program: Program<OracleConditional>,
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
            .map_err(|_| OracleError::AuthFailed)?;

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
    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &mut self,
        min_price: i64,
        max_price: i64,
        max_age_slots: u64,
        max_confidence_bps: u16,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        require!(min_price <= max_price, OracleError::InvalidBounds);
        self.run(expected_nonce, |dw, policy, owner, n| {
            challenges::update_bounds_challenge(
                dw,
                policy,
                min_price,
                max_price,
                max_age_slots,
                max_confidence_bps,
                n,
                owner,
            )
        })?;
        self.policy.min_price = min_price.into();
        self.policy.max_price = max_price.into();
        self.policy.max_age_slots = max_age_slots.into();
        self.policy.max_confidence_bps = max_confidence_bps.into();
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
    check_sysvar_address(addr).map_err(|_| OracleError::AuthFailed.into())
}

fn map_auth_err(e: AuthError) -> OracleError {
    match e {
        AuthError::InvalidNonce => OracleError::InvalidNonce,
        AuthError::UnsupportedScheme => OracleError::UnsupportedScheme,
        _ => OracleError::AuthFailed,
    }
}

/// Parses the relevant fields out of a Pyth Pull V2 `PriceUpdateV2` account.
/// Returns `(price, conf, posted_slot)`. Audit M1: confidence is parsed and
/// returned for relative-uncertainty enforcement at the call site.
#[inline(always)]
fn parse_pyth_pull_v2(data: &[u8]) -> Result<(i64, u64, u64), ProgramError> {
    require!(data.len() >= PYTH_PULL_FULL_LEN, OracleError::OracleAccountInvalid);
    require!(data[0..8] == PYTH_PULL_DISC, OracleError::OracleAccountInvalid);
    let v = data[PYTH_VERIFICATION_OFFSET];
    if v != PYTH_VERIFICATION_FULL {
        return Err(OracleError::OracleVerificationPartial.into());
    }
    let mut price_bytes = [0u8; 8];
    price_bytes.copy_from_slice(&data[PYTH_PRICE_OFFSET..PYTH_PRICE_OFFSET + 8]);
    let price = i64::from_le_bytes(price_bytes);

    let mut conf_bytes = [0u8; 8];
    conf_bytes.copy_from_slice(&data[PYTH_CONF_OFFSET..PYTH_CONF_OFFSET + 8]);
    let conf = u64::from_le_bytes(conf_bytes);

    let mut slot_bytes = [0u8; 8];
    slot_bytes.copy_from_slice(&data[PYTH_POSTED_SLOT_OFFSET..PYTH_POSTED_SLOT_OFFSET + 8]);
    let posted_slot = u64::from_le_bytes(slot_bytes);

    Ok((price, conf, posted_slot))
}
