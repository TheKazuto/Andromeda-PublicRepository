//! Andromeda RulesPolicy v2 — chain-agnostic, custody-free programmable
//! recovery for Ika dWallets on Solana.
//!
//! ## Trust model
//!
//! Every credential — primary OR quorum member — is verified end-to-end on
//! chain via a Solana precompile invocation in the same transaction. There
//! is no off-chain attestor: a compromised Andromeda backend cannot forge
//! any signature, because every signature byte is checked cryptographically
//! by the runtime (`Ed25519SigVerify…`, `KeccakSecp256k1…`,
//! `Secp256r1SigVerify…`).
//!
//! ## Wallet-agnostic UX
//!
//! No instruction in this program requires the user's wallet to be a Solana
//! signer of the transaction. The user signs an off-chain challenge with
//! whatever wallet they have (EVM / Sui / Bitcoin / Cosmos / NEAR / Aptos /
//! Solana / Substrate ed25519 or ecdsa / passkey). The Andromeda gateway
//! then submits and pays gas as the transaction `payer`.
//!
//! Member schemes supported on-chain v1:
//!  - SCHEME_ED25519     (32-byte pubkey)
//!  - SCHEME_SECP256K1   (20-byte eth_address)
//!  - SCHEME_SECP256R1   (33-byte compressed pubkey, raw passkey use)
//!  - SCHEME_WEBAUTHN    (33-byte compressed pubkey, WebAuthn assertion)
//!
//! Primary slot accepts schemes 0/1/2 (not WebAuthn — primary is a long-lived
//! credential, raw passkey use is the right substitute).
//!
//! ## Quorum staging
//!
//! Quorum recovery uses a per-session PDA so the transaction-size limit
//! (1232 bytes) never bounds the quorum size. The flow is:
//!
//! ```text
//! tx 1 (open):       quorum_session_open    — primary authorizes a session
//!                                              by signing a challenge.
//! tx N (contribute): quorum_session_contribute / _webauthn — one tx per
//!                                              member; precompile validates.
//! tx F (finalize):   quorum_session_finalize — anyone may call once
//!                                              `contributions_count >= threshold`;
//!                                              CPI to Ika `approve_message`.
//! tx C (close):      quorum_session_close   — refund rent after finalize/expiry.
//! ```

#![no_std]
#![allow(dead_code)]

use andromeda_auth as auth;
use andromeda_auth::{
    challenge::{
        admin_add_destination_challenge, admin_add_member_challenge,
        admin_propose_cooldown_challenge, admin_propose_daily_limit_challenge,
        admin_propose_quorum_threshold_challenge, admin_remove_destination_challenge,
        admin_remove_member_challenge, admin_revoke_challenge,
        admin_set_cooldown_immediate_challenge, admin_set_daily_limit_immediate_challenge,
        admin_set_primary_challenge, admin_set_quorum_threshold_immediate_challenge,
        primary_recover_challenge, quorum_contribute_challenge, quorum_session_open_challenge,
        rules_policy_init_challenge,
    },
    hash::hashv,
    validate_slot, verify_signature, VerifyInput, MEMBER_SLOT_LEN, SCHEME_ED25519,
    SCHEME_SECP256K1, SCHEME_SECP256R1, SCHEME_WEBAUTHN, WEBAUTHN_AUTH_DATA_MAX,
    WEBAUTHN_CLIENT_DATA_JSON_MAX,
};
use ika_dwallet_quasar::DWalletContext;
use quasar_lang::prelude::*;
use solana_address::Address;

declare_id!("6TX7qG47Fsocuwmgsgo2q3NLCHrbomoQxQLifapU8Thr");

const MAX_MEMBERS: usize = 16;
const MAX_DESTINATIONS: usize = 16;
const MEMBERS_BYTES: usize = MAX_MEMBERS * MEMBER_SLOT_LEN; // 544
const DESTINATIONS_BYTES: usize = MAX_DESTINATIONS * 32; // 512
const MIN_COOLDOWN_SECONDS: u64 = 3600;
const MAX_SESSION_TTL_SECONDS: i64 = 7 * 24 * 3600;

const PENDING_KIND_NONE: u8 = 0;
const PENDING_KIND_QUORUM: u8 = 1;
const PENDING_KIND_DAILY_LIMIT: u8 = 2;
const PENDING_KIND_COOLDOWN: u8 = 3;

#[program]
mod rules_policy_program {
    use super::*;

    /// 0 — bootstrap a new policy.
    ///
    /// Audit C2 fix (Opção 4): `init_authority_slot` is a wallet credential
    /// (Ed25519 / Secp256k1 / Secp256r1) that signs a canonical init
    /// challenge. The PDA is `[b"rules_policy", dwallet, sha256(slot)]`, so
    /// each (dwallet, init_authority) pair produces a distinct PDA — squat
    /// by an attacker on one PDA does not block the legitimate user on
    /// another. `init_authority_hash` is supplied by the caller and verified
    /// to equal `sha256(init_authority_slot)`; it lives in the seed so the
    /// PDA derivation is deterministic given the slot.
    ///
    /// Audit C1 fix: `current_ts` from `Clock` sysvar.
    #[instruction(discriminator = 0)]
    pub fn init_policy(
        ctx: Ctx<InitPolicy>,
        init_authority_slot: [u8; MEMBER_SLOT_LEN],
        init_authority_hash: Address,
        primary_slot: [u8; MEMBER_SLOT_LEN],
        quorum_threshold: u8,
        daily_limit_some: u8,
        daily_limit: u64,
        cooldown_seconds: u64,
        allowed_destinations_some: u8,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let policy_addr = *ctx.accounts.policy.address();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        ctx.accounts.create(
            init_authority_slot,
            init_authority_hash,
            primary_slot,
            quorum_threshold,
            daily_limit_some,
            daily_limit,
            cooldown_seconds,
            allowed_destinations_some,
            current_ts,
        )?;
        emit!(PolicyDeployed {
            policy: policy_addr,
            dwallet: dwallet_addr,
            ts: current_ts,
        });
        Ok(())
    }

    /// 1 — primary bypass via off-chain challenge signature, single-tx.
    ///
    /// Audit C2 fix (Opção 4): `init_authority_hash` is required to derive
    /// the PDA seed. Caller looks it up in the dashboard / db.
    /// Audit C1 fix: `current_ts` from `Clock` sysvar.
    #[instruction(discriminator = 1)]
    pub fn recover_as_primary(
        ctx: Ctx<RecoverAsPrimary>,
        _init_authority_hash: Address,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let policy_addr = *ctx.accounts.policy.address();
        let request_hash = Address::from(message_digest);
        emit!(SignatureRequested {
            policy: policy_addr,
            request_hash,
            ts: current_ts,
        });
        ctx.accounts.recover(
            message_digest,
            metadata_digest,
            user_pubkey,
            signature_scheme,
            message_approval_bump,
            cpi_authority_bump,
            expected_nonce,
        )?;
        emit!(SignatureApproved {
            policy: policy_addr,
            request_hash,
            ts: current_ts,
        });
        Ok(())
    }

    /// 2 — primary opens a quorum session bound to a specific
    /// (message, amount, destination, expiry). Snapshots the current member
    /// roster + threshold into the session PDA so concurrent admin changes
    /// do not affect this recovery in flight.
    ///
    /// Audit C2 (Opção 4) + C1 fixes.
    #[instruction(discriminator = 2)]
    pub fn quorum_session_open(
        ctx: Ctx<QuorumSessionOpen>,
        _init_authority_hash: Address,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        amount: u64,
        destination: [u8; 32],
        expires_at: i64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts.open(
            message_digest,
            metadata_digest,
            user_pubkey,
            signature_scheme,
            message_approval_bump,
            amount,
            destination,
            expires_at,
            current_ts,
        )
    }

    /// 3 — non-WebAuthn member contribution. One member per tx, signature
    /// validated via Ed25519 / Secp256k1 / Secp256r1 precompile in same tx.
    ///
    /// Audit C2 (Opção 4) + C1 fixes.
    #[instruction(discriminator = 3)]
    pub fn quorum_session_contribute(
        ctx: Ctx<QuorumSessionContribute>,
        _init_authority_hash: Address,
        member_index: u8,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts.contribute(member_index, current_ts, &[], &[])
    }

    /// 4 — WebAuthn member contribution. Carries authenticatorData + clientDataJSON
    /// inline so the program can validate that the canonical contribute
    /// challenge appears base64url-no-pad inside the assertion's
    /// `clientDataJSON.challenge` field, then matches the Secp256r1 precompile
    /// signature over `(authenticatorData || sha256(clientDataJSON))`.
    ///
    /// Audit C2 (Opção 4) + C1 fixes.
    #[instruction(discriminator = 4)]
    pub fn quorum_session_contribute_webauthn(
        ctx: Ctx<QuorumSessionContribute>,
        _init_authority_hash: Address,
        member_index: u8,
        webauthn_auth_data_len: u8,
        webauthn_auth_data: [u8; WEBAUTHN_AUTH_DATA_MAX],
        webauthn_cdj_len: u16,
        webauthn_cdj: [u8; WEBAUTHN_CLIENT_DATA_JSON_MAX],
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let auth_len = webauthn_auth_data_len as usize;
        let cdj_len = webauthn_cdj_len as usize;
        require!(
            auth_len <= WEBAUTHN_AUTH_DATA_MAX && cdj_len <= WEBAUTHN_CLIENT_DATA_JSON_MAX,
            RulesPolicyError::AuthFailed
        );
        let auth_slice = &webauthn_auth_data[..auth_len];
        let cdj_slice = &webauthn_cdj[..cdj_len];
        ctx.accounts
            .contribute(member_index, current_ts, auth_slice, cdj_slice)
    }

    /// 5 — anyone may call once `contributions_count >= threshold_snapshot`.
    /// Performs daily-limit / destination-whitelist enforcement and CPIs to
    /// Ika `approve_message`.
    ///
    /// Audit C2 (Opção 4) + C1 fixes.
    #[instruction(discriminator = 5)]
    pub fn quorum_session_finalize(
        ctx: Ctx<QuorumSessionFinalize>,
        _init_authority_hash: Address,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let policy_addr = *ctx.accounts.policy.address();
        let request_hash = Address::from(ctx.accounts.session.message_digest);
        emit!(SignatureRequested {
            policy: policy_addr,
            request_hash,
            ts: current_ts,
        });
        ctx.accounts.finalize(cpi_authority_bump, current_ts)?;
        emit!(SignatureApproved {
            policy: policy_addr,
            request_hash,
            ts: current_ts,
        });
        Ok(())
    }

    /// 6 — close the session PDA after finalize or expiry, refunding rent.
    ///
    /// Audit C2 (Opção 4) + C1 fixes.
    #[instruction(discriminator = 6)]
    pub fn quorum_session_close(
        ctx: Ctx<QuorumSessionClose>,
        _init_authority_hash: Address,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts.close(current_ts)
    }

    // ── Admin (challenge-based, single-tx) ───────────────────────
    //
    // Audit C2 (Opção 4): every admin instruction takes
    // `_init_authority_hash` as the first argument so Quasar can derive
    // the policy PDA via the seed `[b"rules_policy", dwallet, hash]`. The
    // value is consumed only by the seed constraint; the body uses primary
    // signature challenges as before.

    #[instruction(discriminator = 7)]
    pub fn add_member(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        new_member_slot: [u8; MEMBER_SLOT_LEN],
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts.add_member(new_member_slot, expected_nonce)
    }

    #[instruction(discriminator = 8)]
    pub fn remove_member(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        member_slot_to_remove: [u8; MEMBER_SLOT_LEN],
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts
            .remove_member(member_slot_to_remove, expected_nonce)
    }

    #[instruction(discriminator = 9)]
    pub fn add_destination(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        destination: [u8; 32],
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts.add_destination(destination, expected_nonce)
    }

    #[instruction(discriminator = 10)]
    pub fn remove_destination(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        destination: [u8; 32],
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts.remove_destination(destination, expected_nonce)
    }

    #[instruction(discriminator = 11)]
    pub fn revoke(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts.revoke(expected_nonce)
    }

    #[instruction(discriminator = 12)]
    pub fn set_primary(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        new_primary_slot: [u8; MEMBER_SLOT_LEN],
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts.set_primary(new_primary_slot, expected_nonce)
    }

    #[instruction(discriminator = 13)]
    pub fn set_quorum_threshold_immediate(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        new_threshold: u8,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts
            .set_quorum_threshold_immediate(new_threshold, expected_nonce)
    }

    #[instruction(discriminator = 14)]
    pub fn set_daily_limit_immediate(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        new_some: u8,
        new_limit: u64,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts
            .set_daily_limit_immediate(new_some, new_limit, expected_nonce)
    }

    #[instruction(discriminator = 15)]
    pub fn set_cooldown_immediate(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        new_cooldown_seconds: u64,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts
            .set_cooldown_immediate(new_cooldown_seconds, expected_nonce)
    }

    /// Audit C2 (Opção 4) + C1 fixes.
    #[instruction(discriminator = 16)]
    pub fn propose_quorum_threshold_change(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        new_threshold: u8,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts
            .propose_quorum_threshold(new_threshold, expected_nonce, current_ts)
    }

    /// Audit C2 (Opção 4) + C1 fixes.
    #[instruction(discriminator = 17)]
    pub fn propose_daily_limit_change(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        new_some: u8,
        new_limit: u64,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts
            .propose_daily_limit(new_some, new_limit, expected_nonce, current_ts)
    }

    /// Audit C2 (Opção 4) + C1 fixes.
    #[instruction(discriminator = 18)]
    pub fn propose_cooldown_change(
        ctx: Ctx<AdminAction>,
        _init_authority_hash: Address,
        new_cooldown_seconds: u64,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts
            .propose_cooldown(new_cooldown_seconds, expected_nonce, current_ts)
    }

    /// 19 — apply the pending change after cooldown elapsed. No auth needed
    /// (the proposer's authority is captured at propose-time).
    ///
    /// Audit C2 (Opção 4) + C1 fixes.
    #[instruction(discriminator = 19)]
    pub fn apply_pending_change(
        ctx: Ctx<ApplyChange>,
        _init_authority_hash: Address,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts.apply(current_ts)
    }
}

#[error_code]
pub enum RulesPolicyError {
    InvalidThreshold = 6000,
    CooldownTooShort,
    TooManyMembers,
    NotQuorumMember,
    QuorumNotMet,
    DailyLimitExceeded,
    DestinationNotAllowed,
    CooldownActive,
    NoPendingChange,
    DuplicateMember,
    InvalidMemberSlot,
    InvalidNonce,
    AuthFailed,
    UnsupportedScheme,
    SessionExpired,
    SessionAlreadyFinalized,
    SessionNotFinalized,
    SessionFinalizable,
    InvalidSessionTtl,
    AlreadyContributed,
}

// ── Accounts: RulesPolicy ───────────────────────────────────────
//
// Audit C2 fix (Opção 4): PDA seed includes `init_authority_hash`. Each
// (dwallet, init_authority) pair maps to a distinct PDA. Squat by an
// attacker creating their own init_authority cannot block the legitimate
// user, who derives a different PDA. The `init_authority_slot` field is
// stored for traceability and dashboard lookup. `init_authority_hash`
// derived as `sha256(init_authority_slot)` and used for the seed only.

#[account(discriminator = 1, set_inner)]
#[seeds(b"rules_policy", dwallet: Address, init_authority_hash: Address)]
pub struct RulesPolicy {
    pub dwallet: Address,
    pub primary_slot: [u8; MEMBER_SLOT_LEN],
    pub init_authority_slot: [u8; MEMBER_SLOT_LEN],
    pub next_admin_nonce: u64,
    pub next_primary_recover_nonce: u64,
    pub next_session_nonce: u64,
    pub quorum_threshold: u8,
    pub member_count: u8,
    pub daily_limit_some: u8,
    pub allowed_destinations_some: u8,
    pub allowed_destinations_count: u8,
    pub pending_change_some: u8,
    pub members_flat: [u8; MEMBERS_BYTES],
    pub allowed_destinations_flat: [u8; DESTINATIONS_BYTES],
    pub daily_limit: u64,
    pub daily_used: u64,
    pub last_reset_ts: i64,
    pub policy_change_cooldown_seconds: u64,
    pub pending_activates_at: i64,
    pub pending_quorum_threshold: u8,
    pub pending_daily_limit_some: u8,
    pub pending_daily_limit: u64,
    pub pending_cooldown_seconds: u64,
}

// ── Accounts: QuorumSession ─────────────────────────────────────

#[account(discriminator = 2, set_inner)]
#[seeds(b"quorum_session", dwallet: Address, session_nonce: u64)]
pub struct QuorumSession {
    pub dwallet: Address,
    pub policy: Address,
    pub payer_for_close: Address,
    pub session_nonce: u64,
    pub message_digest: [u8; 32],
    pub metadata_digest: [u8; 32],
    pub user_pubkey: [u8; 32],
    pub destination: [u8; 32],
    pub members_snapshot: [u8; MEMBERS_BYTES],
    pub amount: u64,
    pub expires_at: i64,
    pub created_at: i64,
    pub finalized_at: i64,
    pub signature_scheme: u16,
    pub member_count_snapshot: u8,
    pub threshold_snapshot: u8,
    pub message_approval_bump: u8,
    pub contributions_count: u8,
    pub contributions_bitmap: u16,
}

// ── Helpers ─────────────────────────────────────────────────────

#[inline]
fn check_sysvar_addr(addr: &Address) -> Result<(), ProgramError> {
    auth::precompile::check_sysvar_address(addr).map_err(|_| RulesPolicyError::AuthFailed.into())
}

/// Audit C2 (Opção 4) helper: derives the 32-byte hash of an init_authority
/// slot used as the third PDA seed for `RulesPolicy`. The slot is 34 bytes
/// (scheme + identifier + padding); SHA-256 collapses it to a fixed 32-byte
/// `Address`-shaped value suitable for `seeds`.
#[inline]
fn init_authority_hash_from_slot(slot: &[u8; MEMBER_SLOT_LEN]) -> Address {
    Address::from(hashv(&[slot]))
}

/// Verify primary signed `challenge` over `sysvar_data`. Primary slot must be
/// schemes 0/1/2 (Ed25519 / Secp256k1 / Secp256r1).
fn verify_primary_challenge(
    primary_slot: &[u8; MEMBER_SLOT_LEN],
    challenge: &[u8; 32],
    sysvar_data: &[u8],
) -> Result<(), ProgramError> {
    let scheme = primary_slot[0];
    require!(
        scheme == SCHEME_ED25519 || scheme == SCHEME_SECP256K1 || scheme == SCHEME_SECP256R1,
        RulesPolicyError::UnsupportedScheme
    );
    verify_signature(VerifyInput {
        member_slot: primary_slot,
        challenge,
        instructions_sysvar_data: sysvar_data,
        webauthn_auth_data: &[],
        webauthn_client_data_json: &[],
    })
    .map_err(|_| RulesPolicyError::AuthFailed)?;
    Ok(())
}

// ── InitPolicy ──────────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_slot: [u8; 34], init_authority_hash: Address)]
pub struct InitPolicy {
    pub dwallet_account: UncheckedAccount,

    #[account(init, payer = payer, address = RulesPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<RulesPolicy>,

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
        primary_slot: [u8; MEMBER_SLOT_LEN],
        quorum_threshold: u8,
        daily_limit_some: u8,
        daily_limit: u64,
        cooldown_seconds: u64,
        allowed_destinations_some: u8,
        current_ts: i64,
    ) -> Result<(), ProgramError> {
        // Audit C2 (Opção 4): bind init_authority_hash to the slot bytes.
        // The PDA was derived using init_authority_hash; the precompile
        // signature is over the slot. If they don't agree, abort — otherwise
        // someone could derive the PDA from key A and sign with key B.
        let computed = init_authority_hash_from_slot(&init_authority_slot);
        require!(
            computed == init_authority_hash,
            RulesPolicyError::InvalidMemberSlot
        );

        validate_slot(&init_authority_slot).map_err(|_| RulesPolicyError::InvalidMemberSlot)?;
        // init_authority must be a long-lived credential (no WebAuthn —
        // assertions are session-scoped).
        require!(
            init_authority_slot[0] != SCHEME_WEBAUTHN,
            RulesPolicyError::UnsupportedScheme
        );

        require!(quorum_threshold >= 1, RulesPolicyError::InvalidThreshold);
        require!(
            cooldown_seconds >= MIN_COOLDOWN_SECONDS,
            RulesPolicyError::CooldownTooShort
        );
        validate_slot(&primary_slot).map_err(|_| RulesPolicyError::InvalidMemberSlot)?;
        require!(
            primary_slot[0] != SCHEME_WEBAUTHN,
            RulesPolicyError::UnsupportedScheme
        );

        // Audit C2 (Opção 4): verify init precompile signature. The
        // init_authority signs a canonical hash of all init parameters so
        // the gateway cannot tamper with primary_slot, threshold, etc.
        let dwallet_addr = *self.dwallet_account.address();
        let challenge = rules_policy_init_challenge(
            &dwallet_addr,
            &init_authority_slot,
            &primary_slot,
            quorum_threshold,
            daily_limit_some,
            daily_limit,
            cooldown_seconds,
            allowed_destinations_some,
        );
        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| RulesPolicyError::AuthFailed)?;
        verify_signature(VerifyInput {
            member_slot: &init_authority_slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data: &[],
            webauthn_client_data_json: &[],
        })
        .map_err(|_| RulesPolicyError::AuthFailed)?;
        drop(sysvar_data_ref);

        self.policy.set_inner(RulesPolicyInner {
            dwallet: dwallet_addr,
            primary_slot,
            init_authority_slot,
            next_admin_nonce: 0,
            next_primary_recover_nonce: 0,
            next_session_nonce: 0,
            quorum_threshold,
            member_count: 0,
            daily_limit_some,
            allowed_destinations_some,
            allowed_destinations_count: 0,
            pending_change_some: 0,
            members_flat: [0u8; MEMBERS_BYTES],
            allowed_destinations_flat: [0u8; DESTINATIONS_BYTES],
            daily_limit,
            daily_used: 0,
            last_reset_ts: current_ts,
            policy_change_cooldown_seconds: cooldown_seconds,
            pending_activates_at: 0,
            pending_quorum_threshold: 0,
            pending_daily_limit_some: 0,
            pending_daily_limit: 0,
            pending_cooldown_seconds: 0,
        });
        Ok(())
    }
}

// ── RecoverAsPrimary ────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct RecoverAsPrimary {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = RulesPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<RulesPolicy>,

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
}

impl RecoverAsPrimary {
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn recover(
        &mut self,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        let policy_nonce: u64 = self.policy.next_primary_recover_nonce.into();
        require!(expected_nonce == policy_nonce, RulesPolicyError::InvalidNonce);

        let dwallet_addr = *self.dwallet_account.address();
        let primary_slot = self.policy.primary_slot;
        let challenge = primary_recover_challenge(
            &dwallet_addr,
            &message_digest,
            &metadata_digest,
            policy_nonce,
            &primary_slot,
        );

        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| RulesPolicyError::AuthFailed)?;
        verify_primary_challenge(&primary_slot, &challenge, &sysvar_data_ref)?;
        drop(sysvar_data_ref);

        self.policy.next_primary_recover_nonce = (policy_nonce + 1).into();

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

// ── QuorumSessionOpen ───────────────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct QuorumSessionOpen {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = RulesPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<RulesPolicy>,

    #[account(init,
        payer = payer,
        address = QuorumSession::seeds(
            dwallet_account.address(),
            policy.next_session_nonce.into()
        )
    )]
    pub session: Account<QuorumSession>,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
}

impl QuorumSessionOpen {
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        &mut self,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        amount: u64,
        destination: [u8; 32],
        expires_at: i64,
        current_ts: i64,
    ) -> Result<(), ProgramError> {
        let ttl = expires_at.saturating_sub(current_ts);
        require!(
            ttl > 0 && ttl <= MAX_SESSION_TTL_SECONDS,
            RulesPolicyError::InvalidSessionTtl
        );

        let dwallet_addr = *self.dwallet_account.address();
        let primary_slot = self.policy.primary_slot;
        let session_nonce: u64 = self.policy.next_session_nonce.into();

        let challenge = quorum_session_open_challenge(
            &dwallet_addr,
            &message_digest,
            &metadata_digest,
            amount,
            &destination,
            expires_at,
            session_nonce,
            &primary_slot,
        );

        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| RulesPolicyError::AuthFailed)?;
        verify_primary_challenge(&primary_slot, &challenge, &sysvar_data_ref)?;
        drop(sysvar_data_ref);

        let policy_addr = *self.policy.address();
        let payer_addr = *self.payer.address();
        let threshold = self.policy.quorum_threshold;
        let member_count = self.policy.member_count;
        let mut members_snapshot = [0u8; MEMBERS_BYTES];
        members_snapshot.copy_from_slice(&self.policy.members_flat);

        self.session.set_inner(QuorumSessionInner {
            dwallet: dwallet_addr,
            policy: policy_addr,
            payer_for_close: payer_addr,
            session_nonce,
            message_digest,
            metadata_digest,
            user_pubkey,
            destination,
            members_snapshot,
            amount,
            expires_at,
            created_at: current_ts,
            finalized_at: 0,
            signature_scheme,
            member_count_snapshot: member_count,
            threshold_snapshot: threshold,
            message_approval_bump,
            contributions_count: 0,
            contributions_bitmap: 0,
        });

        self.policy.next_session_nonce = (session_nonce + 1).into();
        Ok(())
    }
}

// ── QuorumSessionContribute ─────────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct QuorumSessionContribute {
    pub dwallet_account: UncheckedAccount,

    #[account(address = RulesPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<RulesPolicy>,

    #[account(mut, has_one(policy))]
    pub session: Account<QuorumSession>,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,

    #[account(mut)]
    pub payer: Signer,
}

impl QuorumSessionContribute {
    #[inline(always)]
    pub fn contribute(
        &mut self,
        member_index: u8,
        current_ts: i64,
        webauthn_auth_data: &[u8],
        webauthn_cdj: &[u8],
    ) -> Result<(), ProgramError> {
        require!(
            self.session.finalized_at == 0,
            RulesPolicyError::SessionAlreadyFinalized
        );
        let expires_at: i64 = self.session.expires_at.into();
        require!(current_ts < expires_at, RulesPolicyError::SessionExpired);

        let mc = self.session.member_count_snapshot;
        require!(member_index < mc, RulesPolicyError::NotQuorumMember);

        let bit = 1u16 << (member_index as u16);
        let bitmap: u16 = self.session.contributions_bitmap.into();
        require!(bitmap & bit == 0, RulesPolicyError::AlreadyContributed);

        let off = (member_index as usize) * MEMBER_SLOT_LEN;
        let mut slot = [0u8; MEMBER_SLOT_LEN];
        slot.copy_from_slice(&self.session.members_snapshot[off..off + MEMBER_SLOT_LEN]);
        validate_slot(&slot).map_err(|_| RulesPolicyError::InvalidMemberSlot)?;

        let session_addr = *self.session.address();
        let challenge = quorum_contribute_challenge(&session_addr, &slot);

        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| RulesPolicyError::AuthFailed)?;

        verify_signature(VerifyInput {
            member_slot: &slot,
            challenge: &challenge,
            instructions_sysvar_data: &sysvar_data_ref,
            webauthn_auth_data,
            webauthn_client_data_json: webauthn_cdj,
        })
        .map_err(|_| RulesPolicyError::AuthFailed)?;
        drop(sysvar_data_ref);

        let new_bitmap = bitmap | bit;
        let new_count = self.session.contributions_count + 1;
        self.session.contributions_bitmap = new_bitmap.into();
        self.session.contributions_count = new_count;
        Ok(())
    }
}

// ── QuorumSessionFinalize ───────────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct QuorumSessionFinalize {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = RulesPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<RulesPolicy>,

    #[account(mut, has_one(policy))]
    pub session: Account<QuorumSession>,

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

impl QuorumSessionFinalize {
    #[inline(always)]
    pub fn finalize(
        &mut self,
        cpi_authority_bump: u8,
        current_ts: i64,
    ) -> Result<(), ProgramError> {
        require!(
            self.session.finalized_at == 0,
            RulesPolicyError::SessionAlreadyFinalized
        );
        let expires_at: i64 = self.session.expires_at.into();
        require!(current_ts < expires_at, RulesPolicyError::SessionExpired);
        require!(
            self.session.contributions_count >= self.session.threshold_snapshot,
            RulesPolicyError::QuorumNotMet
        );

        // Daily limit + destination whitelist (state in policy, not session).
        let amount: u64 = self.session.amount.into();
        let destination = self.session.destination;
        let last_reset: i64 = self.policy.last_reset_ts.into();
        let mut daily_used: u64 = self.policy.daily_used.into();
        if current_ts.saturating_sub(last_reset) >= 86_400 {
            daily_used = 0;
            self.policy.last_reset_ts = current_ts.into();
        }
        if self.policy.daily_limit_some == 1 {
            let limit: u64 = self.policy.daily_limit.into();
            let new_used = daily_used
                .checked_add(amount)
                .ok_or(RulesPolicyError::DailyLimitExceeded)?;
            require!(new_used <= limit, RulesPolicyError::DailyLimitExceeded);
            self.policy.daily_used = new_used.into();
        }
        if self.policy.allowed_destinations_some == 1 {
            let count = self.policy.allowed_destinations_count as usize;
            let mut allowed = false;
            for i in 0..count {
                let off = i * 32;
                if &self.policy.allowed_destinations_flat[off..off + 32] == destination.as_slice() {
                    allowed = true;
                    break;
                }
            }
            require!(allowed, RulesPolicyError::DestinationNotAllowed);
        }

        self.session.finalized_at = current_ts.into();

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
            self.session.message_digest,
            self.session.metadata_digest,
            self.session.user_pubkey,
            self.session.signature_scheme.into(),
            self.session.message_approval_bump,
        )
    }
}

// ── QuorumSessionClose ──────────────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct QuorumSessionClose {
    pub dwallet_account: UncheckedAccount,

    #[account(address = RulesPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<RulesPolicy>,

    #[account(mut, has_one(policy))]
    pub session: Account<QuorumSession>,

    /// Receives the rent refund. Must equal `session.payer_for_close`.
    #[account(mut)]
    pub rent_destination: UncheckedAccount,

    pub clock: Sysvar<Clock>,
}

impl QuorumSessionClose {
    /// Closes the session by zeroing its lamports (Solana's standard close
    /// pattern: an account with 0 lamports is garbage-collected after the
    /// transaction). Lamports are transferred to `rent_destination`, which
    /// must match the payer that funded the session at open time.
    #[inline(always)]
    pub fn close(&mut self, current_ts: i64) -> Result<(), ProgramError> {
        let finalized: i64 = self.session.finalized_at.into();
        let expires_at: i64 = self.session.expires_at.into();
        require!(
            finalized != 0 || current_ts >= expires_at,
            RulesPolicyError::SessionFinalizable
        );
        let dest_addr = *self.rent_destination.address();
        let stored = self.session.payer_for_close;
        require!(dest_addr == stored, RulesPolicyError::AuthFailed);
        self.session
            .close(self.rent_destination.to_account_view())
            .map_err(|_| RulesPolicyError::AuthFailed)?;
        Ok(())
    }
}

// ── AdminAction (challenge-based) ───────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct AdminAction {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = RulesPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<RulesPolicy>,

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
        let policy_nonce: u64 = self.policy.next_admin_nonce.into();
        require!(expected_nonce == policy_nonce, RulesPolicyError::InvalidNonce);
        let dwallet_addr = *self.dwallet_account.address();
        let primary_slot = self.policy.primary_slot;
        let challenge = build_challenge(&dwallet_addr, &primary_slot, policy_nonce);
        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| RulesPolicyError::AuthFailed)?;
        verify_primary_challenge(&primary_slot, &challenge, &sysvar_data_ref)?;
        drop(sysvar_data_ref);
        self.policy.next_admin_nonce = (policy_nonce + 1).into();
        Ok(())
    }

    #[inline(always)]
    pub fn add_member(
        &mut self,
        new_member_slot: [u8; MEMBER_SLOT_LEN],
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        validate_slot(&new_member_slot).map_err(|_| RulesPolicyError::InvalidMemberSlot)?;
        self.run(expected_nonce, |dw, primary, n| {
            admin_add_member_challenge(dw, &new_member_slot, n, primary)
        })?;
        let count = self.policy.member_count as usize;
        for i in 0..count {
            let off = i * MEMBER_SLOT_LEN;
            if self.policy.members_flat[off..off + MEMBER_SLOT_LEN] == new_member_slot {
                return Ok(());
            }
        }
        require!(count < MAX_MEMBERS, RulesPolicyError::TooManyMembers);
        let off = count * MEMBER_SLOT_LEN;
        self.policy.members_flat[off..off + MEMBER_SLOT_LEN].copy_from_slice(&new_member_slot);
        self.policy.member_count = (count as u8) + 1;
        Ok(())
    }

    #[inline(always)]
    pub fn remove_member(
        &mut self,
        member_slot_to_remove: [u8; MEMBER_SLOT_LEN],
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, primary, n| {
            admin_remove_member_challenge(dw, &member_slot_to_remove, n, primary)
        })?;
        let count = self.policy.member_count as usize;
        for i in 0..count {
            let off = i * MEMBER_SLOT_LEN;
            if self.policy.members_flat[off..off + MEMBER_SLOT_LEN] == member_slot_to_remove {
                let last = (count - 1) * MEMBER_SLOT_LEN;
                if i != count - 1 {
                    let mut tail = [0u8; MEMBER_SLOT_LEN];
                    tail.copy_from_slice(
                        &self.policy.members_flat[last..last + MEMBER_SLOT_LEN],
                    );
                    self.policy.members_flat[off..off + MEMBER_SLOT_LEN].copy_from_slice(&tail);
                }
                self.policy.members_flat[last..last + MEMBER_SLOT_LEN]
                    .copy_from_slice(&[0u8; MEMBER_SLOT_LEN]);
                self.policy.member_count = (count - 1) as u8;
                if (self.policy.quorum_threshold as usize) > core::cmp::max(1, count - 1) {
                    self.policy.quorum_threshold = core::cmp::max(1, (count - 1) as u8);
                }
                return Ok(());
            }
        }
        Ok(())
    }

    #[inline(always)]
    pub fn add_destination(
        &mut self,
        destination: [u8; 32],
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, primary, n| {
            admin_add_destination_challenge(dw, &destination, n, primary)
        })?;
        let count = self.policy.allowed_destinations_count as usize;
        for i in 0..count {
            let off = i * 32;
            if &self.policy.allowed_destinations_flat[off..off + 32] == destination.as_slice() {
                return Ok(());
            }
        }
        require!(
            count < MAX_DESTINATIONS,
            RulesPolicyError::DestinationNotAllowed
        );
        let off = count * 32;
        self.policy.allowed_destinations_flat[off..off + 32]
            .copy_from_slice(destination.as_slice());
        self.policy.allowed_destinations_count = (count as u8) + 1;
        Ok(())
    }

    #[inline(always)]
    pub fn remove_destination(
        &mut self,
        destination: [u8; 32],
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, primary, n| {
            admin_remove_destination_challenge(dw, &destination, n, primary)
        })?;
        let count = self.policy.allowed_destinations_count as usize;
        for i in 0..count {
            let off = i * 32;
            if &self.policy.allowed_destinations_flat[off..off + 32] == destination.as_slice() {
                let last = (count - 1) * 32;
                if i != count - 1 {
                    let mut tail = [0u8; 32];
                    tail.copy_from_slice(&self.policy.allowed_destinations_flat[last..last + 32]);
                    self.policy.allowed_destinations_flat[off..off + 32].copy_from_slice(&tail);
                }
                self.policy.allowed_destinations_flat[last..last + 32]
                    .copy_from_slice(&[0u8; 32]);
                self.policy.allowed_destinations_count = (count - 1) as u8;
                return Ok(());
            }
        }
        Ok(())
    }

    #[inline(always)]
    pub fn revoke(&mut self, expected_nonce: u64) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, primary, n| {
            admin_revoke_challenge(dw, n, primary)
        })?;
        self.policy.member_count = 0;
        self.policy.quorum_threshold = 1;
        self.policy.pending_change_some = PENDING_KIND_NONE;
        Ok(())
    }

    #[inline(always)]
    pub fn set_primary(
        &mut self,
        new_primary_slot: [u8; MEMBER_SLOT_LEN],
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        validate_slot(&new_primary_slot).map_err(|_| RulesPolicyError::InvalidMemberSlot)?;
        require!(
            new_primary_slot[0] != SCHEME_WEBAUTHN,
            RulesPolicyError::UnsupportedScheme
        );
        self.run(expected_nonce, |dw, primary, n| {
            admin_set_primary_challenge(dw, &new_primary_slot, n, primary)
        })?;
        self.policy.primary_slot = new_primary_slot;
        Ok(())
    }

    #[inline(always)]
    pub fn set_quorum_threshold_immediate(
        &mut self,
        new_threshold: u8,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        require!(new_threshold >= 1, RulesPolicyError::InvalidThreshold);
        self.run(expected_nonce, |dw, primary, n| {
            admin_set_quorum_threshold_immediate_challenge(dw, new_threshold, n, primary)
        })?;
        self.policy.quorum_threshold = new_threshold;
        self.policy.pending_change_some = PENDING_KIND_NONE;
        Ok(())
    }

    #[inline(always)]
    pub fn set_daily_limit_immediate(
        &mut self,
        new_some: u8,
        new_limit: u64,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, primary, n| {
            admin_set_daily_limit_immediate_challenge(dw, new_some, new_limit, n, primary)
        })?;
        self.policy.daily_limit_some = new_some;
        self.policy.daily_limit = new_limit.into();
        self.policy.pending_change_some = PENDING_KIND_NONE;
        Ok(())
    }

    #[inline(always)]
    pub fn set_cooldown_immediate(
        &mut self,
        new_cooldown_seconds: u64,
        expected_nonce: u64,
    ) -> Result<(), ProgramError> {
        require!(
            new_cooldown_seconds >= MIN_COOLDOWN_SECONDS,
            RulesPolicyError::CooldownTooShort
        );
        self.run(expected_nonce, |dw, primary, n| {
            admin_set_cooldown_immediate_challenge(dw, new_cooldown_seconds, n, primary)
        })?;
        self.policy.policy_change_cooldown_seconds = new_cooldown_seconds.into();
        self.policy.pending_change_some = PENDING_KIND_NONE;
        Ok(())
    }

    #[inline(always)]
    pub fn propose_quorum_threshold(
        &mut self,
        new_threshold: u8,
        expected_nonce: u64,
        current_ts: i64,
    ) -> Result<(), ProgramError> {
        require!(new_threshold >= 1, RulesPolicyError::InvalidThreshold);
        self.run(expected_nonce, |dw, primary, n| {
            admin_propose_quorum_threshold_challenge(dw, new_threshold, n, primary)
        })?;
        let cooldown: u64 = self.policy.policy_change_cooldown_seconds.into();
        self.policy.pending_change_some = PENDING_KIND_QUORUM;
        self.policy.pending_activates_at = (current_ts + cooldown as i64).into();
        self.policy.pending_quorum_threshold = new_threshold;
        Ok(())
    }

    #[inline(always)]
    pub fn propose_daily_limit(
        &mut self,
        new_some: u8,
        new_limit: u64,
        expected_nonce: u64,
        current_ts: i64,
    ) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, primary, n| {
            admin_propose_daily_limit_challenge(dw, new_some, new_limit, n, primary)
        })?;
        let cooldown: u64 = self.policy.policy_change_cooldown_seconds.into();
        self.policy.pending_change_some = PENDING_KIND_DAILY_LIMIT;
        self.policy.pending_activates_at = (current_ts + cooldown as i64).into();
        self.policy.pending_daily_limit_some = new_some;
        self.policy.pending_daily_limit = new_limit.into();
        Ok(())
    }

    #[inline(always)]
    pub fn propose_cooldown(
        &mut self,
        new_cooldown_seconds: u64,
        expected_nonce: u64,
        current_ts: i64,
    ) -> Result<(), ProgramError> {
        require!(
            new_cooldown_seconds >= MIN_COOLDOWN_SECONDS,
            RulesPolicyError::CooldownTooShort
        );
        self.run(expected_nonce, |dw, primary, n| {
            admin_propose_cooldown_challenge(dw, new_cooldown_seconds, n, primary)
        })?;
        let cooldown: u64 = self.policy.policy_change_cooldown_seconds.into();
        self.policy.pending_change_some = PENDING_KIND_COOLDOWN;
        self.policy.pending_activates_at = (current_ts + cooldown as i64).into();
        self.policy.pending_cooldown_seconds = new_cooldown_seconds.into();
        Ok(())
    }
}

// ── ApplyChange ─────────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct ApplyChange {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = RulesPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<RulesPolicy>,

    pub clock: Sysvar<Clock>,
}

impl ApplyChange {
    #[inline(always)]
    pub fn apply(&mut self, current_ts: i64) -> Result<(), ProgramError> {
        let kind: u8 = self.policy.pending_change_some;
        require!(kind != PENDING_KIND_NONE, RulesPolicyError::NoPendingChange);
        let activates_at: i64 = self.policy.pending_activates_at.into();
        require!(current_ts >= activates_at, RulesPolicyError::CooldownActive);

        match kind {
            PENDING_KIND_QUORUM => {
                self.policy.quorum_threshold = self.policy.pending_quorum_threshold;
            }
            PENDING_KIND_DAILY_LIMIT => {
                self.policy.daily_limit_some = self.policy.pending_daily_limit_some;
                let pdl: u64 = self.policy.pending_daily_limit.into();
                self.policy.daily_limit = pdl.into();
            }
            PENDING_KIND_COOLDOWN => {
                let pcs: u64 = self.policy.pending_cooldown_seconds.into();
                self.policy.policy_change_cooldown_seconds = pcs.into();
            }
            _ => return Err(RulesPolicyError::NoPendingChange.into()),
        }
        self.policy.pending_change_some = PENDING_KIND_NONE;
        Ok(())
    }
}

// ── Events ──────────────────────────────────────────────────────

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
