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
        oidc_primary_use_challenge, oidc_session_open_challenge, primary_recover_challenge,
        quorum_contribute_challenge, quorum_session_open_challenge, rules_policy_init_challenge,
    },
    hash::hashv,
    validate_oidc_slot, validate_slot, verify_signature, VerifyInput, MEMBER_SLOT_LEN,
    SCHEME_ED25519, SCHEME_OIDC_JWT, SCHEME_SECP256K1, SCHEME_SECP256R1, SCHEME_WEBAUTHN,
    WEBAUTHN_AUTH_DATA_MAX, WEBAUTHN_CLIENT_DATA_JSON_MAX,
};
use andromeda_oidc_verifier as oidc_verifier;
use andromeda_policy_shared::validate_ika_cpi_accounts;
use ika_dwallet_quasar::DWalletContext;
use quasar_lang::prelude::*;
use solana_address::Address;

declare_id!("6TX7qG47Fsocuwmgsgo2q3NLCHrbomoQxQLifapU8Thr");

const MAX_MEMBERS: usize = 16;
const MAX_DESTINATIONS: usize = 16;
const MEMBERS_BYTES: usize = MAX_MEMBERS * MEMBER_SLOT_LEN; // 544
const DESTINATIONS_BYTES: usize = MAX_DESTINATIONS * 32; // 512
const MIN_COOLDOWN_SECONDS: u64 = 3600;
const MAX_COOLDOWN_SECONDS: u64 = 365 * 24 * 3600;
const MAX_SESSION_TTL_SECONDS: i64 = 7 * 24 * 3600;

const PENDING_KIND_NONE: u8 = 0;
const PENDING_KIND_QUORUM: u8 = 1;
const PENDING_KIND_DAILY_LIMIT: u8 = 2;
const PENDING_KIND_COOLDOWN: u8 = 3;

// ── Login Social (`scheme = 4 = OidcJwt`) constants ─────────────
//
// See `loginsocial.md` §6–§8 and `contracts/oidc-verifier`. Login Social lets a
// dWallet's *primary* slot be an OIDC identity (`addr_seed = sha256("andromeda::
// oidc::addr::v1" || lp(iss) || lp(aud) || lp(sub))`). The user proves control
// of that identity by presenting the provider's `id_token` (RS256 JWT), whose
// `nonce` claim binds an ephemeral Ed25519 key the user actually holds; the
// program verifies the JWT signature against the on-chain JWK registry (a
// separate Quasar program — trust root), opens a short-lived `OidcSession` PDA
// bound to that ephemeral key, and from then on authorizes Ika signatures by
// checking a fresh Ed25519 precompile signature (ephemeral key over a per-use
// challenge) — no JWT replay, no off-chain attestor.

/// Lifetime cap of an `OidcSession` from `oidc_session_open` (seconds). Chosen
/// short so it fits inside the provider `id_token`'s own window (Apple ≈ 600 s);
/// the effective expiry is `min(not_after, min(jwt.exp, now + SESSION_TTL))`.
const SESSION_TTL_SECONDS: i64 = 600;

/// How long an abandoned `OidcJwtStaging` account must sit before
/// `oidc_jwt_staging_close` may reclaim its rent (seconds). On the happy path
/// `oidc_session_open` closes the staging immediately.
const STAGING_TTL_SECONDS: i64 = 15 * 60;

/// Hard cap on a staged JWT — matches `OidcJwtStaging.jwt_bytes` and
/// `oidc_verifier::MAX_JWT_LEN`.
const MAX_JWT_LEN: usize = 4096;

/// OIDC issuer allowlist (frozen per environment; audit memo M4 — hardcoded).
/// Google issues `id_token`s with `iss == "https://accounts.google.com"` (it
/// has historically also used the bare `accounts.google.com`; both accepted).
/// Apple uses `iss == "https://appleid.apple.com"`.
const OIDC_ALLOWED_ISSUERS: &[&[u8]] = &[
    b"https://accounts.google.com",
    b"accounts.google.com",
    b"https://appleid.apple.com",
];

/// OIDC audience allowlist — the Andromeda auth-broker `client_id` for this
/// environment (`loginsocial.md` §5.4 item 1). CONFIG: the broker's OAuth
/// client is created at deploy time; this constant must be set to that exact
/// `client_id` before the devnet deploy of `scheme = 4`. It is intentionally a
/// single explicit per-environment value (like a program id) — the verifier
/// path itself is fully functional.
///
/// Devnet (set 2026-05-13): Google OAuth client for the gateway-hosted broker
/// at `https://api.andromedainfra.pro`. This value is part of every Login
/// Social dWallet's `addr_seed` — changing it later orphans all dWallets
/// derived under the old value.
const OIDC_ALLOWED_AUDIENCES: &[&[u8]] =
    &[b"33123645941-v986q5r3n7cfalnq24vasl543dud1e2q.apps.googleusercontent.com"];

/// Read-side mirror of `contracts/jwk-registry`'s account byte layout (frozen).
///
/// `rules-policy` deliberately does **not** depend on the `andromeda_jwk_registry`
/// crate: it is a Quasar `#[program]` whose SBF `entrypoint` symbol would
/// collide with ours at link time. Instead we re-declare just the bytes we read
/// here. Any change to `JwkRegistry`'s on-chain layout MUST be reflected here in
/// the same commit. Source of truth: `contracts/jwk-registry/src/lib.rs`.
mod oidc_jwk {
    use solana_address::Address;

    /// `8xL2mrQ2amDpinQMHJPaEELbgEXWRVGn4PQ7kzDm7vNM` — `andromeda_jwk_registry`'s
    /// program id (must own the `jwk_registry` account passed to `rules-policy`).
    /// Keep in sync with `declare_id!` in `contracts/jwk-registry/src/lib.rs`.
    pub const JWK_REGISTRY_PROGRAM_ID: Address =
        solana_address::address!("8xL2mrQ2amDpinQMHJPaEELbgEXWRVGn4PQ7kzDm7vNM");

    /// PDA seed prefix of the canonical `JwkRegistry` account.
    pub const SEED_PREFIX: &[u8] = b"jwk_registry";
    /// The canonical registry uses the all-zero `registry_seed`.
    pub const CANONICAL_REGISTRY_SEED: [u8; 32] = [0u8; 32];

    /// Status tag for an entry that is live and usable.
    pub const STATUS_ACTIVE: u8 = 2;
    /// RSA-2048 modulus length, big-endian.
    pub const MODULUS_LEN: usize = 256;

    const DISC_LEN: usize = 1;
    // `JwkRegistry` ZC fields, in declaration order (all align-1, no padding):
    //   version u8 | entry_count u8 | reserved0 [u8;6] | authority [u8;32]
    //   | pending_authority [u8;32] | emergency_revoker [u8;32]
    //   | pending_emergency_revoker [u8;32] | timelock_seconds u64
    //   | grace_period_seconds u64 | authority_rotation_ready_at i64
    //   | emergency_revoker_rotation_ready_at i64 | entries_flat [u8; 8*400]
    const RO_GRACE_PERIOD_SECONDS: usize = DISC_LEN + 2 + 6 + 32 + 32 + 32 + 32 + 8; // 145
    const RO_ENTRIES: usize = DISC_LEN + 2 + 6 + 32 + 32 + 32 + 32 + 8 + 8 + 8 + 8; // 169
    pub const MAX_JWKS: usize = 8;
    pub const JWK_ENTRY_LEN: usize = 400;
    const REQUIRED_LEN: usize = RO_ENTRIES + MAX_JWKS * JWK_ENTRY_LEN; // 3369

    // Per-entry offsets within a 400-byte slot (mirror of jwk-registry's `EO_*`):
    const EO_STATUS: usize = 0;
    const EO_ISSUER_HASH: usize = 8;
    const EO_AUDIENCE_HASH: usize = 40;
    const EO_KID_HASH: usize = 72;
    const EO_MODULUS: usize = 104;
    const EO_EXPONENT: usize = 360;
    const EO_VALID_FROM: usize = 376;
    const EO_VALID_UNTIL: usize = 384;

    pub struct ActiveJwk {
        pub modulus_n: [u8; MODULUS_LEN],
        pub exponent_e: u32,
    }

    #[inline]
    fn read_i64(b: &[u8]) -> i64 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&b[..8]);
        i64::from_le_bytes(a)
    }

    #[inline]
    fn read_u32(b: &[u8]) -> u32 {
        let mut a = [0u8; 4];
        a.copy_from_slice(&b[..4]);
        u32::from_le_bytes(a)
    }

    #[inline]
    fn read_u64(b: &[u8]) -> u64 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&b[..8]);
        u64::from_le_bytes(a)
    }

    /// Returns the `STATUS_ACTIVE` entry matching `(issuer_hash, audience_hash,
    /// kid_hash)` iff `valid_from <= now <= valid_until + grace`. Returns `None`
    /// if the data is too short, no such entry exists, or the entry is outside
    /// its validity window (i.e. revoked / expired / not-yet-active are all
    /// rejected). The grace period comes from the registry header — an
    /// emergency `revoke_jwk` flips the status away from ACTIVE, which this
    /// rejects, so revocation also kills already-open sessions on re-check.
    pub fn find_active(
        data: &[u8],
        issuer_hash: &[u8; 32],
        audience_hash: &[u8; 32],
        kid_hash: &[u8; 32],
        now: i64,
    ) -> Option<ActiveJwk> {
        if data.len() < REQUIRED_LEN {
            return None;
        }
        let grace = read_u64(&data[RO_GRACE_PERIOD_SECONDS..RO_GRACE_PERIOD_SECONDS + 8]) as i64;
        for i in 0..MAX_JWKS {
            let base = RO_ENTRIES + i * JWK_ENTRY_LEN;
            if data[base + EO_STATUS] != STATUS_ACTIVE {
                continue;
            }
            if &data[base + EO_ISSUER_HASH..base + EO_ISSUER_HASH + 32] != issuer_hash {
                continue;
            }
            if &data[base + EO_AUDIENCE_HASH..base + EO_AUDIENCE_HASH + 32] != audience_hash {
                continue;
            }
            if &data[base + EO_KID_HASH..base + EO_KID_HASH + 32] != kid_hash {
                continue;
            }
            let valid_from = read_i64(&data[base + EO_VALID_FROM..base + EO_VALID_FROM + 8]);
            let valid_until = read_i64(&data[base + EO_VALID_UNTIL..base + EO_VALID_UNTIL + 8]);
            if now < valid_from || now > valid_until.saturating_add(grace) {
                continue;
            }
            let mut modulus_n = [0u8; MODULUS_LEN];
            modulus_n.copy_from_slice(&data[base + EO_MODULUS..base + EO_MODULUS + MODULUS_LEN]);
            let exponent_e = read_u32(&data[base + EO_EXPONENT..base + EO_EXPONENT + 4]);
            return Some(ActiveJwk {
                modulus_n,
                exponent_e,
            });
        }
        None
    }
}

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
        ctx.accounts.program.emit_event(
            &SignatureRequested {
                policy: policy_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        ctx.accounts.recover(
            message_digest,
            metadata_digest,
            user_pubkey,
            signature_scheme,
            message_approval_bump,
            cpi_authority_bump,
            expected_nonce,
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
        ctx.accounts.program.emit_event(
            &SignatureRequested {
                policy: policy_addr,
                request_hash,
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        ctx.accounts.finalize(cpi_authority_bump, current_ts)?;
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

    // ── Login Social — `scheme = 4 = OidcJwt` (disc 20..=24) ─────
    //
    // See `loginsocial.md` §6–§8 and the `// Login Social constants` block
    // above. These five instructions are only reachable when the policy's
    // *primary* slot is an OIDC identity `[4, addr_seed, 0]`; the
    // challenge-signing flows (`recover_as_primary` etc.) reject scheme 4 in
    // `verify_primary_challenge`, so an OIDC-primary dWallet recovers via OIDC
    // sessions only.

    /// 20 — stage a provider `id_token` (RS256 JWT) into a temporary PDA so
    /// `oidc_session_open` can verify it without exceeding the 1232-byte tx
    /// limit (the JWT plus the open's accounts/precompile would not fit inline).
    /// The JWT is opaque here — its real verification happens at
    /// `oidc_session_open`. Anyone may stage; the PDA is single-use per
    /// `policy.next_staging_nonce`, and its rent is refunded when
    /// `oidc_session_open` consumes it (or by `oidc_jwt_staging_close` after
    /// `STAGING_TTL_SECONDS` if it never is).
    #[instruction(discriminator = 20)]
    pub fn oidc_jwt_stage(
        ctx: Ctx<OidcJwtStage>,
        _init_authority_hash: Address,
        #[max(4096, pfx = 2)] jwt_bytes: &[u8],
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts.stage(jwt_bytes, current_ts)
    }

    /// 21 — verify a staged `id_token` and open a short-lived `OidcSession`.
    ///
    /// Step order (no claim drives an auth decision before the RSA verify):
    ///  1. the policy PDA derives from `(dwallet, init_authority_hash)`;
    ///  2. `policy.primary_slot` is an OIDC slot `[4, addr_seed, 0]`;
    ///  3. `oidc_verifier_version == OIDC_VERIFIER_V1`;
    ///  4. `jwk_registry` is owned by `andromeda_jwk_registry` AND is the
    ///     canonical PDA (`jwk_registry_bump`);
    ///  5. pick the `ACTIVE` JWK for the claimed `(issuer_hash, audience_hash,
    ///     kid_hash)` (a hint — `oidc-verifier::verify` is authoritative);
    ///  6. `oidc-verifier::verify(jwt, that JWK's n/e, allowlists, eph_pk,
    ///     not_after, nonce_randomness, now)` — RSA signature ok, `nonce` binds
    ///     `(eph_pk, not_after, nonce_randomness)`, iss/aud allowlisted,
    ///     exp/iat/nbf sane, plausible lifetime;
    ///  7. the verified `(issuer_hash, audience_hash, kid_hash)` equal the hint,
    ///     and `addr_seed == policy.primary_slot[1..33]`;
    ///  8. an Ed25519 precompile in this tx signed `oidc_session_open_challenge(
    ///     dwallet, primary_slot, eph_pk, not_after, jwt_digest, jwk_registry,
    ///     verifier_version, session_nonce)` with `eph_pk` — proves the user
    ///     holds the ephemeral key;
    ///  9. create the `OidcSession`, bump `policy.next_oidc_session_nonce`,
    ///     close the staging account (rent → its `payer_for_close`), emit.
    #[instruction(discriminator = 21)]
    #[allow(clippy::too_many_arguments)]
    pub fn oidc_session_open(
        ctx: Ctx<OidcSessionOpen>,
        _init_authority_hash: Address,
        eph_pk: [u8; 32],
        not_after_unix_ts: u64,
        nonce_randomness: [u8; 32],
        oidc_verifier_version: u32,
        jwk_registry_bump: u8,
        issuer_hash: [u8; 32],
        audience_hash: [u8; 32],
        kid_hash: [u8; 32],
        // Audit F-1 (2026-05-13): the client signs `oidc_session_open_challenge`
        // off-chain with the policy's `next_oidc_session_nonce` it observed.
        // Validating it explicitly here rejects stale-nonce attempts BEFORE
        // the ~41k CU JWT verify, and surfaces a clear `InvalidNonce` error.
        expected_oidc_session_nonce: u64,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        let dwallet_addr = *ctx.accounts.dwallet_account.address();
        let policy_addr = *ctx.accounts.policy.address();
        let session_addr = *ctx.accounts.session.address();
        let addr_seed = ctx.accounts.open(
            eph_pk,
            not_after_unix_ts,
            nonce_randomness,
            oidc_verifier_version,
            jwk_registry_bump,
            issuer_hash,
            audience_hash,
            kid_hash,
            expected_oidc_session_nonce,
            current_ts,
        )?;
        ctx.accounts.program.emit_event(
            &OidcSessionOpened {
                policy: policy_addr,
                session: session_addr,
                dwallet: dwallet_addr,
                addr_seed: Address::from(addr_seed),
                ts: current_ts,
            },
            &ctx.accounts.event_authority,
            EventAuthority::BUMP,
        )?;
        Ok(())
    }

    /// 22 — authorize an Ika signature through an open `OidcSession`.
    ///
    /// Re-validates: session not expired; `expected_use_nonce` matches; the
    /// policy's primary is still `[4, session.addr_seed, 0]` (a rotation/revoke
    /// of the primary kills the session immediately); the session's JWK is
    /// still `ACTIVE` in the same registry (an emergency `revoke_jwk` kills the
    /// session immediately); and an Ed25519 precompile in this tx signed
    /// `oidc_primary_use_challenge(session, dwallet, message_digest,
    /// metadata_digest, use_nonce, primary_slot)` with the session's `eph_pk`.
    /// Then bumps `next_use_nonce` (before the CPI) and CPIs Ika
    /// `approve_message`.
    #[instruction(discriminator = 22)]
    #[allow(clippy::too_many_arguments)]
    pub fn recover_as_primary_oidc_session(
        ctx: Ctx<RecoverAsPrimaryOidcSession>,
        _init_authority_hash: Address,
        message_digest: [u8; 32],
        metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
        expected_use_nonce: u64,
    ) -> Result<(), ProgramError> {
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
        ctx.accounts.recover(
            message_digest,
            metadata_digest,
            user_pubkey,
            signature_scheme,
            message_approval_bump,
            cpi_authority_bump,
            expected_use_nonce,
            current_ts,
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

    /// 23 — close an expired `OidcSession`, refunding its rent to the
    /// `payer_for_close` captured at open time.
    #[instruction(discriminator = 23)]
    pub fn oidc_session_close(
        ctx: Ctx<OidcSessionClose>,
        _init_authority_hash: Address,
    ) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts.close(current_ts)
    }

    /// 24 — reclaim the rent of an abandoned `OidcJwtStaging` account once
    /// `STAGING_TTL_SECONDS` have passed since it was created, refunding the
    /// `payer_for_close`. On the happy path `oidc_session_open` closes it first.
    #[instruction(discriminator = 24)]
    pub fn oidc_jwt_staging_close(ctx: Ctx<OidcJwtStagingClose>) -> Result<(), ProgramError> {
        let current_ts: i64 = ctx.accounts.clock.unix_timestamp.into();
        ctx.accounts.close(current_ts)
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
    InvalidFlag,
    CooldownTooLong,
    // ── Login Social (`scheme = 4 = OidcJwt`) ──
    /// `jwk_registry` account is not owned by `andromeda_jwk_registry`, is not
    /// the canonical registry, or (on re-use) does not match the one pinned
    /// into the `OidcSession` at open time.
    InvalidJwkRegistry,
    /// Staged JWT is empty or longer than `MAX_JWT_LEN`.
    InvalidJwt,
    /// No `ACTIVE` JWK matching `(issuer_hash, audience_hash, kid_hash)` within
    /// its validity window (+ grace) — covers revoked / expired / not-yet-active
    /// / unknown keys, and so an emergency `revoke_jwk` also fails open sessions.
    JwkNotActive,
    /// `oidc-verifier` rejected the JWT (bad RSA signature, malformed JSON,
    /// nonce mismatch, expired / implausible lifetime, issuer / audience not
    /// allowlisted, …).
    OidcVerifyFailed,
    /// `oidc_verifier_version` does not equal `OIDC_VERIFIER_V1`.
    OidcVerifierVersionMismatch,
    /// `policy.primary_slot` is not `[4, addr_seed, 0]` for the relevant
    /// `addr_seed` (the primary is not an OIDC identity, or it was rotated /
    /// revoked after the session was opened).
    NotOidcPrimary,
    /// `oidc_jwt_staging_close` was called before `created_at + STAGING_TTL`.
    StagingNotExpired,
    /// Clear-signing renderer failed: rendered message overflows
    /// `MAX_HUMAN_MESSAGE_BYTES`, the slot layout is invalid, or a non-ASCII
    /// byte slipped into a template. Should be unreachable for well-formed
    /// inputs; treat as `AuthFailed`-equivalent (the approver's signature
    /// could not be validated because the canonical hash could not be
    /// derived from the typed params).
    ClearSigningRenderFailed,
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
    /// Single-use nonce space for OIDC sessions (`oidc_session_open`), disjoint
    /// from every other nonce. See `loginsocial.md` §7.4/§7.6.
    pub next_oidc_session_nonce: u64,
    /// Single-use nonce space for OIDC JWT staging accounts (`oidc_jwt_stage`),
    /// disjoint from every other nonce.
    pub next_staging_nonce: u64,
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

#[inline]
fn validate_optional_flag(flag: u8) -> Result<(), ProgramError> {
    require!(flag == 0 || flag == 1, RulesPolicyError::InvalidFlag);
    Ok(())
}

#[inline]
fn validate_cooldown(cooldown_seconds: u64) -> Result<(), ProgramError> {
    require!(
        cooldown_seconds >= MIN_COOLDOWN_SECONDS,
        RulesPolicyError::CooldownTooShort
    );
    require!(
        cooldown_seconds <= MAX_COOLDOWN_SECONDS,
        RulesPolicyError::CooldownTooLong
    );
    Ok(())
}

/// Validates a slot intended to be a `RulesPolicy` *primary*: schemes 0 / 1 / 2
/// (challenge-signing wallet credentials, verified via Solana precompiles) or
/// scheme 4 (`OidcJwt` — Login Social identity, verified via `oidc-verifier` +
/// an Ed25519 precompile over the user's ephemeral key). WebAuthn (scheme 3) is
/// rejected: an assertion is session-scoped, not a long-lived primary.
#[inline]
fn validate_rules_policy_primary_slot(slot: &[u8; MEMBER_SLOT_LEN]) -> Result<(), ProgramError> {
    match slot[0] {
        SCHEME_ED25519 | SCHEME_SECP256K1 | SCHEME_SECP256R1 => {
            validate_slot(slot).map_err(|_| RulesPolicyError::InvalidMemberSlot)?;
        }
        SCHEME_OIDC_JWT => {
            validate_oidc_slot(slot).map_err(|_| RulesPolicyError::InvalidMemberSlot)?;
        }
        _ => return Err(RulesPolicyError::UnsupportedScheme.into()),
    }
    Ok(())
}

/// Builds the canonical OIDC primary slot for an `addr_seed`: `[4, addr_seed(32), 0]`.
#[inline]
fn oidc_primary_slot(addr_seed: &[u8; 32]) -> [u8; MEMBER_SLOT_LEN] {
    let mut slot = [0u8; MEMBER_SLOT_LEN];
    slot[0] = SCHEME_OIDC_JWT;
    slot[1..33].copy_from_slice(addr_seed);
    slot
}

/// Validates that `view` is a genuine `JwkRegistry` account: owned by the
/// `andromeda_jwk_registry` program. (Canonicity — the all-zero `registry_seed`
/// PDA — is checked at `oidc_session_open` time via `jwk_registry_bump` and
/// then pinned into the `OidcSession`; on re-use we only re-check the stored
/// address + this owner.)
#[inline]
fn check_jwk_registry_owner(view: &AccountView) -> Result<(), ProgramError> {
    require!(
        view.owner() == &oidc_jwk::JWK_REGISTRY_PROGRAM_ID,
        RulesPolicyError::InvalidJwkRegistry
    );
    Ok(())
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
    pub event_authority: EventAuthority,
    pub program: Program<RulesPolicyProgram>,
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
            (quorum_threshold as usize) <= MAX_MEMBERS,
            RulesPolicyError::InvalidThreshold
        );
        validate_optional_flag(daily_limit_some)?;
        validate_optional_flag(allowed_destinations_some)?;
        validate_cooldown(cooldown_seconds)?;
        // Primary may be schemes 0/1/2 (challenge-signing wallet credentials)
        // OR scheme 4 (OIDC identity — Login Social). Not WebAuthn (session-scoped)
        // and not scheme 3.
        validate_rules_policy_primary_slot(&primary_slot)?;

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
            next_oidc_session_nonce: 0,
            next_staging_nonce: 0,
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
    // NOTE: no separate `caller_program` slot. For the Ika `approve_message`
    // CPI the caller program IS this program, so `recover()` reuses `program`.
    // Passing this program in two slots (`caller_program` + `program`) makes
    // the Quasar `UncheckedAccount` Ref-borrow collide with the `emit_cpi!`
    // self-CPI on the same AccountInfo → `AccountBorrowFailed`.
    pub dwallet_program: UncheckedAccount,
    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<RulesPolicyProgram>,
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
        require!(
            expected_nonce == policy_nonce,
            RulesPolicyError::InvalidNonce
        );

        let dwallet_addr = *self.dwallet_account.address();
        let message_approval_addr = *self.message_approval.address();
        let primary_slot = self.policy.primary_slot;
        let challenge = primary_recover_challenge(
            &dwallet_addr,
            &message_approval_addr,
            &message_digest,
            &metadata_digest,
            &user_pubkey,
            signature_scheme,
            message_approval_bump,
            policy_nonce,
            &primary_slot,
        )
        .map_err(|_| RulesPolicyError::ClearSigningRenderFailed)?;

        check_sysvar_addr(self.instructions_sysvar.address())?;
        let sysvar_view = self.instructions_sysvar.to_account_view();
        let sysvar_data_ref = sysvar_view
            .try_borrow()
            .map_err(|_| RulesPolicyError::AuthFailed)?;
        verify_primary_challenge(&primary_slot, &challenge, &sysvar_data_ref)?;
        drop(sysvar_data_ref);

        self.policy.next_primary_recover_nonce = (policy_nonce + 1).into();
        require!(
            validate_ika_cpi_accounts(
                &self.dwallet_program.to_account_view(),
                &self.dwallet_account.to_account_view(),
            ),
            RulesPolicyError::AuthFailed
        );

        let dwallet_ctx = DWalletContext {
            dwallet_program: self.dwallet_program.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            // The caller program for the Ika CPI is this program itself.
            caller_program: self.program.to_account_view(),
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
            &user_pubkey,
            signature_scheme,
            message_approval_bump,
            amount,
            &destination,
            expires_at,
            session_nonce,
            &primary_slot,
        )
        .map_err(|_| RulesPolicyError::ClearSigningRenderFailed)?;

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
        require!(
            member_count >= threshold,
            RulesPolicyError::InvalidThreshold
        );
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
        let amount: u64 = self.session.amount.into();
        let signature_scheme: u16 = self.session.signature_scheme.into();
        let expires_at_i64: i64 = self.session.expires_at.into();
        let challenge = quorum_contribute_challenge(
            &session_addr,
            &slot,
            &self.session.dwallet,
            amount,
            &self.session.destination,
            &self.session.message_digest,
            &self.session.metadata_digest,
            &self.session.user_pubkey,
            signature_scheme,
            self.session.message_approval_bump,
            expires_at_i64,
        )
        .map_err(|_| RulesPolicyError::ClearSigningRenderFailed)?;

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
    // No separate `caller_program` slot — see RecoverAsPrimary's note.
    // `finalize()` reuses `program` as the Ika CPI caller program.
    pub dwallet_program: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<RulesPolicyProgram>,
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
        require!(
            validate_ika_cpi_accounts(
                &self.dwallet_program.to_account_view(),
                &self.dwallet_account.to_account_view(),
            ),
            RulesPolicyError::AuthFailed
        );

        let dwallet_ctx = DWalletContext {
            dwallet_program: self.dwallet_program.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            // The caller program for the Ika CPI is this program itself.
            caller_program: self.program.to_account_view(),
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
        F: FnOnce(
            &Address,
            &Address,
            &[u8; MEMBER_SLOT_LEN],
            u64,
        ) -> Result<[u8; 32], auth::human_message::HumanMessageError>,
    {
        let policy_nonce: u64 = self.policy.next_admin_nonce.into();
        require!(
            expected_nonce == policy_nonce,
            RulesPolicyError::InvalidNonce
        );
        let dwallet_addr = *self.dwallet_account.address();
        let policy_addr = *self.policy.address();
        let primary_slot = self.policy.primary_slot;
        let challenge = build_challenge(&dwallet_addr, &policy_addr, &primary_slot, policy_nonce)
            .map_err(|_| RulesPolicyError::ClearSigningRenderFailed)?;
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
        self.run(expected_nonce, |dw, policy, primary, n| {
            admin_add_member_challenge(dw, policy, &new_member_slot, n, primary)
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
        self.run(expected_nonce, |dw, policy, primary, n| {
            admin_remove_member_challenge(dw, policy, &member_slot_to_remove, n, primary)
        })?;
        let count = self.policy.member_count as usize;
        for i in 0..count {
            let off = i * MEMBER_SLOT_LEN;
            if self.policy.members_flat[off..off + MEMBER_SLOT_LEN] == member_slot_to_remove {
                let last = (count - 1) * MEMBER_SLOT_LEN;
                if i != count - 1 {
                    let mut tail = [0u8; MEMBER_SLOT_LEN];
                    tail.copy_from_slice(&self.policy.members_flat[last..last + MEMBER_SLOT_LEN]);
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
        self.run(expected_nonce, |dw, policy, primary, n| {
            admin_add_destination_challenge(dw, policy, &destination, n, primary)
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
        self.run(expected_nonce, |dw, policy, primary, n| {
            admin_remove_destination_challenge(dw, policy, &destination, n, primary)
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
                self.policy.allowed_destinations_flat[last..last + 32].copy_from_slice(&[0u8; 32]);
                self.policy.allowed_destinations_count = (count - 1) as u8;
                return Ok(());
            }
        }
        Ok(())
    }

    #[inline(always)]
    pub fn revoke(&mut self, expected_nonce: u64) -> Result<(), ProgramError> {
        self.run(expected_nonce, |dw, policy, primary, n| {
            admin_revoke_challenge(dw, policy, n, primary)
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
        validate_rules_policy_primary_slot(&new_primary_slot)?;
        self.run(expected_nonce, |dw, policy, primary, n| {
            admin_set_primary_challenge(dw, policy, &new_primary_slot, n, primary)
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
        require!(
            new_threshold <= core::cmp::max(1, self.policy.member_count),
            RulesPolicyError::InvalidThreshold
        );
        self.run(expected_nonce, |dw, policy, primary, n| {
            admin_set_quorum_threshold_immediate_challenge(dw, policy, new_threshold, n, primary)
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
        validate_optional_flag(new_some)?;
        self.run(expected_nonce, |dw, policy, primary, n| {
            admin_set_daily_limit_immediate_challenge(dw, policy, new_some, new_limit, n, primary)
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
        validate_cooldown(new_cooldown_seconds)?;
        self.run(expected_nonce, |dw, policy, primary, n| {
            admin_set_cooldown_immediate_challenge(dw, policy, new_cooldown_seconds, n, primary)
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
        require!(
            new_threshold <= core::cmp::max(1, self.policy.member_count),
            RulesPolicyError::InvalidThreshold
        );
        self.run(expected_nonce, |dw, policy, primary, n| {
            admin_propose_quorum_threshold_challenge(dw, policy, new_threshold, n, primary)
        })?;
        let cooldown: u64 = self.policy.policy_change_cooldown_seconds.into();
        self.policy.pending_change_some = PENDING_KIND_QUORUM;
        let activates_at = current_ts
            .checked_add(cooldown as i64)
            .ok_or(RulesPolicyError::CooldownTooLong)?;
        self.policy.pending_activates_at = activates_at.into();
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
        validate_optional_flag(new_some)?;
        self.run(expected_nonce, |dw, policy, primary, n| {
            admin_propose_daily_limit_challenge(dw, policy, new_some, new_limit, n, primary)
        })?;
        let cooldown: u64 = self.policy.policy_change_cooldown_seconds.into();
        self.policy.pending_change_some = PENDING_KIND_DAILY_LIMIT;
        let activates_at = current_ts
            .checked_add(cooldown as i64)
            .ok_or(RulesPolicyError::CooldownTooLong)?;
        self.policy.pending_activates_at = activates_at.into();
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
        validate_cooldown(new_cooldown_seconds)?;
        self.run(expected_nonce, |dw, policy, primary, n| {
            admin_propose_cooldown_challenge(dw, policy, new_cooldown_seconds, n, primary)
        })?;
        let cooldown: u64 = self.policy.policy_change_cooldown_seconds.into();
        self.policy.pending_change_some = PENDING_KIND_COOLDOWN;
        let activates_at = current_ts
            .checked_add(cooldown as i64)
            .ok_or(RulesPolicyError::CooldownTooLong)?;
        self.policy.pending_activates_at = activates_at.into();
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

// ════════════════════════════════════════════════════════════════
// Login Social — `scheme = 4 = OidcJwt`
//
// See `loginsocial.md` §6–§8, the "Login Social constants" block near the top,
// `contracts/oidc-verifier` (RSA verify + claim parsing) and
// `contracts/jwk-registry` (trust root). Two account types — a short-lived
// `OidcJwtStaging` (holds the raw JWT between `oidc_jwt_stage` and
// `oidc_session_open`) and an `OidcSession` (the open session bound to the
// user's ephemeral Ed25519 key) — plus five instruction contexts.
// ════════════════════════════════════════════════════════════════

/// Saturating `u64 -> i64` (timestamps are well below `i64::MAX`; the clamp is
/// defensive against an out-of-range `not_after_unix_ts` from the client).
#[inline]
fn u64_sat_i64(v: u64) -> i64 {
    if v > i64::MAX as u64 {
        i64::MAX
    } else {
        v as i64
    }
}

// ── Account: OidcJwtStaging (disc 4) ────────────────────────────
//
// Fixed-size: a flat `[u8; 4096]` JWT buffer + a `jwt_len`. Deliberately NOT
// `set_inner` — building a 4 KiB `Inner` value on the BPF stack would blow the
// 4 KiB frame; `init` zero-fills the account and the handler writes the few
// header fields + `jwt_bytes[..len]` directly into the zero-copy view (the
// trailing buffer bytes stay zero). Rent (~0.03 SOL) is sponsored by whoever
// calls `oidc_jwt_stage` and refunded when the staging is consumed/closed.

#[account(discriminator = 4)]
#[seeds(b"oidc_jwt_staging", policy: Address, dwallet: Address, staging_nonce: u64)]
pub struct OidcJwtStaging {
    pub dwallet: Address,
    pub policy: Address,
    /// The account that funded this staging — receives the rent refund on close.
    pub payer_for_close: Address,
    pub staging_nonce: u64,
    pub created_at: i64,
    pub jwt_len: u16,
    pub jwt_bytes: [u8; 4096],
}

// ── Account: OidcSession (disc 3) ───────────────────────────────

#[account(discriminator = 3, set_inner)]
#[seeds(b"oidc_session", policy: Address, dwallet: Address, session_nonce: u64)]
pub struct OidcSession {
    pub dwallet: Address,
    pub policy: Address,
    /// The account that funded this session — receives the rent refund on close.
    pub payer_for_close: Address,
    /// The `JwkRegistry` account whose ACTIVE entry was used at open time; its
    /// status is re-checked on every use (an emergency `revoke_jwk` kills it).
    pub jwk_registry: Address,
    /// `sha256("andromeda::oidc::addr::v1" || lp(iss) || lp(aud) || lp(sub))` —
    /// must equal `policy.primary_slot[1..33]` (the policy's OIDC primary).
    pub addr_seed: [u8; 32],
    /// The user's ephemeral Ed25519 public key — every use is authorized by a
    /// fresh Ed25519 precompile signature from this key over a per-use challenge.
    pub eph_pk: [u8; 32],
    /// `sha256(iss)` / `sha256(aud)` / `sha256(kid)` — JWK registry lookup key.
    pub issuer_hash: [u8; 32],
    pub audience_hash: [u8; 32],
    pub kid_hash: [u8; 32],
    pub session_nonce: u64,
    /// Monotonic per-use nonce — consumed before each Ika CPI.
    pub next_use_nonce: u64,
    /// `not_after_unix_ts` chosen by the client at open time (≤ the JWT's `exp`).
    pub not_after_unix_ts: u64,
    /// The JWT's `exp` claim (seconds).
    pub exp_from_jwt: i64,
    /// Effective expiry = `min(not_after, min(exp, created_at + SESSION_TTL))`.
    pub expires_at: i64,
    pub created_at: i64,
    /// Reserved (always 0 — the session is GC'd on close, never "closed but live").
    pub closed_at: i64,
    pub oidc_verifier_version: u32,
}

// ── OidcJwtStage (disc 20) ──────────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct OidcJwtStage {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = RulesPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<RulesPolicy>,

    #[account(init,
        payer = payer,
        address = OidcJwtStaging::seeds(
            policy.address(),
            dwallet_account.address(),
            policy.next_staging_nonce.into()
        )
    )]
    pub staging: Account<OidcJwtStaging>,

    #[account(mut)]
    pub payer: Signer,

    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
}

impl OidcJwtStage {
    #[inline(always)]
    pub fn stage(&mut self, jwt_bytes: &[u8], current_ts: i64) -> Result<(), ProgramError> {
        let n = jwt_bytes.len();
        require!(n > 0 && n <= MAX_JWT_LEN, RulesPolicyError::InvalidJwt);

        let dwallet_addr = *self.dwallet_account.address();
        let policy_addr = *self.policy.address();
        let payer_addr = *self.payer.address();
        let staging_nonce: u64 = self.policy.next_staging_nonce.into();

        self.staging.dwallet = dwallet_addr;
        self.staging.policy = policy_addr;
        self.staging.payer_for_close = payer_addr;
        self.staging.staging_nonce = staging_nonce.into();
        self.staging.created_at = current_ts.into();
        self.staging.jwt_len = (n as u16).into();
        self.staging.jwt_bytes[..n].copy_from_slice(jwt_bytes);

        self.policy.next_staging_nonce = (staging_nonce + 1).into();
        Ok(())
    }
}

// ── OidcSessionOpen (disc 21) ───────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct OidcSessionOpen {
    pub dwallet_account: UncheckedAccount,

    #[account(mut, address = RulesPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<RulesPolicy>,

    #[account(mut, has_one(policy))]
    pub staging: Account<OidcJwtStaging>,

    /// On-chain JWK trust root — owned by `andromeda_jwk_registry` and the
    /// canonical PDA (verified in `open()` via `jwk_registry_bump`).
    pub jwk_registry: UncheckedAccount,

    #[account(init,
        payer = payer,
        address = OidcSession::seeds(
            policy.address(),
            dwallet_account.address(),
            policy.next_oidc_session_nonce.into()
        )
    )]
    pub session: Account<OidcSession>,

    /// Receives the staging account's rent refund. Must equal
    /// `staging.payer_for_close`.
    #[account(mut)]
    pub staging_payer: UncheckedAccount,

    #[account(mut)]
    pub payer: Signer,

    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<RulesPolicyProgram>,
}

impl OidcSessionOpen {
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        &mut self,
        eph_pk: [u8; 32],
        not_after_unix_ts: u64,
        nonce_randomness: [u8; 32],
        oidc_verifier_version: u32,
        jwk_registry_bump: u8,
        issuer_hash: [u8; 32],
        audience_hash: [u8; 32],
        kid_hash: [u8; 32],
        expected_oidc_session_nonce: u64,
        current_ts: i64,
    ) -> Result<[u8; 32], ProgramError> {
        // 0. expected-nonce reject-fast (audit F-1, 2026-05-13). The client
        //    observed `policy.next_oidc_session_nonce = N` off-chain, signed
        //    a challenge that includes `N`, and submits with
        //    `expected_oidc_session_nonce = N`. If the on-chain value has
        //    advanced (someone opened another session in the meantime), the
        //    precompile would fail anyway via challenge-bytes mismatch — but
        //    failing here costs near-zero CU vs ~41k for the JWT verify path,
        //    and surfaces a clear `InvalidNonce` instead of an opaque
        //    `AuthFailed`. The check is repeated again in step 9 against the
        //    SAME field read; the duplication is intentional defense-in-depth.
        let policy_nonce: u64 = self.policy.next_oidc_session_nonce.into();
        require!(
            expected_oidc_session_nonce == policy_nonce,
            RulesPolicyError::InvalidNonce
        );

        // 1. staging belongs to this dWallet (has_one already pinned it to this
        //    policy; the policy PDA already pinned (dwallet, init_authority)).
        let dwallet_addr = *self.dwallet_account.address();
        require!(
            self.staging.dwallet == dwallet_addr,
            RulesPolicyError::InvalidJwt
        );

        // 2. primary must be an OIDC slot `[4, addr_seed, 0]`.
        let primary_slot = self.policy.primary_slot;
        require!(
            primary_slot[0] == SCHEME_OIDC_JWT,
            RulesPolicyError::NotOidcPrimary
        );
        validate_oidc_slot(&primary_slot).map_err(|_| RulesPolicyError::NotOidcPrimary)?;

        // 3. verifier-version pin (also bound into the open challenge below).
        require!(
            oidc_verifier_version == oidc_verifier::OIDC_VERIFIER_V1,
            RulesPolicyError::OidcVerifierVersionMismatch
        );

        // 4. jwk_registry: owned by the registry program AND the canonical PDA.
        let jwk_registry_addr = *self.jwk_registry.address();
        {
            let jwk_view = self.jwk_registry.to_account_view();
            check_jwk_registry_owner(&jwk_view)?;
        }
        quasar_lang::pda::verify_program_address(
            &[
                oidc_jwk::SEED_PREFIX,
                oidc_jwk::CANONICAL_REGISTRY_SEED.as_slice(),
                &[jwk_registry_bump],
            ],
            &oidc_jwk::JWK_REGISTRY_PROGRAM_ID,
            &jwk_registry_addr,
        )
        .map_err(|_| RulesPolicyError::InvalidJwkRegistry)?;

        // 5. pick the ACTIVE JWK for the claimed (iss, aud, kid). The triple is
        //    only a lookup hint — step 7 cross-checks it against the verified
        //    claims, so a wrong hint just fails (no matching JWK / RSA mismatch).
        let active = {
            let jwk_view = self.jwk_registry.to_account_view();
            let data = jwk_view
                .try_borrow()
                .map_err(|_| RulesPolicyError::InvalidJwkRegistry)?;
            oidc_jwk::find_active(&data, &issuer_hash, &audience_hash, &kid_hash, current_ts)
                .ok_or(RulesPolicyError::JwkNotActive)?
        };

        // 6. verify the JWT end-to-end (authoritative). No claim has driven an
        //    auth decision yet — `verify` does the RSA check before trusting
        //    the claims.
        let jwt_len: usize = u16::from(self.staging.jwt_len) as usize;
        require!(
            jwt_len > 0 && jwt_len <= MAX_JWT_LEN,
            RulesPolicyError::InvalidJwt
        );
        let parsed = {
            let jwt = &self.staging.jwt_bytes[..jwt_len];
            oidc_verifier::verify(oidc_verifier::VerifyOidcInput {
                jwt,
                modulus_n: &active.modulus_n,
                exponent_e: active.exponent_e,
                allowed_issuers: OIDC_ALLOWED_ISSUERS,
                allowed_audiences: OIDC_ALLOWED_AUDIENCES,
                eph_pk: &eph_pk,
                not_after_unix_ts,
                nonce_randomness: &nonce_randomness,
                now_unix_ts: current_ts,
            })
            .map_err(|_| RulesPolicyError::OidcVerifyFailed)?
        };

        // 7. the JWK we used must be the one the *verified* claims point to,
        //    and the identity must be the policy's OIDC primary.
        require!(
            parsed.issuer_hash == issuer_hash
                && parsed.audience_hash == audience_hash
                && parsed.kid_hash == kid_hash,
            RulesPolicyError::OidcVerifyFailed
        );
        require!(
            parsed.addr_seed[..] == primary_slot[1..33],
            RulesPolicyError::NotOidcPrimary
        );

        // 8. effective expiry — never past the JWT's exp, never past not_after,
        //    capped at now + SESSION_TTL. `verify` already proved exp > now and
        //    exp >= not_after.
        let exp = parsed.exp_unix_ts;
        let not_after_i = u64_sat_i64(not_after_unix_ts);
        let expires_at = exp
            .min(current_ts.saturating_add(SESSION_TTL_SECONDS))
            .min(not_after_i);
        require!(expires_at > current_ts, RulesPolicyError::InvalidSessionTtl);

        // 9. Ed25519 precompile over the open challenge with eph_pk. The
        //    `expected_oidc_session_nonce` reject-fast (audit F-1, 2026-05-13)
        //    fails BEFORE the precompile work would (which would also fail,
        //    via challenge-bytes mismatch) — useful for both CU savings on
        //    stale-nonce attempts and clearer error reporting.
        let session_nonce: u64 = self.policy.next_oidc_session_nonce.into();
        require!(
            expected_oidc_session_nonce == session_nonce,
            RulesPolicyError::InvalidNonce
        );
        let challenge = oidc_session_open_challenge(
            &dwallet_addr,
            &primary_slot,
            &eph_pk,
            not_after_unix_ts,
            &parsed.jwt_digest,
            &jwk_registry_addr,
            oidc_verifier_version,
            session_nonce,
        )
        .map_err(|_| RulesPolicyError::ClearSigningRenderFailed)?;
        {
            check_sysvar_addr(self.instructions_sysvar.address())?;
            let sysvar_view = self.instructions_sysvar.to_account_view();
            let sysvar_data = sysvar_view
                .try_borrow()
                .map_err(|_| RulesPolicyError::AuthFailed)?;
            auth::precompile::verify_ed25519(&eph_pk, &challenge, &sysvar_data)
                .map_err(|_| RulesPolicyError::AuthFailed)?;
        }

        // 10. create the session, bump the policy nonce.
        let policy_addr = *self.policy.address();
        let session_payer = *self.payer.address();
        let addr_seed = parsed.addr_seed;
        self.session.set_inner(OidcSessionInner {
            dwallet: dwallet_addr,
            policy: policy_addr,
            payer_for_close: session_payer,
            jwk_registry: jwk_registry_addr,
            addr_seed,
            eph_pk,
            issuer_hash,
            audience_hash,
            kid_hash,
            session_nonce,
            next_use_nonce: 0,
            not_after_unix_ts,
            exp_from_jwt: exp,
            expires_at,
            created_at: current_ts,
            closed_at: 0,
            oidc_verifier_version,
        });
        self.policy.next_oidc_session_nonce = (session_nonce + 1).into();

        // 11. close the staging account → refund its rent to the staging payer.
        let staging_payer_addr = *self.staging_payer.address();
        require!(
            staging_payer_addr == self.staging.payer_for_close,
            RulesPolicyError::InvalidJwt
        );
        self.staging
            .close(self.staging_payer.to_account_view())
            .map_err(|_| RulesPolicyError::InvalidJwt)?;

        Ok(addr_seed)
    }
}

// ── RecoverAsPrimaryOidcSession (disc 22) ───────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct RecoverAsPrimaryOidcSession {
    pub dwallet_account: UncheckedAccount,

    #[account(address = RulesPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<RulesPolicy>,

    #[account(mut, has_one(policy))]
    pub session: Account<OidcSession>,

    /// The same JWK trust root pinned into `session` at open time — its current
    /// status is re-checked so an emergency `revoke_jwk` kills this session.
    pub jwk_registry: UncheckedAccount,

    pub coordinator: UncheckedAccount,

    #[account(mut)]
    pub message_approval: UncheckedAccount,

    #[account(mut)]
    pub payer: Signer,

    pub cpi_authority: UncheckedAccount,
    // No separate `caller_program` slot — for the Ika `approve_message` CPI the
    // caller program IS this program, so `recover()` reuses `program` (see the
    // note on `RecoverAsPrimary`).
    pub dwallet_program: UncheckedAccount,
    pub instructions_sysvar: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    pub system_program: Program<SystemProgram>,
    pub event_authority: EventAuthority,
    pub program: Program<RulesPolicyProgram>,
}

impl RecoverAsPrimaryOidcSession {
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
        expected_use_nonce: u64,
        current_ts: i64,
    ) -> Result<(), ProgramError> {
        // 0. verifier-version pin (audit F-2, 2026-05-13). The session
        //    captured the verifier version at open time; if the program is
        //    ever upgraded to introduce V2, old V1 sessions must be re-opened
        //    rather than silently consumed under the new semantics.
        let stored_version: u32 = self.session.oidc_verifier_version.into();
        require!(
            stored_version == oidc_verifier::OIDC_VERIFIER_V1,
            RulesPolicyError::OidcVerifierVersionMismatch
        );

        // 1. session open + unexpired.
        let closed_at: i64 = self.session.closed_at.into();
        require!(closed_at == 0, RulesPolicyError::SessionExpired);
        let expires_at: i64 = self.session.expires_at.into();
        require!(current_ts < expires_at, RulesPolicyError::SessionExpired);

        // 2. use-nonce.
        let use_nonce: u64 = self.session.next_use_nonce.into();
        require!(
            expected_use_nonce == use_nonce,
            RulesPolicyError::InvalidNonce
        );

        // 2b. policy primary must still be `[4, session.addr_seed, 0]` — a
        //     rotation/revoke of the primary after the open invalidates the
        //     session immediately.
        let addr_seed = self.session.addr_seed;
        let expected_primary = oidc_primary_slot(&addr_seed);
        let primary_slot = self.policy.primary_slot;
        require!(
            primary_slot == expected_primary,
            RulesPolicyError::NotOidcPrimary
        );

        // 2c. session's JWK must still be ACTIVE in the same registry — an
        //     emergency `revoke_jwk` (or expiry past grace) kills the session.
        let session_registry = self.session.jwk_registry;
        let jwk_registry_addr = *self.jwk_registry.address();
        require!(
            jwk_registry_addr == session_registry,
            RulesPolicyError::InvalidJwkRegistry
        );
        {
            let jwk_view = self.jwk_registry.to_account_view();
            check_jwk_registry_owner(&jwk_view)?;
            let data = jwk_view
                .try_borrow()
                .map_err(|_| RulesPolicyError::InvalidJwkRegistry)?;
            let issuer_hash = self.session.issuer_hash;
            let audience_hash = self.session.audience_hash;
            let kid_hash = self.session.kid_hash;
            oidc_jwk::find_active(&data, &issuer_hash, &audience_hash, &kid_hash, current_ts)
                .ok_or(RulesPolicyError::JwkNotActive)?;
        }

        // 3. Ed25519 precompile over the per-use challenge with the session's eph_pk.
        let dwallet_addr = *self.dwallet_account.address();
        let session_addr = *self.session.address();
        let message_approval_addr = *self.message_approval.address();
        let eph_pk = self.session.eph_pk;
        let challenge = oidc_primary_use_challenge(
            &session_addr,
            &dwallet_addr,
            &message_approval_addr,
            &message_digest,
            &metadata_digest,
            &user_pubkey,
            signature_scheme,
            message_approval_bump,
            use_nonce,
            &expected_primary,
        )
        .map_err(|_| RulesPolicyError::ClearSigningRenderFailed)?;
        {
            check_sysvar_addr(self.instructions_sysvar.address())?;
            let sysvar_view = self.instructions_sysvar.to_account_view();
            let sysvar_data = sysvar_view
                .try_borrow()
                .map_err(|_| RulesPolicyError::AuthFailed)?;
            auth::precompile::verify_ed25519(&eph_pk, &challenge, &sysvar_data)
                .map_err(|_| RulesPolicyError::AuthFailed)?;
        }

        // 4. consume the use-nonce BEFORE the CPI.
        self.session.next_use_nonce = (use_nonce + 1).into();

        // 5–6. CPI Ika approve_message.
        require!(
            validate_ika_cpi_accounts(
                &self.dwallet_program.to_account_view(),
                &self.dwallet_account.to_account_view(),
            ),
            RulesPolicyError::AuthFailed
        );
        let dwallet_ctx = DWalletContext {
            dwallet_program: self.dwallet_program.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.program.to_account_view(),
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

// ── OidcSessionClose (disc 23) ──────────────────────────────────

#[derive(Accounts)]
#[instruction(init_authority_hash: Address)]
pub struct OidcSessionClose {
    pub dwallet_account: UncheckedAccount,

    #[account(address = RulesPolicy::seeds(
        dwallet_account.address(),
        &init_authority_hash
    ))]
    pub policy: Account<RulesPolicy>,

    #[account(mut, has_one(policy))]
    pub session: Account<OidcSession>,

    /// Receives the rent refund. Must equal `session.payer_for_close`.
    #[account(mut)]
    pub rent_destination: UncheckedAccount,

    pub clock: Sysvar<Clock>,
}

impl OidcSessionClose {
    #[inline(always)]
    pub fn close(&mut self, current_ts: i64) -> Result<(), ProgramError> {
        let closed_at: i64 = self.session.closed_at.into();
        require!(closed_at == 0, RulesPolicyError::SessionFinalizable);
        let expires_at: i64 = self.session.expires_at.into();
        require!(
            current_ts >= expires_at,
            RulesPolicyError::SessionFinalizable
        );
        let dest_addr = *self.rent_destination.address();
        require!(
            dest_addr == self.session.payer_for_close,
            RulesPolicyError::AuthFailed
        );
        self.session
            .close(self.rent_destination.to_account_view())
            .map_err(|_| RulesPolicyError::AuthFailed)?;
        Ok(())
    }
}

// ── OidcJwtStagingClose (disc 24) ───────────────────────────────

#[derive(Accounts)]
pub struct OidcJwtStagingClose {
    #[account(mut)]
    pub staging: Account<OidcJwtStaging>,

    /// Receives the rent refund. Must equal `staging.payer_for_close`.
    #[account(mut)]
    pub rent_destination: UncheckedAccount,

    pub clock: Sysvar<Clock>,
}

impl OidcJwtStagingClose {
    #[inline(always)]
    pub fn close(&mut self, current_ts: i64) -> Result<(), ProgramError> {
        let created_at: i64 = self.staging.created_at.into();
        require!(
            current_ts >= created_at.saturating_add(STAGING_TTL_SECONDS),
            RulesPolicyError::StagingNotExpired
        );
        let dest_addr = *self.rent_destination.address();
        require!(
            dest_addr == self.staging.payer_for_close,
            RulesPolicyError::AuthFailed
        );
        self.staging
            .close(self.rent_destination.to_account_view())
            .map_err(|_| RulesPolicyError::AuthFailed)?;
        Ok(())
    }
}

// ── Event ───────────────────────────────────────────────────────

#[event(discriminator = 3)]
pub struct OidcSessionOpened {
    pub policy: Address,
    pub session: Address,
    pub dwallet: Address,
    /// `sha256("andromeda::oidc::addr::v1" || lp(iss) || lp(aud) || lp(sub))` —
    /// the OIDC primary identity. Never the JWT or the `sub` in clear.
    pub addr_seed: Address,
    pub ts: i64,
}
