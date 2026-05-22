//! Domain-separated, per-operation challenges (clear-signing v2).
//!
//! Every credential signs the bytes returned by these functions off-chain.
//! The on-chain handler recomputes the same hash from the same inputs and
//! requires a matching precompile invocation in the transaction.
//!
//! Each challenge embeds:
//!  * a global `DOMAIN` tag (rules out cross-program replay)
//!  * an operation-specific tag (rules out cross-operation replay)
//!  * the human-readable message bytes, length-prefixed (u16 LE)
//!    — the approver reads this exact text before signing
//!  * the dWallet identity (rules out cross-policy replay)
//!  * a single-use nonce (rules out replay across time)
//!  * the credential's own member-id (rules out signing-on-behalf-of)
//!
//! ─── Clear signing wire format ────────────────────────────────────
//! ```text
//! challenge = sha256(
//!     DOMAIN
//!     || op_tag
//!     || human_message_len_u16_le
//!     || human_message_bytes
//!     || canonical_typed_params...
//! )
//! ```
//!
//! See `docs/SPEC_CLEAR_SIGNING_FROZEN.md` for the canonical templates and
//! `crate::human_message` for the no_std renderers. The TypeScript mirror is
//! `ika-backend/src/recovery/challenge.ts`. Frozen golden vectors live at
//! `ika-backend/src/recovery/__tests__/challenge_vectors.json` (asserted on
//! the TS side; the SBF-only `hashv` here is checked via on-chain / litesvm
//! program tests). Any wire-format change must touch both sides and
//! regenerate the vectors in the same commit.
//!
//! Flows preserved at v1 (no clear signing):
//!  * [`rules_policy_init_challenge`] uses [`DOMAIN_INIT_V1`] — init is
//!    single-shot, PDA-bound, no human approval needed.

use crate::hash::hashv;
use crate::human_message::{self, HumanMessageError, MAX_HUMAN_MESSAGE_BYTES};
use solana_address::Address;

/// Clear-signing domain (Fase 1, all 17 ops below). Bumped from v1 in
/// 2026-05-14 because the wire format now embeds the human-readable
/// message.
pub const DOMAIN: &[u8] = b"andromeda::rules-policy::v2";

/// Init-flow domain. Preserved at v1: init is single-shot per
/// `(dwallet, init_authority_hash)` and does not need clear signing.
pub const DOMAIN_INIT_V1: &[u8] = b"andromeda::rules-policy::v1";

// Init flow tag (no clear signing)
pub const OP_INIT: &[u8] = b"init";

// Recovery flow tags
pub const OP_PRIMARY_RECOVER: &[u8] = b"primary-recover";
pub const OP_QUORUM_SESSION_OPEN: &[u8] = b"quorum-session-open";
pub const OP_QUORUM_CONTRIBUTE: &[u8] = b"quorum-contribute";

// OIDC (Login Social) flow tags — both challenges are signed by the user's
// ephemeral Ed25519 key (which only exists on the user's device). See §6.5 of
// `loginsocial.md` and the TS mirror in `ika-backend/src/recovery/challenge.ts`.
pub const OP_OIDC_SESSION_OPEN: &[u8] = b"oidc-session-open";
pub const OP_OIDC_PRIMARY_USE: &[u8] = b"oidc-primary-use";

// Passkey-primary session flow (D1 Opção A — `SCHEME_WEBAUTHN = 3`). Mirrors
// the OIDC session pattern: open a short-lived session via WebAuthn
// assertion + commit an ephemeral Ed25519 key, then authorize each use via
// a fresh Ed25519 precompile signature from that ephemeral key. The
// WebAuthn assertion itself is verified via the Secp256r1 precompile.
pub const OP_PASSKEY_SESSION_OPEN: &[u8] = b"passkey-session-open";
pub const OP_PASSKEY_PRIMARY_USE: &[u8] = b"passkey-primary-use";

// Admin flow tags (primary signs)
pub const OP_ADMIN_ADD_MEMBER: &[u8] = b"admin-add-member";
pub const OP_ADMIN_REMOVE_MEMBER: &[u8] = b"admin-remove-member";
pub const OP_ADMIN_ADD_DESTINATION: &[u8] = b"admin-add-destination";
pub const OP_ADMIN_REMOVE_DESTINATION: &[u8] = b"admin-remove-destination";
pub const OP_ADMIN_REVOKE: &[u8] = b"admin-revoke";
pub const OP_ADMIN_SET_PRIMARY: &[u8] = b"admin-set-primary";
pub const OP_ADMIN_SET_QUORUM_THRESHOLD_IMMEDIATE: &[u8] = b"admin-set-qt-immediate";
pub const OP_ADMIN_SET_DAILY_LIMIT_IMMEDIATE: &[u8] = b"admin-set-dl-immediate";
pub const OP_ADMIN_SET_COOLDOWN_IMMEDIATE: &[u8] = b"admin-set-cd-immediate";
pub const OP_ADMIN_PROPOSE_QUORUM_THRESHOLD: &[u8] = b"admin-propose-qt";
pub const OP_ADMIN_PROPOSE_DAILY_LIMIT: &[u8] = b"admin-propose-dl";
pub const OP_ADMIN_PROPOSE_COOLDOWN: &[u8] = b"admin-propose-cd";

#[inline(always)]
fn human_len_le(human: &[u8]) -> [u8; 2] {
    // Caller is responsible for guaranteeing `human.len() <= u16::MAX`. All
    // renderers in `crate::human_message` already cap at MAX_HUMAN_MESSAGE_BYTES.
    debug_assert!(human.len() <= MAX_HUMAN_MESSAGE_BYTES);
    (human.len() as u16).to_le_bytes()
}

// ── Init (Opção 4 — init_authority binds the PDA seed) ──────────

/// Init challenge for rules-policy. The init_authority signs this exactly
/// once when creating the policy. The PDA seed includes init_authority, so
/// each (dwallet, init_authority) pair maps to a distinct PDA — the
/// signature here proves the caller really controls init_authority and
/// commits all init parameters.
///
/// Wire format stays at [`DOMAIN_INIT_V1`] (no clear signing — init is
/// single-shot and PDA-bound; UX clarity for create flow is tracked as a
/// future Fase 3).
///
/// Replay protection: PDA uniqueness. The PDA is created with `init`
/// (fails if already exists), so the same signature cannot be replayed to
/// the same PDA. Cross-policy replay is blocked by DOMAIN. Cross-dwallet
/// replay is blocked because dwallet is hashed in.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn rules_policy_init_challenge(
    dwallet: &Address,
    init_authority_slot: &[u8; 34],
    primary_slot: &[u8; 34],
    quorum_threshold: u8,
    daily_limit_some: u8,
    daily_limit: u64,
    cooldown_seconds: u64,
    allowed_destinations_some: u8,
) -> [u8; 32] {
    let qt = [quorum_threshold];
    let dls = [daily_limit_some];
    let dl_le = daily_limit.to_le_bytes();
    let cd_le = cooldown_seconds.to_le_bytes();
    let ads = [allowed_destinations_some];
    hashv(&[
        DOMAIN_INIT_V1,
        OP_INIT,
        dwallet.as_array().as_slice(),
        init_authority_slot,
        primary_slot,
        &qt,
        &dls,
        &dl_le,
        &cd_le,
        &ads,
    ])
}

// ── Recovery (clear-signing v2) ─────────────────────────────────

/// Returns the challenge hash for `primary-recover`. The clear-signing
/// message is rendered internally from the typed params and embedded
/// length-prefixed in the hash. On-chain code uses this; off-chain code
/// that also wants the rendered text can call
/// [`primary_recover_challenge_with_message`].
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn primary_recover_challenge(
    dwallet: &Address,
    message_approval: &Address,
    message_digest: &[u8; 32],
    metadata_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    message_approval_bump: u8,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::primary_recover_message(
        &mut msg_buf,
        dwallet,
        message_digest,
        metadata_digest,
        user_pubkey,
        signature_scheme,
    )?;
    let human = &msg_buf[..len];
    let hash = primary_recover_challenge_with_rendered_message(
        human,
        dwallet,
        message_approval,
        message_digest,
        metadata_digest,
        user_pubkey,
        signature_scheme,
        message_approval_bump,
        nonce,
        primary_slot,
    );
    Ok(hash)
}

/// Same as [`primary_recover_challenge`] but also returns the rendered
/// message bytes (useful for host-side tests and golden vectors).
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn primary_recover_challenge_with_message(
    dwallet: &Address,
    message_approval: &Address,
    message_digest: &[u8; 32],
    metadata_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    message_approval_bump: u8,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<([u8; 32], [u8; MAX_HUMAN_MESSAGE_BYTES], usize), HumanMessageError> {
    let mut msg_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::primary_recover_message(
        &mut msg_buf,
        dwallet,
        message_digest,
        metadata_digest,
        user_pubkey,
        signature_scheme,
    )?;
    let hash = primary_recover_challenge_with_rendered_message(
        &msg_buf[..len],
        dwallet,
        message_approval,
        message_digest,
        metadata_digest,
        user_pubkey,
        signature_scheme,
        message_approval_bump,
        nonce,
        primary_slot,
    );
    Ok((hash, msg_buf, len))
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn primary_recover_challenge_with_rendered_message(
    human: &[u8],
    dwallet: &Address,
    message_approval: &Address,
    message_digest: &[u8; 32],
    metadata_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    message_approval_bump: u8,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    let h_len = human_len_le(human);
    let scheme_le = signature_scheme.to_le_bytes();
    let bump = [message_approval_bump];
    let nonce_le = nonce.to_le_bytes();
    hashv(&[
        DOMAIN,
        OP_PRIMARY_RECOVER,
        &h_len,
        human,
        dwallet.as_array().as_slice(),
        message_approval.as_array().as_slice(),
        message_digest,
        metadata_digest,
        user_pubkey,
        &scheme_le,
        &bump,
        &nonce_le,
        primary_slot,
    ])
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn quorum_session_open_challenge(
    dwallet: &Address,
    message_digest: &[u8; 32],
    metadata_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    message_approval_bump: u8,
    amount: u64,
    destination: &[u8; 32],
    expires_at: i64,
    session_nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::quorum_session_open_message(
        &mut msg_buf,
        dwallet,
        amount,
        destination,
        message_digest,
        metadata_digest,
        signature_scheme,
        expires_at,
    )?;
    Ok(quorum_session_open_challenge_with_rendered_message(
        &msg_buf[..len],
        dwallet,
        message_digest,
        metadata_digest,
        user_pubkey,
        signature_scheme,
        message_approval_bump,
        amount,
        destination,
        expires_at,
        session_nonce,
        primary_slot,
    ))
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn quorum_session_open_challenge_with_message(
    dwallet: &Address,
    message_digest: &[u8; 32],
    metadata_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    message_approval_bump: u8,
    amount: u64,
    destination: &[u8; 32],
    expires_at: i64,
    session_nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<([u8; 32], [u8; MAX_HUMAN_MESSAGE_BYTES], usize), HumanMessageError> {
    let mut msg_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::quorum_session_open_message(
        &mut msg_buf,
        dwallet,
        amount,
        destination,
        message_digest,
        metadata_digest,
        signature_scheme,
        expires_at,
    )?;
    let hash = quorum_session_open_challenge_with_rendered_message(
        &msg_buf[..len],
        dwallet,
        message_digest,
        metadata_digest,
        user_pubkey,
        signature_scheme,
        message_approval_bump,
        amount,
        destination,
        expires_at,
        session_nonce,
        primary_slot,
    );
    Ok((hash, msg_buf, len))
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn quorum_session_open_challenge_with_rendered_message(
    human: &[u8],
    dwallet: &Address,
    message_digest: &[u8; 32],
    metadata_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    message_approval_bump: u8,
    amount: u64,
    destination: &[u8; 32],
    expires_at: i64,
    session_nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    let h_len = human_len_le(human);
    let scheme_le = signature_scheme.to_le_bytes();
    let bump = [message_approval_bump];
    let amount_le = amount.to_le_bytes();
    let expires_le = expires_at.to_le_bytes();
    let nonce_le = session_nonce.to_le_bytes();
    hashv(&[
        DOMAIN,
        OP_QUORUM_SESSION_OPEN,
        &h_len,
        human,
        dwallet.as_array().as_slice(),
        message_digest,
        metadata_digest,
        user_pubkey,
        &scheme_le,
        &bump,
        &amount_le,
        destination,
        &expires_le,
        &nonce_le,
        primary_slot,
    ])
}

/// Quorum-contribute v2 hashes the full session snapshot used in
/// `approve_message`, so that adulterating any field of the session
/// invalidates every member's signature.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn quorum_contribute_challenge(
    session: &Address,
    member_slot: &[u8; 34],
    dwallet: &Address,
    amount: u64,
    destination: &[u8; 32],
    message_digest: &[u8; 32],
    metadata_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    message_approval_bump: u8,
    expires_at: i64,
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::quorum_contribute_message(
        &mut msg_buf,
        session,
        member_slot,
        dwallet,
        amount,
        destination,
        message_digest,
        metadata_digest,
        user_pubkey,
        signature_scheme,
        expires_at,
    )?;
    Ok(quorum_contribute_challenge_with_rendered_message(
        &msg_buf[..len],
        session,
        member_slot,
        dwallet,
        amount,
        destination,
        message_digest,
        metadata_digest,
        user_pubkey,
        signature_scheme,
        message_approval_bump,
        expires_at,
    ))
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn quorum_contribute_challenge_with_message(
    session: &Address,
    member_slot: &[u8; 34],
    dwallet: &Address,
    amount: u64,
    destination: &[u8; 32],
    message_digest: &[u8; 32],
    metadata_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    message_approval_bump: u8,
    expires_at: i64,
) -> Result<([u8; 32], [u8; MAX_HUMAN_MESSAGE_BYTES], usize), HumanMessageError> {
    let mut msg_buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::quorum_contribute_message(
        &mut msg_buf,
        session,
        member_slot,
        dwallet,
        amount,
        destination,
        message_digest,
        metadata_digest,
        user_pubkey,
        signature_scheme,
        expires_at,
    )?;
    let hash = quorum_contribute_challenge_with_rendered_message(
        &msg_buf[..len],
        session,
        member_slot,
        dwallet,
        amount,
        destination,
        message_digest,
        metadata_digest,
        user_pubkey,
        signature_scheme,
        message_approval_bump,
        expires_at,
    );
    Ok((hash, msg_buf, len))
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn quorum_contribute_challenge_with_rendered_message(
    human: &[u8],
    session: &Address,
    member_slot: &[u8; 34],
    dwallet: &Address,
    amount: u64,
    destination: &[u8; 32],
    message_digest: &[u8; 32],
    metadata_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    message_approval_bump: u8,
    expires_at: i64,
) -> [u8; 32] {
    let h_len = human_len_le(human);
    let amount_le = amount.to_le_bytes();
    let scheme_le = signature_scheme.to_le_bytes();
    let bump = [message_approval_bump];
    let expires_le = expires_at.to_le_bytes();
    hashv(&[
        DOMAIN,
        OP_QUORUM_CONTRIBUTE,
        &h_len,
        human,
        session.as_array().as_slice(),
        member_slot,
        dwallet.as_array().as_slice(),
        &amount_le,
        destination,
        message_digest,
        metadata_digest,
        user_pubkey,
        &scheme_le,
        &bump,
        &expires_le,
    ])
}

// ── Admin (primary signs, clear-signing v2) ─────────────────────

/// Maximum extras the legacy `auth` admin format accepts (mirror of
/// `ADMIN_CHALLENGE_MAX_EXTRAS` in `policy_engine`).
pub const ADMIN_HASH_MAX_EXTRAS: usize = 6;

/// M2 audit fix (2026-05-16): each `extras[i]` is prefixed with a `u16 LE`
/// length tag so two variable-length extras can never be concatenated into
/// an ambiguous byte string. Off-chain mirrors MUST emit the same format.
#[inline]
#[allow(clippy::too_many_arguments)]
fn admin_hash_with_human(
    op_tag: &[u8],
    human: &[u8],
    dwallet: &Address,
    policy: &Address,
    nonce: u64,
    primary_slot: &[u8; 34],
    extras: &[&[u8]],
) -> [u8; 32] {
    let h_len = human_len_le(human);
    let nonce_le = nonce.to_le_bytes();
    // 8 fixed parts + up to 6 extras × 2 (length + payload) = 20 slots.
    let mut parts: [&[u8]; 20] = [&[]; 20];
    let mut extra_lens: [[u8; 2]; ADMIN_HASH_MAX_EXTRAS] = [[0u8; 2]; ADMIN_HASH_MAX_EXTRAS];
    parts[0] = DOMAIN;
    parts[1] = op_tag;
    parts[2] = &h_len;
    parts[3] = human;
    parts[4] = dwallet.as_array().as_slice();
    parts[5] = policy.as_array().as_slice();
    parts[6] = &nonce_le;
    parts[7] = primary_slot;
    let mut n = 8usize;
    let extra_count = extras.len().min(ADMIN_HASH_MAX_EXTRAS);
    for i in 0..extra_count {
        extra_lens[i] = (extras[i].len() as u16).to_le_bytes();
    }
    for i in 0..extra_count {
        if n + 1 >= parts.len() {
            break;
        }
        parts[n] = &extra_lens[i];
        parts[n + 1] = extras[i];
        n += 2;
    }
    hashv(&parts[..n])
}

#[inline]
pub fn admin_add_member_challenge(
    dwallet: &Address,
    policy: &Address,
    new_member_slot: &[u8; 34],
    nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::admin_add_member_message(&mut msg, new_member_slot, policy, dwallet)?;
    Ok(admin_hash_with_human(
        OP_ADMIN_ADD_MEMBER,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        primary_slot,
        &[new_member_slot.as_slice()],
    ))
}

#[inline]
pub fn admin_remove_member_challenge(
    dwallet: &Address,
    policy: &Address,
    member_slot_to_remove: &[u8; 34],
    nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::admin_remove_member_message(
        &mut msg,
        member_slot_to_remove,
        policy,
        dwallet,
    )?;
    Ok(admin_hash_with_human(
        OP_ADMIN_REMOVE_MEMBER,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        primary_slot,
        &[member_slot_to_remove.as_slice()],
    ))
}

#[inline]
pub fn admin_add_destination_challenge(
    dwallet: &Address,
    policy: &Address,
    destination: &[u8; 32],
    nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::admin_add_destination_message(&mut msg, destination, policy, dwallet)?;
    Ok(admin_hash_with_human(
        OP_ADMIN_ADD_DESTINATION,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        primary_slot,
        &[destination.as_slice()],
    ))
}

#[inline]
pub fn admin_remove_destination_challenge(
    dwallet: &Address,
    policy: &Address,
    destination: &[u8; 32],
    nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len =
        human_message::admin_remove_destination_message(&mut msg, destination, policy, dwallet)?;
    Ok(admin_hash_with_human(
        OP_ADMIN_REMOVE_DESTINATION,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        primary_slot,
        &[destination.as_slice()],
    ))
}

#[inline]
pub fn admin_revoke_challenge(
    dwallet: &Address,
    policy: &Address,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::admin_revoke_message(&mut msg, policy, dwallet)?;
    Ok(admin_hash_with_human(
        OP_ADMIN_REVOKE,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        primary_slot,
        &[],
    ))
}

#[inline]
pub fn admin_set_primary_challenge(
    dwallet: &Address,
    policy: &Address,
    new_primary_slot: &[u8; 34],
    nonce: u64,
    current_primary_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len =
        human_message::admin_set_primary_message(&mut msg, new_primary_slot, policy, dwallet)?;
    Ok(admin_hash_with_human(
        OP_ADMIN_SET_PRIMARY,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        current_primary_slot,
        &[new_primary_slot.as_slice()],
    ))
}

#[inline]
pub fn admin_set_quorum_threshold_immediate_challenge(
    dwallet: &Address,
    policy: &Address,
    new_threshold: u8,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::admin_set_quorum_threshold_immediate_message(
        &mut msg,
        new_threshold,
        policy,
        dwallet,
    )?;
    let v = [new_threshold];
    Ok(admin_hash_with_human(
        OP_ADMIN_SET_QUORUM_THRESHOLD_IMMEDIATE,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        primary_slot,
        &[&v],
    ))
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn admin_set_daily_limit_immediate_challenge(
    dwallet: &Address,
    policy: &Address,
    new_some: u8,
    new_limit: u64,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::admin_set_daily_limit_immediate_message(
        &mut msg, new_some, new_limit, policy, dwallet,
    )?;
    let some = [new_some];
    let limit_le = new_limit.to_le_bytes();
    Ok(admin_hash_with_human(
        OP_ADMIN_SET_DAILY_LIMIT_IMMEDIATE,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        primary_slot,
        &[&some, &limit_le],
    ))
}

#[inline]
pub fn admin_set_cooldown_immediate_challenge(
    dwallet: &Address,
    policy: &Address,
    new_cooldown_seconds: u64,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::admin_set_cooldown_immediate_message(
        &mut msg,
        new_cooldown_seconds,
        policy,
        dwallet,
    )?;
    let cd_le = new_cooldown_seconds.to_le_bytes();
    Ok(admin_hash_with_human(
        OP_ADMIN_SET_COOLDOWN_IMMEDIATE,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        primary_slot,
        &[&cd_le],
    ))
}

#[inline]
pub fn admin_propose_quorum_threshold_challenge(
    dwallet: &Address,
    policy: &Address,
    new_threshold: u8,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::admin_propose_quorum_threshold_message(
        &mut msg,
        new_threshold,
        policy,
        dwallet,
    )?;
    let v = [new_threshold];
    Ok(admin_hash_with_human(
        OP_ADMIN_PROPOSE_QUORUM_THRESHOLD,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        primary_slot,
        &[&v],
    ))
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn admin_propose_daily_limit_challenge(
    dwallet: &Address,
    policy: &Address,
    new_some: u8,
    new_limit: u64,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::admin_propose_daily_limit_message(
        &mut msg, new_some, new_limit, policy, dwallet,
    )?;
    let some = [new_some];
    let limit_le = new_limit.to_le_bytes();
    Ok(admin_hash_with_human(
        OP_ADMIN_PROPOSE_DAILY_LIMIT,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        primary_slot,
        &[&some, &limit_le],
    ))
}

#[inline]
pub fn admin_propose_cooldown_challenge(
    dwallet: &Address,
    policy: &Address,
    new_cooldown_seconds: u64,
    nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::admin_propose_cooldown_message(
        &mut msg,
        new_cooldown_seconds,
        policy,
        dwallet,
    )?;
    let cd_le = new_cooldown_seconds.to_le_bytes();
    Ok(admin_hash_with_human(
        OP_ADMIN_PROPOSE_COOLDOWN,
        &msg[..len],
        dwallet,
        policy,
        nonce,
        primary_slot,
        &[&cd_le],
    ))
}

// ── OIDC (Login Social, clear-signing v2) ───────────────────────

/// The user signs this with their ephemeral key to open an `OidcSession`. It
/// commits the dWallet identity, the OIDC primary slot, the ephemeral pubkey,
/// the chosen `not_after_unix_ts`, the exact JWT (`jwt_digest = sha256(header.
/// payload)`), the JWK registry account, the verifier version, and the policy's
/// `next_oidc_session_nonce` — so the open is bound to that JWT under that
/// registry/verifier, single-use per the policy nonce, and not replayable
/// across policies/credentials/programs.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn oidc_session_open_challenge(
    dwallet: &Address,
    primary_slot: &[u8; 34],
    eph_pk: &[u8; 32],
    not_after_unix_ts: u64,
    jwt_digest: &[u8; 32],
    jwk_registry: &Address,
    oidc_verifier_version: u32,
    session_nonce: u64,
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len =
        human_message::oidc_session_open_message(&mut msg, dwallet, not_after_unix_ts, eph_pk)?;
    Ok(oidc_session_open_challenge_with_rendered_message(
        &msg[..len],
        dwallet,
        primary_slot,
        eph_pk,
        not_after_unix_ts,
        jwt_digest,
        jwk_registry,
        oidc_verifier_version,
        session_nonce,
    ))
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn oidc_session_open_challenge_with_rendered_message(
    human: &[u8],
    dwallet: &Address,
    primary_slot: &[u8; 34],
    eph_pk: &[u8; 32],
    not_after_unix_ts: u64,
    jwt_digest: &[u8; 32],
    jwk_registry: &Address,
    oidc_verifier_version: u32,
    session_nonce: u64,
) -> [u8; 32] {
    let h_len = human_len_le(human);
    let not_after_le = not_after_unix_ts.to_le_bytes();
    let ver_le = oidc_verifier_version.to_le_bytes();
    let nonce_le = session_nonce.to_le_bytes();
    hashv(&[
        DOMAIN,
        OP_OIDC_SESSION_OPEN,
        &h_len,
        human,
        dwallet.as_array().as_slice(),
        primary_slot,
        eph_pk,
        &not_after_le,
        jwt_digest,
        jwk_registry.as_array().as_slice(),
        &ver_le,
        &nonce_le,
    ])
}

/// The user signs this with their ephemeral key for each signature authorized
/// through an open `OidcSession`. It commits the session PDA (unique per
/// session), the dWallet, the message/metadata digests, the session's
/// `next_use_nonce` (single-use, replay-blocked by the PDA's monotonic nonce),
/// and the OIDC primary slot.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn oidc_primary_use_challenge(
    session: &Address,
    dwallet: &Address,
    message_approval: &Address,
    message_digest: &[u8; 32],
    metadata_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    message_approval_bump: u8,
    use_nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::oidc_primary_use_message(
        &mut msg,
        session,
        dwallet,
        message_digest,
        metadata_digest,
        user_pubkey,
        signature_scheme,
    )?;
    Ok(oidc_primary_use_challenge_with_rendered_message(
        &msg[..len],
        session,
        dwallet,
        message_approval,
        message_digest,
        metadata_digest,
        user_pubkey,
        signature_scheme,
        message_approval_bump,
        use_nonce,
        primary_slot,
    ))
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn oidc_primary_use_challenge_with_rendered_message(
    human: &[u8],
    session: &Address,
    dwallet: &Address,
    message_approval: &Address,
    message_digest: &[u8; 32],
    metadata_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    message_approval_bump: u8,
    use_nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    let h_len = human_len_le(human);
    let scheme_le = signature_scheme.to_le_bytes();
    let bump = [message_approval_bump];
    let nonce_le = use_nonce.to_le_bytes();
    hashv(&[
        DOMAIN,
        OP_OIDC_PRIMARY_USE,
        &h_len,
        human,
        session.as_array().as_slice(),
        dwallet.as_array().as_slice(),
        message_approval.as_array().as_slice(),
        message_digest,
        metadata_digest,
        user_pubkey,
        &scheme_le,
        &bump,
        &nonce_le,
        primary_slot,
    ])
}

// ── Passkey-primary session flow (D1 Opção A) ───────────────────────────
//
// Mirrors the OIDC session pattern. Differences from OIDC:
//
//  * No JWT-side trust root (`jwk_registry`/`verifier_version`) — the
//    WebAuthn assertion is self-contained and verified via the Secp256r1
//    precompile + `clientDataJSON` parse.
//  * `credential_id_hash` (`sha256(credentialId)`) takes the place of
//    `jwt_digest` as the binding to a specific credential.
//  * Primary slot is `[SCHEME_WEBAUTHN, credential_public_key(33), 0]` —
//    the 33-byte compressed secp256r1 pubkey of the passkey credential.
//
// Both challenges embed the rendered human-readable message (clear signing
// v2) and a domain tag (`OP_PASSKEY_SESSION_OPEN` / `OP_PASSKEY_PRIMARY_USE`)
// so they cannot be replayed across operations.

/// Returns the challenge hash that the user's WebAuthn passkey must sign at
/// `passkey_session_open`. Binds the dWallet, the WebAuthn credential
/// (`credential_id_hash` + `primary_slot` carrying the credential pubkey),
/// the ephemeral Ed25519 key that will authorize subsequent uses, the
/// effective expiry, and the policy's `next_passkey_session_nonce`.
///
/// Replay protection: the policy nonce is monotonic and consumed once per
/// open. Cross-policy / cross-dwallet replay blocked by `dwallet` /
/// `primary_slot` / `DOMAIN`.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn passkey_session_open_challenge(
    dwallet: &Address,
    primary_slot: &[u8; 34],
    eph_pk: &[u8; 32],
    not_after_unix_ts: u64,
    credential_id_hash: &[u8; 32],
    session_nonce: u64,
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len =
        human_message::passkey_session_open_message(&mut msg, dwallet, not_after_unix_ts, eph_pk)?;
    Ok(passkey_session_open_challenge_with_rendered_message(
        &msg[..len],
        dwallet,
        primary_slot,
        eph_pk,
        not_after_unix_ts,
        credential_id_hash,
        session_nonce,
    ))
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn passkey_session_open_challenge_with_rendered_message(
    human: &[u8],
    dwallet: &Address,
    primary_slot: &[u8; 34],
    eph_pk: &[u8; 32],
    not_after_unix_ts: u64,
    credential_id_hash: &[u8; 32],
    session_nonce: u64,
) -> [u8; 32] {
    let h_len = human_len_le(human);
    let not_after_le = not_after_unix_ts.to_le_bytes();
    let nonce_le = session_nonce.to_le_bytes();
    hashv(&[
        DOMAIN,
        OP_PASSKEY_SESSION_OPEN,
        &h_len,
        human,
        dwallet.as_array().as_slice(),
        primary_slot,
        eph_pk,
        &not_after_le,
        credential_id_hash,
        &nonce_le,
    ])
}

/// Returns the challenge hash that the user's ephemeral Ed25519 key must sign
/// for each `recover_as_primary_passkey_session` call. Single-use per session
/// via `use_nonce` (monotonic, advanced before the CPI).
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn passkey_primary_use_challenge(
    session: &Address,
    dwallet: &Address,
    message_approval: &Address,
    message_digest: &[u8; 32],
    metadata_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    message_approval_bump: u8,
    use_nonce: u64,
    primary_slot: &[u8; 34],
) -> Result<[u8; 32], HumanMessageError> {
    let mut msg = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = human_message::passkey_primary_use_message(
        &mut msg,
        session,
        dwallet,
        message_digest,
        metadata_digest,
        user_pubkey,
        signature_scheme,
    )?;
    Ok(passkey_primary_use_challenge_with_rendered_message(
        &msg[..len],
        session,
        dwallet,
        message_approval,
        message_digest,
        metadata_digest,
        user_pubkey,
        signature_scheme,
        message_approval_bump,
        use_nonce,
        primary_slot,
    ))
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn passkey_primary_use_challenge_with_rendered_message(
    human: &[u8],
    session: &Address,
    dwallet: &Address,
    message_approval: &Address,
    message_digest: &[u8; 32],
    metadata_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    message_approval_bump: u8,
    use_nonce: u64,
    primary_slot: &[u8; 34],
) -> [u8; 32] {
    let h_len = human_len_le(human);
    let scheme_le = signature_scheme.to_le_bytes();
    let bump = [message_approval_bump];
    let nonce_le = use_nonce.to_le_bytes();
    hashv(&[
        DOMAIN,
        OP_PASSKEY_PRIMARY_USE,
        &h_len,
        human,
        session.as_array().as_slice(),
        dwallet.as_array().as_slice(),
        message_approval.as_array().as_slice(),
        message_digest,
        metadata_digest,
        user_pubkey,
        &scheme_le,
        &bump,
        &nonce_le,
        primary_slot,
    ])
}
