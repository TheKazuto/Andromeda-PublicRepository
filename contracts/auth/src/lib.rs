#![no_std]
#![allow(dead_code)]

//! Shared on-chain auth primitives for Andromeda Quasar policies.
//!
//! Every credential is verified end-to-end on-chain via a Solana precompile
//! invocation in the same transaction. There is no off-chain attestor: if the
//! Andromeda backend were compromised, an attacker still cannot forge any
//! member's signature, because the proof of signature lives in the precompile
//! call (Ed25519 / Secp256k1 / Secp256r1) which the runtime validates
//! cryptographically.
//!
//! ─── Member slot layout (34 bytes) ───────────────────────────────────────
//! ```text
//! slot[0]      = scheme tag
//! slot[1..1+L] = identifier bytes (L = 20, 32, or 33 depending on scheme)
//! slot[..]     = zero padding to 34 bytes
//! ```
//!
//! ─── Schemes ────────────────────────────────────────────────────────────
//! ```text
//! 0 = Ed25519      identifier = 32-byte pubkey       (Solana / Sui / NEAR / Aptos / Cosmos / Substrate ed25519)
//! 1 = Secp256k1    identifier = 20-byte eth_address  (EVM / Bitcoin / Cosmos secp256k1 / Substrate ecdsa)
//! 2 = Secp256r1    identifier = 33-byte compressed   (passkey with raw pubkey)
//! 3 = WebAuthn     identifier = 33-byte compressed   (passkey with WebAuthn assertion: validates challenge in clientDataJSON)
//! 4 = OidcJwt      identifier = 32-byte addr_seed    (Login Social — see below; rules-policy primary only)
//! ```
//!
//! Schemes 0..=3 are the "base" schemes every Andromeda Quasar program
//! understands ([`validate_slot`] / [`verify_signature`]). Scheme 4 (OIDC) is
//! context-specific: it carries `addr_seed = sha256("andromeda::oidc::addr::v1"
//! || lp(iss) || lp(aud) || lp(sub))`, it is verified by
//! `contracts/oidc-verifier` (RSA over the provider's `id_token`) + an Ed25519
//! precompile over the user's ephemeral key — NOT by [`verify_signature`] — and
//! only `rules-policy` accepts it, as a *primary* slot, via [`validate_oidc_slot`].
//! `MAX_SCHEME` stays at 3 so the 7 owner-style templates keep rejecting it.
//!
//! sr25519 / Ristretto / Bitcoin-Taproot have no Solana precompile and are
//! NOT supported on-chain. Substrate users wishing to use a Polkadot account
//! must enroll an Ed25519 or Secp256k1 (ECDSA) Substrate key.

pub mod admin;
pub mod challenge;
pub mod hash;
pub mod precompile;

use hash::hashv;
use precompile::PrecompileError;

pub const SCHEME_ED25519: u8 = 0;
pub const SCHEME_SECP256K1: u8 = 1;
pub const SCHEME_SECP256R1: u8 = 2;
pub const SCHEME_WEBAUTHN: u8 = 3;
/// `scheme = 4 = OidcJwt` — identifier = 32-byte `addr_seed`
/// (`sha256("andromeda::oidc::addr::v1" || lp(iss) || lp(aud) || lp(sub))`).
///
/// Deliberately NOT a "base" scheme: it is verified by `contracts/oidc-verifier`
/// (RSA over the provider JWT) plus an Ed25519 precompile over the user's
/// ephemeral key — NOT by [`verify_signature`] (which would treat it as "a
/// signature over a 32-byte challenge", which it is not). The 7 owner-style
/// templates use [`validate_slot`] / [`validate_member_slot_base`], which
/// reject scheme 4; only `rules-policy` accepts it (as a *primary*) via
/// [`validate_oidc_slot`]. Hence `MAX_SCHEME` is intentionally left at 3.
pub const SCHEME_OIDC_JWT: u8 = 4;

/// Highest "base" scheme (0..=3) — the schemes every Andromeda Quasar program
/// understands via [`validate_slot`] / [`verify_signature`]. Scheme 4 (OIDC) is
/// context-specific and is *not* counted here on purpose.
pub const MAX_SCHEME: u8 = SCHEME_WEBAUTHN;

pub const MEMBER_SLOT_LEN: usize = 34;

/// Hard caps for WebAuthn payloads carried inside a `quorum_session_contribute`
/// instruction. These bound the on-chain compute cost and stack usage.
pub const WEBAUTHN_AUTH_DATA_MAX: usize = 64;
pub const WEBAUTHN_CLIENT_DATA_JSON_MAX: usize = 192;
pub const WEBAUTHN_MESSAGE_MAX: usize = WEBAUTHN_AUTH_DATA_MAX + 32;

#[derive(Debug)]
pub enum AuthError {
    UnsupportedScheme,
    InvalidIdentifierLen,
    InvalidSlotLayout,
    InvalidWebAuthnPayload,
    InvalidNonce,
    Precompile(PrecompileError),
}

impl From<PrecompileError> for AuthError {
    fn from(e: PrecompileError) -> Self {
        AuthError::Precompile(e)
    }
}

#[inline]
pub fn id_len_for_scheme(scheme: u8) -> Result<usize, AuthError> {
    match scheme {
        SCHEME_ED25519 => Ok(32),
        SCHEME_SECP256K1 => Ok(20),
        SCHEME_SECP256R1 => Ok(33),
        SCHEME_WEBAUTHN => Ok(33),
        SCHEME_OIDC_JWT => Ok(32), // addr_seed
        _ => Err(AuthError::UnsupportedScheme),
    }
}

/// Builds a canonical 34-byte member slot from `(scheme, identifier)` with
/// zero padding. Errors if the identifier length does not match the scheme.
pub fn build_member_slot(scheme: u8, identifier: &[u8]) -> Result<[u8; MEMBER_SLOT_LEN], AuthError> {
    let expected = id_len_for_scheme(scheme)?;
    if identifier.len() != expected {
        return Err(AuthError::InvalidIdentifierLen);
    }
    let mut slot = [0u8; MEMBER_SLOT_LEN];
    slot[0] = scheme;
    slot[1..1 + identifier.len()].copy_from_slice(identifier);
    Ok(slot)
}

/// Validates a stored slot for a **base** scheme (0..=3): known scheme,
/// identifier bytes followed by zero padding all the way to byte 33. Scheme 4
/// (OIDC) is rejected here — use [`validate_oidc_slot`].
pub fn validate_member_slot_base(slot: &[u8; MEMBER_SLOT_LEN]) -> Result<(), AuthError> {
    let scheme = slot[0];
    if scheme > MAX_SCHEME {
        return Err(AuthError::UnsupportedScheme);
    }
    let id_len = id_len_for_scheme(scheme)?;
    let padding_start = 1 + id_len;
    for &b in &slot[padding_start..] {
        if b != 0 {
            return Err(AuthError::InvalidSlotLayout);
        }
    }
    Ok(())
}

/// Alias retained for the 7 owner-style templates that call `validate_slot`.
/// Identical to [`validate_member_slot_base`] — rejects scheme 4 (OIDC).
#[inline]
pub fn validate_slot(slot: &[u8; MEMBER_SLOT_LEN]) -> Result<(), AuthError> {
    validate_member_slot_base(slot)
}

/// Validates an OIDC primary slot: exactly `[SCHEME_OIDC_JWT, addr_seed(32), 0]`.
/// Only `rules-policy` should use this, and only for the *primary* slot — OIDC
/// is not a quorum-member scheme in the MVP.
pub fn validate_oidc_slot(slot: &[u8; MEMBER_SLOT_LEN]) -> Result<(), AuthError> {
    if slot[0] != SCHEME_OIDC_JWT {
        return Err(AuthError::UnsupportedScheme);
    }
    let id_len = id_len_for_scheme(SCHEME_OIDC_JWT)?; // == 32
    for &b in &slot[1 + id_len..] {
        if b != 0 {
            return Err(AuthError::InvalidSlotLayout);
        }
    }
    Ok(())
}

/// Inputs needed to verify a credential signed `challenge`.
///
/// For non-WebAuthn schemes (0, 1, 2), `webauthn_auth_data` and
/// `webauthn_client_data_json` must be empty slices.
///
/// For `SCHEME_WEBAUTHN`, the caller passes the raw `authenticatorData` and
/// `clientDataJSON` so the program can:
///   1. Verify that the canonical `challenge` appears base64url-no-pad inside
///      `clientDataJSON`'s `"challenge"` field.
///   2. Reconstruct the WebAuthn signed message
///      (`authenticatorData || sha256(clientDataJSON)`) and look up the
///      Secp256r1 precompile invocation that signed it.
pub struct VerifyInput<'a> {
    pub member_slot: &'a [u8; MEMBER_SLOT_LEN],
    pub challenge: &'a [u8; 32],
    pub instructions_sysvar_data: &'a [u8],
    pub webauthn_auth_data: &'a [u8],
    pub webauthn_client_data_json: &'a [u8],
}

pub fn verify_signature(input: VerifyInput<'_>) -> Result<(), AuthError> {
    let scheme = input.member_slot[0];
    match scheme {
        SCHEME_ED25519 => {
            let pubkey: &[u8; 32] = (&input.member_slot[1..33])
                .try_into()
                .map_err(|_| AuthError::InvalidSlotLayout)?;
            precompile::verify_ed25519(pubkey, input.challenge, input.instructions_sysvar_data)?;
            Ok(())
        }
        SCHEME_SECP256K1 => {
            let eth_address: &[u8; 20] = (&input.member_slot[1..21])
                .try_into()
                .map_err(|_| AuthError::InvalidSlotLayout)?;
            precompile::verify_secp256k1(
                eth_address,
                input.challenge,
                input.instructions_sysvar_data,
            )?;
            Ok(())
        }
        SCHEME_SECP256R1 => {
            let pubkey: &[u8; 33] = (&input.member_slot[1..34])
                .try_into()
                .map_err(|_| AuthError::InvalidSlotLayout)?;
            precompile::verify_secp256r1(pubkey, input.challenge, input.instructions_sysvar_data)?;
            Ok(())
        }
        SCHEME_WEBAUTHN => {
            let pubkey: &[u8; 33] = (&input.member_slot[1..34])
                .try_into()
                .map_err(|_| AuthError::InvalidSlotLayout)?;
            verify_webauthn(
                pubkey,
                input.challenge,
                input.instructions_sysvar_data,
                input.webauthn_auth_data,
                input.webauthn_client_data_json,
            )
        }
        // OIDC is not "a signature over a 32-byte challenge" — it is verified by
        // `contracts/oidc-verifier` (RSA over the provider JWT) plus an Ed25519
        // precompile over the ephemeral key, both inside `rules-policy`. Never
        // route it through `verify_signature`.
        SCHEME_OIDC_JWT => Err(AuthError::UnsupportedScheme),
        _ => Err(AuthError::UnsupportedScheme),
    }
}

fn verify_webauthn(
    expected_pubkey: &[u8; 33],
    challenge: &[u8; 32],
    sysvar_data: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
) -> Result<(), AuthError> {
    if authenticator_data.is_empty()
        || authenticator_data.len() > WEBAUTHN_AUTH_DATA_MAX
        || client_data_json.is_empty()
        || client_data_json.len() > WEBAUTHN_CLIENT_DATA_JSON_MAX
    {
        return Err(AuthError::InvalidWebAuthnPayload);
    }

    // 1. Confirm the canonical challenge appears as the EXACT value of the
    //    "challenge" field of clientDataJSON, in base64url-no-pad form.
    //    32 raw bytes → exactly 43 chars. Strict anchoring (audit C3 fix):
    //    we locate `"challenge":"` and require the next 43 bytes to be the
    //    expected b64 challenge, followed immediately by `"`. Substring
    //    matching anywhere in the JSON is rejected — that pattern allowed
    //    phishing scenarios where the attacker tricked the authenticator
    //    into signing a longer challenge that contained the canonical one
    //    as a substring.
    let mut challenge_b64 = [0u8; 43];
    encode_base64url_nopad_32(challenge, &mut challenge_b64);
    let needle = b"\"challenge\":\"";
    let key_pos = find_subslice(client_data_json, needle)
        .ok_or(AuthError::InvalidWebAuthnPayload)?;
    let value_start = key_pos
        .checked_add(needle.len())
        .ok_or(AuthError::InvalidWebAuthnPayload)?;
    let value_end = value_start
        .checked_add(43)
        .ok_or(AuthError::InvalidWebAuthnPayload)?;
    // Need at least 1 byte after the 43 chars (the closing `"`).
    if value_end >= client_data_json.len() {
        return Err(AuthError::InvalidWebAuthnPayload);
    }
    if client_data_json[value_start..value_end] != challenge_b64[..] {
        return Err(AuthError::InvalidWebAuthnPayload);
    }
    if client_data_json[value_end] != b'"' {
        return Err(AuthError::InvalidWebAuthnPayload);
    }

    // 2. Reconstruct WebAuthn signed message.
    let cdj_hash = hashv(&[client_data_json]);
    let mut signed = [0u8; WEBAUTHN_MESSAGE_MAX];
    let n = authenticator_data.len();
    signed[..n].copy_from_slice(authenticator_data);
    signed[n..n + 32].copy_from_slice(&cdj_hash);
    let signed_slice = &signed[..n + 32];

    // 3. Look up matching Secp256r1 precompile invocation.
    precompile::verify_secp256r1(expected_pubkey, signed_slice, sysvar_data)?;
    Ok(())
}

/// Returns the offset of the first occurrence of `needle` in `haystack`, or
/// `None` if not found. Empty needle matches at offset 0.
#[inline]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    let limit = haystack.len() - needle.len();
    for i in 0..=limit {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

/// base64url no-pad encoding of exactly 32 input bytes → 43 output bytes.
fn encode_base64url_nopad_32(input: &[u8; 32], out: &mut [u8; 43]) {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut o = 0usize;
    let mut i = 0usize;
    while i + 3 <= 30 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out[o] = ALPHABET[((n >> 18) & 0x3F) as usize];
        out[o + 1] = ALPHABET[((n >> 12) & 0x3F) as usize];
        out[o + 2] = ALPHABET[((n >> 6) & 0x3F) as usize];
        out[o + 3] = ALPHABET[(n & 0x3F) as usize];
        i += 3;
        o += 4;
    }
    // Last 2 bytes: 16 bits → 3 base64 chars (no pad).
    let n = ((input[30] as u32) << 8) | (input[31] as u32);
    out[o] = ALPHABET[((n >> 10) & 0x3F) as usize];
    out[o + 1] = ALPHABET[((n >> 4) & 0x3F) as usize];
    out[o + 2] = ALPHABET[((n << 2) & 0x3F) as usize];
}
