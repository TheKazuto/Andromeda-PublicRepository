//! Andromeda — `oidc-verifier`: a `no_std` library that verifies an OIDC
//! `id_token` (JWT, `RS256`) **directly on-chain** for the Login Social feature
//! ("Caminho A" — see `loginsocial.md` §2, §6, §7.2).
//!
//! Given a JWT (from `rules-policy`'s `OidcJwtStaging` account) and the RSA
//! modulus/exponent of the provider key (from the `jwk-registry` account),
//! [`verify`]:
//!  1. splits `header.payload.signature` and strictly base64url-decodes them;
//!  2. strictly parses the JOSE header (`alg == "RS256"`, a `kid`, no
//!     `crit`/`jku`/`x5u`) and the claims (`iss`, `aud`, `sub`, `nonce`, `iat`,
//!     `exp`, optional `nbf` — `aud` only as a string);
//!  3. checks `iss`/`aud` against the environment allowlists;
//!  4. verifies the RSA-2048 / EMSA-PKCS1-v1_5(SHA-256) signature via the
//!     `sol_big_mod_exp` syscall — *encode-then-compare over all 256 bytes*;
//!  5. (only then trusting the claims) recomputes the canonical `oidc_nonce`
//!     from `(eph_pk, not_after_unix_ts, nonce_randomness)` and requires the
//!     `nonce` claim to equal it;
//!  6. checks `exp > now`, `exp >= not_after_unix_ts`, `iat <= now + skew`,
//!     `nbf <= now + skew`, and a plausible token lifetime;
//!  7. derives `addr_seed = SHA256("andromeda::oidc::addr::v1" || lp(iss) ||
//!     lp(aud) || lp(sub))` (length-prefixed) and the `(issuer_hash,
//!     audience_hash, kid_hash)` SHA-256s, plus `jwt_digest = SHA256(header.payload)`.
//!
//! Versioned by [`OIDC_VERIFIER_V1`] — bump if the wire/derivation format
//! changes (no ceremony / trusted setup is involved).
//!
//! Measured on `solana-program-test` SBF (the `loginsocial-spike`):
//! `sol_big_mod_exp` for RSA-2048 / `e = 65537` ≈ ~33k CU; the full `verify`
//! (SHA-256 of ~700–1100 B + PKCS#1 build + RSA + 256-byte compare + JSON parse
//! + nonce recompute + `addr_seed`) ≈ ~41k CU.

#![cfg_attr(not(test), no_std)]
#![allow(clippy::result_unit_err)]

pub mod claims;
pub mod hash;
pub mod jwt;
pub mod pkcs1;

use pkcs1::RSA_BYTES;

// ── Versioning & domain tags (frozen — see loginsocial.md §6) ──

/// On-chain verifier format version. Mirrored by `IKA_OIDC_VERIFIER_VERSION`
/// and embedded in the `oidc-session-open` challenge so a JWT only serves under
/// the version it was opened with.
pub const OIDC_VERIFIER_V1: u32 = 1;

/// Domain tag for `addr_seed` derivation.
pub const OIDC_ADDR_DOMAIN: &[u8] = b"andromeda::oidc::addr::v1";
/// Domain tag for the `oidc_nonce` derivation.
pub const OIDC_NONCE_DOMAIN: &[u8] = b"andromeda::oidc::nonce::v1";

// ── Bounds & policy constants ──────────────────────────────────

/// Hard cap on the JWT length (matches `OidcJwtStaging.jwt_bytes`).
pub const MAX_JWT_LEN: usize = 4096;
/// Max decoded JOSE header (a real one is ~60–100 B).
pub const MAX_HEADER_DECODED: usize = 256;
/// Max decoded payload. An `openid`-scope `id_token` is ~250 B; 1 KiB is slack
/// and keeps `verify`'s stack frame small.
pub const MAX_PAYLOAD_DECODED: usize = 1024;
/// The only RSA public exponent accepted.
pub const RSA_EXPONENT: u32 = 65_537;
/// Clock skew tolerance for `iat` / `nbf` (seconds).
pub const SKEW_SECONDS: i64 = 300;
/// Upper bound on `exp - iat` (Google ≈ 3600 s, Apple ≈ 600 s — 4 h is slack
/// that still rejects an absurdly long-lived crafted token).
pub const MAX_TOKEN_LIFETIME_SECONDS: i64 = 4 * 3600;
/// Length of the canonical base64url-no-pad `oidc_nonce` (32 bytes → 43 chars).
pub const OIDC_NONCE_B64_LEN: usize = 43;

// ── Public types ───────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct VerifyOidcInput<'a> {
    /// The compact JWS: `header.payload.signature` ASCII bytes.
    pub jwt: &'a [u8],
    /// RSA modulus `n`, big-endian, **exactly 256 bytes** (from the ACTIVE
    /// `JwkRegistry` entry).
    pub modulus_n: &'a [u8],
    /// RSA public exponent (from the registry entry) — must be `65537`.
    pub exponent_e: u32,
    /// Allowed `iss` values for this environment (constant set).
    pub allowed_issuers: &'a [&'a [u8]],
    /// Allowed `aud` values for this environment (the auth-broker `client_id`(s)).
    pub allowed_audiences: &'a [&'a [u8]],
    /// The user's ephemeral Ed25519 public key (from the instruction data).
    pub eph_pk: &'a [u8; 32],
    /// `not_after_unix_ts` chosen by the client (≤ the JWT's `exp`).
    pub not_after_unix_ts: u64,
    /// 32 bytes of nonce randomness (from the instruction data).
    pub nonce_randomness: &'a [u8; 32],
    /// `Clock` sysvar timestamp.
    pub now_unix_ts: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedOidc {
    /// `SHA256("andromeda::oidc::addr::v1" || lp(iss) || lp(aud) || lp(sub))`.
    pub addr_seed: [u8; 32],
    /// `SHA256(iss)` — registry lookup component.
    pub issuer_hash: [u8; 32],
    /// `SHA256(aud)` — registry lookup component.
    pub audience_hash: [u8; 32],
    /// `SHA256(kid)` — registry lookup component.
    pub kid_hash: [u8; 32],
    /// `SHA256(header.payload)` — the JWS signing input; bound into the
    /// `oidc-session-open` challenge.
    pub jwt_digest: [u8; 32],
    /// The `exp` claim, as `i64` seconds.
    pub exp_unix_ts: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcVerifyError {
    /// Empty / too long / not three non-empty segments / signature not 256 B.
    MalformedJwt,
    /// A segment is not valid canonical base64url-no-pad.
    Base64Decode,
    /// `exponent_e != 65537`.
    UnsupportedExponent,
    /// Modulus is not exactly 256 B, or not a full odd 2048-bit value.
    InvalidModulus,
    /// RSA verify / PKCS#1 EM mismatch, or `sig ≥ n`.
    BadSignature,
    /// Malformed JOSE header, missing/duplicate `alg`/`kid`, or `crit`/`jku`/`x5u` present.
    MalformedHeader,
    /// `alg != "RS256"`.
    UnsupportedAlg,
    /// Malformed claims JSON, missing/duplicate claim, array-valued `aud`, bad
    /// escape in a compared claim, or a malformed `iat`/`exp`/`nbf`.
    MalformedClaims,
    /// `iss` not in the environment allowlist.
    IssuerNotAllowed,
    /// `aud` not in the environment allowlist.
    AudienceNotAllowed,
    /// The `nonce` claim does not equal the recomputed `oidc_nonce`.
    NonceMismatch,
    /// `exp <= now`.
    TokenExpired,
    /// `exp < not_after_unix_ts`.
    ExpBeforeNotAfter,
    /// `iat > now + skew`.
    IssuedInFuture,
    /// `nbf > now + skew`.
    NotYetValid,
    /// `exp < iat` or `exp - iat` exceeds the plausible-lifetime cap.
    ImplausibleLifetime,
    /// The verifier was given an empty issuer/audience allowlist (misconfiguration).
    BadConfig,
}

// ── verify ─────────────────────────────────────────────────────

/// Verifies the JWT end-to-end. See the module docs for the step ordering — in
/// particular, *no claim is used for an auth decision before the RSA signature
/// is verified* (steps 6–8 follow step 5).
pub fn verify(input: VerifyOidcInput<'_>) -> Result<ParsedOidc, OidcVerifyError> {
    use OidcVerifyError as E;

    // 0. fixed-profile / structural pre-checks.
    if input.jwt.is_empty() || input.jwt.len() > MAX_JWT_LEN {
        return Err(E::MalformedJwt);
    }
    if input.exponent_e != RSA_EXPONENT {
        return Err(E::UnsupportedExponent);
    }
    if input.modulus_n.len() != RSA_BYTES {
        return Err(E::InvalidModulus);
    }
    let mut modulus = [0u8; RSA_BYTES];
    modulus.copy_from_slice(input.modulus_n);
    // Full 2048-bit (top bit set) and odd ⇒ a real RSA modulus.
    if modulus[0] & 0x80 == 0 || modulus[RSA_BYTES - 1] & 1 == 0 {
        return Err(E::InvalidModulus);
    }
    if input.allowed_issuers.is_empty() || input.allowed_audiences.is_empty() {
        return Err(E::BadConfig);
    }

    // 1. split into header.payload.signature.
    let seg = jwt::split(input.jwt)?;

    // 2. base64url-decode the three segments into bounded buffers.
    let mut hdr_buf = [0u8; MAX_HEADER_DECODED];
    let hdr = jwt::b64url_decode_into(seg.header_b64, &mut hdr_buf)?;
    let mut pl_buf = [0u8; MAX_PAYLOAD_DECODED];
    let pl = jwt::b64url_decode_into(seg.payload_b64, &mut pl_buf)?;
    let mut sig_buf = [0u8; RSA_BYTES];
    {
        let sig = jwt::b64url_decode_into(seg.sig_b64, &mut sig_buf)?;
        // RS256 signature must be exactly len(n) = 256 bytes.
        if sig.len() != RSA_BYTES {
            return Err(E::MalformedJwt);
        }
    }
    // Signature integer must be strictly < n.
    if !pkcs1::lt_be(&sig_buf, &modulus) {
        return Err(E::BadSignature);
    }

    // 3. strict, untrusted parse of header + claims.
    let header = claims::parse_header(hdr)?;
    let cl = claims::parse_claims(pl)?;

    // 4. issuer / audience allowlist (exact comparisons against a constant set).
    if !contains_exact(input.allowed_issuers, cl.iss) {
        return Err(E::IssuerNotAllowed);
    }
    if !contains_exact(input.allowed_audiences, cl.aud) {
        return Err(E::AudienceNotAllowed);
    }

    // 5. RSA verify (PKCS#1 v1.5, SHA-256) — encode-then-compare over all 256 bytes.
    let h = hash::sha256(seg.signing_input);
    let jwt_digest = h;
    let expected_em = pkcs1::build_em_sha256(&h);
    let recovered = pkcs1::rsa2048_modexp(&sig_buf, &modulus);
    if !pkcs1::eq_256(&recovered, &expected_em) {
        return Err(E::BadSignature);
    }

    // ── the claims are authentic from here on ──

    // 6. nonce binding.
    let nonce_recomputed = recompute_oidc_nonce(input.eph_pk, input.not_after_unix_ts, input.nonce_randomness);
    if cl.nonce != &nonce_recomputed[..] {
        return Err(E::NonceMismatch);
    }

    // 7. time validity.
    let now = input.now_unix_ts;
    if cl.exp <= now {
        return Err(E::TokenExpired);
    }
    let not_after_i = u64_sat_i64(input.not_after_unix_ts);
    if cl.exp < not_after_i {
        return Err(E::ExpBeforeNotAfter);
    }
    if cl.iat > now.saturating_add(SKEW_SECONDS) {
        return Err(E::IssuedInFuture);
    }
    if let Some(nbf) = cl.nbf {
        if nbf > now.saturating_add(SKEW_SECONDS) {
            return Err(E::NotYetValid);
        }
    }
    if cl.exp < cl.iat || cl.exp.saturating_sub(cl.iat) > MAX_TOKEN_LIFETIME_SECONDS {
        return Err(E::ImplausibleLifetime);
    }

    // 8. derive identity hashes + addr_seed.
    let kid_hash = hash::sha256(header.kid);
    let issuer_hash = hash::sha256(cl.iss);
    let audience_hash = hash::sha256(cl.aud);
    let addr_seed = derive_addr_seed(cl.iss, cl.aud, cl.sub);

    Ok(ParsedOidc { addr_seed, issuer_hash, audience_hash, kid_hash, jwt_digest, exp_unix_ts: cl.exp })
}

// ── derivations ────────────────────────────────────────────────

/// `SHA256("andromeda::oidc::addr::v1" || u16le(len(iss)) || iss || u16le(len(aud)) || aud || u16le(len(sub)) || sub)`.
pub fn derive_addr_seed(iss: &[u8], aud: &[u8], sub: &[u8]) -> [u8; 32] {
    let iss_len = (iss.len() as u16).to_le_bytes();
    let aud_len = (aud.len() as u16).to_le_bytes();
    let sub_len = (sub.len() as u16).to_le_bytes();
    hash::sha256v(&[OIDC_ADDR_DOMAIN, &iss_len, iss, &aud_len, aud, &sub_len, sub])
}

/// `base64url_nopad( SHA256("andromeda::oidc::nonce::v1" || eph_pk || not_after_unix_ts_le(u64) || nonce_randomness) )`.
pub fn recompute_oidc_nonce(eph_pk: &[u8; 32], not_after_unix_ts: u64, nonce_randomness: &[u8; 32]) -> [u8; OIDC_NONCE_B64_LEN] {
    let not_after_le = not_after_unix_ts.to_le_bytes();
    let h = hash::sha256v(&[OIDC_NONCE_DOMAIN, eph_pk, &not_after_le, nonce_randomness]);
    let mut out = [0u8; OIDC_NONCE_B64_LEN];
    jwt::encode_base64url_nopad_32(&h, &mut out);
    out
}

// ── small helpers ──────────────────────────────────────────────

#[inline]
fn contains_exact(set: &[&[u8]], v: &[u8]) -> bool {
    set.iter().any(|&e| e == v)
}

/// Saturating `u64 → i64`.
#[inline]
fn u64_sat_i64(v: u64) -> i64 {
    if v > i64::MAX as u64 {
        i64::MAX
    } else {
        v as i64
    }
}

// ── tests (host) ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_basics() {
        let mut out = [0u8; 8];
        assert_eq!(jwt::b64url_decode_into(b"AAAA", &mut out).unwrap(), &[0, 0, 0]);
        assert_eq!(jwt::b64url_decode_into(b"____", &mut out).unwrap(), &[0xff, 0xff, 0xff]);
        assert_eq!(jwt::b64url_decode_into(b"AA", &mut out).unwrap(), &[0]);
        assert_eq!(jwt::b64url_decode_into(b"AQ", &mut out).unwrap(), &[1]);
        assert_eq!(jwt::b64url_decode_into(b"AAA", &mut out).unwrap(), &[0, 0]);
        // rejects: '=' padding, '+'/'/', len % 4 == 1, non-canonical trailing bits, overflow
        assert!(jwt::b64url_decode_into(b"AAA=", &mut out).is_err());
        assert!(jwt::b64url_decode_into(b"AA+/", &mut out).is_err());
        assert!(jwt::b64url_decode_into(b"AAAAA", &mut out).is_err());
        assert!(jwt::b64url_decode_into(b"AB", &mut out).is_err()); // low 4 bits of 2nd char nonzero
        assert!(jwt::b64url_decode_into(b"AAB", &mut out).is_err()); // low 2 bits of 3rd char nonzero
        let mut tiny = [0u8; 1];
        assert!(jwt::b64url_decode_into(b"AAAA", &mut tiny).is_err()); // would need 3 bytes
    }

    #[test]
    fn split_basics() {
        let s = jwt::split(b"aGVhZA.cGF5bG9hZA.c2ln").unwrap();
        assert_eq!(s.header_b64, b"aGVhZA");
        assert_eq!(s.payload_b64, b"cGF5bG9hZA");
        assert_eq!(s.sig_b64, b"c2ln");
        assert_eq!(s.signing_input, b"aGVhZA.cGF5bG9hZA");
        assert!(jwt::split(b"a.b").is_err()); // only one dot
        assert!(jwt::split(b"a.b.c.d").is_err()); // three dots
        assert!(jwt::split(b".b.c").is_err()); // empty header
        assert!(jwt::split(b"a..c").is_err()); // empty payload
        assert!(jwt::split(b"a.b.").is_err()); // empty signature
    }

    #[test]
    fn header_ok_and_rejections() {
        assert!(claims::parse_header(br#"{"alg":"RS256","kid":"k1","typ":"JWT"}"#).is_ok());
        assert!(claims::parse_header(br#"{"kid":"k1"}"#).is_err()); // no alg
        assert_eq!(
            claims::parse_header(br#"{"alg":"HS256","kid":"k1"}"#).unwrap_err(),
            OidcVerifyError::UnsupportedAlg
        );
        assert!(claims::parse_header(br#"{"alg":"RS256"}"#).is_err()); // no kid
        assert!(claims::parse_header(br#"{"alg":"RS256","alg":"RS256","kid":"k1"}"#).is_err()); // dup
        assert!(claims::parse_header(br#"{"alg":"RS256","kid":"k1","crit":["x"]}"#).is_err());
        assert!(claims::parse_header(br#"{"alg":"RS256","kid":"k1","jku":"https://evil"}"#).is_err());
        assert!(claims::parse_header(br#"{"alg":"RS256","kid":"k1","x5u":"https://evil"}"#).is_err());
        assert!(claims::parse_header(br#"{"alg":"RS256","kid":"a\"b"}"#).is_err()); // backslash in kid
        assert!(claims::parse_header(br#"{"alg":"RS256","kid":"k1"} junk"#).is_err()); // trailing
        assert!(claims::parse_header(br#"{"alg":"RS256","kid":""}"#).is_err()); // empty kid
        assert!(claims::parse_header(br#"not json"#).is_err());
    }

    fn good_payload() -> &'static [u8] {
        br#"{"iss":"https://accounts.google.com","aud":"broker-id","sub":"107492837465019283746","nonce":"abcdefghijklmnopqrstuvwxyzABCDEF0123456789-_","iat":1770000000,"exp":1770003600,"azp":"x"}"#
    }

    #[test]
    fn claims_ok_and_rejections() {
        let c = claims::parse_claims(good_payload()).unwrap();
        assert_eq!(c.iss, b"https://accounts.google.com");
        assert_eq!(c.aud, b"broker-id");
        assert_eq!(c.iat, 1770000000);
        assert_eq!(c.exp, 1770003600);
        assert_eq!(c.nbf, None);
        // missing required claim
        assert!(claims::parse_claims(br#"{"aud":"x","sub":"s","nonce":"n","iat":1,"exp":2}"#).is_err());
        // duplicate aud
        assert!(claims::parse_claims(br#"{"iss":"i","aud":"a","aud":"b","sub":"s","nonce":"n","iat":1,"exp":2}"#).is_err());
        // array aud
        assert!(claims::parse_claims(br#"{"iss":"i","aud":["a","b"],"sub":"s","nonce":"n","iat":1,"exp":2}"#).is_err());
        // iat as string
        assert!(claims::parse_claims(br#"{"iss":"i","aud":"a","sub":"s","nonce":"n","iat":"1","exp":2}"#).is_err());
        // iat as float
        assert!(claims::parse_claims(br#"{"iss":"i","aud":"a","sub":"s","nonce":"n","iat":1.5,"exp":2}"#).is_err());
        // iat leading zero
        assert!(claims::parse_claims(br#"{"iss":"i","aud":"a","sub":"s","nonce":"n","iat":01,"exp":2}"#).is_err());
        // backslash in iss
        assert!(claims::parse_claims(br#"{"iss":"i\"x","aud":"a","sub":"s","nonce":"n","iat":1,"exp":2}"#).is_err());
        // nbf accepted
        let c2 = claims::parse_claims(br#"{"iss":"i","aud":"a","sub":"s","nonce":"n","iat":1,"exp":2,"nbf":3}"#).unwrap();
        assert_eq!(c2.nbf, Some(3));
    }

    #[test]
    fn nonce_and_addr_seed_deterministic() {
        let eph = [7u8; 32];
        let rand = [9u8; 32];
        let n1 = recompute_oidc_nonce(&eph, 1_770_003_000, &rand);
        let n2 = recompute_oidc_nonce(&eph, 1_770_003_000, &rand);
        assert_eq!(n1, n2);
        assert_eq!(n1.len(), OIDC_NONCE_B64_LEN);
        // all chars in the base64url alphabet
        assert!(n1.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
        // different not_after ⇒ different nonce
        let n3 = recompute_oidc_nonce(&eph, 1_770_003_001, &rand);
        assert_ne!(n1, n3);

        let a1 = derive_addr_seed(b"https://accounts.google.com", b"broker-id", b"sub-1");
        let a2 = derive_addr_seed(b"https://accounts.google.com", b"broker-id", b"sub-1");
        assert_eq!(a1, a2);
        let a3 = derive_addr_seed(b"https://accounts.google.com", b"broker-id", b"sub-2");
        assert_ne!(a1, a3);
        // length-prefixing makes concatenation unambiguous: ("ab","c") != ("a","bc")
        let x = derive_addr_seed(b"ab", b"c", b"d");
        let y = derive_addr_seed(b"a", b"bc", b"d");
        assert_ne!(x, y);
    }

    #[test]
    fn verify_pre_checks() {
        let n = [0u8; RSA_BYTES];
        let eph = [0u8; 32];
        let rand = [0u8; 32];
        let issuers: [&[u8]; 1] = [b"https://accounts.google.com"];
        let auds: [&[u8]; 1] = [b"broker-id"];
        let base = VerifyOidcInput {
            jwt: b"a.b.c",
            modulus_n: &n,
            exponent_e: RSA_EXPONENT,
            allowed_issuers: &issuers,
            allowed_audiences: &auds,
            eph_pk: &eph,
            not_after_unix_ts: 0,
            nonce_randomness: &rand,
            now_unix_ts: 1_770_000_000,
        };
        // wrong exponent
        assert_eq!(verify(VerifyOidcInput { exponent_e: 3, ..base }).unwrap_err(), OidcVerifyError::UnsupportedExponent);
        // bad modulus profile (all zeros: top bit not set, even)
        assert_eq!(verify(base).unwrap_err(), OidcVerifyError::InvalidModulus);
        // jwt too long
        let big = [b'a'; MAX_JWT_LEN + 1];
        assert_eq!(verify(VerifyOidcInput { jwt: &big, ..base }).unwrap_err(), OidcVerifyError::MalformedJwt);
        // empty allowlist ⇒ BadConfig (with an otherwise-ok modulus)
        let mut good_n = [0u8; RSA_BYTES];
        good_n[0] = 0x80;
        good_n[RSA_BYTES - 1] = 0x01;
        let empty: [&[u8]; 0] = [];
        assert_eq!(
            verify(VerifyOidcInput { modulus_n: &good_n, allowed_issuers: &empty, ..base }).unwrap_err(),
            OidcVerifyError::BadConfig
        );
        // a structurally-broken JWT fails at the split/decode phase (before any RSA work)
        assert!(verify(VerifyOidcInput { jwt: b"not-a-jwt", modulus_n: &good_n, ..base }).is_err());
    }
}
