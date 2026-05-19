//! RSA-2048 / RS256 verification primitives: the `sol_big_mod_exp` syscall
//! wrapper, the EMSA-PKCS1-v1_5 (SHA-256) expected encoded message, and a
//! full-block constant-flow comparison.
//!
//! The verify is "encode-then-compare": we build the *expected* 256-byte EM
//! block from the SHA-256 of the JWS signing input, compute
//! `recovered = sig^65537 mod n`, and require `recovered == EM` over **all
//! 256 bytes** with no early return. This rejects the classic Bleichenbacher /
//! "BERserk" family (DigestInfo in the wrong place, short padding, trailing
//! garbage, low-exponent forgeries) — anything that is not the one canonical EM
//! fails.

pub const RSA_BYTES: usize = 256;

/// DigestInfo prefix for SHA-256 (RFC 8017 EMSA-PKCS1-v1_5), 19 bytes.
const DIGEST_INFO_SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Number of `0xFF` padding bytes: `256 - 2 (00 01) - 1 (00 separator) - 19 (DigestInfo) - 32 (hash)`.
const PS_LEN: usize = RSA_BYTES - 2 - 1 - DIGEST_INFO_SHA256.len() - 32; // == 202

/// Builds the canonical EMSA-PKCS1-v1_5 encoded message for a 32-byte SHA-256
/// digest under a 2048-bit modulus:
/// `00 01 || FF*202 || 00 || DigestInfo(SHA-256) || h`.
pub fn build_em_sha256(h: &[u8; 32]) -> [u8; RSA_BYTES] {
    let mut em = [0u8; RSA_BYTES];
    em[0] = 0x00;
    em[1] = 0x01;
    let ps_end = 2 + PS_LEN; // index of the 0x00 separator
    for b in em.iter_mut().take(ps_end).skip(2) {
        *b = 0xFF;
    }
    em[ps_end] = 0x00;
    em[ps_end + 1..ps_end + 1 + DIGEST_INFO_SHA256.len()].copy_from_slice(&DIGEST_INFO_SHA256);
    em[ps_end + 1 + DIGEST_INFO_SHA256.len()..RSA_BYTES].copy_from_slice(h);
    em
}

/// `a == b` over all 256 bytes, accumulating differences (no data-dependent
/// branch, no early return).
///
/// M4 audit fix (2026-05-16): the final equality is now branchless. The XOR
/// accumulation was already constant-time, but the trailing `diff == 0` was a
/// compiler-visible branch on a secret-tainted byte. Result: a 0/1 bool
/// derived via `(diff.wrapping_sub(1) >> 8) & 1` — purely arithmetic.
pub fn eq_256(a: &[u8; RSA_BYTES], b: &[u8; RSA_BYTES]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..RSA_BYTES {
        diff |= a[i] ^ b[i];
    }
    // 0 ⇒ true (1), anything else ⇒ false (0). Underflow on 0 wraps to 0xFF…;
    // shifting the top bit of the u16 result into bit 0 yields exactly that.
    (((diff as u16).wrapping_sub(1) >> 8) as u8) & 1 == 1
}

/// `a < b` for two equal-length big-endian byte strings (used to reject a
/// signature integer `≥ n`).
///
/// M3 audit fix (2026-05-16): constant-flow comparison. The classic
/// short-circuiting variant could leak the most-significant differing-bit
/// position via timing. `n` is public (it comes from the JWK registry), so
/// the practical leak is minimal — but on-chain code should never rely on
/// "the secret isn't here" arguments for crypto primitives.
///
/// Algorithm: walk every byte, tracking two 1-bit flags (`gt`, `lt`).
/// `done` becomes 1 once either flag has been latched; remaining bytes are
/// then ignored without branching on data values.
pub fn lt_be(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    let mut lt: u8 = 0;
    let mut gt: u8 = 0;
    for i in 0..a.len() {
        let ai = a[i];
        let bi = b[i];
        // `a_lt_b` = 1 iff ai < bi, 0 otherwise. Branchless via subtraction:
        // (bi - ai) overflows when bi < ai, producing high bit. The XOR
        // pattern flips the result so we get a clean 0/1.
        let a_lt_b = ((ai as u16).wrapping_sub(bi as u16) >> 15) as u8 & 1;
        let a_gt_b = ((bi as u16).wrapping_sub(ai as u16) >> 15) as u8 & 1;
        // `done = gt | lt`. We only latch into lt/gt if `done == 0`, i.e.
        // the first differing byte wins (matches big-endian semantics).
        let done = gt | lt;
        let mask = done ^ 1; // 1 while undecided, 0 once decided
        lt |= mask & a_lt_b;
        gt |= mask & a_gt_b;
    }
    lt == 1
}

// ── modexp: syscall on SBF, num-bigint on the host ─────────────
//
// SBF code paths are gated on the `oidc-rsa` cargo feature. When OFF (e.g.
// when targeting a Solana cluster where the `sol_big_mod_exp` feature gate
// is not yet active), `rsa2048_modexp` now returns an explicit error
// (`OidcVerifyError::BadSignature`) rather than a 0xFF sentinel buffer —
// L4 audit fix (2026-05-16). The previous sentinel design was "rejects all
// inputs, by accident, because the PKCS#1 padding check downstream
// happens to fail." A future refactor that changes the PKCS#1 layout
// (e.g. PSS) would silently turn into "accepts all inputs." Explicit
// `Err` removes that footgun. Login Social via OIDC remains unavailable
// until the syscall lights up and the program is redeployed with the
// feature on.

#[cfg(all(target_os = "solana", feature = "oidc-rsa"))]
#[repr(C)]
struct BigModExpParams {
    base: *const u8,
    base_len: u64,
    exponent: *const u8,
    exponent_len: u64,
    modulus: *const u8,
    modulus_len: u64,
}

#[cfg(all(target_os = "solana", feature = "oidc-rsa"))]
extern "C" {
    fn sol_big_mod_exp(params: *const u8, result: *mut u8) -> u64;
}

/// `recovered = base^65537 mod modulus`, all big-endian, all exactly 256 bytes.
///
/// Returns `Err(OidcVerifyError::BadSignature)` when built with `oidc-rsa` off
/// on Solana — see L4 audit fix above.
pub fn rsa2048_modexp(
    base: &[u8; RSA_BYTES],
    modulus: &[u8; RSA_BYTES],
) -> Result<[u8; RSA_BYTES], crate::OidcVerifyError> {
    let mut result = [0u8; RSA_BYTES];
    #[cfg(all(target_os = "solana", feature = "oidc-rsa"))]
    {
        const EXP: [u8; 3] = [0x01, 0x00, 0x01]; // 65537, big-endian
        let params = BigModExpParams {
            base: base.as_ptr(),
            base_len: RSA_BYTES as u64,
            exponent: EXP.as_ptr(),
            exponent_len: EXP.len() as u64,
            modulus: modulus.as_ptr(),
            modulus_len: RSA_BYTES as u64,
        };
        unsafe {
            sol_big_mod_exp(&params as *const BigModExpParams as *const u8, result.as_mut_ptr());
        }
    }
    #[cfg(all(target_os = "solana", not(feature = "oidc-rsa")))]
    {
        // L4 audit fix (2026-05-16): explicit error instead of sentinel.
        let _ = (base, modulus, result);
        return Err(crate::OidcVerifyError::BadSignature);
    }
    #[cfg(not(target_os = "solana"))]
    {
        const EXP: [u8; 3] = [0x01, 0x00, 0x01];
        let _ = EXP; // host implementation uses BigUint::from(65_537u32) below
        use num_bigint::BigUint;
        let b = BigUint::from_bytes_be(base);
        let e = BigUint::from(65_537u32);
        let m = BigUint::from_bytes_be(modulus);
        let r = b.modpow(&e, &m).to_bytes_be();
        // right-align into the 256-byte buffer (big-endian, leading zeros)
        let n = r.len().min(RSA_BYTES);
        result[RSA_BYTES - n..].copy_from_slice(&r[r.len() - n..]);
    }
    Ok(result)
}
