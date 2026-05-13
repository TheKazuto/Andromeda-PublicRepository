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
pub fn eq_256(a: &[u8; RSA_BYTES], b: &[u8; RSA_BYTES]) -> bool {
    let mut diff = 0u8;
    for i in 0..RSA_BYTES {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// `a < b` for two equal-length big-endian byte strings (used to reject a
/// signature integer `≥ n`).
pub fn lt_be(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    for i in 0..a.len() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false // equal ⇒ not strictly less
}

// ── modexp: syscall on SBF, num-bigint on the host ─────────────

#[cfg(target_os = "solana")]
#[repr(C)]
struct BigModExpParams {
    base: *const u8,
    base_len: u64,
    exponent: *const u8,
    exponent_len: u64,
    modulus: *const u8,
    modulus_len: u64,
}

#[cfg(target_os = "solana")]
extern "C" {
    fn sol_big_mod_exp(params: *const u8, result: *mut u8) -> u64;
}

/// `recovered = base^65537 mod modulus`, all big-endian, all exactly 256 bytes.
pub fn rsa2048_modexp(base: &[u8; RSA_BYTES], modulus: &[u8; RSA_BYTES]) -> [u8; RSA_BYTES] {
    const EXP: [u8; 3] = [0x01, 0x00, 0x01]; // 65537, big-endian
    let mut result = [0u8; RSA_BYTES];
    #[cfg(target_os = "solana")]
    {
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
    #[cfg(not(target_os = "solana"))]
    {
        use num_bigint::BigUint;
        let b = BigUint::from_bytes_be(base);
        let e = BigUint::from(65_537u32);
        let m = BigUint::from_bytes_be(modulus);
        let r = b.modpow(&e, &m).to_bytes_be();
        // right-align into the 256-byte buffer (big-endian, leading zeros)
        let n = r.len().min(RSA_BYTES);
        result[RSA_BYTES - n..].copy_from_slice(&r[r.len() - n..]);
    }
    result
}
