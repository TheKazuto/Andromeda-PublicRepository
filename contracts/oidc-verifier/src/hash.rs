//! SHA-256: the `sol_sha256` syscall on SBF; the `sha2` crate on the host.
//!
//! Unlike `andromeda_auth::hash::hashv` (which panics off-SBF on purpose), this
//! one has a real host implementation so that `oidc-verifier`'s unit tests
//! compute the exact same digests the runtime would (the `addr_seed` /
//! `oidc_nonce` derivations are tested on the host). The SBF path is identical
//! in behaviour.

#[cfg(target_os = "solana")]
extern "C" {
    fn sol_sha256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64;
}

/// `SHA-256(concat(parts...))`.
#[inline]
pub fn sha256v(parts: &[&[u8]]) -> [u8; 32] {
    #[cfg(target_os = "solana")]
    {
        let mut result = [0u8; 32];
        // The syscall takes the raw layout of `&[&[u8]]` (a slice of
        // `(ptr: u64, len: u64)` fat pointers) — exactly what the runtime wants.
        unsafe {
            sol_sha256(parts as *const _ as *const u8, parts.len() as u64, result.as_mut_ptr());
        }
        result
    }
    #[cfg(not(target_os = "solana"))]
    {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        let out = h.finalize();
        let mut r = [0u8; 32];
        r.copy_from_slice(&out);
        r
    }
}

/// `SHA-256(data)`.
#[inline]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha256v(&[data])
}
