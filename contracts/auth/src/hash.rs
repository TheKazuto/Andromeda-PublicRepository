//! Thin wrapper over Solana's `sol_sha256` syscall.
//!
//! We avoid `solana-sha256-hasher` because its transitive dependencies pull in
//! `std`, which conflicts with our `#![no_std]` SBF build. The syscall takes
//! the raw layout of `&[&[u8]]` (a slice of fat pointers, each
//! `(ptr: u64, len: u64)`), which is exactly what the Solana runtime expects.

#[cfg(target_os = "solana")]
extern "C" {
    fn sol_sha256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64;
}

/// Computes `SHA-256(concat(parts...))` using the Solana runtime syscall.
///
/// **L1 (audit 2026-05) hardening**: panics on non-SBF targets instead of
/// silently returning 32 zero bytes. Returning all zeros made it possible
/// for a host-side accidental call to produce a deterministic but
/// trivially-collision-prone hash (every input maps to the same digest),
/// which is a footgun for any caller that uses this for PDA derivation,
/// nonce, or challenge construction. Production code must run under
/// `target_os = "solana"`; host tests should use `litesvm` or stub this
/// at the call site.
#[inline]
pub fn hashv(parts: &[&[u8]]) -> [u8; 32] {
    #[cfg(target_os = "solana")]
    {
        let mut result = [0u8; 32];
        unsafe {
            sol_sha256(
                parts as *const _ as *const u8,
                parts.len() as u64,
                result.as_mut_ptr(),
            );
        }
        result
    }
    #[cfg(not(target_os = "solana"))]
    {
        let _ = parts;
        panic!(
            "andromeda_auth::hash::hashv called on non-SBF target — \
             this hash MUST run inside the Solana runtime; use litesvm \
             or stub at the call site for host tests."
        );
    }
}
