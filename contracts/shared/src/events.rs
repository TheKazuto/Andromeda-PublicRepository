//! Canonical event family emitted by every Andromeda policy template.
//!
//! Each template re-declares these events with `#[event(discriminator = N)]`
//! locally because Quasar requires events to be declared inside the same
//! crate that emits them. This module documents the canonical schema so all
//! templates stay aligned for the off-chain webhook listener.

use quasar_lang::prelude::*;

/// Emitted on `init_policy` (each template uses discriminator 0).
#[event(discriminator = 0)]
pub struct PolicyDeployed {
    pub policy: Address,
    pub dwallet: Address,
    pub owner: Address,
    pub ts: i64,
}

/// Emitted before constraint checks. Mirrors the request hash so off-chain
/// observers can correlate with the eventual approval/rejection.
#[event(discriminator = 1)]
pub struct SignatureRequested {
    pub policy: Address,
    pub request_hash: Address,
    pub ts: i64,
}

/// Emitted right before the CPI to Ika fires.
#[event(discriminator = 2)]
pub struct SignatureApproved {
    pub policy: Address,
    pub request_hash: Address,
    pub ts: i64,
}

/// Emitted when a constraint check fails — `reason_code` mirrors the
/// template's error code (offset 6000+). Field order keeps the struct
/// padding-free: i64 (align 8) before u32 (align 4).
#[event(discriminator = 3)]
pub struct SignatureRejected {
    pub policy: Address,
    pub request_hash: Address,
    pub ts: i64,
    pub reason_code: u64,
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
