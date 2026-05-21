//! Andromeda — Pyth adapter (Quasar).
//!
//! Normalises a Pyth `PriceUpdateV2` account (Pyth Solana Receiver, Pull V2)
//! into the **canonical 64-byte price view** that the `policy-engine`'s
//! `KIND_ORACLE` dispatch reads directly from `aux_data[0..64]`:
//!
//! ```text
//! [0..32]  feed_id        (opaque, not checked by policy-engine)
//! [32..40] price          i64 LE   — canonical decimal-1e8 fixed point
//! [40..48] confidence     u64 LE   — same scale as price
//! [48..56] _reserved
//! [56..64] publish_time   i64 LE
//! ```
//!
//! Why an adapter and not consuming `PriceUpdateV2` directly: its layout (and
//! Anchor discriminator) does not match the canonical view, and the audits of
//! 2026-05-16 / 2026-05-19 froze `KIND_ORACLE` on that canonical layout. The
//! adapter isolates Pyth so a future `PriceUpdateV2` revision never reopens the
//! policy-engine perimeter.
//!
//! The `FeedCache` account is a **raw PDA owned by this program** — created via
//! the System program with NO Quasar/Anchor discriminator, so byte 0 is the
//! start of `feed_id`. A normal `#[account]` would push an 8-byte discriminator
//! to offset 0 and corrupt every canonical field. `AdapterConfig` is a normal
//! `#[account]` (only this program reads it).
//!
//! Layout / IDs / offsets are empirically confirmed against a live mainnet
//! sponsored SOL/USD `PriceUpdateV2` account and frozen in `fixtures/pyth/`
//! (`pyth_fixtures.json`), mirrored by Rust + Go drift tests.
//!
//! pre-alpha: deployed on devnet only; do not custody real value.

#![no_std]
#![allow(dead_code)]

use quasar_lang::cpi::{system, Signer as CpiSigner};
use quasar_lang::prelude::*;
use solana_address::Address;

declare_id!("A6xjw8jkJTFjpjHCRSFxVt1d1KbBZdh3XBNYvTfLZxP2");

// ── Pyth constants (confirmed via live account 7UVimffx… on mainnet) ────────

/// Pyth Solana Receiver (Pull V2) — owner of every `PriceUpdateV2` account.
/// Same ID on mainnet and devnet. base58 `rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ`.
pub const PYTH_RECEIVER_PROGRAM_ID: Address = Address::new_from_array([
    12, 183, 250, 187, 82, 247, 166, 72, 187, 91, 49, 125, 154, 1, 139, 144, 87, 203, 2, 71, 116,
    250, 254, 1, 230, 196, 223, 152, 204, 56, 88, 129,
]);

/// Anchor account discriminator for `PriceUpdateV2`
/// (`sha256("account:PriceUpdateV2")[..8]`).
pub const PYTH_PRICE_UPDATE_V2_DISCRIMINATOR: [u8; 8] =
    [0x22, 0xf1, 0x23, 0x63, 0x9d, 0x7e, 0xf4, 0xcd];

/// Allocated size of a `PriceUpdateV2` account (Anchor `LEN`).
pub const PYTH_PRICE_UPDATE_V2_LEN: usize = 134;

/// `verification_level` byte value for `Full` (Borsh enum variant 1). `Partial`
/// is variant 0 and is rejected — only consensus-verified prices are accepted.
pub const VERIFICATION_FULL: u8 = 1;

// PriceUpdateV2 field offsets for a `Full` account (Borsh — `Full` is a 1-byte
// enum tag, so `price_message` starts at 41, NOT the 2-byte allocation slot).
const PU_VERIFICATION_LEVEL: usize = 40; // 1
const PU_FEED_ID: usize = 41; // 32
const PU_PRICE: usize = 73; // 8  i64 LE
const PU_CONF: usize = 81; // 8  u64 LE
const PU_EXPONENT: usize = 89; // 4  i32 LE
const PU_PUBLISH_TIME: usize = 93; // 8  i64 LE

// ── FeedCache raw layout (this program's owned PDA) ─────────────────────────

/// Total bytes of a `FeedCache` PDA.
pub const FEED_CACHE_LEN: usize = 136;

// Canonical view (bytes 0..64) — PUBLIC ABI read by `policy-engine`. Never
// change without updating `POLICY_ENGINE_ABI`, fixtures and drift tests.
const FC_FEED_ID: usize = 0; // 32
const FC_PRICE: usize = 32; // 8  i64 LE (decimal 1e8)
const FC_CONFIDENCE: usize = 40; // 8  u64 LE (decimal 1e8)
const FC_RESERVED: usize = 48; // 8  zero
const FC_PUBLISH_TIME: usize = 56; // 8  i64 LE

// Adapter metadata (bytes 64..136) — internal, may evolve with versioning.
const FC_PRICE_UPDATE: usize = 64; // 32  last PriceUpdateV2 account read
const FC_RAW_PRICE: usize = 96; // 8   i64 LE  raw Pyth price
const FC_RAW_CONF: usize = 104; // 8   u64 LE  raw Pyth conf
const FC_LAST_REFRESHED: usize = 112; // 8   i64 LE  on-chain clock at refresh
const FC_RAW_EXPONENT: usize = 120; // 4   i32 LE  raw Pyth exponent
const FC_REFRESH_COUNT: usize = 124; // 4   u32 LE  operational counter
const FC_PAUSED: usize = 128; // 1   per-feed kill switch (1 = paused)
                              // 129..136 pad

/// Canonical fixed-point exponent: stored value = real_price * 10^8.
pub const CANONICAL_EXPONENT: i32 = -8;

// ── Sanity caps ─────────────────────────────────────────────────────────────

/// Max age of a Pyth `publish_time` accepted by `refresh_feed`. The real
/// freshness gate is per-rule in the policy-engine; this is a coarse upper
/// bound to reject obviously stale updates.
pub const MAX_PRICE_STALENESS_SECONDS: i64 = 24 * 3_600;
/// Max time a `publish_time` may sit in the future (clock-skew tolerance).
/// Without this bound, a far-future timestamp from a compromised/buggy upstream
/// would be accepted and then permanently block the feed via the
/// strictly-advancing `publish_time` check (no later, normal-timestamped update
/// could ever beat it). Fail-closed: reject anything implausibly ahead.
pub const MAX_PRICE_FUTURE_SECONDS: i64 = 120;
/// Minimum spacing between two successful refreshes of the same feed.
pub const MIN_REFRESH_INTERVAL_SECONDS: i64 = 1;

pub const VERSION: u8 = 1;

const ZERO_ADDRESS: Address = Address::new_from_array([0u8; 32]);

// ── Program ─────────────────────────────────────────────────────────────────

#[program]
mod andromeda_pyth_adapter {
    use super::*;

    /// 0 — Create the singleton `AdapterConfig`. `authority` co-signs (so a
    /// front-runner cannot squat the PDA), `backup` is a separate ops key that
    /// alone may rotate authority and may also pause.
    #[instruction(discriminator = 0)]
    pub fn init_adapter(
        ctx: Ctx<InitAdapter>,
        authority_addr: Address,
        backup: Address,
    ) -> Result<(), ProgramError> {
        ctx.accounts.create(authority_addr, backup)?;
        emit!(AdapterInitialized {
            authority: authority_addr,
            backup,
        });
        Ok(())
    }

    /// 1 — Create a raw `FeedCache` PDA for `feed_id` (`seeds =
    /// [b"feed_cache", feed_id]`). `bump` is supplied by the caller; the
    /// `invoke_signed` create enforces it. Permissionless (F7.1): anyone may
    /// create a feed cache; integrity comes from on-chain Pyth verification at
    /// refresh, not from who calls.
    #[instruction(discriminator = 1)]
    pub fn init_feed_cache(
        ctx: Ctx<InitFeedCache>,
        feed_id: Address,
        bump: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.create(&feed_id, bump)?;
        emit!(FeedCacheCreated { feed_id });
        Ok(())
    }

    /// 2 — Read a `PriceUpdateV2`, validate it, normalise to the canonical view
    /// and persist it into the feed's `FeedCache`. authority-gated (the crank).
    #[instruction(discriminator = 2)]
    pub fn refresh_feed(ctx: Ctx<RefreshFeed>) -> Result<(), ProgramError> {
        ctx.accounts.refresh()
    }

    /// 3 — Rotate `authority`. Only `backup` may call (Vault Transit key in
    /// mainnet).
    #[instruction(discriminator = 3)]
    pub fn transfer_authority(
        ctx: Ctx<AdminConfig>,
        new_authority: Address,
    ) -> Result<(), ProgramError> {
        ctx.accounts.transfer_authority(new_authority)?;
        emit!(AuthorityTransferred { new_authority });
        Ok(())
    }

    /// 4 — Global kill switch. Callable by `authority` OR `backup`.
    #[instruction(discriminator = 4)]
    pub fn set_global_pause(ctx: Ctx<AdminConfig>, paused: u8) -> Result<(), ProgramError> {
        let normalised = ctx.accounts.set_global_pause(paused)?;
        emit!(GlobalPauseSet { paused: normalised });
        Ok(())
    }

    /// 5 — Per-feed kill switch. Callable by `authority` OR `backup`. Pausing
    /// also zeroes `publish_time` so the policy-engine rejects the feed
    /// immediately via its freshness check (fail-closed), not only at the next
    /// (blocked) refresh.
    #[instruction(discriminator = 5)]
    pub fn set_feed_pause(ctx: Ctx<AdminFeed>, paused: u8) -> Result<(), ProgramError> {
        ctx.accounts.set_feed_pause(paused)
    }
}

// ── Errors (Anchor convention → ProgramError::Custom(6000 + n)) ─────────────

#[error_code]
pub enum AdapterError {
    /// `price_update` is not owned by the Pyth Solana Receiver.
    InvalidPythProgram = 6000,
    /// `publish_time + MAX_PRICE_STALENESS_SECONDS < now` (or overflow).
    StaleFeed,
    /// Pyth reported a negative price (unsupported).
    NegativePrice,
    /// Exponent is positive, or the resulting 10^x scale overflowed.
    InvalidExponent,
    /// A successful refresh happened less than `MIN_REFRESH_INTERVAL_SECONDS` ago.
    RefreshTooSoon,
    /// `price_update` / `feed_cache` is too small or could not be borrowed.
    PriceUpdateMalformed,
    /// Parsed `feed_id` does not match the `FeedCache`'s stored `feed_id`.
    FeedIdMismatch,
    /// Normalisation result does not fit in the canonical integer type.
    PriceOverflow,
    /// The feed is paused (per-feed kill switch).
    FeedPaused,
    /// `price_update` discriminator is not `PriceUpdateV2`.
    PythDiscriminatorMismatch,
    /// `publish_time` did not strictly advance (replay / regression).
    PublishTimeRegression,
    /// Signer is not the configured `authority` / `backup` for this action.
    Unauthorized,
    /// `init_adapter`: a role is zero, or the two roles are equal, or the
    /// co-signer mismatches.
    InvalidRoles,
    /// `init_feed_cache`: the `FeedCache` already exists.
    AlreadyInitialized,
    /// The global kill switch is engaged.
    GlobalPaused,
}

// ── Events (log-based; informational for the relayer / metrics) ─────────────

#[event(discriminator = 0)]
pub struct AdapterInitialized {
    pub authority: Address,
    pub backup: Address,
}

#[event(discriminator = 1)]
pub struct FeedCacheCreated {
    pub feed_id: Address,
}

#[event(discriminator = 2)]
pub struct FeedRefreshed {
    pub feed_id: Address,
    pub price: i64,
    pub conf: u64,
    pub publish_time: i64,
}

#[event(discriminator = 3)]
pub struct AuthorityTransferred {
    pub new_authority: Address,
}

#[event(discriminator = 4)]
pub struct GlobalPauseSet {
    pub paused: u8,
}

#[event(discriminator = 5)]
pub struct FeedPauseSet {
    pub feed_id: Address,
    pub paused: u8,
}

// ── AdapterConfig (singleton; only this program reads it) ───────────────────

#[account(discriminator = 1, set_inner)]
#[seeds(b"adapter_config")]
pub struct AdapterConfig {
    pub version: u8,
    pub paused_global: u8,
    pub _pad0: [u8; 6],
    /// The crank key allowed to refresh / create feeds.
    pub authority: Address,
    /// Separate ops key: rotates authority and may pause.
    pub backup: Address,
}

// ── Pure helpers ────────────────────────────────────────────────────────────

#[inline]
fn rd_i64(b: &[u8], o: usize) -> i64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    i64::from_le_bytes(a)
}
#[inline]
fn rd_u64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}
#[inline]
fn rd_i32(b: &[u8], o: usize) -> i32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[o..o + 4]);
    i32::from_le_bytes(a)
}
#[inline]
fn rd_u32(b: &[u8], o: usize) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[o..o + 4]);
    u32::from_le_bytes(a)
}
#[inline]
fn wr_i64(b: &mut [u8], o: usize, v: i64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn wr_u64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn wr_i32(b: &mut [u8], o: usize, v: i32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn wr_u32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

#[inline]
fn pow10(e: u32) -> Option<u128> {
    10u128.checked_pow(e)
}

/// Normalise a signed Pyth value `(value, expo)` to canonical decimal 1e8:
/// `canonical = value * 10^(expo + 8)`. Scaling down (expo < -8) truncates
/// toward zero (value is non-negative here). Mirrored by `oraclerelay` (Go).
pub fn to_canonical_i64(value: i64, expo: i32) -> Result<i64, ProgramError> {
    let shift = expo + 8;
    if shift >= 0 {
        let scale = pow10(shift as u32).ok_or(AdapterError::PriceOverflow)?;
        let scaled = (value as i128)
            .checked_mul(scale as i128)
            .ok_or(AdapterError::PriceOverflow)?;
        i64::try_from(scaled).map_err(|_| AdapterError::PriceOverflow.into())
    } else {
        // A pow10 overflow here means an absurdly negative exponent (< -46);
        // it's an overflow of the divisor scale, so report PriceOverflow to
        // match the multiply branch (consistency). Unreachable with real Pyth
        // exponents (-5..-12).
        let scale = pow10((-shift) as u32).ok_or(AdapterError::PriceOverflow)?;
        Ok((value as i128 / scale as i128) as i64)
    }
}

/// Unsigned variant of [`to_canonical_i64`] (for `confidence`).
pub fn to_canonical_u64(value: u64, expo: i32) -> Result<u64, ProgramError> {
    let shift = expo + 8;
    if shift >= 0 {
        let scale = pow10(shift as u32).ok_or(AdapterError::PriceOverflow)?;
        let scaled = (value as u128)
            .checked_mul(scale)
            .ok_or(AdapterError::PriceOverflow)?;
        u64::try_from(scaled).map_err(|_| AdapterError::PriceOverflow.into())
    } else {
        // See to_canonical_i64: PriceOverflow for divisor-scale overflow.
        let scale = pow10((-shift) as u32).ok_or(AdapterError::PriceOverflow)?;
        Ok((value as u128 / scale) as u64)
    }
}

// ── InitAdapter ─────────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitAdapter {
    #[account(init, payer = payer, address = AdapterConfig::seeds())]
    pub config: Account<AdapterConfig>,
    /// Must equal the `authority_addr` argument.
    pub authority: Signer,
    #[account(mut)]
    pub payer: Signer,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
}

impl InitAdapter {
    #[inline(always)]
    pub fn create(&mut self, authority: Address, backup: Address) -> Result<(), ProgramError> {
        require!(
            *self.authority.address() == authority
                && authority != ZERO_ADDRESS
                && backup != ZERO_ADDRESS
                && authority != backup,
            AdapterError::InvalidRoles
        );
        self.config.set_inner(AdapterConfigInner {
            version: VERSION,
            paused_global: 0,
            _pad0: [0u8; 6],
            authority,
            backup,
        });
        Ok(())
    }
}

// ── InitFeedCache ───────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitFeedCache {
    #[account(address = AdapterConfig::seeds())]
    pub config: Account<AdapterConfig>,
    /// Raw PDA (`seeds = [b"feed_cache", feed_id]`), created here.
    #[account(mut)]
    pub feed_cache: UncheckedAccount,
    /// Funds the rent. Permissionless: any payer may create a feed's cache —
    /// there is exactly one canonical PDA per `feed_id` and the creator pays
    /// its rent, so this cannot be abused (no fake price is possible; that is
    /// gated by `refresh_feed`'s Pyth verification).
    #[account(mut)]
    pub payer: Signer,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
}

impl InitFeedCache {
    #[inline(always)]
    pub fn create(&mut self, feed_id: &Address, bump: u8) -> Result<(), ProgramError> {
        require!(self.config.paused_global == 0, AdapterError::GlobalPaused);
        require!(
            self.feed_cache.to_account_view().data_len() == 0,
            AdapterError::AlreadyInitialized
        );

        let bump_arr = [bump];
        let seeds = [
            Seed::from(b"feed_cache" as &[u8]),
            Seed::from(feed_id.as_ref()),
            Seed::from(bump_arr.as_ref()),
        ];
        let signer = CpiSigner::from(&seeds);

        let rent = &*self.rent;
        let payer_view = self.payer.to_account_view();
        // SAFETY: `feed_cache` is the instruction's own (unchecked) account; this
        // is the sole mutable view taken in this scope, and the borrow below goes
        // through try_borrow_mut() for proper aliasing checks.
        let fc_view = unsafe { self.feed_cache.to_account_view_mut() };
        system::init_account_with_rent(
            payer_view,
            &mut *fc_view,
            FEED_CACHE_LEN as u64,
            &crate::ID,
            &[signer],
            rent,
        )?;

        let mut fc = fc_view
            .try_borrow_mut()
            .map_err(|_| AdapterError::PriceUpdateMalformed)?;
        // Defensive: a successful init allocates exactly FEED_CACHE_LEN, so this
        // always holds — but assert it before slicing (consistency with refresh /
        // set_feed_pause, and a guard against any future allocation change).
        require!(
            fc.len() >= FEED_CACHE_LEN,
            AdapterError::PriceUpdateMalformed
        );
        fc[FC_FEED_ID..FC_FEED_ID + 32].copy_from_slice(feed_id.as_ref());
        Ok(())
    }
}

// ── RefreshFeed ─────────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct RefreshFeed {
    #[account(address = AdapterConfig::seeds())]
    pub config: Account<AdapterConfig>,
    #[account(mut)]
    pub feed_cache: UncheckedAccount,
    /// The Pyth `PriceUpdateV2` account (owned by the Pyth receiver).
    pub price_update: UncheckedAccount,
    pub clock: Sysvar<Clock>,
    // Permissionless: no signer. The price is verified from Pyth (owner +
    // discriminator + Full) and must strictly advance, so the caller (whoever
    // pays the tx fee) cannot inject a fake or stale price. This shifts the
    // refresh cost to whoever wants the feed fresh, not Andromeda.
}

impl RefreshFeed {
    #[inline(always)]
    pub fn refresh(&mut self) -> Result<(), ProgramError> {
        require!(self.config.paused_global == 0, AdapterError::GlobalPaused);

        let now: i64 = self.clock.unix_timestamp.into();

        // ── Parse the PriceUpdateV2 (read-only) ───────────────────────────
        let pu_view = self.price_update.to_account_view();
        require!(
            pu_view.owned_by(&PYTH_RECEIVER_PROGRAM_ID),
            AdapterError::InvalidPythProgram
        );
        let pu_addr = *pu_view.address();
        let pu = pu_view
            .try_borrow()
            .map_err(|_| AdapterError::PriceUpdateMalformed)?;
        require!(
            pu.len() >= PYTH_PRICE_UPDATE_V2_LEN,
            AdapterError::PriceUpdateMalformed
        );
        require!(
            pu[0..8] == PYTH_PRICE_UPDATE_V2_DISCRIMINATOR,
            AdapterError::PythDiscriminatorMismatch
        );
        require!(
            pu[PU_VERIFICATION_LEVEL] == VERIFICATION_FULL,
            AdapterError::PriceUpdateMalformed
        );
        let mut feed_id = [0u8; 32];
        feed_id.copy_from_slice(&pu[PU_FEED_ID..PU_FEED_ID + 32]);
        let raw_price = rd_i64(&pu, PU_PRICE);
        let raw_conf = rd_u64(&pu, PU_CONF);
        let expo = rd_i32(&pu, PU_EXPONENT);
        let publish_time = rd_i64(&pu, PU_PUBLISH_TIME);
        drop(pu);

        // ── Validate ──────────────────────────────────────────────────────
        require!(expo <= 0, AdapterError::InvalidExponent);
        require!(raw_price >= 0, AdapterError::NegativePrice);
        let expires_at = publish_time
            .checked_add(MAX_PRICE_STALENESS_SECONDS)
            .ok_or(AdapterError::StaleFeed)?;
        require!(expires_at >= now, AdapterError::StaleFeed);
        // Anti-future (defense-in-depth): bound how far ahead of the on-chain
        // clock a price may be timestamped, so a poisoned far-future update
        // cannot lock the feed forever via the strictly-advancing check.
        require!(
            publish_time <= now.saturating_add(MAX_PRICE_FUTURE_SECONDS),
            AdapterError::StaleFeed
        );

        let canon_price = to_canonical_i64(raw_price, expo)?;
        let canon_conf = to_canonical_u64(raw_conf, expo)?;

        // ── Persist into the raw FeedCache (read-write) ───────────────────
        //
        // No explicit PDA re-derivation is needed here. Two facts make the
        // `owned_by(crate::ID)` + `feed_id`-match pair sufficient to bind this
        // to the canonical FeedCache for the parsed feed:
        //   1. The only way to create an adapter-owned account is
        //      `init_feed_cache`, which uses `invoke_signed` with
        //      `[b"feed_cache", feed_id, bump]`; the runtime therefore forces
        //      every adapter-owned FeedCache to live at its canonical PDA.
        //   2. `init_feed_cache` writes `feed_id` into bytes [0..32].
        // Hence "adapter-owned ∧ feed_id == X" ⟹ "canonical PDA of X". refresh
        // is permissionless (F7.1): integrity comes from the owned_by check
        // below + the on-chain Pyth verification, NOT from who supplies the
        // accounts (a wrong account is rejected by owned_by / feed_id match).
        // SAFETY: feed_cache is the instruction's own account; this is the sole
        // mutable view taken in scope and the borrow below goes through
        // try_borrow_mut() for proper aliasing checks.
        let fc_view = unsafe { self.feed_cache.to_account_view_mut() };
        require!(fc_view.owned_by(&crate::ID), AdapterError::Unauthorized);
        let mut fc = fc_view
            .try_borrow_mut()
            .map_err(|_| AdapterError::PriceUpdateMalformed)?;
        require!(
            fc.len() >= FEED_CACHE_LEN,
            AdapterError::PriceUpdateMalformed
        );
        require!(
            fc[FC_FEED_ID..FC_FEED_ID + 32] == feed_id,
            AdapterError::FeedIdMismatch
        );
        require!(fc[FC_PAUSED] == 0, AdapterError::FeedPaused);
        let last_publish = rd_i64(&fc, FC_PUBLISH_TIME);
        require!(
            publish_time > last_publish,
            AdapterError::PublishTimeRegression
        );
        let last_refreshed = rd_i64(&fc, FC_LAST_REFRESHED);
        require!(
            now.saturating_sub(last_refreshed) >= MIN_REFRESH_INTERVAL_SECONDS,
            AdapterError::RefreshTooSoon
        );

        wr_i64(&mut fc, FC_PRICE, canon_price);
        wr_u64(&mut fc, FC_CONFIDENCE, canon_conf);
        wr_i64(&mut fc, FC_PUBLISH_TIME, publish_time);
        fc[FC_PRICE_UPDATE..FC_PRICE_UPDATE + 32].copy_from_slice(pu_addr.as_ref());
        wr_i64(&mut fc, FC_RAW_PRICE, raw_price);
        wr_u64(&mut fc, FC_RAW_CONF, raw_conf);
        wr_i64(&mut fc, FC_LAST_REFRESHED, now);
        wr_i32(&mut fc, FC_RAW_EXPONENT, expo);
        let count = rd_u32(&fc, FC_REFRESH_COUNT).wrapping_add(1);
        wr_u32(&mut fc, FC_REFRESH_COUNT, count);
        drop(fc);

        emit!(FeedRefreshed {
            feed_id: Address::new_from_array(feed_id),
            price: canon_price,
            conf: canon_conf,
            publish_time,
        });
        Ok(())
    }
}

// ── AdminConfig (transfer_authority / set_global_pause) ─────────────────────

#[derive(Accounts)]
pub struct AdminConfig {
    #[account(mut, address = AdapterConfig::seeds())]
    pub config: Account<AdapterConfig>,
    pub signer: Signer,
}

impl AdminConfig {
    #[inline(always)]
    pub fn transfer_authority(&mut self, new_authority: Address) -> Result<(), ProgramError> {
        require!(
            *self.signer.address() == self.config.backup,
            AdapterError::Unauthorized
        );
        require!(
            new_authority != ZERO_ADDRESS && new_authority != self.config.backup,
            AdapterError::InvalidRoles
        );
        self.config.authority = new_authority;
        Ok(())
    }

    #[inline(always)]
    pub fn set_global_pause(&mut self, paused: u8) -> Result<u8, ProgramError> {
        let signer = *self.signer.address();
        require!(
            signer == self.config.authority || signer == self.config.backup,
            AdapterError::Unauthorized
        );
        let normalised = u8::from(paused != 0);
        self.config.paused_global = normalised;
        Ok(normalised)
    }
}

// ── AdminFeed (set_feed_pause) ──────────────────────────────────────────────

#[derive(Accounts)]
pub struct AdminFeed {
    #[account(address = AdapterConfig::seeds())]
    pub config: Account<AdapterConfig>,
    #[account(mut)]
    pub feed_cache: UncheckedAccount,
    pub signer: Signer,
}

impl AdminFeed {
    #[inline(always)]
    pub fn set_feed_pause(&mut self, paused: u8) -> Result<(), ProgramError> {
        let signer = *self.signer.address();
        require!(
            signer == self.config.authority || signer == self.config.backup,
            AdapterError::Unauthorized
        );
        let normalised = u8::from(paused != 0);

        // SAFETY: feed_cache is the instruction's own account; this is the sole
        // mutable view taken in scope and the borrow below goes through
        // try_borrow_mut() for proper aliasing checks.
        let fc_view = unsafe { self.feed_cache.to_account_view_mut() };
        require!(fc_view.owned_by(&crate::ID), AdapterError::Unauthorized);
        let mut fc = fc_view
            .try_borrow_mut()
            .map_err(|_| AdapterError::PriceUpdateMalformed)?;
        require!(
            fc.len() >= FEED_CACHE_LEN,
            AdapterError::PriceUpdateMalformed
        );

        fc[FC_PAUSED] = normalised;
        if normalised == 1 {
            // Force-stale so the policy-engine rejects the feed at once.
            wr_i64(&mut fc, FC_PUBLISH_TIME, 0);
        }
        let mut feed_id = [0u8; 32];
        feed_id.copy_from_slice(&fc[FC_FEED_ID..FC_FEED_ID + 32]);
        drop(fc);

        emit!(FeedPauseSet {
            feed_id: Address::new_from_array(feed_id),
            paused: normalised,
        });
        Ok(())
    }
}
