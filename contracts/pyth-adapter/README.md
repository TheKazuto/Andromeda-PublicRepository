# andromeda-pyth-adapter

Quasar (Solana) program that normalises a Pyth `PriceUpdateV2` account into the
**canonical 64-byte price view** consumed by the `policy-engine` `KIND_ORACLE`
dispatch. It is the only oracle provider Andromeda supports.

Pre-alpha, devnet only — do not custody real value.

Program id (devnet, deployed): `A6xjw8jkJTFjpjHCRSFxVt1d1KbBZdh3XBNYvTfLZxP2`
(keypair: `program-keypair.json`; upgrade authority `B98zhthMGHUexMAwuJvud83M4LKTQgw6CbtgXS5vPgBZ`).

## Why

`policy-engine` reads an oracle price straight from `aux_data[0..64]`:

```
[0..32]  feed_id        (opaque)
[32..40] price          i64 LE   — decimal 1e8 (1 USD = 100_000_000)
[40..48] confidence     u64 LE   — same scale
[48..56] _reserved
[56..64] publish_time   i64 LE
```

A Pyth `PriceUpdateV2` does not match this layout (Anchor account, different
offsets). The adapter parses it manually (no `pyth-solana-receiver-sdk`, which
pulls `anchor-lang`) and re-writes the canonical view into a per-feed PDA.

## FeedCache — raw owned PDA

`FeedCache` is **not** a normal `#[account]` (that puts an 8-byte discriminator
at offset 0 and would corrupt `feed_id`/`price`/...). It is created via the
System program with NO discriminator, owned by this program. Layout (136 bytes):

```
0..64    canonical view (ABI — policy-engine reads this; DO NOT change without
         updating fixtures + drift tests + POLICY_ENGINE ABI)
64..96   price_update   (last PriceUpdateV2 account read)
96..104  raw_price i64 | 104..112 raw_conf u64 | 112..120 last_refreshed i64
120..124 raw_exponent i32 | 124..128 refresh_count u32 | 128 paused u8
```

`seeds = [b"feed_cache", feed_id]`.

## Instructions

| Disc | Name | Signer | Purpose |
|------|------|--------|---------|
| 0 | `init_adapter(authority, backup)` | authority co-signs | create singleton `AdapterConfig` |
| 1 | `init_feed_cache(feed_id, bump)` | anyone (permissionless) | create the raw `FeedCache` PDA |
| 2 | `refresh_feed` | anyone (permissionless) | parse `PriceUpdateV2`, normalise, write canonical view |
| 3 | `transfer_authority(new_authority)` | backup | rotate the authority |
| 4 | `set_global_pause(paused)` | authority OR backup | global kill switch |
| 5 | `set_feed_pause(paused)` | authority OR backup | per-feed kill switch (also force-stales) |

`init_feed_cache` and `refresh_feed` are **permissionless** (F7.1): price
integrity comes from the on-chain Pyth verification in `refresh_feed`, not from
who calls — a wrong account is rejected by the owner/discriminator/feed_id
checks. Only the kill switches (`pause`) and `transfer_authority` are gated.

Errors map to `ProgramError::Custom(6000 + n)` (see `AdapterError`).

## `refresh_feed` gates

- `price_update.owner == rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ` (Pyth receiver)
- Anchor discriminator == `PriceUpdateV2` (`22 f1 23 63 9d 7e f4 cd`)
- `verification_level == Full` (Partial rejected)
- `exponent <= 0`, `price >= 0`
- `publish_time` strictly advances (anti-replay), is within 24h (anti-stale), and
  is not implausibly in the future (anti-future skew)
- normalisation overflow → error

`PriceUpdateV2` is Borsh: `Full` is a 1-byte enum tag, so `feed_id` starts at
offset 41 (not 48). Layout frozen in `../../fixtures/pyth/` (captured from a live
mainnet account) and asserted by Rust + Go drift tests.

## Build & test

```bash
cargo build-sbf                                   # this program
# SBF integration tests (loads the .so into Quasar SVM):
(cd ../sbf-tests && cargo test --test pyth_adapter)
```

The on-chain ↔ off-chain integration is also covered by
`contracts/sbf-tests/tests/policy_engine_v3.rs` (oracle dispatch reads an
adapter-owned canonical cache) and `gateway/internal/oraclerelay/pyth_test.go`
(Go normaliser mirror).

## Keeping feeds fresh (sponsored by the gateway)

The hosted gateway sponsors the refresh so a developer never needs SOL or a
Solana keypair. A feed is made fresh at the moment it matters — when a signature
is produced:

- **Refresh-on-sign (default):** the gateway prepends a `refresh_feed` to every
  gas-sponsored `request_signature` that reads a sponsored `FeedCache`, so the
  price the rule checks is fresh at signing time
  (`gateway/internal/oraclerelay/refresher.go`).
- **Managed price-trigger monitor (default for triggers):** for "fire when price
  hits X", the gateway reads the live price off-chain and submits the
  `request_signature` when the band holds (`gateway/internal/oraclemonitor/`).
- **Periodic crank (off by default):** the leader-elected crank
  (`gateway/internal/oraclerelay/`) can periodically call `refresh_feed`; it is
  retired by default (`PYTH_ADAPTER_CRANK_ENABLED=false`) since the two paths
  above keep feeds fresh on demand. The crank service still runs the one-shot
  bootstrap that creates each `FeedCache`.

Because `refresh_feed` is permissionless, a keeper or client can also assemble
`[post_update + refresh_feed + request_signature]` and pay for it itself
(on-demand). MVP feed sources are Pyth sponsored price feed accounts.
