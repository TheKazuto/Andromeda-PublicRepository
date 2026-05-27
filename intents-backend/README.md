# intents-backend

Stateless private engine that powers **Andromeda Intents** — practical
multichain swaps (AI-native, via REST + MCP) executed over Ika dWallets
(custody-free), with liquidity from the LI.FI aggregator.

It is the **router**: it talks to LI.FI, builds the unsigned swap transaction,
exposes the exact bytes to sign, and after the gateway returns the dWallet
signature inserts it and broadcasts. It never touches keys, policy, or billing.

## Supported chain families

Each family plugs in as a `ChainAdapter` (see `internal/swap/adapter.go`); adding
a new family is one file (`adapter_<family>.go`) registered in `NewService`.

| Family (`chainKind`) | Curve / scheme | Envelope | LI.FI coverage |
|---|---|---|---|
| `evm` | Secp256k1 / EcdsaKeccak256 (0) | EIP-1559 (type 2) + EIP-155 legacy (type 0) fallback | 69 chains (Ethereum, Arbitrum, Base, BNB, OP, Polygon, Avalanche, HyperEVM, Monad, Hyperliquid, …) |
| `solana` | Curve25519 / EddsaSha512 (5) | none (raw message bytes) | 1 (Solana mainnet) |
| `sui` | Curve25519 / EddsaSha512 (5) | Sui intent (BCS `[0,0,0] \|\| txBytes` → blake2b256) | 1 (Sui mainnet) |

**Not covered:** Bitcoin (UTXO). LI.FI roteia BTC via NEAR Intents and requires
a BIP32 xpub at quote time — the Andromeda dWallet is a single key, not an HD
tree, so single-address support would need either a synthesized xpub (risky in
pre-alpha) or a dWallet v2 with BIP32 derivation. See
`Updates Andromeda/Updates intents/_SPIKE_BITCOIN_LIFI.md`.

Total: 71 of 72 chains LI.FI routes today (≥98%).

Scope: **swaps on EVM, Solana and Sui, same-chain and cross-chain (bridge)**.

## EVM signing model

1. LI.FI returns a `transactionRequest` ({to, from, data, value, gas, fees,
   chainId, nonce}). `/prepare` validates `from == dWallet` and assigns the
   chain's pending nonce. It then builds the unsigned signing payload based on
   the fee fields LI.FI returned:
   - **EIP-1559 (type 2)** when `maxFeePerGas` is present: `0x02 || rlp([chainId,
     nonce, maxPriorityFee, maxFee, gas, to, value, data, []])`.
   - **EIP-155 legacy (type 0)** when LI.FI returns only `gasPrice` (BSC and a
     few others): `rlp([nonce, gasPrice, gas, to, value, data, chainId, 0, 0])`.
   The persisted snapshot carries the `txType` so `/finalize` re-encodes with
   the matching envelope.

   When the input is an ERC20 whose allowance for the router is insufficient,
   `/prepare` also builds an `approve` tx to run before the swap (approve at
   nonce N, swap at N+1) on the same tx type as the swap.
   `messageToSignHex` is the unsigned payload; the gateway forwards it to
   `prepare-message` (eip155, scheme 0 = ECDSA-Keccak256). `messageDigestHex`
   is `keccak256(messageToSignHex)` — the on-chain `MessageApproval` PDA key.
2. The gateway authorizes via PolicyEngine and signs via `ika-backend`, getting
   a 65-byte ECDSA signature `r||s||v` (v = yParity for type-2, EIP-155 v for
   type-0).
3. `/finalize` appends the signature to the RLP and broadcasts via
   `eth_sendRawTransaction`, failing over across the chain's RPCs. The EVM tx
   hash is `keccak256(signed)`, so an ambiguous broadcast still returns a hash
   to reconcile. RLP + keccak are hand-rolled (no go-ethereum dependency).

## Boundaries (do not cross)

- **Private network only.** The gateway is the sole caller, authenticating with
  `X-Internal-Key`. This service is never exposed to the public internet.
- **Stateless.** No database. The intent state lives in the gateway's Postgres
  (the gateway owns the schema). This service scales horizontally by replicas.
- **No multi-tenant auth / rate-limit / quota / billing.** Those belong to the
  gateway. This service only protects itself and LI.FI (circuit breaker +
  local backpressure).
- **Custody-free.** Signing happens in `ika-backend` via the gateway. This
  service only inserts a signature the gateway hands it and broadcasts.

## Gas model

The Andromeda gas-sponsor pays **only** the Ika protocol (PolicyEngine approval)
transactions, which are Solana txs built by the gateway. The **swap** transaction
is signed by the dWallet and broadcast here, so it is paid from the **dWallet's
own source-chain balance** — it never passes through the gas-sponsor. The dWallet
must hold the source chain's native token (SOL on Solana, ETH/BNB/… on EVM,
SUI on Sui) for gas; `/prepare` returns `nativeFeeEstimate` (and
`requiresAtaCreation` for Solana) so the caller can pre-check via
`/native-balance`.

## Endpoints (internal, `X-Internal-Key`)

| Method | Path | Purpose |
|---|---|---|
| POST | `/quote` | LI.FI dry quote → price, unified `transactionFeeUsd`, `nativeFeeEstimate`. Preview cached briefly (`QUOTE_CACHE_TTL_SECONDS`). |
| POST | `/prepare` | Build the unsigned tx + the message-to-sign + route snapshot (+ optional ERC20 approve). No digest/keys. |
| POST | `/derive-message` | Re-derive the message-to-sign + digest from a persisted unsigned tx, so the gateway re-validates the snapshot before signing. |
| POST | `/finalize` | Insert the dWallet signature and broadcast. Returns `txHash` or `broadcastUnknown`. |
| GET | `/native-balance` | dWallet native-token balance on a chain, so the gateway pre-checks swap gas. |
| GET | `/evm/receipt` | Whether an EVM tx (e.g. an ERC20 approve) is mined and succeeded. |
| GET | `/tx-status` | Normalize LI.FI `/status` for a broadcast tx (tracks the bridge on cross-chain). |
| GET | `/chains` | Proxy LI.FI `/chains` (also warms the broadcast RPC cache). |
| GET | `/tokens` | Proxy LI.FI `/tokens`. |
| GET | `/health`, `/health/ready` | Liveness / readiness (ready once the `/chains` cache is warm and the LI.FI breaker is closed). |
| GET | `/metrics` | Prometheus. |

## Signing model (Solana)

1. LI.FI returns `transactionRequest.data` = base64 `VersionedTransaction` with
   the dWallet as fee payer + sole signer.
2. `/prepare` validates the invariants (fee payer == dWallet, no foreign required
   signer) and returns:
   - `unsignedTxB64` — the canonical snapshot (the gateway persists it),
   - `messageToSignHex` — the serialized Solana message; the gateway forwards it
     to `ika-backend /v1/dwallet/prepare-message` as `payloadHex`,
   - `messageDigestHex` — `keccak256(messageToSignHex)`, the on-chain
     `MessageApproval` PDA key (matches `ika-backend` `schemeDigest`),
   - `signChainId` (CAIP-2), `signScheme` (5 = Ed25519), `chainNativeAddress`.
3. The gateway authorizes via PolicyEngine v3 and signs via `ika-backend`,
   getting a raw 64-byte Ed25519 signature.
4. `/finalize` inserts that signature at the fee-payer slot and broadcasts. The
   Solana txid equals the fee payer's signature, so even an ambiguous broadcast
   returns a hash the gateway can reconcile against — never a blind retry.

## Signing model (Sui)

1. LI.FI returns `transactionRequest.data` = base64 of BCS-encoded
   `TransactionData` (Move VM tx). Today's source is Cetus (same-chain Sui)
   plus Wormhole / Mayan for cross-chain Sui ↔ EVM.
2. `/prepare` checks that LI.FI's `action.fromAddress` matches the dWallet's
   canonical Sui address (`expandSuiAddress` normalizes short-form ↔ full-form),
   then returns:
   - `unsignedTxB64` — the raw txBytes the network executes,
   - `messageToSignHex` — the same raw txBytes (no envelope yet); ika-backend
     applies `blake2b256([0,0,0] || txBytes)` automatically with
     `kind="transaction"` (see `ika-backend/src/chain/preprocess.ts`),
   - `messageDigestHex` — `keccak256(blake2b256(...))`, the on-chain
     `MessageApproval` PDA key. The intents-backend Go side and the ika TS side
     share a fixture (`fixtures/chain/preprocess-v1.json` →
     `TestSuiEnvelopeMatchesIkaFixture`) so this stays byte-identical.
   - `signChainId` = `sui:mainnet`, `signScheme` = 5 (EddsaSha512).
3. The gateway signs and `/finalize` wraps the raw 64-byte Ed25519 signature in
   the Sui-flagged shape (1-byte scheme flag `0x00` + sig + pubkey, base64'd)
   and calls `sui_executeTransactionBlock`. The Sui digest is deterministic
   from txBytes alone (`base58(blake2b256(intent || txBytes))`) so an ambiguous
   broadcast still returns a hash to reconcile against.

## Configuration

See `.env.example`. RPC overrides (`SOLANA_RPC_URL`, `EVM_RPC_URLS_JSON`,
`SUI_RPC_URL`) are optional — by default the broadcast uses the public RPCs
LI.FI publishes in `/chains`. The integrator fee (`LIFI_FEE_BPS`) is capped by
`LIFI_FEE_MAX_BPS` and validated at boot. `QUOTE_CACHE_TTL_SECONDS` (default 5,
0 to disable) sets a short per-replica cache for quote PREVIEWS only; the
transaction is never cached (prepare always re-quotes fresh).

## Run

```bash
go build ./...
go test ./...
go run ./cmd/server
```

Pre-alpha on Solana devnet — not for real value; state resets at Alpha 1.
