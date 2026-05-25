# intents-backend

Stateless private engine that powers **Andromeda Intents** — practical
multichain swaps (AI-native, via REST + MCP) executed over Ika dWallets
(custody-free), with liquidity from the LI.FI aggregator.

It is the **router**: it talks to LI.FI, builds the unsigned swap transaction,
exposes the exact bytes to sign, and after the gateway returns the dWallet
signature inserts it and broadcasts. It never touches keys, policy, or billing.
Scope: **swaps on Solana and EVM, same-chain and cross-chain (bridge)**.

## EVM signing model

1. LI.FI returns a `transactionRequest` ({to, from, data, value, gas, fees,
   chainId, nonce}). `/prepare` validates `from == dWallet`, assigns the chain's
   pending nonce, and builds the EIP-1559 signing payload `0x02 || rlp([chainId,
   nonce, maxPriorityFee, maxFee, gas, to, value, data, []])`. When the input is
   an ERC20 whose allowance for the router is insufficient, it also builds an
   `approve` tx to run before the swap (the approve takes nonce N, the swap N+1).
   `messageToSignHex` is that payload; the gateway forwards it to
   `prepare-message` (eip155, scheme 0 = ECDSA-Keccak256).
2. The gateway authorizes via PolicyEngine and signs via `ika-backend`, getting
   a 65-byte ECDSA signature `r||s||v` (v = yParity).
3. `/finalize` appends `yParity, r, s` to the RLP and broadcasts via
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
own balance** — it never passes through the gas-sponsor. The dWallet must hold
the destination chain's native token (SOL) for gas; the quote returns
`nativeFeeEstimate` and `requiresAtaCreation` so the caller can pre-check.

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
   - `signChainId` (CAIP-2), `signScheme` (5 = Ed25519), `chainNativeAddress`.
3. The gateway authorizes via PolicyEngine v3 and signs via `ika-backend`,
   getting a raw 64-byte Ed25519 signature.
4. `/finalize` inserts that signature at the fee-payer slot and broadcasts. The
   Solana txid equals the fee payer's signature, so even an ambiguous broadcast
   returns a hash the gateway can reconcile against — never a blind retry.

## Configuration

See `.env.example`. RPC overrides (`SOLANA_RPC_URL`, `EVM_RPC_URLS_JSON`) are
optional — by default the broadcast uses the public RPCs LI.FI publishes in
`/chains`. The integrator fee (`LIFI_FEE_BPS`) is capped by `LIFI_FEE_MAX_BPS`
and validated at boot. `QUOTE_CACHE_TTL_SECONDS` (default 5, 0 to disable) sets a
short per-replica cache for quote PREVIEWS only; the transaction is never cached
(prepare always re-quotes fresh).

## Run

```bash
go build ./...
go test ./...
go run ./cmd/server
```

Pre-alpha on Solana devnet — not for real value; state resets at Alpha 1.
