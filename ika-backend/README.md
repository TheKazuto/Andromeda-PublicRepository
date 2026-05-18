# ika-backend

Andromeda's MPC engine, integrated with the Solana variant of Ika dWallet (`ika-pre-alpha`). Connects any blockchain to the Ika 2PC-MPC protocol without requiring a client-side SDK.

> **Pre-alpha.** Devnet only. Single mock signer. No cryptographic MPC guarantee. Do not custody real value.

Stack: Node 24+ · TypeScript 6 · Express 5 · @grpc/grpc-js · @solana/kit · @noble/curves · bs58 · pg · jose · zod · pino · helmet · compression · Vitest · Railway.

## Communicates with

- **`gateway/`** — sole consumer. Auth via `X-Api-Key` over Railway private network.
- **Ika gRPC** (`pre-alpha-dev-1.ika.ika-network.net:443`) — 2PC-MPC validator network.
- **Solana RPC** (devnet) — submit + on-chain dWallet state reads.
- **`policy-engine` program** (Quasar, in `contracts/policy-engine/`) — controls dWallet authority and enforces every recovery / admin / signing flow on-chain (zero attestor).
- **Postgres** — cache/UX (the chain is the source of truth for dWallets).

Does not talk to `encrypt-backend`, `backend/` or external clients directly.

## Project layout

```
ika-backend/
├── src/
│   ├── server.ts
│   ├── config.ts                   # Zod-validated env (base + oidc + passkey + gasSponsor)
│   ├── safeError.ts                # Sanitized errors + trace id
│   ├── logger.ts                   # pino + redaction
│   ├── cmd/migrate.ts              # `npm run migrate` entrypoint
│   ├── http/                       # auth (X-Api-Key / admin), healthz, idempotency mirror
│   ├── engine/                     # MPC core
│   │   ├── grpc-client.ts          # Ika gRPC client
│   │   ├── solana-rpc.ts           # @solana/kit
│   │   ├── tx-builder.ts
│   │   ├── submit.ts               # Submit Ika dWallet tx via gRPC (raw BCS response)
│   │   ├── gas-sponsor.ts          # Fee-payer keypair + Solana sendTransaction + confirm
│   │   ├── precompiles.ts          # Ed25519/Secp256k1/Secp256r1 ix
│   │   ├── pda.ts
│   │   ├── routes.ts               # Mounts low-level prepare/submit + high-level MCP routes
│   │   ├── {dkg,sign,presign,future-sign,re-encrypt-share}.ts
│   │   └── ika-client/             # High-level tenant-scoped dWallet ops (MCP tools)
│   │       ├── routes.ts           # /create, /transfer-ownership, /presign, /sign
│   │       ├── wallet.ts           # Per-tenant keystore + dWallet lifecycle (incl. attachPolicyEngine)
│   │       ├── keystore.ts         # Passphrase-encrypted key material (cache/UX)
│   │       ├── request.ts          # gRPC request shaping
│   │       └── bcs.ts              # BCS codecs for Ika request payloads
│   ├── clients/
│   │   ├── ika/                    # transfer-ownership instruction codec
│   │   └── policyEngine/           # Codecs + instructions + program PDA for PolicyEngine v3
│   ├── oidc/                       # Opt-in (Login Social): /v1/oidc/{nonce,validate} + JWT derivations
│   ├── store/                      # Postgres pool + migrations + cleanup job
│   └── __tests__/
├── proto/                          # Ika .proto files (populate from upstream — boot fails without them)
├── scripts/                        # gen-keypair.mjs, run-migrations.ts (dev)
├── .env.example                    # Authoritative list of every env var
├── Dockerfile
├── railway.json
└── package.json
```

## Layers (opt-in)

| Layer | Flag | Endpoints |
|-------|------|-----------|
| MPC engine | always on | `/v1/dwallet/*` |
| Login Social (OIDC) pre-flow | `IKA_OIDC_ENABLED` | `/v1/oidc/{nonce,validate}` |

All policy / admin / recovery surfaces live on the **gateway** under `/v1/policy/*` (PolicyEngine v3). This backend only exposes the MPC engine and the OIDC pre-flow helpers — no policy / recovery state machine.

## Endpoints

Every route under `/v1/*` requires `X-Api-Key` (`INTERNAL_API_KEY`). All responses use the
standard envelope (`{ success: true, data }` / `{ success: false, error, traceId? }`). An
`Idempotency-Key` header is honoured as a defensive mirror (primary enforcement lives at the gateway).

### MPC engine — high-level (MCP tools)

Tenant-scoped dWallet operations. The gateway auto-mirrors each as an MCP tool and forwards the
tenant identity in the **`X-Andromeda-User-Id`** header — these routes reject any request that
arrives without it (i.e. not via the gateway). dWallets here are pre-alpha/devnet and wiped at
Alpha 1; the response carries the disclaimer.

| Route | MCP tool | Notes |
|-------|----------|-------|
| `POST /v1/dwallet/create` | `create_dwallet` | `passphrase` (≥12), optional `curve` (`Curve25519`/`Secp256k1`/`Secp256r1`), optional `attachPolicyEngine: true` (deploys a fresh PolicyEngine v3 and delegates the dWallet's authority in the same call). |
| `POST /v1/dwallet/transfer-ownership` | `transfer_ownership` | Delegates dWallet authority to a new account (e.g. a PolicyEngine v3 CPI authority PDA). |
| `POST /v1/dwallet/presign` | `presign` | Allocates a presign session. |
| `POST /v1/dwallet/sign` | `sign_message` | Signs a message using an approval + presign → returns `signatureBase64`. |

### MPC engine — low-level (prepare → submit)
- `POST /v1/dwallet/dkg/prepare` — `{ curve, userPublicKeyBase58 }` → returns the BCS `SignedRequestData` (base64) to sign, plus `sessionPreimageBase64`, `epoch` and `intendedChainSenderBase58`
- `POST /v1/dwallet/{dkg,sign,presign,future-sign,re-encrypt-share,make-share-public}/submit`
- `POST /v1/dwallet/future-sign/complete/submit`
- `GET  /v1/dwallet/presigns/:userPubkey` — `:userPubkey` is base64

### Login Social — OIDC pre-flow

`IKA_OIDC_ENABLED=true` mounts the two read-only OIDC helpers. They produce the canonical OAuth `nonce` and pre-validate the provider `id_token` (JWKS + claims) before any gas is spent on-chain. The on-chain OIDC primary recovery (PolicyEngine v3 F9c) is currently blocked on the `sol_big_mod_exp` syscall and will consume these helpers when it lands.

| Route | Purpose |
|-------|---------|
| `POST /v1/oidc/nonce` | Given an ephemeral Ed25519 pubkey, returns the canonical `oidc_nonce` to use as the OAuth `nonce`. The client doesn't need to know the byte layout. |
| `POST /v1/oidc/validate` | Off-chain pre-check of an `id_token` (provider JWKS + claims + `nonce` shape). Returns derived hashes only — never the raw `sub` / JWT. |

**Cross-client identity.** `addrSeed = sha256("andromeda::oidc::addr::v1" || lp(iss) || lp(aud) || lp(sub))`. Same Google/Apple account → same `addrSeed` → same dWallet across apps on Andromeda. The `aud` portion uses a single global Andromeda OAuth client per environment so cross-app portability holds.

**Privacy.** Never log JWTs, raw `sub`, email, or name. Audit log entries store only addresses + hashes.

### Health & metrics
- `GET /health` — liveness (no auth)
- `GET /health/deep` — Postgres + Ika gRPC + Solana RPC checks; requires `X-Api-Key: <IKA_ADMIN_API_KEY>`
- `GET /metrics` — Prometheus (Railway private network). HTTP latency, pg pool stats, gRPC per-method latency + breaker state, Solana RPC latency + breaker, blockhash cache hits/misses, gas sponsor queue depth/wait/balance/duplicate-signature, idempotency hits/misses/conflicts.

## Environment variables

`.env.example` is the authoritative, fully-commented list. Boot is fail-fast: every invalid or
missing required value is aggregated and printed, and the process exits.

### Required (always)
| Var | Notes |
|-----|-------|
| `INTERNAL_API_KEY` | Secret for the `X-Api-Key` header on all `/v1/*` routes. Minimum 32 chars — boot fails fast on shorter values to reject `dev123` / `changeme` misconfigurations. |
| `DATABASE_URL` | Postgres DSN. |
| `IKA_GRPC_URL` | Ika validator network gRPC (`https://pre-alpha-dev-1.ika.ika-network.net:443`). |
| `IKA_PROGRAM_ID` | Ika Solana program ID (`87W54kGYFQ1rgWqMeu4XTPHWXWmXSQCcjm8vCTfiq1oY`). |
| `SOLANA_RPC_URL` | Solana devnet RPC. |

### Core (optional, with defaults)
| Var | Default | Notes |
|-----|---------|-------|
| `PORT` | `8080` | HTTP listen port. |
| `NODE_ENV` | `development` | `development` / `production` / `test`. |
| `LOG_LEVEL` | `info` | `fatal` / `error` / `warn` / `info` / `debug` / `trace`. |
| `IKA_ADMIN_API_KEY` | _(unset)_ | Required for `GET /health/deep`. |
| `ALLOWED_ORIGINS` | _(empty → CORS off)_ | CSV of origins allowed on `/v1/oidc/*`. Engine routes never set CORS. |
| `IKA_GRPC_TLS` | `true` | TLS for the Ika gRPC channel. |
| `SOLANA_COMMITMENT` | `confirmed` | `processed` / `confirmed` / `finalized`. |
| `PGSSLMODE` | _(unset)_ | Postgres SSL mode (e.g. `prefer`, `require`). |
| `IKA_PG_POOL_MAX` | `20` | Max Postgres pool size. |
| `IKA_PG_CONNECTION_TIMEOUT_MS` | `3000` | Postgres connection timeout (ms). |
| `PG_POOL_IDLE_TIMEOUT_MS` | `30000` | Drop idle pg clients after N ms. |
| `PG_STATEMENT_TIMEOUT_MS` | `30000` | Postgres `statement_timeout` applied on every new connection. |
| `PG_IDLE_IN_TX_TIMEOUT_MS` | `60000` | Postgres `idle_in_transaction_session_timeout`. |
| `SENTRY_DSN` | _(unset)_ | Optional error reporting. |

### Gas sponsor
| Var | Default | Notes |
|-----|---------|-------|
| `ANDROMEDA_GAS_SPONSOR_KEYPAIR` | _(none)_ | JSON byte array (64 B), `solana-keygen` format. Single fee payer. Pays SOL for every admin / transfer-ownership / PolicyEngine v3 tx so users never need a Solana wallet. Legacy alias: `IKA_GAS_SPONSOR_KEYPAIR`. Never commit it; keep it funded. |
| `ANDROMEDA_GAS_SPONSOR_KEYPAIRS` | _(none)_ | Pool of N fee payers. Two accepted formats: nested JSON `[[1,2,...],[3,4,...]]` OR semicolon-separated `[1,2,...];[3,4,...]`. When set, `signAndSendInstructions` picks the least-loaded fee payer (smallest queue depth) for each tx. Wins over `_KEYPAIR` when both are set. |
| `IKA_GAS_SPONSOR_MIN_BALANCE_SOL` | `0.5` | Warn threshold for the sponsor balance. |
| `IKA_GAS_SPONSOR_MAX_GAS_PER_OP_LAMPORTS` | `20000000` | Per-op gas ceiling. |
| `ANDROMEDA_GAS_SPONSOR_QUEUE_MAX` | `50` | Max concurrent + queued requests per fee payer. Excess returns 503 with `Retry-After`. Per-fee-payer serialisation prevents duplicate-signature submits when instructions collide.

Concurrent sends for the same fee payer are serialised via a per-address promise chain
(`withFeePayerLock`). Cross-fee-payer concurrency is fully parallel — each fee payer keeps its own
mutex. Metrics `ika_gas_sponsor_{queue_depth,queue_wait_seconds,rejected_total}` are labelled by
fee payer address.

### Per-replica + multi-replica safety

| Concern | Defence |
|---|---|
| Multiple replicas applying migrations in parallel | `pg_advisory_xact_lock` inside a dedicated transaction on `pool.connect()`. INSERT `ON CONFLICT DO NOTHING`. Latest file: `016_idempotency_atomic.sql`. |
| Same `Idempotency-Key` racing across replicas | `INSERT … ON CONFLICT DO UPDATE … WHERE` modifying CTE — one round-trip claim with `status=in_progress` + `reservation_id`. The replica that didn't win sees 409 `idempotency_in_progress` until the owner finalises (or the lease expires). Required on `/dwallet/{submit,create,transfer-ownership,presign,sign}`. |
| Same fee payer being used in parallel for two unrelated txs | `withFeePayerLock(address)` promise-chain mutex per fee payer. |
| Solana RPC outage | Per-op circuit breaker (`getLatestBlockhash`, `sendTransaction`). `blockhash_expired` does NOT trip the breaker (normal under load); 429/503/timeout do. |
| Ika gRPC validator outage | Per-method circuit breaker. `SubmitTransaction` only retries on `UNAVAILABLE`; reads retry on `UNAVAILABLE`/`DEADLINE_EXCEEDED`/`RESOURCE_EXHAUSTED`. Deadlines: 10s for reads, 30s for submits (override per-method via `IKA_GRPC_DEADLINE_<METHOD>_SEC`). |
| Stale blockhash mid-submit | `invalidateBlockhashCache()` called automatically on `BlockhashNotFound` / `TransactionExpiredBlockheightExceeded`. Never re-signs an already-signed tx with a fresh blockhash. |

### PolicyEngine v3 (opt-in — `IKA_POLICY_ENGINE_ENABLED=true`)

When enabled, `POST /v1/dwallet/create` accepts `attachPolicyEngine: true` — the dWallet is created and a fresh PolicyEngine v3 is deployed + the dWallet's authority is delegated to it in the same call. All admin / recovery / approve flows then live on the gateway `/v1/policy/*` surface.

| Var | Default | Notes |
|-----|---------|-------|
| `IKA_POLICY_ENGINE_ENABLED` | `false` | Master flag. |
| `ANDROMEDA_POLICY_ENGINE_PROGRAM_ID` | _(none)_ | Deployed `policy-engine` Quasar program. Devnet: `ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL`. |

### Login Social — OIDC pre-flow (opt-in — `IKA_OIDC_ENABLED=true`)

Mounts `/v1/oidc/{nonce,validate}`. Boot refuses to start if no provider is enabled or required config is missing.

| Var | Default | Notes |
|-----|---------|-------|
| `IKA_OIDC_ENABLED` | `false` | Master flag. |
| `IKA_OIDC_GOOGLE_ENABLED` | `false` | Accept Google `id_token`s (`iss=https://accounts.google.com`). |
| `IKA_OIDC_GOOGLE_CLIENT_ID` | _(none)_ | The auth-broker's Google OAuth client_id. Required when Google is enabled. |
| `IKA_OIDC_APPLE_ENABLED` | `false` | Accept Apple `id_token`s (`iss=https://appleid.apple.com`). |
| `IKA_OIDC_APPLE_CLIENT_ID` | _(none)_ | Apple Services ID. Required when Apple is enabled. |
| `IKA_OIDC_ALLOWED_AUDIENCES` | _(none)_ | CSV of allowed `aud` claims. Required when enabled. |
| `IKA_OIDC_LOG_SUBJECT_HMAC_SECRET` | _(none)_ | HMAC key (≥32 bytes, hex) for hashing `sub` in logs/metrics. **Required when enabled.** Generate with `openssl rand -hex 32`. Rotation invalidates historical correlation only. |

## Setup

```bash
cp .env.example .env
# fill at minimum: INTERNAL_API_KEY, DATABASE_URL, IKA_GRPC_URL,
#                  SOLANA_RPC_URL, IKA_PROGRAM_ID
# to also enable PolicyEngine v3 attach: IKA_POLICY_ENGINE_ENABLED=true,
#                  ANDROMEDA_POLICY_ENGINE_PROGRAM_ID, ANDROMEDA_GAS_SPONSOR_KEYPAIR

# Proto files from upstream Ika (boot fails without them)
cd proto && git clone --depth=1 https://github.com/dwallet-labs/ika-pre-alpha /tmp/ika
cp /tmp/ika/proto/*.proto . && cd ..

npm install
npm run dev          # tsx watch src/server.ts
```

### Scripts

| Command | What it does |
|---------|--------------|
| `npm run dev` | Watch-mode dev server. |
| `npm run build` | `tsc` → `dist/`. |
| `npm start` | Run the compiled server (`dist/server.js`). Migrations run automatically on boot. |
| `npm run typecheck` | `tsc --noEmit`. |
| `npm test` / `npm run test:watch` | Vitest. |
| `npm run migrate` | Run Postgres migrations against `DATABASE_URL` (uses `dist/`; build first). |
| `npm run migrate:dev` | Same, via `tsx` (no build). |
| `node scripts/gen-keypair.mjs <out-path>` | Generate a Solana keypair as a JSON byte array file + print its address (for `ANDROMEDA_GAS_SPONSOR_KEYPAIR`). |
