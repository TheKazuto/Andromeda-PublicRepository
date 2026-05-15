# encrypt-backend

FHE engine for the **Encrypt** network (pre-alpha on Solana). Stateless HTTP server exposing primitives and high-level operations under a `prepare → submit` pattern (custody-free).

> **Pre-alpha.** No real cryptography guarantee. Devnet only. Do not custody real data.

Stack: Node 22+ · TypeScript 6 · Hono 4 · @solana/kit 6 · @solana-program/{system,compute-budget} · @encrypt.xyz/pre-alpha-solana-client · Zod · pino · Upstash Redis (optional) · HashiCorp Vault Transit (optional) · Railway.

## Communicates with

- **`gateway/`** — sole consumer. Auth via `X-Internal-Key` over Railway private network.
- **Encrypt gRPC** (`ENCRYPT_GRPC_URL`) — `CreateInput`, `ReadCiphertext`.
- **Solana RPC** (`SOLANA_RPC_URL`) — devnet, blockhash + submit.
- **Vault Transit** (optional) — signs FHE decisions via the `andromeda-fhe` key.
- **Upstash Redis** (optional) — NEK and ciphertext cache.

Does not talk to `ika-backend`, `backend/` or external clients directly.

## Project layout

```
encrypt-backend/
├── src/
│   ├── server.ts           # Hono bootstrap (secureHeaders, CORS, bodyLimit, idempotency, graceful shutdown)
│   ├── config.ts           # Env vars (Zod, fail-fast)
│   ├── auth/               # X-Internal-Key middleware
│   ├── routes/             # Hono routes per area:
│   │                       #   health, ciphertext, graph, dsl, wallet, transaction,
│   │                       #   decrypt, nek, events, authority, fees, ownership, decision
│   ├── encrypt/            # gRPC client (pre-warm), CreateInput, ReadCiphertext, NEK (cache + singleflight), authorized
│   ├── solana/             # @solana/kit connection, program IDs, ix builders, blockhash cache
│   ├── graph/              # Builders for the Encrypt program instructions (executor, ownership, gateway,
│   │                       #   fees, authority), discriminators, ciphertext-account derivation
│   ├── dsl/                # FHE types + operation registry
│   ├── wallet/             # initBalance, depositWithdraw, transfer, balanceCheck
│   ├── decrypt/            # request + poll
│   ├── transaction/        # submit + status helpers
│   ├── cache/              # Upstash Redis
│   ├── http/               # Idempotency middleware
│   └── lib/                # logger, errors, validation, serialization, responses, timeout,
│                           #   vault (Transit signer), gasSponsor (infra — see below)
├── .env.example
├── Dockerfile
├── railway.toml
└── package.json
```

## prepare → submit pattern

Endpoints that produce Solana transactions **never sign** — they return `unsignedTx` base64 for the client to sign and submit back via `/v1/private-tx/submit`.

```
POST /v1/wallet/transfer/prepare → { unsignedTx: { base64, ... } }
[client signs locally]
POST /v1/private-tx/submit       → { signature }
```

> **Gas sponsor (infra ready, not yet wired — 2026-05-07).** `src/lib/gasSponsor.ts` +
> `ANDROMEDA_GAS_SPONSOR_KEYPAIR` exist so the engine can flip to a wallet-agnostic
> gas-sponsored flow once the Encrypt program upstream accepts challenge-based authority
> (or an `encrypt-proxy` program lands). Until then the `prepare → submit` flow above is the
> only path; the keypair env var is optional and unused by endpoints.

## Endpoints

Every route under `/v1/*` requires `X-Internal-Key`. `/health` and `/health/info` are public.
An `Idempotency-Key` header is honoured on `/v1/*` (defensive mirror; primary enforcement is at the
gateway). Errors use `{ error: { code, message } }`.

### Health
- `GET /health` — liveness
- `GET /health/info` — public info
- `GET /health/deep/{grpc,solana,cache}` — deep checks (authenticated)

### Ciphertext (gRPC primitives)
- `POST /v1/ciphertext/create` — `EncryptService.CreateInput`
- `POST /v1/ciphertext/read` — `EncryptService.ReadCiphertext`
- `GET  /v1/ciphertext/account/:address` — read raw on-chain data

### NEK (Network Encryption Key)
- `GET  /v1/nek/current`
- `POST /v1/nek/override`
- `POST /v1/nek/authorize`

### Graph (Executor disc 1..6)
- `POST /v1/graph/{execute,register,execute-registered,commit}/prepare`
- `POST /v1/graph/submit`
- `GET  /v1/graph/status/:signature`
- `GET  /v1/graph/operations`
- `POST /v1/graph/operations/register-bytes`

### DSL (high-level operations)
- `GET  /v1/dsl/types`
- `POST /v1/dsl/op/prepare`

### Wallet (private wallets)
- `POST /v1/wallet/balance/init` — build the encrypted-balance init tx
- `POST /v1/wallet/balance/{deposit,withdraw,check}/prepare`
- `POST /v1/wallet/transfer/prepare`
- `GET  /v1/wallet/balance/:account`

### Transaction
- `POST /v1/private-tx/submit`
- `GET  /v1/private-tx/status/:signature`

### Decrypt (Gateway disc 10..12)
- `POST /v1/decrypt/request/prepare`
- `GET  /v1/decrypt/poll/:account`

### Ownership (disc 7..9)
- `POST /v1/ownership/{transfer,copy,make-public}/prepare`

### Fees (disc 13..18)
- `POST /v1/fees/deposit/{create,top-up,withdraw,request-withdraw,reimburse}/prepare`
- `POST /v1/fees/config/update/prepare`

### Authority (disc 19..21)
- `POST /v1/authority/{add,remove,register-nek}/prepare`

### Events
- `POST /v1/events/emit/prepare`
- `GET  /v1/events/by-signature/:signature`

### Decision (Confidential Workflows)
- `POST /v1/encrypt/decision/sign` — signs FHE decision via Vault Transit. Enabled by `FHE_DECISION_SIGNING_ENABLED=true`.

## Environment variables

`.env.example` is the reference. Boot is fail-fast: an invalid value aborts startup.

### Required
| Var | Notes |
|-----|-------|
| `INTERNAL_API_KEY` | Secret for the `X-Internal-Key` header (min. 16 chars). |

### External connections
| Var | Default | Notes |
|-----|---------|-------|
| `ENCRYPT_GRPC_URL` | `https://pre-alpha-dev-1.encrypt.ika-network.net:443` | Encrypt network gRPC. |
| `ENCRYPT_PROGRAM_ID` | `4ebfzWdKnrnGseuQpezXdG8yCdHqwQ1SSBHD3bWArND8` | Encrypt Solana program ID. |
| `SOLANA_RPC_URL` | `https://api.devnet.solana.com` | HTTP RPC. |
| `SOLANA_RPC_WS_URL` | `wss://api.devnet.solana.com` | WebSocket RPC. |
| `SOLANA_COMMITMENT` | `confirmed` | `processed` / `confirmed` / `finalized`. |
| `SOLANA_DEFAULT_PRIORITY_FEE_MICROLAMPORTS` | `0` | Default priority fee (µLamports/CU); `0` disables. Per-request overrides still apply. |

### NEK (Network Encryption Key)
| Var | Default | Notes |
|-----|---------|-------|
| `ENCRYPT_NEK_PUBLIC_KEY_BASE64` | empty | Optional NEK loaded at boot (32 B base64). |
| `ENCRYPT_NEK_IMMUTABLE` | `false` | When `true`, locks the first NEK set (env or first `/v1/nek/override`); later overrides return `409`. **Recommended in production** — flipping an active NEK orphans existing ciphertexts. |

### Cache (optional)
| Var | Default | Notes |
|-----|---------|-------|
| `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN` | empty | Without both, persistent cache is disabled (in-process caches still work). |
| `CACHE_TTL_NEK` / `CACHE_TTL_CIPHERTEXT` | `300` / `60` | Redis TTLs (seconds). |
| `NEK_INMEM_CACHE_TTL_MS` | `30000` | In-process NEK cache TTL. |
| `BLOCKHASH_CACHE_TTL_MS` | `12000` | In-process blockhash cache TTL. |

### Timeouts
| Var | Default | Notes |
|-----|---------|-------|
| `ENCRYPT_GRPC_TIMEOUT_MS` | `10000` | Encrypt gRPC call timeout. |
| `SOLANA_RPC_TIMEOUT_MS` | `10000` | Solana RPC call timeout. |
| `REDIS_TIMEOUT_MS` | `2000` | Upstash REST timeout. |

### Confidential Workflows (opt-in)
Enables `POST /v1/encrypt/decision/sign` (otherwise `503`). These are read directly from the
environment (not in `config.ts`). The 4 `FHE_AUTHORITY_VAULT_*` vars are all-or-nothing — a
partially-filled bundle errors at first request.

| Var | Notes |
|-----|-------|
| `FHE_DECISION_SIGNING_ENABLED` | `true` to enable the route. |
| `FHE_MOCK_MODE` | `true` for devnet mock — the route honours a `mock_authorize` body field instead of running real FHE evaluation (required in pre-alpha; disable in production). |
| `FHE_AUTHORITY_VAULT_ADDR` | Vault Transit URL (private network). |
| `FHE_AUTHORITY_VAULT_TOKEN` | Periodic token with the `andromeda-fhe-signer` policy. |
| `FHE_AUTHORITY_VAULT_KEY_NAME` | ed25519 key name (`andromeda-fhe`). |
| `FHE_AUTHORITY_VAULT_PUBKEY_B64` | ed25519 pubkey (32 B base64) for local re-verification of every signature. |
| `FHE_AUTHORITY_PUBKEY_B64` | Fallback pubkey published as `FHEGatedPolicy.fhe_authority` when Vault is not configured (placeholder mode). |

### Gas sponsor (infra ready, not wired)
| Var | Notes |
|-----|-------|
| `ANDROMEDA_GAS_SPONSOR_KEYPAIR` | JSON byte array of a 64-byte `solana-keygen` keypair. Optional and currently unused by endpoints — see the prepare → submit section. Never commit it. |

### Other
| Var | Default | Notes |
|-----|---------|-------|
| `PORT` | `3010` | HTTP port. |
| `NODE_ENV` | `development` | `development` / `production` / `test`. |
| `LOG_LEVEL` | `info` | `fatal` / `error` / `warn` / `info` / `debug` / `trace`. |
| `ALLOWED_ORIGINS` | empty | CSV CORS allowlist (`/v1/*` and `/health`). Empty in production = no cross-origin; in development empty falls back to `*`. |
| `MAX_BODY_BYTES` | `4194304` | Global request body limit (4 MB — fits large `graphBytes`). |
| `SHUTDOWN_TIMEOUT_MS` | `10000` | Drain timeout on SIGTERM/SIGINT. |

## Setup

```bash
cp .env.example .env
# fill INTERNAL_API_KEY (min. 16 chars)
npm install
npm run dev          # tsx watch src/server.ts — default port :3010
```

### Scripts

| Command | What it does |
|---------|--------------|
| `npm run dev` | Watch-mode dev server. |
| `npm run build` | `tsc` → `dist/`. |
| `npm start` | Run the compiled server (`dist/server.js`). |
| `npm run typecheck` | `tsc --noEmit`. |
| `npm test` | Runs `src/routes/decision.test.ts` via `node --test` + `tsx`. Only the FHE decision canonical encoding is covered today; broader suite pending. |
| `npm run lint` | Placeholder — no linter configured yet. |

## Required post-deploy operation

1. Register default graph bytecode via `POST /v1/graph/operations/register-bytes`.
2. Set the active NEK via `POST /v1/nek/override` or the `ENCRYPT_NEK_PUBLIC_KEY_BASE64` env var.
