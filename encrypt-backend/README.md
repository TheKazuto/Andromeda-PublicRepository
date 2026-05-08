# encrypt-backend

FHE engine for the **Encrypt** network (pre-alpha on Solana). Stateless HTTP server exposing primitives and high-level operations under a `prepare → submit` pattern (custody-free).

> **Pre-alpha.** No real cryptography guarantee. Devnet only. Do not custody real data.

Stack: Node 22+ · TypeScript 6 · Hono 4 · @solana/kit 6 · @encrypt.xyz/pre-alpha-solana-client · Zod · pino · Upstash Redis (optional) · Railway.

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
│   ├── server.ts           # Hono bootstrap (CORS, bodyLimit, graceful shutdown)
│   ├── config.ts           # Env vars (Zod)
│   ├── auth/               # X-Internal-Key middleware
│   ├── routes/             # Hono routes per area
│   ├── encrypt/            # gRPC client + NEK (cache + singleflight)
│   ├── solana/             # @solana/kit connection + ix builders + blockhash cache
│   ├── graph/              # Builders for the 22 Encrypt program instructions
│   ├── dsl/                # FHE types + operation registry
│   ├── wallet/             # Init, deposit, withdraw, transfer, check
│   ├── decrypt/            # Request + poll
│   ├── transaction/        # Submit + status helpers
│   ├── cache/              # Upstash Redis
│   ├── http/               # Idempotency middleware
│   └── lib/                # Logger, errors, validation, serialization
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

## Endpoints

Every route under `/v1/*` requires `X-Internal-Key`. `/health` and `/health/info` are public.

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
- `POST /v1/wallet/balance/{init,deposit,withdraw,check}/prepare`
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

### Required
| Var | Notes |
|-----|-------|
| `INTERNAL_API_KEY` | Secret for the `X-Internal-Key` header (min. 16 chars). |

### External connections
| Var | Default | Notes |
|-----|---------|-------|
| `ENCRYPT_GRPC_URL` | pre-alpha gRPC | Encrypt network gRPC. |
| `ENCRYPT_PROGRAM_ID` | devnet | Encrypt Solana program ID. |
| `SOLANA_RPC_URL` | `https://api.devnet.solana.com` | HTTP RPC. |
| `SOLANA_RPC_WS_URL` | `wss://api.devnet.solana.com` | WebSocket RPC. |
| `SOLANA_COMMITMENT` | `confirmed` | `processed` / `confirmed` / `finalized`. |

### NEK (Network Encryption Key)
| Var | Default | Notes |
|-----|---------|-------|
| `ENCRYPT_NEK_PUBLIC_KEY_BASE64` | empty | Optional NEK loaded at boot (32 B base64). |
| `ENCRYPT_NEK_IMMUTABLE` | `false` | When `true`, locks the first NEK set. **Recommended in production.** |

### Cache (optional)
| Var | Notes |
|-----|-------|
| `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN` | Without these, persistent cache is disabled. |
| `CACHE_TTL_NEK` / `CACHE_TTL_CIPHERTEXT` | TTL in seconds (300 / 60 default). |

### Confidential Workflows (opt-in)
Enables `/v1/encrypt/decision/sign`. The 4 Vault vars are all-or-nothing.

| Var | Notes |
|-----|-------|
| `FHE_DECISION_SIGNING_ENABLED` | `true` to enable. |
| `FHE_AUTHORITY_VAULT_ADDR` | Vault Transit URL (private network). |
| `FHE_AUTHORITY_VAULT_TOKEN` | Periodic token with `andromeda-fhe-signer` policy. |
| `FHE_AUTHORITY_VAULT_KEY_NAME` | ed25519 key name (`andromeda-fhe`). |
| `FHE_AUTHORITY_VAULT_PUBKEY_B64` | ed25519 pubkey (32 B base64) for local re-verification. |
| `FHE_MOCK_MODE` | `true` for devnet mock (required in pre-alpha). |

### Other
| Var | Default | Notes |
|-----|---------|-------|
| `PORT` | `3010` | HTTP port. |
| `NODE_ENV` | `development` | `development` / `production` / `test`. |
| `LOG_LEVEL` | `info` | `fatal` / `error` / `warn` / `info` / `debug` / `trace`. |
| `ALLOWED_ORIGINS` | empty | CSV CORS allowlist. Empty in production = no cross-origin. |
| `MAX_BODY_BYTES` | `4194304` | Global request body limit. |
| `SHUTDOWN_TIMEOUT_MS` | `10000` | Drain timeout on SIGTERM. |

## Setup

```bash
cp .env.example .env
# fill INTERNAL_API_KEY (min. 16 chars)
npm install
npm run dev
```

Default port `:3010`. Production: `npm run build && npm start`.

## Required post-deploy operation

1. Register default graph bytecode via `POST /v1/graph/operations/register-bytes`.
2. Set the active NEK via `POST /v1/nek/override` or `ENCRYPT_NEK_PUBLIC_KEY_BASE64` env var.
