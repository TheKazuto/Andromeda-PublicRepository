# ika-backend

Andromeda's MPC engine, integrated with the Solana variant of Ika dWallet (`ika-pre-alpha`). Connects any blockchain to the Ika 2PC-MPC protocol without requiring a client-side SDK.

> **Pre-alpha.** Devnet only. Single mock signer. No cryptographic MPC guarantee. Do not custody real value.

Stack: Node 24+ · TypeScript 6 · Express 5 · @grpc/grpc-js · @solana/kit · @noble/curves · pg · jose · zod · pino · Vitest · Railway.

## Communicates with

- **`gateway/`** — sole consumer. Auth via `X-Api-Key` over Railway private network.
- **Ika gRPC** (`pre-alpha-dev-1.ika.ika-network.net:443`) — 2PC-MPC validator network.
- **Solana RPC** (devnet) — submit + on-chain dWallet state reads.
- **`RulesPolicy` program** (Quasar, in `contracts/rules-policy/`) — controls dWallet authority and enforces recovery policies on-chain (zero attestor).
- **Postgres** — cache/UX (the chain is the source of truth for dWallets).

Does not talk to `encrypt-backend`, `backend/` or external clients directly.

## Project layout

```
ika-backend/
├── src/
│   ├── server.ts
│   ├── config.ts
│   ├── http/                       # auth, healthz, idempotency
│   ├── engine/                     # MPC core
│   │   ├── grpc-client.ts          # Ika gRPC client
│   │   ├── solana-rpc.ts           # @solana/kit
│   │   ├── tx-builder.ts
│   │   ├── gas-sponsor.ts          # Fee payer keypair
│   │   ├── precompiles.ts          # Ed25519/Secp256k1/Secp256r1 ix
│   │   ├── pda.ts
│   │   └── {dkg,sign,presign,future-sign,re-encrypt-share}.ts
│   ├── identity/                   # Opt-in: OAuth, email, passkey
│   ├── recovery/
│   │   ├── verifiers/              # 7 off-chain schemes
│   │   ├── discovery/              # Off-chain ownership proof
│   │   ├── primary/                # Single-tx flow
│   │   ├── quorum/                 # PDA staging multi-tx
│   │   ├── policy/                 # Admin actions
│   │   ├── adapters/               # PolicyAdapter, SolanaAdapter
│   │   └── challenge.ts            # Byte-for-byte mirror of auth/challenge.rs
│   ├── clients/rulesPolicy/        # Codecs + instructions + program PDA
│   ├── store/                      # Postgres pool + migrations + cleanup
│   └── __tests__/
├── proto/                          # Ika .proto files (populate from upstream)
├── docs/{RECOVERY,STATUS}.md
├── PLAN.md
├── Dockerfile
├── railway.json
└── package.json
```

## Layers (opt-in)

| Layer | Flag | Endpoints |
|-------|------|-----------|
| MPC engine | always on | `/v1/dwallet/*` |
| Identity | `IKA_IDENTITY_ENABLED` | `/v1/identity/*` |
| Recovery (discovery) | `IKA_RECOVERY_ENABLED` | `/v1/recovery/{challenge,resolve}` |
| Recovery (policy) | `IKA_RECOVERY_POLICY_ENABLED` | `/v1/recovery/{primary,quorum,policy}/*` |

## Endpoints

Every route under `/v1/*` requires `X-Api-Key` (`INTERNAL_API_KEY`).

### MPC engine
- `POST /v1/dwallet/dkg/prepare` — returns envelope hint
- `POST /v1/dwallet/{dkg,sign,presign,future-sign,re-encrypt-share,make-share-public}/submit`
- `POST /v1/dwallet/future-sign/complete/submit`
- `GET  /v1/dwallet/presigns/:userPubkey`

### Recovery — Discovery (off-chain ownership proof)
- `POST /v1/recovery/challenge` — emits canonical message + nonce
- `POST /v1/recovery/resolve` — verifies signature, returns dWallets

Off-chain schemes (separated by curve + message format + address encoding):

| Scheme | Chains covered |
|---|---|
| `ed25519-raw` | Solana |
| `ed25519-near` | NEAR (NEP-413) |
| `ed25519-aptos` | Aptos (AIP-62) |
| `secp256k1-eip191` | All EVM |
| `secp256k1-adr036` | All Cosmos-SDK |
| `secp256k1-bitcoin` | Bitcoin (BIP-137 + BIP-322) |
| `sr25519-substrate` | All Substrate |

### Recovery v2 — challenge-based + gas-sponsored

Every on-chain flow: backend returns a 32-byte digest; user signs off-chain with any credential; backend assembles the Solana tx and signs it as **gas sponsor** (`ANDROMEDA_GAS_SPONSOR_KEYPAIR`). User never needs a Solana wallet.

On-chain schemes (validated via Solana precompile, **zero attestor**):

| Scheme | Identifier | Covers |
|--------|------------|--------|
| Ed25519 | 32 B (pubkey) | Solana, Sui, NEAR, Aptos, Cosmos ed25519, Substrate ed25519 |
| Secp256k1 | 20 B (eth_address) | EVM, Bitcoin, Cosmos secp256k1, Substrate ECDSA |
| Secp256r1 | 33 B (compressed) | Raw passkey |
| WebAuthn | 33 B (compressed) | Passkey with on-chain `clientDataJSON` validation |

#### Primary (single-tx)
- `POST /v1/recovery/primary/challenge`
- `POST /v1/recovery/primary/submit`

#### Quorum (PDA staging, multi-tx)
- `POST /v1/recovery/quorum/session/open/challenge`
- `POST /v1/recovery/quorum/session/open`
- `POST /v1/recovery/quorum/session/contribute/challenge`
- `POST /v1/recovery/quorum/session/contribute`
- `POST /v1/recovery/quorum/session/finalize`
- `POST /v1/recovery/quorum/session/close`
- `GET  /v1/recovery/quorum/session/:address`

#### Policy (admin challenge-based)
- `POST /v1/recovery/policy/preview` — validates config
- `POST /v1/recovery/policy/deploy` — bootstrap (gas sponsor pays)
- `GET  /v1/recovery/policy/:dwalletAddress` — on-chain state
- `POST /v1/recovery/policy/admin/challenge` — challenge for any of the 12 admin actions
- `POST /v1/recovery/policy/admin/submit`
- `POST /v1/recovery/policy/apply-pending`

### Identity (opt-in)
OAuth (Google/Apple/Twitter/GitHub), email magic link, passkey-as-identity (WebAuthn PRF). Enabled by `IKA_IDENTITY_ENABLED=true`.

### Health
- `GET /health` — liveness
- `GET /health/deep` — Postgres + Ika gRPC + Solana RPC (admin API key)

## Environment variables

### Required
| Var | Notes |
|-----|-------|
| `INTERNAL_API_KEY` | Secret for the `X-Api-Key` header. |
| `DATABASE_URL` | Postgres DSN. |
| `IKA_GRPC_URL` | Ika validator network gRPC (`pre-alpha-dev-1.ika.ika-network.net:443`). |
| `IKA_PROGRAM_ID` | Ika Solana program ID. |
| `SOLANA_RPC_URL` | Solana devnet RPC. |
| `JWT_SECRET` | Identity session token (when enabled). |

### Identity Layer (opt-in)
Enabled by `IKA_IDENTITY_ENABLED=true`. Each provider opt-in individually.

| Var | Notes |
|-----|-------|
| `IKA_IDENTITY_ENABLED` | `true` to enable identity (OAuth + email + passkey). |
| `IKA_IDENTITY_GOOGLE_ENABLED` + `GOOGLE_CLIENT_ID/SECRET` | Google OAuth. |
| `IKA_IDENTITY_APPLE_ENABLED` + `APPLE_CLIENT_ID/TEAM_ID/KEY_ID/PRIVATE_KEY` | Apple Sign-in. |
| `IKA_IDENTITY_TWITTER_ENABLED` + `TWITTER_CLIENT_ID/SECRET` | Twitter OAuth. |
| `IKA_IDENTITY_GITHUB_ENABLED` + `GITHUB_CLIENT_ID/SECRET` | GitHub OAuth. |
| `IKA_IDENTITY_EMAIL_ENABLED` + `SMTP_*` | Email magic link. |
| `IKA_IDENTITY_PASSKEY_ENABLED` + `IKA_IDENTITY_PASSKEY_RP_ID` + `IKA_IDENTITY_PASSKEY_PRF_SALT` | WebAuthn PRF. **PRF salt is immutable** — do not rotate. |
| `IKA_IDENTITY_AUDIT_LOG_ENABLED` | `true` for optional audit log. |

### Recovery Layer (opt-in)
| Var | Notes |
|-----|-------|
| `IKA_RECOVERY_ENABLED` | Enables discovery (`/v1/recovery/{challenge,resolve}`). |
| `IKA_RECOVERY_POLICY_ENABLED` | Enables on-chain primary/quorum/policy. |
| `IKA_RECOVERY_POLICY_PROGRAM_ID` | `RulesPolicy` (Quasar) program ID. |
| `IKA_COORDINATOR_ADDRESS` | Ika coordinator address. |
| `ANDROMEDA_GAS_SPONSOR_KEYPAIR` | JSON byte array (64 B). Required when Recovery v2 is active — pays gas for every tx. |

### Performance (optional)
| Var | Default | Notes |
|-----|---------|-------|
| `IKA_PG_POOL_MAX` | `20` | Max Postgres pool size. |
| `IKA_PG_CONNECTION_TIMEOUT_MS` | `3000` | Postgres connection timeout. |
| `LOG_LEVEL` | `info` | `fatal` / `error` / `warn` / `info` / `debug` / `trace`. |

## Setup

```bash
cp .env.example .env
# fill at minimum: INTERNAL_API_KEY, DATABASE_URL, IKA_GRPC_URL,
#                  SOLANA_RPC_URL, IKA_PROGRAM_ID

# Proto files from upstream Ika
cd proto && git clone --depth=1 https://github.com/dwallet-labs/ika-pre-alpha /tmp/ika
cp /tmp/ika/proto/*.proto . && cd ..

npm install
npm run dev
```

Supported curves: Ed25519 (Solana, NEAR, Aptos, Cosmos Ed25519), SECP256K1 (EVM, Bitcoin, Cosmos secp256k1), SECP256R1 (P-256, WebAuthn), Ristretto (Substrate/Polkadot).

Full Recovery spec in `docs/RECOVERY.md`. Status in `docs/STATUS.md`.
