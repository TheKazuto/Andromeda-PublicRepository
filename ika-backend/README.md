# ika-backend

Andromeda's MPC engine, integrated with the Solana variant of Ika dWallet (`ika-pre-alpha`). Connects any blockchain to the Ika 2PC-MPC protocol without requiring a client-side SDK.

> **Pre-alpha.** Devnet only. Single mock signer. No cryptographic MPC guarantee. Do not custody real value.

Stack: Node 24+ · TypeScript 6 · Express 5 · @grpc/grpc-js · @solana/kit · @noble/curves · bs58 · pg · jose · zod · pino · helmet · compression · Vitest · Railway.

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
│   ├── config.ts                   # Zod-validated env (base + identity + recovery + gasSponsor)
│   ├── safeError.ts                # Sanitized errors + trace id
│   ├── logger.ts                   # pino + redaction
│   ├── cmd/migrate.ts              # `npm run migrate` entrypoint
│   ├── http/                       # auth (X-Api-Key / admin), healthz, idempotency mirror
│   ├── engine/                     # MPC core
│   │   ├── grpc-client.ts          # Ika gRPC client
│   │   ├── solana-rpc.ts           # @solana/kit
│   │   ├── tx-builder.ts
│   │   ├── submit.ts               # Submit + confirm Solana txs
│   │   ├── gas-sponsor.ts          # Fee payer keypair
│   │   ├── precompiles.ts          # Ed25519/Secp256k1/Secp256r1 ix
│   │   ├── pda.ts
│   │   ├── routes.ts               # Mounts low-level prepare/submit + high-level MCP routes
│   │   ├── {dkg,sign,presign,future-sign,re-encrypt-share}.ts
│   │   └── ika-client/             # High-level tenant-scoped dWallet ops (MCP tools)
│   │       ├── routes.ts           # /create, /transfer-ownership, /approve, /admin/add-member, /presign, /sign
│   │       ├── wallet.ts           # Per-tenant keystore + dWallet lifecycle
│   │       ├── keystore.ts         # Passphrase-encrypted key material (cache/UX)
│   │       ├── request.ts          # gRPC request shaping
│   │       └── bcs.ts              # BCS codecs for Ika request payloads
│   ├── clients/
│   │   ├── ika/                    # transfer-ownership instruction codec
│   │   ├── policies/               # Read on-chain policy account state
│   │   └── rulesPolicy/            # Codecs + instructions + program PDA
│   ├── identity/                   # Opt-in: OAuth, email, passkey, linking, sessions, audit, PII-at-rest
│   ├── recovery/
│   │   ├── verifiers/              # 7 off-chain schemes
│   │   ├── discovery/              # Off-chain ownership proof
│   │   ├── primary/                # Single-tx flow
│   │   ├── quorum/                 # PDA staging multi-tx
│   │   ├── policy/                 # Admin actions
│   │   ├── adapters/               # PolicyAdapter, SolanaAdapter
│   │   ├── message.ts              # Canonical discovery message
│   │   └── challenge.ts            # Byte-for-byte mirror of auth/challenge.rs
│   ├── store/                      # Postgres pool + migrations + cleanup job
│   └── __tests__/
├── proto/                          # Ika .proto files (populate from upstream — boot fails without them)
├── scripts/                        # gen-keypair.mjs, run-migrations.ts (dev)
├── docs/{RECOVERY,STATUS}.md
├── .env.example                    # Authoritative list of every env var
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
| `POST /v1/dwallet/create` | `create_dwallet` | `passphrase` (≥12), optional `curve` (`Curve25519`/`Secp256k1`/`Secp256r1`), optional `attachRecoveryPolicy` + `primaryRecoveryOwner` (needs the recovery policy layer). |
| `POST /v1/dwallet/transfer-ownership` | `transfer_ownership` | Delegates dWallet authority to a new account (e.g. a `rules-policy` CPI authority PDA). |
| `POST /v1/dwallet/approve` | `approve` | Owner authorises a message → returns `approvalTxSignature` + `approvalSlot`. |
| `POST /v1/dwallet/admin/add-member` | `admin_add_member` | Adds a recovery member (keystore-primary policies only). |
| `POST /v1/dwallet/presign` | `presign` | Allocates a presign session. |
| `POST /v1/dwallet/sign` | `sign_message` | Signs a message using an approval + presign → returns `signatureBase64`. |

### MPC engine — low-level (prepare → submit)
- `POST /v1/dwallet/dkg/prepare` — `{ curve, userPublicKeyBase58 }` → returns the BCS `SignedRequestData` (base64) to sign, plus `sessionPreimageBase64`, `epoch` and `intendedChainSenderBase58`
- `POST /v1/dwallet/{dkg,sign,presign,future-sign,re-encrypt-share,make-share-public}/submit`
- `POST /v1/dwallet/future-sign/complete/submit`
- `GET  /v1/dwallet/presigns/:userPubkey` — `:userPubkey` is base64

### Recovery — Discovery (off-chain ownership proof)
- `POST /v1/recovery/challenge` — emits canonical message + nonce
- `POST /v1/recovery/resolve` — verifies the signature; returns the proven wallet plus its dWallets. Auto-enumerates Andromeda-managed dWallets (32-byte ed25519 / 20-byte EVM primary owners); accepts an optional `dwalletAddress` to confirm an external/bare dWallet

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

OAuth (Google/Apple/Twitter/GitHub), email magic link, passkey-as-identity (WebAuthn PRF).
Mounted under `/v1/identity/*` only when `IKA_IDENTITY_ENABLED=true`; each provider is gated by its
own flag. CORS is enabled here (unlike the engine routes). `walletAddress = sha256("<provider>:<subject>")`
— deterministic, so any client that authenticates the same account derives the same dWallet.

- `GET  /v1/identity/providers` — which providers are enabled
- `POST /v1/identity/oauth/{start,callback}` — OAuth (PKCE; `provider` in body)
- `POST /v1/identity/email/{request,verify}` — magic link (`/request` is anti-enumeration: always `200`)
- `POST /v1/identity/passkey/register/{options,verify}` — WebAuthn PRF registration
- `POST /v1/identity/passkey/authenticate/{options,verify}` — WebAuthn PRF login
- `GET  /v1/identity/me` · `POST /v1/identity/refresh` · `POST /v1/identity/logout` — session (Bearer JWT; `/refresh` is public, single-use rotated refresh token)
- `GET  /v1/identity/me/export` — GDPR JSON dump
- `DELETE /v1/identity/me` — GDPR purge (on-chain dWallet remains, with disclaimer)
- Account linking (Bearer JWT): `POST /v1/identity/link/oauth/{start,callback}`, `POST /v1/identity/link/email/{request,verify}`, `POST /v1/identity/link/passkey/register/{options,verify}`, `DELETE /v1/identity/link/:provider/:subject`

### Health
- `GET /health` — liveness (no auth)
- `GET /health/deep` — Postgres + Ika gRPC + Solana RPC checks; requires `X-Api-Key: <IKA_ADMIN_API_KEY>`

## Environment variables

`.env.example` is the authoritative, fully-commented list. Boot is fail-fast: every invalid or
missing required value is aggregated and printed, and the process exits.

### Required (always)
| Var | Notes |
|-----|-------|
| `INTERNAL_API_KEY` | Secret for the `X-Api-Key` header on all `/v1/*` routes. |
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
| `ALLOWED_ORIGINS` | _(empty → CORS off)_ | CSV of origins allowed on `/v1/identity/*` and `/v1/recovery/*`. Engine routes never set CORS. |
| `IKA_GRPC_TLS` | `true` | TLS for the Ika gRPC channel. |
| `SOLANA_COMMITMENT` | `confirmed` | `processed` / `confirmed` / `finalized`. |
| `PGSSLMODE` | _(unset)_ | Postgres SSL mode (e.g. `prefer`, `require`). |
| `IKA_PG_POOL_MAX` | `20` | Max Postgres pool size. |
| `IKA_PG_CONNECTION_TIMEOUT_MS` | `3000` | Postgres connection timeout (ms). |
| `SENTRY_DSN` | _(unset)_ | Optional error reporting. |

### Identity Layer (opt-in — `IKA_IDENTITY_ENABLED=true`)
Each provider has its own `*_ENABLED` flag. When identity is on, `IKA_IDENTITY_JWT_SECRET` (≥32 chars)
and `IKA_IDENTITY_PII_KEY` (32 bytes, base64) are required or the boot refuses to start.

| Var | Notes |
|-----|-------|
| `IKA_IDENTITY_ENABLED` | Master flag. |
| `IKA_IDENTITY_JWT_SECRET` | Session-token signing key, ≥32 chars (`openssl rand -hex 32`). **Required when enabled.** |
| `IKA_IDENTITY_PII_KEY` | 32-byte master key for PII encryption-at-rest (`openssl rand -base64 32`). **Required when enabled.** |
| `IKA_IDENTITY_JWT_ISSUER` / `_JWT_AUDIENCE` | Default `ika-backend` / `andromeda-client`. |
| `IKA_IDENTITY_JWT_TTL_SECONDS` / `_REFRESH_TOKEN_TTL_DAYS` | Default `900` / `7`. |
| `IKA_IDENTITY_AUDIT_LOG_ENABLED` | Optional sanitized audit log. |
| `IKA_IDENTITY_PERSIST_EMAIL` / `_PERSIST_DISPLAY_NAME` | Default `false`. |
| `IKA_IDENTITY_OAUTH_GOOGLE_ENABLED` + `..._OAUTH_GOOGLE_CLIENT_ID` / `_CLIENT_SECRET` / `_REDIRECT_URIS` | Google OAuth. |
| `IKA_IDENTITY_OAUTH_APPLE_ENABLED` + `..._OAUTH_APPLE_CLIENT_ID` / `_TEAM_ID` / `_KEY_ID` / `_PRIVATE_KEY` / `_REDIRECT_URIS` | Apple Sign-in. |
| `IKA_IDENTITY_OAUTH_TWITTER_ENABLED` + `..._OAUTH_TWITTER_CLIENT_ID` / `_CLIENT_SECRET` / `_REDIRECT_URIS` | Twitter (X) OAuth. |
| `IKA_IDENTITY_OAUTH_GITHUB_ENABLED` + `..._OAUTH_GITHUB_CLIENT_ID` / `_CLIENT_SECRET` / `_REDIRECT_URIS` | GitHub OAuth. |
| `IKA_IDENTITY_EMAIL_ENABLED` + `..._EMAIL_TRANSPORT` (`smtp`/`memory`) / `_EMAIL_FROM` / `_EMAIL_SMTP_URL` / `_EMAIL_FRONTEND_CALLBACK_URL` / `_EMAIL_TOKEN_TTL_SECONDS` / `_EMAIL_RATE_LIMIT_PER_EMAIL_PER_HOUR` / `_EMAIL_RATE_LIMIT_PER_IP_PER_HOUR` | Email magic link. `FROM`, `FRONTEND_CALLBACK_URL` required when enabled; `SMTP_URL` required with `smtp` transport. |
| `IKA_IDENTITY_PASSKEY_ENABLED` + `..._PASSKEY_RP_ID` / `_PASSKEY_RP_NAME` / `_PASSKEY_ORIGINS` / `_PASSKEY_PRF_SALT` | WebAuthn PRF. `RP_ID` + `PRF_SALT` (64 hex chars) required when enabled. **`PRF_SALT` is immutable after first boot** — rotating it orphans every passkey-derived wallet; the backend refuses to start if it changes. |

### Recovery Layer (opt-in)

`IKA_RECOVERY_ENABLED=true` alone mounts **only** the discovery routes (`/v1/recovery/{challenge,resolve}`).
When `IKA_RECOVERY_POLICY_ENABLED=true`, the boot **refuses to start** unless `IKA_RECOVERY_POLICY_PROGRAM_ID`,
`IKA_COORDINATOR_ADDRESS`, and a gas-sponsor keypair are all set (errors aggregated and printed; look for
`Recovery Layer enabled` with `policyEnabled: true` in the boot log to confirm it took).

| Var | Default | Notes |
|-----|---------|-------|
| `IKA_RECOVERY_ENABLED` | `false` | Enables discovery (`/v1/recovery/{challenge,resolve}`). |
| `IKA_RECOVERY_CHALLENGE_TTL_SECONDS` | `300` | Discovery/recovery challenge lifetime. |
| `IKA_RECOVERY_QUORUM_SESSION_TTL_SECONDS` | `600` | Quorum staging-session lifetime. |
| `IKA_RECOVERY_VERSION` | `andromeda-ika-recovery-v1` | Domain-separation version tag. |
| `IKA_RECOVERY_POLICY_ENABLED` | `false` | Enables on-chain primary/quorum/policy (`/v1/recovery/{primary,quorum,policy}/*`). Requires the next three. |
| `IKA_RECOVERY_POLICY_PROGRAM_ID` | _(none)_ | Deployed `rules-policy` (Quasar) program. Devnet: `6TX7qG47Fsocuwmgsgo2q3NLCHrbomoQxQLifapU8Thr`. |
| `IKA_COORDINATOR_ADDRESS` | _(none)_ | Ika `DWalletCoordinator` account = `PDA(["dwallet_coordinator"], IKA_PROGRAM_ID)`. Devnet: `V5giRyf1Rk9Lhn7sjq6LYnBv6TN8ZgSuRx654mPdYoA`. Re-derive: `solana find-program-derived-address <IKA_PROGRAM_ID> string:dwallet_coordinator`. |
| `IKA_RECOVERY_POLICY_DEFAULT_COOLDOWN_SECONDS` | `604800` | Default recovery cooldown. |
| `IKA_RECOVERY_POLICY_MIN_COOLDOWN_SECONDS` | `3600` | Floor for the cooldown. |
| `ANDROMEDA_GAS_SPONSOR_KEYPAIR` | _(none)_ | JSON byte array (64 B), `solana-keygen` format. **Required when policy recovery is active** — pays SOL for every recovery/admin/quorum tx so users never need a Solana wallet. Legacy alias: `IKA_GAS_SPONSOR_KEYPAIR`. Never commit it; keep it funded. |
| `IKA_GAS_SPONSOR_MIN_BALANCE_SOL` | `0.5` | Warn threshold for the sponsor balance. |
| `IKA_RECOVERY_MAX_GAS_PER_OP_LAMPORTS` | `20000000` | Per-op gas ceiling. |

## Setup

```bash
cp .env.example .env
# fill at minimum: INTERNAL_API_KEY, DATABASE_URL, IKA_GRPC_URL,
#                  SOLANA_RPC_URL, IKA_PROGRAM_ID
# to also enable policy recovery: IKA_RECOVERY_ENABLED=true,
#                  IKA_RECOVERY_POLICY_ENABLED=true, IKA_RECOVERY_POLICY_PROGRAM_ID,
#                  IKA_COORDINATOR_ADDRESS, ANDROMEDA_GAS_SPONSOR_KEYPAIR

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

Supported curves: Ed25519 (Solana, NEAR, Aptos, Cosmos Ed25519), SECP256K1 (EVM, Bitcoin, Cosmos secp256k1), SECP256R1 (P-256, WebAuthn), Ristretto (Substrate/Polkadot).

Full Recovery spec in `docs/RECOVERY.md`. Status in `docs/STATUS.md`. Roadmap in `PLAN.md`.
