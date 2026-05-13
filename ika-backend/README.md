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
│   ├── oidc/                       # Opt-in (Login Social): /v1/oidc/{nonce,validate} + JWT derivations
│   ├── recovery/
│   │   ├── verifiers/              # 7 off-chain schemes
│   │   ├── discovery/              # Off-chain ownership proof
│   │   ├── primary/                # Single-tx flow
│   │   ├── quorum/                 # PDA staging multi-tx
│   │   ├── policy/                 # Admin actions
│   │   ├── oidc/                   # Opt-in (Login Social): /v1/recovery/primary/oidc/*
│   │   ├── adapters/               # PolicyAdapter, SolanaAdapter (incl. solana/oidc.ts flow module)
│   │   ├── message.ts              # Canonical discovery message
│   │   └── challenge.ts            # Byte-for-byte mirror of auth/challenge.rs (incl. OP_OIDC_*)
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
| Recovery (discovery) | `IKA_RECOVERY_ENABLED` | `/v1/recovery/{challenge,resolve}` |
| Recovery (policy) | `IKA_RECOVERY_POLICY_ENABLED` | `/v1/recovery/{primary,quorum,policy}/*` |
| Login Social (OIDC) | `IKA_OIDC_ENABLED` (requires policy layer + `jwk-registry` deployed) | `/v1/oidc/{nonce,validate}` + `/v1/recovery/primary/oidc/*` |

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
| OidcJwt (scheme=4) | `[4, addr_seed(32), 0]` | Google / Apple `id_token` via the on-chain `oidc-verifier` (RSA-2048 + JWK registry) — auth path is JWT + ephemeral Ed25519 (NOT a signature over a 32-byte challenge); see Login Social section below |

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

### Recovery — Login Social (OIDC primary, scheme=4)

`IKA_OIDC_ENABLED=true` mounts the OIDC routes. Identity is verified entirely on-chain (RSA-2048 over the provider's `id_token`, JWK registry, ephemeral Ed25519 binding — **zero attestor**). The OAuth handshake itself is brokered by `gateway/`'s `/v1/oauth/*` routes; this backend handles validation + the gas-sponsored recovery flow. Full spec in `loginsocial.md`.

| Route | Purpose |
|-------|---------|
| `POST /v1/oidc/nonce` | Given an ephemeral Ed25519 pubkey, returns the canonical `oidc_nonce` to use as the OAuth `nonce`. The client doesn't need to know the byte layout. |
| `POST /v1/oidc/validate` | Off-chain pre-check of an `id_token` (provider JWKS + claims + `nonce` shape). Returns derived hashes only — never the raw `sub` / JWT. |
| `POST /v1/recovery/primary/oidc/stage` | Stages the `id_token` into an on-chain `OidcJwtStaging` PDA. |
| `POST /v1/recovery/primary/oidc/open/challenge` | Returns the `oidc-session-open` challenge for the ephemeral key to sign. |
| `POST /v1/recovery/primary/oidc/open` | Verifies JWT + RSA + claims + ephemeral signature; creates the short-lived `OidcSession` (≤ 600 s). |
| `POST /v1/recovery/primary/oidc/use/challenge` | Per-use challenge bound to the session + the message about to be approved. |
| `POST /v1/recovery/primary/oidc/use/submit` | Authorises one Ika `approve_message` through the open session. |
| `POST /v1/recovery/primary/oidc/close` | Closes an expired session (rent refund). |
| `POST /v1/recovery/primary/oidc/staging/close` | Reclaims an abandoned staging account. |

The trust root for the JWKs lives in a separate on-chain `jwk-registry` program. The off-chain `jwk-rotator` worker (see [`jwk-rotator/README.md`](../jwk-rotator/README.md)) keeps it in sync with the provider JWKS.

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
| `ALLOWED_ORIGINS` | _(empty → CORS off)_ | CSV of origins allowed on `/v1/recovery/*` and `/v1/oidc/*`. Engine routes never set CORS. |
| `IKA_GRPC_TLS` | `true` | TLS for the Ika gRPC channel. |
| `SOLANA_COMMITMENT` | `confirmed` | `processed` / `confirmed` / `finalized`. |
| `PGSSLMODE` | _(unset)_ | Postgres SSL mode (e.g. `prefer`, `require`). |
| `IKA_PG_POOL_MAX` | `20` | Max Postgres pool size. |
| `IKA_PG_CONNECTION_TIMEOUT_MS` | `3000` | Postgres connection timeout (ms). |
| `SENTRY_DSN` | _(unset)_ | Optional error reporting. |

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

### Login Social — OIDC primary (opt-in — `IKA_OIDC_ENABLED=true`)

Mounts `/v1/oidc/{nonce,validate}` + `/v1/recovery/primary/oidc/*`. Requires the policy recovery layer to also be on (`IKA_RECOVERY_POLICY_ENABLED=true`) and the `jwk-registry` program to be deployed + bootstrapped. Boot refuses to start if any required value is missing or if no provider is enabled. Full spec in `loginsocial.md` §6 / §9.

| Var | Default | Notes |
|-----|---------|-------|
| `IKA_OIDC_ENABLED` | `false` | Master flag. Requires `IKA_RECOVERY_POLICY_ENABLED=true`. |
| `IKA_OIDC_GOOGLE_ENABLED` | `false` | Accept Google `id_token`s (`iss=https://accounts.google.com`). |
| `IKA_OIDC_GOOGLE_CLIENT_ID` | _(none)_ | The auth-broker's Google OAuth client_id. Required when Google is enabled. |
| `IKA_OIDC_APPLE_ENABLED` | `false` | Accept Apple `id_token`s (`iss=https://appleid.apple.com`). |
| `IKA_OIDC_APPLE_CLIENT_ID` | _(none)_ | Apple Services ID. Required when Apple is enabled. |
| `IKA_OIDC_ALLOWED_AUDIENCES` | _(none)_ | CSV of allowed `aud` claims. Must mirror the on-chain `OIDC_ALLOWED_AUDIENCES` constant in `rules-policy`. Required when enabled. |
| `IKA_OIDC_JWK_REGISTRY_ADDRESS` | _(none)_ | Address of the on-chain `JwkRegistry` account (canonical PDA of the `jwk-registry` program). Required when enabled. |
| `IKA_OIDC_VERIFIER_VERSION` | `1` | Must equal the on-chain `OIDC_VERIFIER_V1`. Bumps with any wire-format change. |
| `IKA_OIDC_LOG_SUBJECT_HMAC_SECRET` | _(none)_ | HMAC key (≥32 bytes, hex) for hashing `sub` in logs/metrics. **Required when enabled.** Generate with `openssl rand -hex 32`. Rotation invalidates historical correlation only — no operational impact. Never reuse another secret. |

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

Full Recovery spec in `docs/RECOVERY.md`. Status in `docs/STATUS.md`. Roadmap in `PLAN.md`. Login Social plan + crypto spec in `loginsocial.md`; pre-deploy audit report in `docs/AUDIT_LOGINSOCIAL_2026_05.md`.
