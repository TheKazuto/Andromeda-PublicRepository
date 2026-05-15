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
│   │   ├── passkey/                # Opt-in (Keyspring): /v1/recovery/primary/passkey/* + store helpers
│   │   ├── adapters/               # PolicyAdapter, SolanaAdapter (solana/oidc.ts + solana/passkey.ts flow modules)
│   │   ├── message.ts              # Canonical discovery message
│   │   └── challenge.ts            # Byte-for-byte mirror of auth/challenge.rs (incl. OP_OIDC_* + OP_PASSKEY_*)
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
| Passkey-PRF (Keyspring) | `IKA_PASSKEY_ENABLED` (requires policy layer) | `/v1/recovery/primary/passkey/*` |

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

#### Clear Signing v2 (shipped 2026-05-14)

Every `/challenge` route in this backend returns a deterministic
human-readable text alongside the 32-byte challenge bytes. The on-chain
program recomputes the same text from the same typed parameters and
embeds it (length-prefixed `u16 LE`) into the SHA-256 the credential
signs — so a compromised backend cannot swap destination, member,
amount, nonce or session without the approver seeing the swap in the
text they are about to sign.

**Wire format on-chain.**

```
challenge = sha256(
    DOMAIN              // e.g. "andromeda::rules-policy::v2"
    || op_tag           // e.g. "primary-recover" / "admin-add-member" / "oidc-session-open"
    || human_len_u16_le // 2 bytes, little-endian length of the next field
    || human_message    // plain ASCII, ≤ 768 bytes
    || dwallet || ...   // remaining typed parameters
)
```

`MAX_HUMAN_MESSAGE_BYTES = 768`. ASCII only (`0x20..=0x7E`). Bumped from
the original 512 because `quorum-contribute` carries the full session
snapshot plus the member-slot text in worst case.

**API response shape.** Every `*/challenge` route returns:

```json
{
  "data": {
    "challengeBase64": "...",
    "humanMessage": "Add member scheme:0;id:... to policy 4xyz... for dWallet 9abc...",
    "clearSigning": {
      "version": "rules-policy-clear-v1",
      "operation": "admin-add-member",
      "fields": {
        "dwallet": "9abc...",
        "policy": "4xyz...",
        "expectedNonce": "7",
        "newMemberSlotHex": "00ab..."
      }
    },
    "expectedNonce": "7"
  }
}
```

* `humanMessage` — the exact ASCII text the approver MUST see before
  signing. Plain text, no locale, no truncation.
* `clearSigning.version` — `rules-policy-clear-v1` for every route in
  this backend.
* `clearSigning.operation` — canonical op tag (`primary-recover`,
  `quorum-session-open`, `quorum-contribute`, the 12 `admin-*`,
  `oidc-session-open`, `oidc-primary-use`).
* `clearSigning.fields` — curated map of typed parameters (Solana
  addresses base58, hashes hex, integers as decimal strings). Never the
  raw JWT, never `sub` / `email` / PII.

**Templates covered (17 ops).** Recovery: `primary-recover`,
`quorum-session-open`, `quorum-contribute`. Admin (primary signs):
`admin-add-member`, `admin-remove-member`, `admin-add-destination`,
`admin-remove-destination`, `admin-revoke`, `admin-set-primary`,
`admin-set-qt-immediate`, `admin-set-dl-immediate`,
`admin-set-cd-immediate`, `admin-propose-qt`, `admin-propose-dl`,
`admin-propose-cd`. OIDC: `oidc-session-open`, `oidc-primary-use`.

Flows preserved at v1 (no clear signing) because they are single-shot,
PDA-bound or non-human-signed: `OP_INIT` of every program,
`request-signature` runtime digests, `passkey-step-up::step-up`
(WebAuthn embeds its own `clientDataJSON.challenge`),
`fhe-gated::decision` (signed by Vault Transit KMS, not a human),
`session-keys::create-session`.

**`submit` never trusts caller-supplied text.** Every `/submit` route
ignores any `humanMessage` in the body and recomputes the challenge from
the same typed params it received. If the on-chain hash doesn't match,
the precompile fails and the transaction reverts.

**OIDC privacy.** OIDC templates use addresses, 32-byte hashes, and the
ephemeral pubkey. Never the JWT, the raw `sub`, the email, or the name.

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

`IKA_OIDC_ENABLED=true` mounts the OIDC routes. Identity is verified entirely on-chain (RSA-2048 over the provider's `id_token`, JWK registry, ephemeral Ed25519 binding — **zero attestor**). The OAuth handshake itself is brokered by `gateway/`'s `/v1/oauth/*` routes; this backend handles validation + the gas-sponsored recovery flow.

**Flow (devnet pre-alpha).**

1. Client generates an ephemeral Ed25519 keypair on device.
2. `POST /v1/oidc/nonce { ephPkBase64 }` → returns the canonical `oidcNonce` to embed in the OAuth `nonce`.
3. Client runs the OAuth handshake (gateway's `/v1/oauth/*` routes) with `scope=openid` → receives `id_token`.
4. `POST /v1/oidc/validate { idToken }` → off-chain pre-check (provider JWKS + claims + nonce shape). Returns `addrSeed` + `issuerHash` + `audienceHash` + `subjectHash`.
5. `POST /v1/recovery/primary/oidc/stage` → stages the `id_token` into an on-chain `OidcJwtStaging` PDA.
6. `POST /v1/recovery/primary/oidc/open/challenge` → returns the `oidc-session-open` challenge (with `humanMessage` + `clearSigning`). Client signs the 32 bytes with the ephemeral key.
7. `POST /v1/recovery/primary/oidc/open` → on-chain: verifies RSA over the JWT + claims + JWK registry + the ephemeral signature → creates the short-lived `OidcSession` PDA (≤ 600 s).
8. For each signature: `POST /v1/recovery/primary/oidc/use/challenge` → per-use challenge → client signs with ephemeral key → `POST /v1/recovery/primary/oidc/use/submit` → on-chain Ika `approve_message`.
9. `POST /v1/recovery/primary/oidc/close` → close expired session (rent refund).

**Cross-client identity.** `addrSeed = sha256("andromeda::oidc::addr::v1" || lp(iss) || lp(aud) || lp(sub))`. Same Google/Apple account → same `addrSeed` → same dWallet across apps on Andromeda. The `aud` portion uses a single global Andromeda OAuth client per environment so cross-app portability holds.

**Required programs deployed on Solana.** `rules-policy` (with `scheme=4`/OidcJwt primary), `jwk-registry` (trust root for provider JWKs), `oidc-verifier` (RS256 on-chain via `sol_big_mod_exp`). Each `jwk-registry` triplet is `(issuerHash, audienceHash, kidHash) → modulus`. Off-chain rotator keeps the registry in sync with provider JWKS.

**`sol_big_mod_exp` feature gate.** The on-chain RSA verify uses the Solana syscall `sol_big_mod_exp`. If the gate `EBq48m8irRKuE7ZnMTLvLg2UuGSqhe8s8oMqnmja1fJw` is `inactive` in the target cluster, the `rules-policy` program must be rebuilt with `cargo build-sbf --no-default-features` (forwards `--no-default-features` to `andromeda_oidc_verifier`, which then returns a sentinel buffer for every modexp). With the stub, OIDC opens/uses fail every signature comparison; primary recovery, quorum, admin actions are unaffected.

**Privacy.** Never log JWTs, raw `sub`, email, or name. Audit log entries store only addresses + hashes + the rendered `humanMessage` (which by construction also uses only addresses + hashes).

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

The trust root for the JWKs lives in a separate on-chain `jwk-registry` program. The off-chain `jwk-rotator/` worker (in the monorepo root) keeps it in sync with the provider JWKS via the `jwk-registry::propose` and `::commit` flow (proposal → timelock → commit), so a rogue provider key cannot be inserted instantly.

### Recovery — Passkey-PRF (WebAuthn primary, scheme=3)

`IKA_PASSKEY_ENABLED=true` mounts the passkey routes (Keyspring Fase 3 — D1 Opção A of `PLAN_KEYSPRING_INTEGRATION_2026_05.md`). A passkey credential lives in `policy.primary_slot` as `[SCHEME_WEBAUTHN, credential_pubkey(33)]`, but on-chain it is **session-scoped**: every use of the primary goes through a short-lived `PasskeySession` PDA opened by a single WebAuthn assertion and authorized per-use by an Ed25519 signature from the ephemeral key committed at open time. The PRF secret never leaves the browser (D12).

```
POST /v1/recovery/primary/passkey/credentials/register-init     # server issues a single-use challenge for navigator.credentials.create
POST /v1/recovery/primary/passkey/credentials/register-complete # persists credential (D6 hard limit 5/dwallet enforced in tx)
GET  /v1/recovery/primary/passkey/credentials?dwalletAddress=…  # lists active credentials (public metadata only)
POST /v1/recovery/primary/passkey/credentials/:id/revoke        # D5 guard: refuses to revoke the last active recovery method (HTTP 409)

POST /v1/recovery/primary/passkey/open/challenge   # passkey_session_open_challenge — signed by WebAuthn (Secp256r1)
POST /v1/recovery/primary/passkey/open             # ix 25 passkey_session_open + Secp256r1 precompile
POST /v1/recovery/primary/passkey/use/challenge    # passkey_primary_use_challenge — signed by ephemeral Ed25519
POST /v1/recovery/primary/passkey/use/submit       # ix 26 recover_as_primary_passkey_session + CPI Ika approve_message
POST /v1/recovery/primary/passkey/close            # ix 27 passkey_session_close (rent refund to gas sponsor)
GET  /v1/recovery/primary/passkey/capabilities     # rp_id / origin / salt mode / TTLs / on-chain WebAuthn bounds
```

**Custody-free.** The user signs the open challenge with a WebAuthn assertion (authenticator's secure element) and each per-use challenge with a per-session Ed25519 key. The gas sponsor pays the Solana fee; the on-chain `rules-policy` is the only authority. Even if the backend is compromised it cannot forge a signature.

**Salt strategy (D3).** Only `IKA_PASSKEY_SALT_MODE=per_credential` is accepted in production. Each credential gets a stable `salt_id` (UUID v4) + `salt_hash` (sha256 of the raw salt). The raw salt itself is derived `HKDF(server_secret, salt_id)` at use time and never persisted.

**RP ID (D2) — per-tenant via `api_keys.allowed_origins`.** Andromeda is B2D: every client runs on its own domain. The `rp_id` / `rp_origin` of a registration is resolved from the API key's existing CORS `allowed_origins` (migration 017) — the gateway forwards that list as `X-Andromeda-Allowed-Origins` (CSV) and the passkey routes validate the client's chosen origin against it. When a key has exactly one allowed origin the client may omit `rpOrigin`; when it has multiple, the client passes `rpOrigin` per call. `rpId` defaults to the registrable apex of the host (e.g. `app.cliente.com` → `cliente.com`) but the client may pick a stricter subdomain rpId as long as it is a suffix of the host. The env defaults (`IKA_PASSKEY_RP_ID` / `IKA_PASSKEY_RP_ORIGIN`) are used only when the key has no `allowed_origins` — that path covers the Andromeda dashboard itself. **Pinned at registration**: the resolved `(rpId, rpOrigin)` pair is persisted into `passkey_credentials` and into the `register-init` challenge's metadata so a client can't swap it between `-init` and `-complete`. Once a credential is registered, its rp_id is **IMMUTABLE** for that credential — rotating the apex on the api key orphans existing credentials but does not affect new ones.

**Multiple passkeys per dWallet (D6).** Up to 5 active credentials per dWallet. Cross-device use case: 1 hardware key + 1 iCloud Keychain + 1 Google Password Manager + 1 Windows Hello + 1 reserve. The limit is enforced inside a `SELECT … FOR UPDATE` transaction at `register-complete` so concurrent registers can't both win the 5th slot.

**Bound payload sizes (D13).** `authenticatorData` and `clientDataJSON` are each capped at 192 bytes on-chain. Samsung Pass returns `authData = 84 bytes` in the Fase 0 spike; the 192-byte cap leaves ~2.3× margin for future authenticators with multiple active extensions.

**Cross-language drift gate.** Challenge bytes + human-message renderers + primary slot layout + WebAuthn bounds are mirrored byte-for-byte in `contracts/auth/src/challenge.rs`, `contracts/auth/src/human_message.rs`, `ika-backend/src/recovery/challenge.ts`, and `fixtures/passkey_prf/v1/`. CI runs the matching Rust + TS fixture tests; any drift fails both jobs.

### Health
- `GET /health` — liveness (no auth)
- `GET /health/deep` — Postgres + Ika gRPC + Solana RPC checks; requires `X-Api-Key: <IKA_ADMIN_API_KEY>`

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

Mounts `/v1/oidc/{nonce,validate}` + `/v1/recovery/primary/oidc/*`. Requires the policy recovery layer to also be on (`IKA_RECOVERY_POLICY_ENABLED=true`) and the `jwk-registry` program to be deployed + bootstrapped. Boot refuses to start if any required value is missing or if no provider is enabled.

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

### Passkey-PRF (opt-in — `IKA_PASSKEY_ENABLED=true`)

Mounts `/v1/recovery/primary/passkey/*`. Requires the policy recovery layer (`IKA_RECOVERY_POLICY_ENABLED=true`). Boot refuses to start if `IKA_PASSKEY_SALT_MODE` is anything other than `per_credential` (D3 fail-fast).

| Var | Default | Notes |
|-----|---------|-------|
| `IKA_PASSKEY_ENABLED` | `false` | Master flag. Requires `IKA_RECOVERY_POLICY_ENABLED=true`. |
| `IKA_PASSKEY_RP_ID` | _(none)_ | **Fallback** RP_ID when the calling api_key has no `allowed_origins`. Production (Andromeda dashboard fallback): `andromedainfra.pro`. Per-tenant clients DON'T need this — they declare origins on their API key in the dashboard. |
| `IKA_PASSKEY_RP_ORIGIN` | _(none)_ | **Fallback** origin paired with `IKA_PASSKEY_RP_ID`. Same logic. |
| `IKA_PASSKEY_CHALLENGE_TTL_SECONDS` | `120` | TTL of `register-init` / pre-open challenges (single-use, consumed by the matching `-complete` / `-submit`). |
| `IKA_PASSKEY_SALT_MODE` | `per_credential` | **Only `per_credential` accepted in production.** Boot fails on `global`. See D3. |
| `IKA_PASSKEY_SESSION_TTL_SECONDS` | `600` | UI hint for session lifetime. The on-chain `rules-policy` enforces its own `SESSION_TTL_SECONDS = 600` cap regardless. |

Migration `015_passkey_credentials.sql` adds `passkey_credentials`, `passkey_challenges`, and `recovery_bindings`. These tables are owned exclusively by ika-backend (D4) — the gateway never reads them directly.

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
