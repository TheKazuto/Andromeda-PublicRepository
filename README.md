<div align="center">
  <img src="Logo.png" alt="Andromeda" width="180" />

  <h1>Andromeda</h1>

  <p><strong>Multi-chain MPC + FHE infrastructure as REST and MCP.</strong></p>

  <p>Connect any blockchain to threshold signing and confidential computing<br/>without writing Rust, Move, or running a single node.</p>

  <p>
    <img src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg" alt="License" />
    <img src="https://img.shields.io/badge/status-devnet%20pre--alpha-orange.svg" alt="Status" />
    <img src="https://img.shields.io/badge/Solana%20programs-8-9945ff.svg" alt="Solana programs" />
    <img src="https://img.shields.io/badge/MCP-tools%20auto--generated-7c3aed.svg" alt="MCP" />
    <img src="https://img.shields.io/badge/OpenAPI-3.1-6BA539.svg" alt="OpenAPI" />
  </p>
</div>

> ⚠️ *Andromeda is under development. Any structure or feature may have its code and operational design altered in the interest of greater efficiency and security.*

---

## How we help teams adopt Ika and Encrypt

Ika and Encrypt deliver world-class primitives — 2PC-MPC threshold signing and homomorphic computation on Solana. Andromeda's role is to make those primitives painless to adopt for any team that wants to ship on top of them, without forcing the integrator to run validators, learn Rust, or build the surrounding product platform from scratch.

- **Zero-install integration.** Andromeda exposes every Ika operation and every Encrypt instruction as stateless REST. Teams integrate from any language in hours, without running gRPC clients, validator nodes, or a Node runtime on their side.

- **Audited policy templates ready to use.** Adopting Ika to power signing usually means authoring custom Solana programs that hold dWallet authority. We ship 8 audited Quasar templates (recovery, allowlist, velocity, time-lock, oracle, passkey, FHE-gated, session keys) so teams skip months of Rust + audit cycles.

- **Wallet-agnostic UX out of the box.** End users of Ika/Encrypt-powered apps come from every ecosystem. We built a gas-sponsor + challenge-based authentication layer so an EVM, BTC, Cosmos, NEAR, Aptos or passkey user can interact with the stack without ever holding SOL or installing a Solana wallet.

- **Production-ready developer tooling.** Beyond the cryptographic core, teams building on Ika/Encrypt benefit from surfaces that ship as part of the same platform: a native MCP server (so AI agents and IDEs integrate without glue code), HMAC-signed webhooks for on-chain events, an externally verifiable ed25519 audit log per tenant, idempotency keys on every mutating endpoint, OpenAPI 3.1 specs, dry-run simulation before signing, and auto-batching of multiple signatures into the smallest number of Solana transactions.

---

## Who it's for

Andromeda is a **B2D (Business-to-Developer)** platform.

- **Web3 developers** building multi-chain apps that need a unified signing surface across EVM, Solana, Bitcoin, Cosmos, NEAR, Aptos, Substrate.
- **Wallet and smart-wallet teams** that need cross-chain recovery and on-chain policy enforcement without writing Rust.
- **DeFi protocols** that need treasury policies (allowlists, velocity guards, oracle circuit breakers) enforced by Solana programs, not by a centralised backend.
- **AI agent builders** integrating signing capabilities into LLM workflows via MCP — no SDK, no glue code, just a streamable HTTP endpoint.
- **Compliance-driven products** that need an externally verifiable audit log, GDPR-ready identity, and KMS-backed signing keys from day one.

---

## Use cases

Cases that Andromeda specifically unblocks — not generic Web3 use cases.

- **Cross-chain smart wallets** — same identity drives signing across EVM, Solana, Bitcoin, Cosmos, NEAR and Aptos. The user signs into the app once and the dWallet derived from the OAuth subject is consistent across every client.
- **DAO treasuries with on-chain rule enforcement** — a Solana Quasar program (allowlist-destinations + velocity-guard) holds the dWallet authority. The treasury can only interact with whitelisted programs, capped at N signatures per slot window, with no ability for the gateway to bypass the policy.
- **Trading bots with scoped delegation** — the session-keys template grants a temporary key with on-chain limits on slot expiry, number of uses, amount per transaction, and allowed destination programs. Multiple sessions per dWallet (up to 2^32 concurrent), each with its own monotonic replay nonce.
- **AI agents that sign transactions** — every REST route on the gateway is auto-mirrored as an MCP tool. Drop the endpoint into Claude Desktop or Cursor and the agent can call signing, recovery, or policy operations natively.
- **Social recovery without a Solana wallet** — primary or M-of-N quorum recovery where the user signs a 32-byte challenge with whatever wallet they already own (MetaMask, Phantom, Keplr, Sui, BTC cold wallet, passkey). Andromeda pays gas and submits the Solana transaction.
- **FHE-gated confidential signing** — authorisation logic that runs on encrypted inputs. The decision is signed by an ed25519 key held in HashiCorp Vault Transit, then validated by an on-chain Quasar program before the Ika signature is released.

---

## Extra features

26 capabilities delivered on top of the Ika/Encrypt primitives.

### Multi-chain core
- **Any wallet, any chain adapter for Ika** — uniform REST surface over 4 cryptographic curves (Ed25519, SECP256K1, SECP256R1, Ristretto).
- **Multi-chain signing pipeline** — DKG, Presign, Sign, Future-Sign, Imported Key, Re-Encrypt Share exposed as stateless REST primitives.

### Wallet-agnostic + gas sponsor
- **Gas sponsor** — Andromeda absorbs Solana fees on every flow it controls. End users sign 32-byte canonical challenges with whatever wallet they already own; the gateway pays gas and submits.

### Custody-free recovery
- **Recovery layer (primary + M-of-N quorum)** — primary single-sig flow + multi-tx PDA staging quorum. No bound on quorum size.
- **Cross-chain recovery schemes** — 7 off-chain ownership-proof schemes + 4 on-chain credential schemes, all validated by Solana precompiles. Zero attestor.
- **On-chain RulesPolicy** — Quasar program that holds dWallet authority with the policy PDA seeded by an init-authority hash (front-running protected), the Solana clock as the only time source, and strict pattern matching on the WebAuthn challenge field.

### Policy templates
- **8 Quasar policy templates** — rules-policy, allowlist-destinations, velocity-guard, time-lock, oracle-conditional, passkey-step-up, fhe-gated, session-keys. All audited, all wallet-agnostic.
- **Session keys with multi-session** — up to 2^32 concurrent sessions per dWallet, each with a monotonic replay nonce that binds the message digest, amount, destination program, and signature nonce together.

### Confidential computing
- **Confidential Workflows pipeline** — Encrypt FHE evaluation flows into Vault Transit ed25519, then into the Quasar fhe-gated policy, then into the Ika signature. An on-chain authority allowlist plus a non-zero decision-age window are enforced before any signature is released.

### On-chain awareness + future-sign
- **Webhook-driven Future-Sign** — arm a trigger (oracle / slot / event / external webhook), Andromeda fires the signature when the condition matches.
- **IDL-aware Solana listener** — websocket subscription that parses the 6 canonical Andromeda events and 4 Anchor self-CPI events from Ika, fanning out to per-tenant webhooks.
- **HMAC-signed webhook system** — replay-protected (5-minute window), retries with backoff, dead-letter queue.

### Optional identity layer
- **Identity Layer** — OAuth (Google/Apple/Twitter/GitHub) + email magic link + passkey-as-identity (WebAuthn PRF). The dWallet address is derived deterministically from the OAuth provider plus subject identifier, so any client doing OAuth on the same account derives the same wallet — cross-client recovery comes for free.
- **Anti-enumeration + atomic single-use tokens** — the email-request endpoint always returns 200 (so attackers cannot probe which emails have accounts), and every token is consumed via an atomic single-use SQL update.
- **PII encryption-at-rest** — AES-256-GCM envelope applied to identity records, account-link records, and email-token rows in Postgres. A DB dump leak does not become a PII leak.
- **GDPR endpoints** — GET /me/export returns a full JSON dump of the user's identifiable data; DELETE /me cascades a purge across all linked records.

### API surface
- **API key management with scopes and IP allowlist** — granular permissions (read, write, admin, wildcard), CIDR allowlist per key, SHA-256 hashing, async last-used tracking.

### Developer experience
- **MCP Server with auto-generated tools** — 60 tools auto-registered from the same route catalogue that drives REST. Drop into Claude Desktop or Cursor with zero glue code.
- **Capabilities endpoint** — public introspection of what is wired in this deployment (engines, features, MCP transport, route count).
- **OpenAPI 3.1 + curl + Postman** — every public endpoint comes with a typed schema and copy-paste examples in Node, Go, Python, Rust.
- **SDK metadata endpoint** — for any deployed policy, the gateway returns a tarball URL plus an install command for a typed TypeScript client tailored to that policy.

### Operational excellence
- **Idempotency-Key** — safe retries on every mutating endpoint, byte-identical replay, body-collision detection (422).
- **Dry-run / Simulate** — uses Solana simulateTransaction and returns a structured diagnostic with would-succeed flag, failure boundary, estimated compute units, emitted events, and full logs.
- **Auto-batching of signatures** — pack up to 64 signature requests into K Solana transactions (greedy packing, 1180-byte cap, max 16 per tx).

### Compliance + KMS
- **Signed exportable Audit Log** — per-tenant ed25519 hash chain signed by HashiCorp Vault Transit. Externally verifiable without trusting Andromeda.
- **Vault Transit KMS** — two separate ed25519 keys (one for audit signing, one for FHE authority), each with a sign-only policy and its own periodic token. Andromeda never sees the private material.

---

## Architecture

```
                 ┌──────────────────────────────────┐
                 │   External clients (any chain)   │
                 │   REST + MCP + Webhooks          │
                 └────────────────┬─────────────────┘
                                  │ X-Api-Key
                                  ▼
                 ┌──────────────────────────────────┐
                 │           Gateway (Go)           │
                 │  Auth + Quotas + MCP + Audit +   │
                 │  Idempotency + Webhooks + Batch  │
                 └─────┬────────────────────┬───────┘
                       │ private network    │ private network
                       ▼                    ▼
              ┌────────────────┐    ┌─────────────────┐
              │  ika-backend   │    │ encrypt-backend │
              │  MPC engine    │    │   FHE engine    │
              └────┬───────────┘    └────────┬────────┘
                   │ gRPC                    │ gRPC
                   ▼                         ▼
              Ika validator             Encrypt network
                network                   (devnet)

     ┌────────────────────────────────────────────────────┐
     │  Solana devnet — 8 Quasar policy programs          │
     │  Hold dWallet authority, validate every sig        │
     │  via runtime precompiles (zero attestor)           │
     └────────────────────────────────────────────────────┘

     Postgres (shared with backend)   |   HashiCorp Vault Transit
     Stripe + SMTP (backend service)  |   Cloudflare Pages (dashboard)
```

The product surface is composed of **5 services** plus **8 on-chain Quasar programs**.

| Service | Stack | Role |
|---------|-------|------|
| gateway | Go 1.25, chi, pgx, Redis | Hot path. Auth, quota, rate limit, MCP server, reverse-proxy to engines, audit log. |
| ika-backend | Node 24, Express 5, @grpc/grpc-js, @solana/kit | MPC engine. gRPC to Ika validator network, recovery layer, identity layer. |
| encrypt-backend | Node 22, Hono 4, @encrypt.xyz/pre-alpha-solana-client | FHE engine. 22 Encrypt instructions + high-level wallet primitives. |
| backend | Go 1.25, chi, pgx, Stripe | Product surface. Auth, customer endpoints, billing, admin console. |
| dashboard | Next.js 16, React 19, Tailwind 4 | Static export. Customer dashboard + admin console + landing. |

---

## Quick start

### Try it now (no install)

A live deployment is available — judge the platform without cloning anything.

```bash
# Public capability snapshot — no auth
curl <GATEWAY_URL>/capabilities

# OpenAPI 3.1 spec — auto-generated from routes
curl <GATEWAY_URL>/openapi.json

# Public pricing catalogue
curl <GATEWAY_URL>/v1/pricing
```

For authenticated endpoints, request a devnet API key by signing up at DASHBOARD_URL/signup.

### Wallet-agnostic recovery (signature flow)

Demonstrates the gas-sponsored, challenge-based UX. The user signs a 32-byte challenge with whatever wallet they already own; Andromeda assembles, signs and submits the Solana transaction.

```bash
# 1. Request a recovery challenge
curl -X POST <GATEWAY_URL>/v1/recovery/primary/challenge \
  -H "X-Api-Key: $ANDROMEDA_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "dwalletAddress": "<DWALLET_ADDRESS>",
    "messageHashHex": "<32-BYTE-HEX>"
  }'
# → { "challengeBase64": "...", "expectedNonce": 7, "primaryScheme": "Ed25519" }

# 2. User signs `challengeBase64` off-chain with their wallet
#    (MetaMask, Phantom, Keplr, Sui Wallet, BTC cold wallet, passkey, etc.)

# 3. Submit the signature — Andromeda pays gas and broadcasts
curl -X POST <GATEWAY_URL>/v1/recovery/primary/submit \
  -H "X-Api-Key: $ANDROMEDA_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "dwalletAddress": "<DWALLET_ADDRESS>",
    "messageHashHex": "<32-BYTE-HEX>",
    "signatureBase64": "<USER_SIGNATURE>",
    "expectedNonce": 7
  }'
# → { "txSignature": "...", "messageApprovalAddress": "..." }
```

The end user never holds SOL, never installs a Solana wallet, never sees a Solana RPC endpoint.

### Connect via MCP

Drop the gateway endpoint into any MCP client (Claude Desktop, Cursor, custom):

```json
{
  "mcpServers": {
    "andromeda": {
      "url": "<GATEWAY_URL>/mcp",
      "headers": {
        "X-Api-Key": "<ANDROMEDA_KEY>"
      }
    }
  }
}
```

The agent can immediately call any of the 60 auto-generated tools, covering signing, recovery, policy operations, webhooks, audit log queries, and the full Encrypt FHE surface.

### Run locally

The monorepo runs on Postgres + Redis + 5 services. Each service has its own .env.example.

```bash
git clone <REPO_URL> andromeda
cd andromeda

# 1. Provision Postgres and (optionally) Redis locally.

# 2. Boot each service in its own terminal.
( cd backend         && cp .env.example .env && go mod download && go run ./cmd/server )
( cd gateway         && cp .env.example .env && go mod download && go run ./cmd/server )
( cd ika-backend     && cp .env.example .env && npm install && npm run dev )
( cd encrypt-backend && cp .env.example .env && npm install && npm run dev )
( cd dashboard       && cp .env.local.example .env.local && npm install && npm run dev )

# 3. Open the dashboard.
open http://localhost:3000
```

Service ports: backend on 8080, gateway on 8081, ika-backend on 3020, encrypt-backend on 3010, dashboard on 3000.

### Build

Every service ships a Dockerfile and a Railway config. The dashboard exports to a static "out" directory for Cloudflare Pages.

```bash
( cd backend         && go build -o bin/backend ./cmd/server )
( cd gateway         && go build -o bin/gateway ./cmd/server )
( cd ika-backend     && npm run build )
( cd encrypt-backend && npm run build )
( cd dashboard       && npm run build )      # static export → out/
```

### Test

```bash
( cd backend         && go test ./... )
( cd gateway         && go test ./... )
( cd ika-backend     && npm test )
( cd encrypt-backend && npm test )
```

---

## Deployments

All artefacts live on Solana **devnet** during pre-alpha.

| Component | URL / Address |
|-----------|---------------|
| Landing page | LANDING_URL |
| Dashboard | DASHBOARD_URL |
| Gateway API | GATEWAY_URL |
| OpenAPI spec | GATEWAY_URL/openapi.json |
| MCP endpoint | GATEWAY_URL/mcp |
| Capabilities endpoint | GATEWAY_URL/capabilities |

### On-chain programs (Solana devnet)

| Program | Address | Purpose |
|---------|---------|---------|
| rules-policy | PROGRAM_ID | Recovery primary + M-of-N quorum + cooldown + daily limit |
| allowlist-destinations | PROGRAM_ID | Restrict signing to whitelisted destination programs |
| velocity-guard | PROGRAM_ID | Rate-limit signatures per slot window |
| time-lock | PROGRAM_ID | Restrict signing to allowed slot ranges |
| oracle-conditional | PROGRAM_ID | Pyth Pull V2 circuit breaker |
| passkey-step-up | PROGRAM_ID | Require passkey proof above threshold |
| fhe-gated | PROGRAM_ID | Gate signing on confidential FHE evaluation |
| session-keys | PROGRAM_ID | Multi-session scoped delegation |

---

## Status

**Pre-alpha. Devnet only. Do not custody real value.**

- Ika integration runs against the public pre-alpha validator network with a single mock signer. No cryptographic MPC guarantee yet.
- Encrypt integration runs against the public pre-alpha network. No real FHE confidentiality guarantee yet.
- All 8 Quasar policy programs were security-audited internally in May 2026 (front-running, time source, replay protection, type confusion, oracle owner check). Pre-mainnet third-party audit pending.

---

## License

Dual-licensed under **Apache-2.0 OR MIT**.

## Team

Built by **Shinka Labs** — shinkalabs.com
