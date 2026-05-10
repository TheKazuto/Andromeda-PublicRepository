<div align="center">
  <img src="Logo.png" alt="Andromeda" width="180" />

  <h1>Andromeda</h1>

  <p><strong>Multi-chain MPC + FHE infrastructure as API and MCP Server.</strong></p>

  <p>One API for cross-chain signing, confidential compute, and social recovery.<br/>No SDK, no node, no seed phrase, no chain-specific wallet for your users.</p>

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

## What is Andromeda?

Andromeda is hosted infrastructure that turns two of Solana's most powerful primitives, Ika's 2PC-MPC threshold signing and Encrypt's homomorphic computation, into plain REST endpoints and MCP tools.

Threshold signing lets a single identity control wallets on every chain (EVM, Bitcoin, Cosmos, NEAR, Aptos, Solana, Substrate) with no seed phrase and no single point of compromise. Confidential computing lets authorization logic run directly on encrypted data. Both are extraordinary, and both today require running validator clients, writing Rust or Move programs that hold wallet authority, and shipping a Node runtime to your users.

Andromeda removes all of that. You call an HTTPS endpoint. We run the engines, the on-chain policy programs, the gas, the wallet-agnostic auth layer, and the product surface around it. Your users never see the chain underneath: no wallet to install, no SOL to hold, no MPC network to learn.

## Why it matters

- **Multi-chain is still mostly glue code.** Every team rebuilds key management, recovery, and per-chain signing from scratch. Andromeda is one API for all of it.
- **"Smart wallet" usually means "trust our backend."** Andromeda's policies (allowlists, velocity guards, time-locks, oracle circuit breakers, session keys) are enforced by Solana programs that hold the dWallet authority. The gateway literally cannot bypass them.
- **Recovery is crypto's unsolved UX problem.** Andromeda does social recovery where the user proves ownership of *any* credential they already have (MetaMask, Phantom, a BTC cold wallet, Gmail, Apple, a passkey) by signing a 32-byte challenge. Andromeda pays the gas and submits the Solana transaction. Zero attestor: every signature is checked by a Solana runtime precompile, so a compromised Andromeda backend still cannot forge anyone's approval.
- **AI agents need to sign things.** Every REST route is auto-mirrored as an MCP tool, so an agent in Claude Desktop or Cursor can do signing, recovery and policy operations natively, with no SDK and no glue code.

### Built on Ika + Encrypt

Andromeda doesn't reimplement the cryptography; it wraps it. Ika provides the 2PC-MPC dWallets; Encrypt provides the FHE evaluation; Andromeda provides everything around them: 8 audited Quasar policy programs, the recovery and identity layers, gas sponsorship, MCP, HMAC-signed webhooks, an externally verifiable ed25519 audit log, and OpenAPI 3.1. The hard cryptographic guarantees come from those networks; the developer experience comes from us.

Reference docs: [Ika](https://docs.ika.xyz/) · [Encrypt](https://docs.encrypt.xyz/).

---

## Who it's for

Andromeda is a **B2D (Business-to-Developer)** platform.

- **Web3 developers** building multi-chain apps that need a unified signing surface across EVM, Solana, Bitcoin, Cosmos, NEAR, Aptos, Substrate.
- **Wallet and smart-wallet teams** that need cross-chain recovery and on-chain policy enforcement without writing Rust.
- **DeFi protocols** that need treasury policies (allowlists, velocity guards, oracle circuit breakers) enforced by Solana programs, not by a centralised backend.
- **AI agent builders** integrating signing capabilities into LLM workflows via MCP: no SDK, no glue code, just a streamable HTTP endpoint.
- **Compliance-driven products** that need an externally verifiable audit log, GDPR-ready identity, and KMS-backed signing keys from day one.

---

## Use cases

Cases that Andromeda specifically unblocks, not generic Web3 use cases.

- **Cross-chain smart wallets.** Same identity drives signing across EVM, Solana, Bitcoin, Cosmos, NEAR and Aptos. The user signs into the app once and the dWallet derived from the OAuth subject is consistent across every client.
- **DAO treasuries with on-chain rule enforcement.** A Solana Quasar program (allowlist-destinations + velocity-guard) holds the dWallet authority. The treasury can only interact with whitelisted programs, capped at N signatures per slot window, with no ability for the gateway to bypass the policy.
- **Trading bots with scoped delegation.** The session-keys template grants a temporary key with on-chain limits on slot expiry, number of uses, amount per transaction, and allowed destination programs. Multiple sessions per dWallet (up to 2^32 concurrent), each with its own monotonic replay nonce.
- **AI agents that sign transactions.** Every REST route on the gateway is auto-mirrored as an MCP tool. Drop the endpoint into Claude Desktop or Cursor and the agent can call signing, recovery, or policy operations natively.
- **Social recovery with the wallet you already have.** A dWallet can be configured with a primary owner plus a roster of recovery owners: another device's passkey, a hardware wallet, trusted friends or family, a backup service. If the user ever loses their seed phrase, the dWallet is restored when any M-of-N of those owners each sign a 32-byte challenge with whatever they already use (MetaMask, Phantom, a BTC cold wallet, Gmail, Apple, and a passkey). Andromeda sponsors the gas and submits the on-chain transaction; the user needs no SDK and no extra wallet.
- **FHE-gated confidential signing.** Authorisation logic that runs on encrypted inputs. The decision is signed by an ed25519 key held in HashiCorp Vault, then validated on-chain by a Quasar program before the Ika signature is released. Useful for compliance checks, sealed-bid auctions, and private treasury rules.

---

## What the platform ships

26 capabilities beyond the core Ika and Encrypt primitives: the surrounding product that you'd otherwise have to build yourself.

### Multi-chain core
- **Any wallet, any chain adapter for Ika on Solana.** Uniform REST surface over 4 cryptographic curves (Ed25519, SECP256K1, SECP256R1, Ristretto).
- **Multi-chain signing pipeline.** DKG, Presign, Sign, Future-Sign, Imported Key, Re-Encrypt Share exposed as stateless REST primitives.

### Wallet-agnostic + gas sponsor
- **Gas sponsor.** Andromeda absorbs Solana fees on every flow it controls. End users sign 32-byte canonical challenges with whatever wallet they already own; the gateway pays gas and submits.

### Custody-free recovery
- **Recovery layer (primary + M-of-N quorum).** Primary single-sig flow plus multi-tx PDA staging quorum. No bound on quorum size.
- **Cross-chain recovery schemes.** 7 off-chain ownership-proof schemes plus 4 on-chain credential schemes, all validated by Solana precompiles. Zero attestor.
- **On-chain RulesPolicy.** Quasar program that holds dWallet authority with the policy PDA seeded by an init-authority hash (front-running protected), the Solana clock as the only time source, and strict pattern matching on the WebAuthn challenge field.

### Policy templates
- **8 Quasar policy templates.** rules-policy, allowlist-destinations, velocity-guard, time-lock, oracle-conditional, passkey-step-up, fhe-gated, session-keys. All audited, all wallet-agnostic.
- **Session keys with multi-session.** Up to 2^32 concurrent sessions per dWallet, each with a monotonic replay nonce that binds the message digest, amount, destination program, and signature nonce together.

### Confidential computing
- **Confidential Workflows pipeline.** Encrypt FHE evaluation flows into Vault Transit ed25519, then into the Quasar fhe-gated policy, then into the Ika signature. An on-chain authority allowlist plus a non-zero decision-age window are enforced before any signature is released.

### On-chain awareness + future-sign
- **Webhook-driven Future-Sign.** Arm a trigger (oracle / slot / event / external webhook), Andromeda fires the signature when the condition matches.
- **IDL-aware Solana listener.** Websocket subscription that parses the 6 canonical Andromeda events and 4 Anchor self-CPI events from Ika, fanning out to per-tenant webhooks.
- **HMAC-signed webhook system.** Replay-protected (5-minute window), retries with backoff, dead-letter queue.

### Optional identity layer
- **Identity Layer.** OAuth (Google/Apple/Twitter/GitHub) plus email magic link plus passkey-as-identity (WebAuthn PRF). The dWallet address is derived deterministically from the OAuth provider plus subject identifier, so any client doing OAuth on the same account derives the same wallet, and cross-client recovery comes for free.
- **Anti-enumeration + atomic single-use tokens.** The email-request endpoint always returns 200 (so attackers cannot probe which emails have accounts), and every token is consumed via an atomic single-use SQL update.
- **PII encryption-at-rest.** AES-256-GCM envelope applied to identity records, account-link records, and email-token rows in Postgres. A DB dump leak does not become a PII leak.
- **GDPR endpoints.** GET /me/export returns a full JSON dump of the user's identifiable data; DELETE /me cascades a purge across all linked records.

### API surface
- **API key management with scopes and IP allowlist.** Granular permissions (read, write, admin, wildcard), CIDR allowlist per key, SHA-256 hashing, async last-used tracking.

### Developer experience
- **MCP Server with auto-generated tools.** 60 tools auto-registered from the same route catalogue that drives REST. Drop into Claude Desktop or Cursor with zero glue code.
- **Capabilities endpoint.** Public introspection of what is wired in this deployment (engines, features, MCP transport, route count).
- **OpenAPI 3.1 + curl + Postman.** Every public endpoint comes with a typed schema and copy-paste examples in Node, Go, Python, Rust.
- **SDK metadata endpoint.** For any deployed policy, the gateway returns a tarball URL plus an install command for a typed TypeScript client tailored to that policy.

### Operational excellence
- **Idempotency-Key.** Safe retries on every mutating endpoint, byte-identical replay, body-collision detection (422).
- **Dry-run / Simulate.** Uses Solana simulateTransaction and returns a structured diagnostic with would-succeed flag, failure boundary, estimated compute units, emitted events, and full logs.
- **Auto-batching of signatures.** Pack up to 64 signature requests into K Solana transactions (greedy packing, 1180-byte cap, max 16 per tx).

### Compliance + KMS
- **Signed exportable Audit Log.** Per-tenant ed25519 hash chain signed by HashiCorp Vault Transit. Externally verifiable without trusting Andromeda.
- **Vault Transit KMS.** Two separate ed25519 keys (one for audit signing, one for FHE authority), each with a sign-only policy and its own periodic token. Andromeda never sees the private material.

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
     │  Solana devnet: 8 Quasar policy programs           │
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

A live deployment is available. Judge the platform without cloning anything.

```bash
# Public capability snapshot (no auth)
curl https://api.andromedainfra.pro/capabilities

# OpenAPI 3.1 spec (auto-generated from routes)
curl https://api.andromedainfra.pro/openapi.json

# Public pricing catalogue
curl https://api.andromedainfra.pro/v1/pricing
```

For authenticated endpoints, request a devnet API key by signing up at https://app.andromedainfra.pro/signup.

### Wallet-agnostic recovery (signature flow)

Demonstrates the gas-sponsored, challenge-based UX. The user signs a 32-byte challenge with whatever wallet they already own; Andromeda assembles, signs and submits the Solana transaction.

```bash
# 1. Request a recovery challenge
curl -X POST https://api.andromedainfra.pro/v1/recovery/primary/challenge \
  -H "X-Api-Key: $ANDROMEDA_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "dwalletAddress": "<DWALLET_ADDRESS>",
    "messageHashHex": "<32-BYTE-HEX>"
  }'
# returns { "challengeBase64": "...", "expectedNonce": 7, "primaryScheme": "Ed25519" }

# 2. User signs `challengeBase64` off-chain with their credential
#    (MetaMask, Phantom, BTC cold wallet, Gmail, Apple, passkey, etc.)

# 3. Submit the signature. Andromeda pays gas and broadcasts
curl -X POST https://api.andromedainfra.pro/v1/recovery/primary/submit \
  -H "X-Api-Key: $ANDROMEDA_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "dwalletAddress": "<DWALLET_ADDRESS>",
    "messageHashHex": "<32-BYTE-HEX>",
    "signatureBase64": "<USER_SIGNATURE>",
    "expectedNonce": 7
  }'
# returns { "txSignature": "...", "messageApprovalAddress": "..." }
```

The end user never holds SOL, never installs a new wallet, never sees an RPC endpoint.

### Connect via MCP

Drop the gateway endpoint into any MCP client (Claude Desktop, Cursor, custom):

```json
{
  "mcpServers": {
    "andromeda": {
      "url": "https://api.andromedainfra.pro/mcp",
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
git clone https://github.com/TheKazuto/Andromeda-PublicRepository andromeda
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
( cd dashboard       && npm run build )      # static export to out/
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
| Landing page | https://andromedainfra.pro |
| Dashboard | https://app.andromedainfra.pro |
| Gateway API | https://api.andromedainfra.pro |
| OpenAPI spec | https://api.andromedainfra.pro/openapi.json |
| MCP endpoint | https://api.andromedainfra.pro/mcp |
| Capabilities endpoint | https://api.andromedainfra.pro/capabilities |

### On-chain programs (Solana devnet)

| Program | Address | Purpose |
|---------|---------|---------|
| rules-policy | 6TX7qG47Fsocuwmgsgo2q3NLCHrbomoQxQLifapU8Thr | Recovery primary + M-of-N quorum + cooldown + daily limit |
| allowlist-destinations | 91hycWu3sTbRELUDBTkqbyaEse1fVFDX3RmW9uPNQqFx | Restrict signing to whitelisted destination programs |
| velocity-guard | DVAkrYe4SWzihvbh94GC6aB7ESf1h4yxiSDyetq1jkdW | Rate-limit signatures per slot window |
| time-lock | 2i4bE6s7oc8kkziQETy55SGWQXxwotkpERr9XMv7Q7qs | Restrict signing to allowed slot ranges |
| oracle-conditional | Wi6x2Y4YTYcv4aMz7AQRF2UELE36fZNKhsAoCFq2ssM | Pyth Pull V2 circuit breaker |
| passkey-step-up | 7xNwfNHtN11kf5JFNhsQTuciBskmWmZ8XcHSAeNdvorC | Require passkey proof above threshold |
| fhe-gated | 6NhfKThEydSHH6R7gBm94reo3simopRJmb4nDzkKU7np | Gate signing on confidential FHE evaluation |
| session-keys | 3Y2QaXiJH3aSiooDnGQsZQhYN72r47mYYbHp9YWyiASm | Multi-session scoped delegation |

### Omniboard: retail showcase (in development)

[Omniboard](https://omniboard.pro) is our retail-facing product, built entirely on top of Andromeda. Where Andromeda is the developer infrastructure (B2D), Omniboard is the consumer-facing app that puts the platform in front of end users: spin up a cross-chain wallet, attach on-chain policies, run signature flows and social recovery from the browser, with no code. It is still under active development; the link above is a preview of where it will live.

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

Built by **Shinka Labs**, https://www.shinkalabs.tech/
