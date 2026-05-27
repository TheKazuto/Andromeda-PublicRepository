<div align="center">
  <img src="Logo.png" alt="Andromeda" width="180" />

  <h1>Andromeda</h1>

  <p><strong>Multi-chain MPC + FHE infrastructure as API and MCP Server.</strong></p>

  <p>One API for cross-chain signing, intents, confidential compute, and social recovery.<br/>No SDK, no node, no seed phrase, no chain-specific wallet for your users.</p>

  <p>
    <img src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg" alt="License" />
    <img src="https://img.shields.io/badge/status-devnet%20pre--alpha-orange.svg" alt="Status" />
    <img src="https://img.shields.io/badge/Solana%20programs-4-9945ff.svg" alt="Solana programs" />
    <img src="https://img.shields.io/badge/MCP-tools%20auto--generated-7c3aed.svg" alt="MCP" />
    <img src="https://img.shields.io/badge/OpenAPI-3.1-6BA539.svg" alt="OpenAPI" />
  </p>
</div>

> ⚠️ *Andromeda is under development. Any structure or feature may have its code and operational design altered in the interest of greater efficiency and security.*

---

## What is Andromeda?

Andromeda is hosted infrastructure that turns two of Solana's most powerful primitives, Ika's 2PC-MPC threshold signing and Encrypt's homomorphic computation, into plain REST endpoints and MCP tools.

Threshold signing lets a single identity control wallets across chains (EVM, Bitcoin, Solana, Sui, Cosmos, Tron, TON, Stellar, Aptos, and more) with no seed phrase and no single point of compromise. Confidential computing lets authorization logic run directly on encrypted data. Both are extraordinary, and both today require running validator clients, writing Rust or Move programs that hold wallet authority, and shipping a Node runtime to your users.

Andromeda removes all of that. You call an HTTPS endpoint. We run the engines, the on-chain policy programs, the gas, the wallet-agnostic auth layer, and the product surface around it. Your users never see the chain underneath: no wallet to install, no SOL to hold, no MPC network to learn.

## Why it matters

- **Multi-chain is still mostly glue code.** Every team rebuilds key management, recovery, and per-chain signing from scratch. Andromeda is one API for all of it.
- **"Smart wallet" usually means "trust our backend."** Andromeda's policies (allowlists, velocity guards, time-locks, oracle circuit breakers, session keys, FHE-gated confidential decisions, passkey step-up, recovery) are enforced by a single Solana program — the **PolicyEngine v3** — that holds the dWallet authority. The gateway literally cannot bypass it.
- **Recovery is crypto's unsolved UX problem.** Andromeda does social recovery where the user proves ownership of *any* credential they already have (MetaMask, Phantom, a BTC cold wallet, Gmail, Apple, a passkey) by signing a 32-byte challenge. Andromeda pays the gas and submits the Solana transaction. Zero attestor: every signature is checked by a Solana runtime precompile, so a compromised Andromeda backend still cannot forge anyone's approval.
- **AI agents need to sign things.** Every REST route is auto-mirrored as an MCP tool, so an agent in Claude Desktop or Cursor can do signing, recovery and policy operations natively, with no SDK and no glue code.

### Built on Ika + Encrypt

Andromeda doesn't reimplement the cryptography; it wraps it. Ika provides the 2PC-MPC dWallets; Encrypt provides the FHE evaluation; Andromeda provides everything around them: 4 Solana programs (the PolicyEngine v3 unifies all rule kinds in one program, plus the `jwk-registry` and `oidc-verifier` that back Login Social, and the `pyth-adapter` that bridges Pyth price feeds into the oracle rule), gas sponsorship, MCP, HMAC-signed webhooks, an externally verifiable ed25519 audit log, and OpenAPI 3.1. The hard cryptographic guarantees come from those networks; the developer experience comes from us.

Reference docs: [Ika](https://docs.ika.xyz/) · [Encrypt](https://docs.encrypt.xyz/).

---

## Who it's for

Andromeda is a **B2D (Business-to-Developer)** platform.

- **Web3 developers** building multi-chain apps that need a unified signing surface across EVM, Solana, Bitcoin, Sui, Cosmos, Tron, TON, Stellar, Aptos.
- **Wallet and smart-wallet teams** that need cross-chain recovery and on-chain policy enforcement without writing Rust.
- **DeFi protocols** that need treasury policies (allowlists, velocity guards, oracle circuit breakers) enforced by Solana programs, not by a centralised backend.
- **AI agent builders** integrating signing capabilities into LLM workflows via MCP: no SDK, no glue code, just a streamable HTTP endpoint.
- **Compliance-driven products** that need an externally verifiable audit log and KMS-backed signing keys from day one.

---

## Use cases

Cases that Andromeda specifically unblocks, not generic Web3 use cases.

- **Cross-chain smart wallets.** Same identity drives signing across EVM, Solana, Bitcoin, Sui, Cosmos, Tron, TON and Aptos. The user signs into the app once and the same dWallet works on every chain.
- **Multichain swaps for apps and AI agents.** Quote, build, sign and broadcast a token swap over a dWallet, custody-free, with liquidity from the LI.FI aggregator. The same flow works same-chain (Solana, EVM, Sui) and cross-chain (bridge). An AI agent can do it natively over MCP: no DEX integration, no bridge SDK, no wallet for the user.
- **Onboarding without a wallet (Login Social).** The user signs in with Google or Apple and gets a cross-chain dWallet immediately, with no wallet to install, no seed phrase, no SOL to hold. The same Google/Apple account derives the same dWallet in any app on Andromeda: one identity, one wallet, every chain.
- **DAO treasuries with on-chain rule enforcement.** A single Solana Quasar program — the PolicyEngine v3 — holds the dWallet authority with a composable allowlist + velocity rule attached. The treasury can only interact with whitelisted programs, capped at N signatures per slot window, with no ability for the gateway to bypass the policy.
- **Trading bots and AI agents with scoped delegation.** The `KIND_SESSION_KEY` rule of the PolicyEngine grants a temporary key with on-chain limits on slot expiry, number of uses, amount per transaction, and allowed destination programs. Multiple sessions per dWallet (up to 2^32 concurrent), each with its own monotonic replay nonce. The full lifecycle is exposed as REST (`/v1/policy/session/*`); the session keypair lives on the dev side, never in the gateway.
- **AI agents that sign transactions.** Every REST route on the gateway is auto-mirrored as an MCP tool. Drop the endpoint into Claude Desktop or Cursor and the agent can call signing, recovery, or policy operations natively.
- **Social recovery with the wallet you already have.** A dWallet can be configured with a primary owner plus a roster of recovery owners: another device's passkey, a hardware wallet, trusted friends or family, a backup service. If the user ever loses their seed phrase, the dWallet is restored when any M-of-N of those owners each sign a 32-byte challenge with whatever they already use (MetaMask, Phantom, a BTC cold wallet, Gmail, Apple, and a passkey). Andromeda sponsors the gas and submits the on-chain transaction; the user needs no SDK and no extra wallet.
- **FHE-gated confidential signing.** Authorisation logic that runs on encrypted inputs. The decision is signed by an ed25519 key held in HashiCorp Vault, then validated on-chain by a Quasar program before the Ika signature is released. Useful for compliance checks, sealed-bid auctions, and private treasury rules.

---

## What the platform ships

Capabilities beyond the core Ika and Encrypt primitives: the surrounding product that you'd otherwise have to build yourself.

### Multi-chain core
- **Any wallet, any chain adapter for Ika on Solana.** Uniform REST surface over 4 cryptographic curves (Ed25519, SECP256K1, SECP256R1, Ristretto).
- **Multi-chain signing pipeline.** DKG, Presign, Sign, Future-Sign, Imported Key, Re-Encrypt Share exposed as stateless REST primitives.
- **Chain-native address derivation & message prep.** One read-only call returns every chain-native address a dWallet can hold; another returns the envelope-applied bytes to sign plus the on-chain digest. 20 chain families: EVM, Bitcoin (SegWit + legacy), Solana, Sui, Cosmos, Tron, TON, Stellar, Algorand, Aptos, MultiversX, Filecoin, VeChain, Avalanche, Casper, Tezos, IOTA, NEAR, Substrate (ed25519), and Zcash (transparent). All but Zcash are validated byte-for-byte against that chain's official SDK; Zcash transparent (t-address, ZIP-243 secp256k1) is anchored to an independent address reference and a live end-to-end signing smoke. Shielded z-addresses are out of scope (the network only signs the transparent ECDSA path).

### Wallet-agnostic + gas sponsor
- **Gas sponsor.** Andromeda absorbs Solana fees on every flow it controls. End users sign 32-byte canonical challenges with whatever wallet they already own; the gateway pays gas and submits.

### Custody-free recovery (`KIND_RECOVERY` rule)
- **Recovery rule (primary + M-of-N quorum).** Primary single-sig flow plus multi-tx PDA staging quorum. No bound on quorum size. Lives as one rule slot inside the PolicyEngine.
- **Cross-chain credentials.** 4 on-chain credential schemes (Ed25519, Secp256k1, Secp256r1, WebAuthn) validated by Solana precompiles. Zero attestor.
- **Init-authority-hash seeded PDA.** The `PolicyEngine` PDA is seeded by a hash that includes the init authority — the address cannot be front-run.
- **Clear signing on every governance approval.** Every challenge renders a deterministic ASCII message the approver reads before signing; the on-chain program recomputes the same text and embeds it into the challenge hash, so a compromised gateway cannot swap destination, member, amount, nonce or session without the approver seeing the swap. Monetary values (oracle price bounds, USD spending caps) render as human-readable decimals — the approver reads `3000.5`, not `300050000000`.

### PolicyEngine v3
- **One Quasar program, 8 composable rule kinds.** `KIND_ALLOWLIST`, `KIND_VELOCITY`, `KIND_TIME_LOCK`, `KIND_ORACLE`, `KIND_PASSKEY`, `KIND_FHE_GATED`, `KIND_SESSION_KEY`, `KIND_RECOVERY`. Up to 16 active rule slots per dWallet, each with its own sub-PDA and per-rule generation counter. Hot-path `request_signature` walks every active slot's sub-PDA, runs the per-kind dispatch, and CPIs Ika `approve_message` as the last side-effect — fail-closed by design.
- **Session keys with multi-session.** Up to 2^32 concurrent sessions per dWallet, each with a monotonic replay nonce that binds the message digest, amount, destination program, and signature nonce together.
- **Semantic swap clear-signing.** When authorizing a swap, the owner reads `"Swap X of <from_token> for at least Y of <to_token> on <chain> …"` bound to the actual trade — not a generic hex digest — so a compromised gateway cannot substitute a different swap.
- **Bundle signing for multi-leg flows.** One owner signature can unlock up to 4 `request_signature` legs on-chain (e.g. EVM two-step: approve + swap in one prompt); the bundle hash is op-tag-agnostic so legs can mix signing kinds.

### Login Social
- **Sign in with Google or Apple, get a dWallet immediately.** No wallet to install, no seed phrase, no SOL. Identity is verified entirely on-chain (RSA over the `id_token`, zero attestor). A compromised Andromeda backend still cannot forge anyone's login. The same Google/Apple account derives the same dWallet in any app on Andromeda: one identity, one wallet, every chain.

### Confidential computing
- **Confidential Workflows pipeline.** Encrypt FHE evaluation flows into Vault Transit ed25519, then into the PolicyEngine v3 `KIND_FHE_GATED` rule, then into the Ika signature. An on-chain authority allowlist plus a non-zero decision-age window are enforced before any signature is released.

### On-chain awareness + future-sign
- **Webhook-driven Future-Sign.** Arm a trigger (oracle / slot / event / external webhook), Andromeda fires the signature when the condition matches.
- **Oracle price triggers (managed).** Arm a stop-loss / take-profit and Andromeda watches the live Pyth price, firing the pre-built `request_signature` when the band holds, gas-sponsored, with no SOL and no bot to run. The on-chain `KIND_ORACLE` rule re-checks the real price, so the monitor can never sign outside the band. Backed by the `pyth-adapter` program; feed freshness is sponsored (refresh-on-sign).
- **IDL-aware Solana listener.** Websocket subscription that parses the 6 canonical Andromeda events and 4 Anchor self-CPI events from Ika, fanning out to per-tenant webhooks.
- **HMAC-signed webhook system.** Replay-protected (5-minute window), retries with backoff, dead-letter queue.

### Multichain swaps (Intents)
- **LI.FI parity.** Andromeda routes 71 of the 72 chains LI.FI exposes today: EVM (69 chains), Solana and Sui.
- **Swap intents over dWallets.** Liquidity from the LI.FI aggregator; the dWallet signs and the PolicyEngine gates every signature. The gas-sponsor pays only the Ika approval, the swap gas comes from the dWallet's own balance. REST + MCP, no SDK.
- **Intent types available today:**
  - **Same-chain swap** — token to token on one chain (Solana, EVM, Sui).
  - **Cross-chain swap (bridge)** — source and destination on different chains; the destination must be the dWallet's own address on the target chain.
- **Per-intent flow.** `quote` (price + unified fee + native-gas estimate), `simulate` (route, fees and advisory risk, nothing signed), `prepare` (build the intent), `submit` (authorize + sign + broadcast), `status`.
- **Zero-trust submit.** Between `prepare` and `submit`, the dWallet owner signs an off-chain challenge bound to the swap (`intents/swap/challenge`). Solana and Sui same-chain take one signature; EVM takes one bundle signature when the ERC20 needs an approve before the swap (single signature otherwise). The gateway cannot relay without it.
- **Safety.** Mandatory idempotency on prepare/submit, byte-for-byte re-validation of the persisted payload before signing, advisory risk + simulation, ERC20 two-step approve, and no blind retry on an uncertain broadcast (a reconciler resolves it from the chain).

### Pre-sign safety (advisory)
- **Transaction simulation (multi-chain).** Before signing, simulate against the destination chain and get the real effects back. EVM/Tron run a real `eth_call` (true revert) + `eth_estimateGas`; Solana runs `simulateTransaction`. Structured effects (native/token transfers, approvals, contract calls) are decoded from the transaction. The developer supplies their own destination-chain RPC per request — Andromeda hosts none — and the analysis degrades honestly to static calldata decoding when no RPC is given. That static decoding spans EVM/Tron, Solana, and nine more families (Cosmos, Bitcoin, VeChain, NEAR, Aptos, MultiversX, Algorand, Filecoin, Sui); a family with no decoder returns an explicit "cannot verify" instead of a false "safe".
- **Risk scoring.** A risk level (none → critical) with reasons, from a self-hosted scam-address blocklist (MetaMask eth-phishing + OpenChain), a per-tenant denylist/allowlist, this dWallet's destination history, and calldata heuristics (unlimited approvals, `setApprovalForAll`, drainer patterns). **Advisory only**: it never blocks or refuses a signature — the on-chain policies stay the hard protection. The analysis is bound to the digest you sign, and the client RPC is SSRF-validated server-side.

### API surface
- **API key management with scopes and IP allowlist.** Granular permissions (read, write, admin, wildcard), CIDR allowlist per key, SHA-256 hashing, async last-used tracking.

### Developer experience
- **MCP Server with auto-generated tools.** Every REST route is auto-registered as an MCP tool from the same catalogue. Drop into Claude Desktop or Cursor with zero glue code.
- **Capabilities endpoint.** Public introspection of what is wired in this deployment (engines, features, MCP transport, route count).
- **OpenAPI 3.1 + curl + Postman.** Every public endpoint comes with a typed schema and copy-paste examples in Node, Go, Python, Rust.
- **SDK metadata endpoint.** For any deployed policy, the gateway returns a tarball URL plus an install command for a typed TypeScript client tailored to that policy.

### Operational excellence
- **Idempotency-Key.** Safe retries on every mutating endpoint, byte-identical replay, body-collision detection (422).
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
                 │  + OAuth broker (Login Social)   │
                 └─────────────────────────┬────────┘
                                           │ private network
                       ┌───────────────────┼───────────────────┐
                       ▼                   ▼                   ▼
              ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
              │   ika-backend   │  │ encrypt-backend │  │ intents-backend │
              │   MPC engine    │  │   FHE engine    │  │   swap router   │
              └────────┬────────┘  └────────┬────────┘  └────────┬────────┘
                       │ gRPC              │ gRPC              │ HTTPS
                       ▼                   ▼                   ▼
                 Ika validator     Encrypt network    LI.FI aggregator
                    network            (devnet)          + chain RPCs

     ┌────────────────────────────────────────────────────┐
     │  Solana devnet: PolicyEngine v3 + jwk-registry +   │
     │  oidc-verifier + pyth-adapter (oracle). Hold       │
     │  dWallet authority; every signature is checked via │
     │  runtime precompiles (zero attestor).              │
     └────────────────────────────────────────────────────┘
                          ▲
                          │ propose_jwk (authority)
                          │
                 ┌──────────────────┐    ┌────────────────────┐
                 │   jwk-rotator    │───▶│ Google/Apple JWKS  │
                 │   (worker)       │    │  (public TLS)      │
                 └──────────────────┘    └────────────────────┘

     Postgres (shared with backend)   |   HashiCorp Vault Transit
     Stripe + SMTP (backend service)  |   Cloudflare Pages (dashboard)
```

The product surface is composed of **7 services** plus **4 on-chain programs**.

| Service | Stack | Role |
|---------|-------|------|
| gateway | Go 1.25, chi, pgx, Redis | Hot path. Auth, quota, rate limit, MCP server, reverse-proxy to engines, audit log, PolicyEngine v3 admin surface (`/v1/policy/*`). |
| ika-backend | Node 24, Express 5, @grpc/grpc-js, @solana/kit | MPC engine. gRPC to Ika validator network, dWallet lifecycle, OIDC pre-flow helpers. |
| encrypt-backend | Node 22, Hono 4, @encrypt.xyz/pre-alpha-solana-client | FHE engine. 22 Encrypt instructions + high-level wallet primitives. |
| intents-backend | Go 1.25, chi, gobreaker | Swap router. Talks to the LI.FI aggregator, builds the unsigned swap, inserts the dWallet signature and broadcasts. Stateless, custody-free. |
| backend | Go 1.25, chi, pgx, Stripe | Product surface. Auth, customer endpoints, billing, admin console. |
| dashboard | Next.js 16, React 19, Tailwind 4 | Static export. Customer dashboard + admin console + landing. |
| jwk-rotator | Node 24, TypeScript, @solana/web3.js | Off-chain watcher. Fetches Google/Apple JWKS, proposes new keys on-chain via the `jwk-registry` authority. Required for Login Social. |

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

Demonstrates the gas-sponsored, challenge-based UX. The user signs a 32-byte challenge with whatever wallet they already own; Andromeda assembles, signs and submits the Solana transaction. Both endpoints are served locally by the gateway — the PolicyEngine v3 transaction is built in-process, signed as gas sponsor, and broadcast in one round-trip per step.

```bash
# 1. Request a recovery challenge
curl -X POST https://api.andromedainfra.pro/v1/policy/recover-as-primary/challenge \
  -H "X-Api-Key: $ANDROMEDA_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "dwallet_address": "<DWALLET_ADDRESS>",
    "message_digest_hex": "<32-BYTE-HEX>",
    "destination_hex": "<32-BYTE-HEX>",
    "user_pubkey_hex": "<32-BYTE-HEX>"
  }'
# returns { "challenge_hex": "...", "human_message": "...", "primary_scheme": 0, ... }

# 2. User signs `challenge_hex` off-chain with their credential
#    (MetaMask, Phantom, BTC cold wallet, a passkey, etc.)

# 3. Submit the signature. Andromeda pays gas and broadcasts
curl -X POST https://api.andromedainfra.pro/v1/policy/recover-as-primary/submit \
  -H "X-Api-Key: $ANDROMEDA_KEY" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{
    "dwallet_address": "<DWALLET_ADDRESS>",
    "message_digest_hex": "<32-BYTE-HEX>",
    "destination_hex": "<32-BYTE-HEX>",
    "user_pubkey_hex": "<32-BYTE-HEX>",
    "signature_base64": "<USER_SIGNATURE>"
  }'
# returns { "tx_signature": "...", "engine_address": "..." }
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

The agent can immediately call any of the auto-generated tools, covering signing, PolicyEngine v3 admin and recovery flows (`policy.engine.*`), OIDC pre-flow, webhooks, audit log queries, and the full Encrypt FHE surface.

### Run locally

The monorepo runs on Postgres + Redis + 7 services. Each service has its own .env.example.

```bash
git clone https://github.com/TheKazuto/Andromeda-PublicRepository andromeda
cd andromeda

# 1. Provision Postgres and (optionally) Redis locally.

# 2. Boot each service in its own terminal.
( cd backend         && cp .env.example .env && go mod download && go run ./cmd/server )
( cd gateway         && cp .env.example .env && go mod download && go run ./cmd/server )
( cd intents-backend && cp .env.example .env && go mod download && go run ./cmd/server )   # swap router, optional
( cd ika-backend     && cp .env.example .env && npm install && npm run dev )
( cd encrypt-backend && cp .env.example .env && npm install && npm run dev )
( cd dashboard       && cp .env.local.example .env.local && npm install && npm run dev )
( cd jwk-rotator     && cp .env.example .env && npm install && npm run start )    # worker, optional

# 3. Open the dashboard.
open http://localhost:3000
```

Service ports: backend on 8080, gateway on 8081, intents-backend on 8082, ika-backend on 3020, encrypt-backend on 3010, dashboard on 3000. `jwk-rotator` is a background worker, with no HTTP port.

### Build

Every service ships a Dockerfile and a Railway config. The dashboard exports to a static "out" directory for Cloudflare Pages.

```bash
( cd backend         && go build -o bin/backend ./cmd/server )
( cd gateway         && go build -o bin/gateway ./cmd/server )
( cd intents-backend && go build -o bin/intents ./cmd/server )
( cd ika-backend     && npm run build )
( cd encrypt-backend && npm run build )
( cd dashboard       && npm run build )      # static export to out/
( cd jwk-rotator     && npm run typecheck )  # tsx-runtime; no build step
```

### Test

```bash
( cd backend         && go test ./... )
( cd gateway         && go test ./... )
( cd intents-backend && go test ./... )
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
| policy-engine | ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL | The unified policy / recovery / signing engine. Holds dWallet authority. Composable rule slots: `KIND_ALLOWLIST`, `KIND_VELOCITY`, `KIND_TIME_LOCK`, `KIND_ORACLE`, `KIND_PASSKEY`, `KIND_FHE_GATED`, `KIND_SESSION_KEY`, `KIND_RECOVERY` (primary + M-of-N quorum + cooldown + daily limit). |
| jwk-registry | 8xL2mrQ2amDpinQMHJPaEELbgEXWRVGn4PQ7kzDm7vNM | On-chain trust root for OIDC RSA-2048 keys (Google/Apple). Login Social. |
| oidc-verifier | _(library)_ | On-chain RSA-2048 verification of provider `id_token`s. Reads the `jwk-registry`. Gated on the Solana `sol_big_mod_exp` syscall. |
| pyth-adapter | A6xjw8jkJTFjpjHCRSFxVt1d1KbBZdh3XBNYvTfLZxP2 | Normalises Pyth price feeds into the canonical view the `KIND_ORACLE` rule reads. Powers price circuit breakers + managed price triggers. |

### Omniboard: retail showcase (in development)

[Omniboard](https://omniboard.pro) is our retail-facing product, built entirely on top of Andromeda. Where Andromeda is the developer infrastructure (B2D), Omniboard is the consumer-facing app that puts the platform in front of end users: spin up a cross-chain wallet, attach on-chain policies, run signature flows and social recovery from the browser, with no code. It is still under active development; the link above is a preview of where it will live.

---

## Status

**Pre-alpha. Devnet only. Do not custody real value.**

- Ika integration runs against the public pre-alpha validator network with a single mock signer. No cryptographic MPC guarantee yet.
- Encrypt integration runs against the public pre-alpha network. No real FHE confidentiality guarantee yet.
- The PolicyEngine v3 program (including every rule kind) was security-audited internally in May 2026 (front-running, time source, replay protection, type confusion, oracle owner check).
- Login Social (the `jwk-registry` program, the `oidc-verifier` library, and the `scheme=4` OIDC primary path inside the PolicyEngine) was security-audited separately in May 2026; see `docs/AUDIT_LOGINSOCIAL_2026_05.md`. Two hardening recommendations (F-1, F-2) applied. The on-chain OIDC primary path is currently gated on the Solana `sol_big_mod_exp` syscall.
- Pre-mainnet third-party audit pending across the whole on-chain surface.

---

## License

Dual-licensed under **Apache-2.0 OR MIT**.

## Team

Built by **Shinka Labs**, https://www.shinkalabs.tech/
