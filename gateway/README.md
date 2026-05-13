# andromeda-gateway

Hot-path service of Andromeda. Authenticates external API clients, enforces plan-based quotas + rate limits, hosts the **MCP server** at `/mcp`, and reverse-proxies to the private engines (`ika-backend`, `encrypt-backend`).

Stack: Go 1.25 · chi · pgx · Redis · gobreaker · Prometheus · OpenTelemetry · Railway.

## Communicates with

- **External clients** — REST (`/v1/*`) and MCP (`/mcp`), authenticated with `X-Api-Key`.
- **`ika-backend`** (private network, `IKA_UPSTREAM_URL` + `X-Api-Key`) — MPC engine.
- **`encrypt-backend`** (private network, `ENCRYPT_UPSTREAM_URL` + `X-Internal-Key`) — FHE engine.
- **`backend/`** — shares the same Postgres pool. Gateway owns the schema; backend reads/writes.
- **Vault Transit** — signs the audit log chain (`andromeda-audit` ed25519 key).
- **Solana RPC** — on-chain event listener and policy state reads.
- **Dashboard** — public pricing catalogue (`/v1/pricing`, `/v1/pricing/estimate`).

```
client ──▶ gateway ──▶ ika-backend       (MPC engine, X-Api-Key)
              │  └──▶ encrypt-backend    (FHE engine, X-Internal-Key)
              ├── auth (X-Api-Key + scopes + IP allowlist + Origin allowlist)
              ├── quota (credits → monthly → overage, atomic)
              ├── rate limit (Redis sliding window)
              ├── circuit breaker (per-upstream)
              ├── usage log (async)
              └── metrics + tracing
```

## Project layout

```
gateway/
├── cmd/server/             # main.go entrypoint
├── internal/
│   ├── api/                # HTTP handlers
│   ├── auth/               # API key auth, scopes, IP + Origin allowlist, andromeda_auth Go mirror
│   ├── routes/             # Route catalogue (REST + MCP source of truth)
│   ├── upstream/           # Reverse-proxy to ika + encrypt engines
│   ├── pricing/            # Token cost cache (pricer worker)
│   ├── ratelimit/          # Redis sliding window
│   ├── idempotency/        # Idempotency-Key store
│   ├── usage/              # Async usage log writer
│   ├── webhooks/           # CRUD + dispatcher worker (HMAC + retries)
│   ├── policies/           # 8 Quasar policy templates (Go side)
│   ├── futuresign/         # Trigger watcher (oracle/slot/event/external)
│   ├── audit/              # Per-tenant ed25519 hash chain
│   ├── netsafety/          # SSRF guard for outbound URLs
│   ├── mcp/                # MCP JSON-RPC + SSE server
│   ├── gasponsor/          # Solana fee payer keypair
│   ├── observability/      # OpenTelemetry tracing
│   ├── metrics/            # Prometheus collectors
│   ├── openapi/            # Auto-generated OpenAPI 3.1
│   ├── store/              # Postgres + migrations
│   ├── redisclient/        # Redis pool
│   └── config/             # Env loader
├── openapi.yaml
├── Dockerfile
├── railway.toml
└── go.mod
```

## Public endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness |
| GET | `/health/ready` | Readiness (DB + Redis + upstream + DLQ) |
| GET | `/openapi.json` | OpenAPI 3.1 spec |
| GET | `/capabilities` | Public feature matrix — includes `features.futureSignWatcher`, `features.redisBackedIdempotency`, and `features.rateLimitMode` (`"disabled"` / `"fail_open"` / `"fail_closed"`) so clients can tell which gateway-native features are actually operational, not just wired |
| GET | `/v1/pricing` | Token cost per route |
| POST | `/v1/pricing/estimate` | Estimate cost for a workload |
| GET | `/metrics` | Prometheus, `X-Admin-Token`-gated |

## Authenticated endpoints (`X-Api-Key`)

Every successful response carries `X-Andromeda-Tokens-{Cost,Used,Limit}` and `X-Andromeda-Upstream`
headers; deprecated routes also get RFC 8594 `Deprecation`/`Sunset` headers. The gateway forwards the
authenticated tenant identity to the engines as `X-Andromeda-User-Id` (required by the high-level,
tenant-scoped dWallet ops). Read-class routes need scope `read`; everything else needs `write`; the
gateway-native admin features (webhooks, audit, policies, future-sign) need scope `admin`. Request
bodies are capped at 25 MiB.

| Group | Routes (under `/v1`) | Scope | Upstream |
|-------|----------------------|-------|----------|
| **dWallet — high-level (MCP tools)** | `dwallet/create`, `dwallet/transfer-ownership`, `dwallet/approve`, `dwallet/admin/add-member`, `dwallet/presign`, `dwallet/sign` (→ MCP `create_dwallet` / `transfer_ownership` / `approve` / `admin_add_member` / `presign` / `sign_message`) | write | ika |
| **dWallet — low-level** | `dwallet/dkg/{prepare,submit}`, `dwallet/{sign,presign,future-sign,future-sign/complete,re-encrypt-share,make-share-public}/submit`, `GET dwallet/presigns/{userPubkey}` | write / read | ika |
| **Recovery — discovery** | `recovery/{challenge,resolve}` | write | ika |
| **Recovery — primary** | `recovery/primary/{challenge,submit}` | write | ika |
| **Recovery — quorum** | `recovery/quorum/session/{open/challenge,open,contribute/challenge,contribute,finalize,close}`, `GET recovery/quorum/session/{address}` | write / read | ika |
| **Recovery — policy** | `recovery/policy/{preview,deploy,admin/challenge,admin/submit,apply-pending}`, `GET recovery/policy/{dwalletAddress}` | write / read | ika |
| **Recovery — Login Social (OIDC primary)** | `recovery/primary/oidc/{stage,open/challenge,open,use/challenge,use/submit,close,staging/close}`, `oidc/validate` — staged `id_token` carriers get an 8 KiB body cap | write / read | ika |
| **OAuth broker (Login Social)** | `GET oauth/{authorize,callback}`, `POST oauth/token-exchange` — gateway-hosted Andromeda OAuth client (Google + Apple, `scope=openid` only). Authorization Code + PKCE. Free (no token cost). | write | gateway |
| **Private TX** | `private-tx/submit`, `GET private-tx/status/{signature}` | write / read | encrypt |
| **Ciphertext** | `ciphertext/{create,read}`, `GET ciphertext/account/{address}` | write / read | encrypt |
| **Graph** | `graph/{execute,register,execute-registered,commit}/prepare`, `graph/submit`, `graph/operations/register-bytes`, `GET graph/{status/{signature},operations}` | write / read | encrypt |
| **DSL** | `GET dsl/types`, `dsl/op/prepare` | read / write | encrypt |
| **Decrypt** | `decrypt/request/prepare`, `GET decrypt/poll/{account}` | write / read | encrypt |
| **NEK** | `GET nek/current` | read | encrypt |
| **Events** | `events/emit/prepare`, `GET events/by-signature/{signature}` | write / read | encrypt |
| **Wallet (private)** | `wallet/balance/init` | write | encrypt |
| **Authority / Fees / Ownership** | `authority/{add,remove,register-nek}/prepare`, `fees/deposit/{create,top-up,withdraw,request-withdraw,reimburse}/prepare`, `fees/config/update/prepare`, `ownership/{transfer,copy,make-public}/prepare` | write | encrypt |
| **Webhooks** | CRUD + retry | admin | gateway |
| **Audit log** | per-tenant signed hash-chain read | admin | gateway |
| **Future-sign triggers** | oracle / slot / event / external watchers | admin | gateway |
| **Policies** | 8 Quasar templates: rules-policy, allowlist-destinations, velocity-guard, time-lock, oracle-conditional, passkey-step-up, fhe-gated, session-keys. Endpoints: `templates`, `init`, `admin/challenge`, `admin/submit`, `request-signature`. Wallet-agnostic + gas-sponsored. | admin | gateway |
| **SDK metadata** | `GET /v1/policies/{address}/sdk` → typed TypeScript SDK tarball location | admin | gateway |
| **Simulate** | `POST /v1/signatures/simulate` → dry-run via `simulateTransaction` | admin | gateway |
| **Auto-batching** | `POST /v1/signatures/batch` → up to 64 ops in K txs | admin | gateway |
| **Confidential** | `POST /v1/confidential/sign` → FHE evaluation (encrypt-backend) + Vault sign + fhe-gated tx | admin | gateway |

Full machine-readable catalogue of the proxied routes in `internal/routes/routes.go`; everything
(including the gateway-native endpoints above) is in `/openapi.json`.

**Error envelope.** Every gateway-native error response is `{"error": "<message>", "code": "<snake_case>"}` —
flat, two string fields, uniform across `/v1/policies/*`, `/v1/webhooks/*`, `/v1/audit/*`,
`/v1/future-sign/*` and the proxy layer. (Errors *forwarded* from an engine keep that engine's body
verbatim. The `/mcp` endpoint speaks JSON-RPC and uses its own error object.)

## MCP server (`/mcp`)

JSON-RPC 2.0 over Streamable HTTP. Tools auto-generated from the same `routes.go` that drives the REST API — every API capability is also an MCP tool.

| Endpoint | Purpose |
|----------|---------|
| `POST /mcp` | JSON-RPC requests: `initialize`, `notifications/initialized`, `tools/list`, `tools/call`, `ping` |
| `GET /mcp` | SSE stream with 15s keepalive (server-initiated notifications) |

Each tool advertises an input schema and behaviour annotations:

```json
{
  "name": "ika.sign.submit",
  "description": "POST /v1/dwallet/sign/submit → ika-backend (custody-free proxy).",
  "inputSchema": { "type": "object", "properties": { ... } },
  "annotations": {
    "destructiveHint": true,
    "idempotentHint": true,
    "openWorldHint": true
  }
}
```

- **Auth**: same `X-Api-Key` as REST.
- **Charging**: per-tool token cost mirrors the matching REST route (e.g. `mcp.tool=ika.sign.submit` → 50 tokens).
- **Refund on tool error**: same path as REST 5xx refund.
- **Idempotency**: `Idempotency-Key` header at HTTP layer (single body match). Included in the CORS `AllowedHeaders`, so browser clients can use it on cross-origin calls.

Clients connect with any MCP-compatible client (Claude Desktop, Cursor, custom). Setup config is shown in the dashboard at `/dashboard/mcp-server`.

## Token economy

Every route has a token cost (1 / 5 / 25 / 50 / 125). Plans hold a monthly allowance.

| Plan | Tokens/mo | Price/mo | Read RPS | Tx RPS |
|------|----------:|---------:|---------:|-------:|
| Free | 2,000 | $0 | 10 | 1 |
| Pro | 15,000 | $49 | 50 | 5 |
| Business | 160,000 | $499 | 200 | 50 |
| Premium | 350,000 | $999 | 500 | 100 |
| Enterprise | 1M+ | $1,999+ | 1000+ | 200+ |

Consumption order (atomic): `credits → monthly → overage`. Refund on upstream 5xx reverses each bucket.

## Background workers

| Worker | Cadence | Purpose | Enabled when |
|--------|--------:|---------|--------------|
| `pricer` | `PRICING_REFRESH_SECONDS` (60s) | Cache `request_costs` | always |
| `usage-recorder` | inline / buffered | Async usage events | always |
| `webhook-dispatcher` | 5s | Deliver webhook events with HMAC + retries | always |
| `solana-listener` | continuous | `logsSubscribe` → CanonicalEvent fanout to tenants | `SOLANA_RPC_URL` set + ≥1 program id |
| `future-sign-watcher` | 5s (slot/time) · 30s (external) | Fire future-sign triggers (oracle/slot/event/external) → ika engine | `IKA_UPSTREAM_URL` + `INTERNAL_API_KEY` set |
| `metrics-scraper` | 15s | Sample runtime gauges (usage buffer, etc.) | metrics enabled |

The pricing-history applier, admin bootstrap, mailer/quota/pricing notification workers, the Stripe
service and the gift observer moved to the `backend/` service (architecture split M1–M4).

## Environment variables

`.env.example` is the reference. Boot is fail-fast — `DATABASE_URL` is always required, and in
`ENV=production` the gateway also refuses to start without `ADMIN_TOKEN` (≥32 chars, non-default),
`INTERNAL_API_KEY`, `IKA_UPSTREAM_URL` and `ENCRYPT_UPSTREAM_URL`.

### Required
| Var | Notes |
|-----|-------|
| `DATABASE_URL` | Postgres DSN. Same DB the `backend/` service uses (gateway owns the schema). |

### Required in production (validated at boot)
| Var | Notes |
|-----|-------|
| `ADMIN_TOKEN` | Strong secret (≥32 chars). Gates `/metrics`. Dev fallback `dev-only-admin-token-change-me` is rejected in production. |
| `INTERNAL_API_KEY` | Shared secret — sent as `X-Api-Key` to ika-backend and `X-Internal-Key` to encrypt-backend. The same value must be set in both engines. |
| `IKA_UPSTREAM_URL` | Private-network URL of ika-backend. |
| `ENCRYPT_UPSTREAM_URL` | Private-network URL of encrypt-backend. |
| `REDIS_URL` | Backs rate limiting **and** idempotency — both are no-ops without it, so production refuses to boot if it is empty. |
| `RATE_LIMIT_FAIL_OPEN` | Must be `false` in production: when Redis is unreachable the gateway returns `503` rather than serving unthrottled. Production refuses to boot if it is `true`. |
| `TRUSTED_PROXY_CIDRS` | Behind the Railway edge proxy this **must** contain the proxy's range, otherwise API keys with an `ip_allowlist` are rejected with `ip_allowlist_unsupported`. A malformed CIDR is fatal in production. |

### Recommended
| Var | Notes |
|-----|-------|
| `ALLOWED_ORIGINS` | CSV CORS allowlist for the dashboard. Empty = no cross-origin (server-to-server only). |
| `ANDROMEDA_DASHBOARD_BASE_URL` | Public dashboard URL. Used to build shareable links (e.g. gift-card redeem). Empty → relative paths. |

### Server
| Var | Default | Notes |
|-----|---------|-------|
| `PORT` | `8081` | Injected by Railway — do not set it there. |
| `ENV` | `development` | `development` / `production`. Drives the boot validations above and the OTel `deployment.environment`. |
| `LOG_LEVEL` | `info` | slog level. |

### Audit signing
| Var | Notes |
|-----|-------|
| `ANDROMEDA_AUDIT_SIGNER` | `env` (default, dev) or `vault` (HashiCorp Vault Transit, ed25519). In `production` with `env`, a loud warning is logged — migrate to `vault` (see `docs/AUDIT_KMS.md`). |
| `ANDROMEDA_AUDIT_PRIVATE_KEY` | Base64 ed25519 (32-byte seed or 64-byte key). Used only when signer = `env`. Falls back to an ephemeral key if empty in dev. |
| `ANDROMEDA_AUDIT_VAULT_{ADDR,TOKEN,KEY_NAME,PUBKEY_B64}` | Required (all-or-nothing) when signer = `vault`. Every signature is locally re-verified against `PUBKEY_B64`. |

### Solana / policies
| Var | Notes |
|-----|-------|
| `SOLANA_RPC_URL` | Enables the on-chain event listener; also required (with the two below) for the policies service. |
| `IKA_PROGRAM_ID` | Ika dWallet program (must match the ika-backend's). |
| `IKA_COORDINATOR_ADDRESS` | Ika `DWalletCoordinator` PDA. The **policies service** mounts only when `SOLANA_RPC_URL` + `IKA_PROGRAM_ID` + `IKA_COORDINATOR_ADDRESS` are all set. |
| `ANDROMEDA_TEMPLATE_PROGRAM_IDS_JSON` | `{"template-name":"program-id"}` map for the 8 deployed templates. A template missing here is still listed by `/v1/policies/templates` but `deploy`/`request-signature` return `503`. |
| `ANDROMEDA_GAS_SPONSOR_KEYPAIR` | JSON byte array (64 B, `solana-keygen` format). Gateway pays gas for every policy/recovery Solana tx so users never need a Solana wallet. Never commit it; keep it funded. |
| `ANDROMEDA_SDK_BASE_URL` + `ANDROMEDA_SDK_VERSION_TAG` | SDK-tarball location for `GET /v1/policies/{address}/sdk`. Tag defaults to `sdk-v0.1.0`. |

### OpenTelemetry (opt-in)
| Var | Notes |
|-----|-------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/HTTP collector URL. When unset, otel is a no-op. |
| `OTEL_EXPORTER_OTLP_HEADERS` | Auth headers (standard OTLP env, honoured by the exporter SDK). |
| `OTEL_SERVICE_NAME` | Default `andromeda-gateway`. |
| `OTEL_TRACES_SAMPLER_ARG` | 0.0–1.0, default `0.1`. |

### Tuning
| Var | Default | Notes |
|-----|---------|-------|
| `RATE_LIMIT_FAIL_OPEN` | `true` (dev) | When Redis is unreachable: `true` allows requests through, `false` rejects with `503`. **Must be `false` in production** (see *Required in production*). |
| `DEFAULT_REQUEST_COST` | `1` | Fallback token cost for route keys not in `request_costs` (must be ≥ 1). |
| `PRICING_REFRESH_SECONDS` | `60` | Pricer cache refresh interval. |
| `UPSTREAM_TIMEOUT_SECONDS` | `30` | Default upstream timeout (per-route overrides exist for heavy MPC ops — DKG, sign, quorum finalize: 90–120s). |
| `TRUSTED_PROXY_CIDRS` | empty | CIDRs of reverse proxies whose `X-Forwarded-For` / `X-Real-IP` may be trusted for API-key IP allowlists. Empty = trust only the socket peer. **Required behind an edge proxy** (see *Required in production*); a malformed CIDR is fatal in production, a warning in dev. |

## Run locally

```bash
cp .env.example .env
go mod download
go run ./cmd/server
```

Listens on `:8081`.

## Tests

```bash
go test ./...                              # unit + httptest integration (no external deps)
go test -tags integration ./internal/store/...   # quota engine vs a real Postgres (needs Docker)
```

The `integration`-tagged tests in `internal/store` spin up a throwaway Postgres
via testcontainers, run the embedded migrations, and exercise
`ConsumeTokensV2` / `RefundTokensV2` / `ComputeBalance` end to end. They are
excluded from the default build; CI runs them in a separate job (`go-ci.yml`).
