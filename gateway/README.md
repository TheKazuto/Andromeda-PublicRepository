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
| GET | `/capabilities` | Public feature matrix |
| GET | `/v1/pricing` | Token cost per route |
| POST | `/v1/pricing/estimate` | Estimate cost for a workload |
| GET | `/metrics` | Prometheus, `X-Admin-Token`-gated |

## Authenticated endpoints (`X-Api-Key`)

Every successful response carries `X-Andromeda-Tokens-{Cost,Used,Limit}` and `X-Andromeda-Upstream` headers.

| Group | Routes | Upstream |
|-------|--------|----------|
| **dWallet** | `dwallet/{dkg,sign,presign,future-sign,re-encrypt-share,make-share-public}/{prepare,submit}` | ika |
| **Recovery — discovery** | `recovery/{challenge,resolve}` | ika |
| **Recovery — primary** | `recovery/primary/{challenge,submit}` | ika |
| **Recovery — quorum** | `recovery/quorum/session/{open,contribute,finalize,close,...}` | ika |
| **Recovery — policy** | `recovery/policy/{preview,deploy,admin/challenge,admin/submit,apply-pending}` | ika |
| **Identity** | `identity/email/{request,verify}`, OAuth, passkey | ika |
| **Private TX** | `private-tx/{submit,status}` | encrypt |
| **Ciphertext** | `ciphertext/{create,read,account/{address}}` | encrypt |
| **Graph / DSL / NEK / Decrypt / Events** | full FHE primitives | encrypt |
| **Wallet (private)** | `wallet/{balance,transfer,...}/prepare` | encrypt |
| **Authority / Fees / Ownership** | Encrypt program admin ops | encrypt |
| **Webhooks** | CRUD + retry, scope=admin | gateway |
| **Audit log** | per-tenant signed chain read | gateway |
| **Future-sign triggers** | oracle / slot / event / external watchers | gateway |
| **Policies** | 8 Quasar templates: rules-policy, allowlist-destinations, velocity-guard, time-lock, oracle-conditional, passkey-step-up, fhe-gated, session-keys. Endpoints: `init`, `admin/challenge`, `admin/submit`, `request-signature`. Wallet-agnostic + gas-sponsored. | gateway |
| **SDK metadata** | `GET /v1/policies/{address}/sdk` → typed TypeScript SDK tarball | gateway |
| **Simulate** | `POST /v1/signatures/simulate` → dry-run via `simulateTransaction` | gateway |
| **Auto-batching** | `POST /v1/signatures/batch` → up to 64 ops in K txs | gateway |
| **Confidential** | `POST /v1/confidential/sign` → FHE evaluation + Vault sign + fhe-gated tx | gateway |

Full machine-readable catalogue in `internal/routes/routes.go` and `/openapi.json`.

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
- **Idempotency**: `Idempotency-Key` header at HTTP layer (single body match).

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

| Worker | Cadence | Purpose |
|--------|--------:|---------|
| `pricer` | 60s | Cache `request_costs` |
| `webhook-dispatcher` | 5s | Deliver webhook events with HMAC + retries |
| `solana-listener` | continuous | logsSubscribe → CanonicalEvent fanout |
| `metrics-scraper` | 15s | Sample gauges |
| `usage-recorder` | inline | Async usage events |

## Environment variables

### Required
| Var | Notes |
|-----|-------|
| `DATABASE_URL` | Postgres DSN. Same DB the backend uses. |
| `ADMIN_TOKEN` | Strong secret (≥32 chars). Gates `/metrics`. |

### Required in production
| Var | Notes |
|-----|-------|
| `INTERNAL_API_KEY` | Shared secret. Sent as X-Api-Key to ika-backend and X-Internal-Key to encrypt-backend. The same value must be set in both engines. |
| `IKA_UPSTREAM_URL` | Private network URL of ika-backend. |
| `ENCRYPT_UPSTREAM_URL` | Private network URL of encrypt-backend. |
| `REDIS_URL` | Without it, rate limit + idempotency are no-ops. |
| `ALLOWED_ORIGINS` | CORS allowlist for the dashboard. |

### Audit signing (production)
| Var | Notes |
|-----|-------|
| `ANDROMEDA_AUDIT_SIGNER` | `env` (dev) or `vault` (production HashiCorp Vault Transit). |
| `ANDROMEDA_AUDIT_PRIVATE_KEY` | Required when `=env`. Base64 ed25519. |
| `ANDROMEDA_AUDIT_VAULT_{ADDR,TOKEN,KEY_NAME,PUBKEY_B64}` | Required when `=vault`. All-or-nothing. |

### Solana / policies
| Var | Notes |
|-----|-------|
| `SOLANA_RPC_URL` | Enables on-chain event listener. |
| `IKA_PROGRAM_ID` + `IKA_COORDINATOR_ADDRESS` | Required for policies service. |
| `ANDROMEDA_TEMPLATE_PROGRAM_IDS_JSON` | `{template-name: program-id}` map for the 8 deployed templates. |
| `ANDROMEDA_GAS_SPONSOR_KEYPAIR` | JSON byte array (64 B). Gateway pays gas for every Solana tx. |
| `ANDROMEDA_SDK_BASE_URL` + `ANDROMEDA_SDK_VERSION_TAG` | SDK tarball serving for `/v1/policies/{address}/sdk`. |

### OpenTelemetry (opt-in)
| Var | Notes |
|-----|-------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/HTTP collector URL. When unset, otel is no-op. |
| `OTEL_EXPORTER_OTLP_HEADERS` | Auth headers. |
| `OTEL_SERVICE_NAME` | Default `andromeda-gateway`. |
| `OTEL_TRACES_SAMPLER_ARG` | 0.0–1.0, default 0.1. |

### Tuning
| Var | Default | Notes |
|-----|---------|-------|
| `RATE_LIMIT_FAIL_OPEN` | `true` | Allow through when Redis unreachable. |
| `DEFAULT_REQUEST_COST` | `1` | Fallback cost for unknown route_keys. |
| `PRICING_REFRESH_SECONDS` | `60` | Pricer cache refresh. |
| `UPSTREAM_TIMEOUT_SECONDS` | `30` | Default upstream timeout. |
| `TRUSTED_PROXY_CIDRS` | empty | CIDRs allowed to supply `X-Forwarded-For`. |

`PORT` is injected by Railway — do not set it.

## Run locally

```bash
cp .env.example .env
go mod download
go run ./cmd/server
```

Listens on `:8081`.
