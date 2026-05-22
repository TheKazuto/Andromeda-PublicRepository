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
│   ├── auth/               # API key auth, scopes, IP + Origin allowlist, andromeda_auth Go mirror, clear-signing
│   ├── oauth/              # OAuth broker handlers (Login Social — Google + Apple, Authorization Code + PKCE)
│   ├── routes/             # Route catalogue (REST + MCP source of truth)
│   ├── upstream/           # Reverse-proxy to ika + encrypt engines
│   ├── pricing/            # Token cost cache (pricer worker)
│   ├── ratelimit/          # Redis sliding window
│   ├── idempotency/        # Idempotency-Key store
│   ├── usage/              # Async usage log writer
│   ├── webhooks/           # CRUD + dispatcher worker (HMAC + retries)
│   ├── policy/             # PolicyEngine v3 service (Go side): challenges, codecs, PDA derivation, request_signature builders, recover_as_primary + quorum_session_* + passkey_session_* handlers
│   ├── futuresign/         # Trigger watcher (oracle/slot/event/external)
│   ├── oraclerelay/        # Pyth adapter: FeedCache bootstrap + refresh-on-sign + /v1/oracle/* admin + Hermes catalog (crank off by default)
│   ├── oraclemonitor/      # Managed price-trigger keeper: arms → fires request_signature when a band holds
│   ├── audit/              # Per-tenant ed25519 hash chain (env or Vault Transit signer)
│   ├── netsafety/          # SSRF guard for outbound URLs
│   ├── mcp/                # MCP JSON-RPC + SSE server
│   ├── gasponsor/          # Solana fee payer keypair
│   ├── observability/      # OpenTelemetry tracing
│   ├── metrics/            # Prometheus collectors
│   ├── openapi/            # Auto-generated OpenAPI 3.1
│   ├── store/              # Postgres + migrations
│   ├── redisclient/        # Redis pool
│   ├── httpx/              # JSON envelope + BindAndValidate (strict decode + go-playground/validator/v10 + custom tags: solana_pubkey, base64, base64_len, hex_len)
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
| GET | `/capabilities` | Public feature matrix — includes `features.futureSignWatcher`, `features.oracleMonitor` (price-trigger keeper running), `features.redisBackedIdempotency`, and `features.rateLimitMode` (`"disabled"` / `"fail_open"` / `"fail_closed"`) so clients can tell which gateway-native features are actually operational, not just wired |
| GET | `/v1/pricing` | Token cost per route |
| POST | `/v1/pricing/estimate` | Estimate cost for a workload |
| GET | `/metrics` | Prometheus, `X-Admin-Token`-gated |
| GET·POST·DELETE | `/v1/oracle/catalog`, `/v1/oracle/feeds`, `/v1/oracle/feeds/{id}/{refresh,pause,resume}` | Pyth feed management — `X-Admin-Token`-gated (feeds are global shared infra: a tenant key must never register/pause platform feeds). |

## Authenticated endpoints (`X-Api-Key`)

Every successful response carries `X-Andromeda-Tokens-{Cost,Used,Limit}` and `X-Andromeda-Upstream`
headers. The gateway forwards the authenticated tenant identity to the engines as `X-Andromeda-User-Id`
(required by the high-level, tenant-scoped dWallet ops). Read-class routes need scope `read`;
everything else needs `write`; the gateway-native admin features (webhooks, audit, PolicyEngine v3
admin, future-sign) need scope `admin`. Request bodies are capped at 10 MiB by default (override via
`GATEWAY_MAX_BODY_BYTES`); signing/mutating routes carry tighter per-route caps (1 MiB) at the
handler level.

Every response is served with `Cache-Control: no-store` and `Vary: Origin, Authorization, X-Api-Key`
by default — only the public allowlist (`/capabilities`, `/openapi.json`, `/openapi.yaml`,
`/v1/pricing`, `/health`, `/health/ready`) is cacheable at the CDN. Defence-in-depth headers (HSTS in
production, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`,
`Cross-Origin-Resource-Policy`) are on every response.

| Group | Routes (under `/v1`) | Scope | Source |
|-------|----------------------|-------|--------|
| **dWallet — high-level (MCP tools)** | `dwallet/create` (accepts `attachPolicyEngine: true`), `dwallet/transfer-ownership`, `dwallet/presign`, `dwallet/sign` (→ MCP `create_dwallet` / `transfer_ownership` / `presign` / `sign_message`) | write | proxied to ika-backend |
| **dWallet — multi-chain (read-only)** | `GET dwallet/addresses/{dwalletAddress}` (every chain-native address for the dWallet's curve), `dwallet/prepare-message` (envelope + on-chain digest) (→ MCP `dwallet_addresses` / `prepare_message`) | read | proxied to ika-backend |
| **dWallet — low-level** | `dwallet/dkg/{prepare,submit}`, `dwallet/{sign,presign,future-sign,future-sign/complete,re-encrypt-share,make-share-public}/submit`, `GET dwallet/presigns/{userPubkey}` | write / read | proxied to ika-backend |
| **PolicyEngine v3 — read** | `GET policy/{dwallet}` — engine state (header, every active rule slot, members, destinations, nonces) | read | local |
| **PolicyEngine v3 — admin** | `policy/init/{challenge,submit}`, `policy/rules/add/{challenge,submit}`, `policy/rules/{ruleIndex}/items/add/{challenge,submit}` — challenge → owner-signs → submit. Admin scope, Idempotency-Key MANDATORY on every submit. | admin | local |
| **PolicyEngine v3 — recovery** | `policy/recover-as-primary/{challenge,submit}` (single-tx primary) · `policy/quorum/session/{open,contribute}/{challenge,submit}` · `policy/quorum/session/{finalize,close}` · `policy/passkey/session/open/{challenge,submit}` · `policy/passkey/use/{challenge,submit}` · `policy/passkey/session/close` | write | local |
| **PolicyEngine v3 — request signature** | `policy/request-signature/{challenge,submit}` — runtime metadata digest (V2: binds `amount` + `asset_index` for `KIND_SPENDING_USD`) + on-chain dispatch loop across every active rule slot + CPI Ika `approve_message`. `signature_scheme` accepts 0..6 (incl. EdDSA=5 for Solana/Sui). | write | local |
| **Login Social — OIDC pre-flow** | `POST oidc/{nonce,validate}` — canonical OAuth `nonce` builder + provider JWKS pre-validation of `id_token`s. 8 KiB body cap on `/validate` (carries a JWT). | write / read | proxied to ika-backend |
| **OAuth broker (Login Social)** | `GET oauth/{authorize,callback}`, `POST oauth/token-exchange` — gateway-hosted Andromeda OAuth client (Google + Apple, `scope=openid` only). Authorization Code + PKCE. Free (no token cost). | write | gateway |
| **Private TX** | `private-tx/submit`, `GET private-tx/status/{signature}` | write / read | proxied to encrypt-backend |
| **Ciphertext** | `ciphertext/{create,read}`, `GET ciphertext/account/{address}` | write / read | proxied to encrypt-backend |
| **Graph** | `graph/{execute,register,execute-registered,commit}/prepare`, `graph/submit`, `graph/operations/register-bytes`, `GET graph/{status/{signature},operations}` | write / read | proxied to encrypt-backend |
| **DSL** | `GET dsl/types`, `dsl/op/prepare` | read / write | proxied to encrypt-backend |
| **Decrypt** | `decrypt/request/prepare`, `GET decrypt/poll/{account}` | write / read | proxied to encrypt-backend |
| **NEK** | `GET nek/current` | read | proxied to encrypt-backend |
| **Events** | `events/emit/prepare`, `GET events/by-signature/{signature}` | write / read | proxied to encrypt-backend |
| **Wallet (private)** | `wallet/balance/init` | write | proxied to encrypt-backend |
| **Authority / Fees / Ownership** | `authority/{add,remove,register-nek}/prepare`, `fees/deposit/{create,top-up,withdraw,request-withdraw,reimburse}/prepare`, `fees/config/update/prepare`, `ownership/{transfer,copy,make-public}/prepare` | write | proxied to encrypt-backend |
| **Webhooks** | CRUD + retry | admin | gateway |
| **Audit log** | `GET audit/log`, `GET audit/log/export`, `GET audit/log/verify`, `GET audit/log/{seq}/proof` — per-tenant signed hash-chain (read + export + verify + Merkle proof). The `verify` response also carries the tenant's ed25519 `publicKeyB64` so external replayers can re-check signatures. | admin | gateway |
| **Future-sign triggers** | oracle / slot / event / external watchers | admin | gateway |
| **Oracle price triggers** | `oracle/triggers` (arm / list / get / cancel) — managed Pyth price-trigger keeper: fires a pre-built `request_signature` when the price band holds. Fan-out via webhooks (`oracle_trigger.fired` / `.expired`). | write | gateway |

Full machine-readable catalogue of the proxied routes in `internal/routes/routes.go`; everything
(including the gateway-native endpoints above) is in `/openapi.json`.

### Clear Signing v2

Every PolicyEngine v3 challenge — `init`, `rules.add`, `rules.items.add`, `recover-as-primary`,
`quorum.session.{open,contribute}`, `passkey.session.{open}` and `passkey.use` — returns a
deterministic human-readable text that the on-chain program recomputes from the same typed
parameters and embeds (length-prefixed `u16 LE`) into the SHA-256 the credential signs. A
compromised gateway cannot swap destination, member, amount, nonce or session without the approver
seeing the swap in the text they are about to sign.

**Wire format on-chain.**

```
challenge = sha256(
    DOMAIN              // e.g. "andromeda::policy-engine::v3"
    || op_tag           // e.g. "add-allowlist" / "primary-recover" / "passkey-session-open"
    || human_len_u16_le // 2 bytes, little-endian
    || human_message    // plain ASCII, ≤ 768 bytes
    || engine || dwallet || rule_kind || rule_index || rule_generation_le || expected_nonce_le
    || config_hash || owner_slot
    || (u16_le(len(extra[0])) || extra[0])   // M2 audit fix (2026-05-16): each
    || (u16_le(len(extra[1])) || extra[1])   // extra is length-prefixed so two
    || ...                                   // variable-length extras can never
                                             // concatenate ambiguously.
)
```

`MAX_HUMAN_MESSAGE_BYTES = 768`. ASCII only (`0x20..=0x7E`). Up to 12 extras (`ADMIN_CHALLENGE_MAX_EXTRAS`). Each extra ≤ 65 535 bytes.

**Gateway response shape (`POST /v1/policy/rules/add/challenge`).**

```json
{
  "challenge_hex": "u0guEFzHirl5Nt4+TVq3Okjctoi5Vkk+oSmxJFKmAIk=",
  "human_message": "Add allowlist rule (slot 0, generation 1) to engine 8AnE… for dWallet 9abc…",
  "preimage_hex": "...",
  "config_hash_hex": "...",
  "engine_address": "8AnETQSm…",
  "rule_pda": "GpL7g4Y6…",
  "op_tag": "add-allowlist",
  "program_id": "ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL"
}
```

* `human_message` — the exact ASCII text the approver MUST see before signing. Plain text, no locale, no truncation.
* `op_tag` — canonical operation tag, e.g. `init` / `init-with-recovery` / `add-allowlist` / `add-velocity` / `add-time-lock` / `add-oracle` / `add-passkey` / `add-fhe-gated` / `add-session-key` / `add-recovery` / `add-rule-spending-usd` / `allowlist-add-dest` / `oracle-add-feed` / `spending-usd-add-feed` / `primary-recover` / `quorum-session-open` / `quorum-contribute` / `passkey-session-open` / `passkey-primary-use`.
* `config_hash_hex` — sha256 of the canonical config payload for the rule (immutable identity of the rule at this generation).

**`/submit` never trusts caller text.** The handler recomputes the challenge from the same typed
parameters in the body and ignores any `human_message` the caller passed. If the on-chain SHA-256
doesn't match what the precompile validated, the transaction fails.

**Audit trail.** Every successful PolicyEngine v3 submit appends one entry to the per-tenant
ed25519-signed audit chain (mapped from `policy.PolicyEngineAuditEvent` to the canonical
`audit.Event` envelope by the `policyEngineAuditBridge`). Payload includes the action tag
(`init` / `rule.add` / `rule.items.add` / `request-signature` / `recover-as-primary` / `quorum.*` /
`passkey.*`), engine address, dWallet, tx signature, and a JSON `extra` block with route-specific
context (rule kind, rule index, member or destination added, etc.).

**No SDK required.** Clients call the gateway directly over HTTP / MCP tool, render `human_message`
to the user, take the off-chain signature with any wallet (EVM / Bitcoin / Cosmos / NEAR / Aptos /
Solana / passkey), and POST it back to `/submit`. The gateway pays the Solana fee.

**Error envelope.** Every gateway-native error response is `{"error": "<message>", "code": "<snake_case>"}` —
flat, two string fields, uniform across `/v1/policy/*`, `/v1/webhooks/*`, `/v1/audit/*`,
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

| Worker | Cadence | Purpose | Enabled when | Multi-replica |
|--------|--------:|---------|--------------|---------------|
| `pricer` | `PRICING_REFRESH_SECONDS` (60s) | Cache `request_costs` | always | safe |
| `usage-recorder` | inline / buffered | Async usage events | always | safe (per-replica buffer) |
| `webhook-dispatcher` | 1s tick, 20 workers, batch 100, 60s lease | Deliver webhooks with HMAC + retries; recovers stuck `in_flight` rows every 30s; per-destination token bucket (50 rps / 100 burst) | always | safe (FOR UPDATE SKIP LOCKED + lease) |
| `audit-signer-worker` | 500 ms | Drains `audit_log` rows with `signature IS NULL` and writes ed25519 signatures (Vault / env). Append no longer signs inline. | always | safe (FOR UPDATE SKIP LOCKED) |
| `audit-snapshot-worker` | 24h | Daily NDJSON.gz dump of `audit_log` to R2/S3 for DR. | `AUDIT_SNAPSHOT_ENABLED=true` + S3 creds | leader-elected |
| `solana-listener` | continuous | `logsSubscribe` → CanonicalEvent fanout to tenants | `SOLANA_RPC_URL` set + ≥1 program id | leader-elected |
| `future-sign-watcher` | 5s (slot/time) · 30s (external) | Fire future-sign triggers (oracle/slot/event/external) → ika engine | `IKA_UPSTREAM_URL` + `INTERNAL_API_KEY` set | leader-elected |
| `oracle-monitor` | `ORACLE_MONITOR_TICK_SECONDS` (default 10s) | Read live Pyth prices (Hermes) and fire pre-built `request_signature` when a price band holds; reaps stuck `firing` to terminal `failed` (no double-sign) | policy-engine + gas sponsor + `SOLANA_RPC_URL` set | leader-elected |
| `oracle-relay` | bootstrap one-shot; periodic crank only if `PYTH_ADAPTER_CRANK_ENABLED=true` | Bootstrap FeedCache PDAs + serve `/v1/oracle/*` admin routes. Periodic refresh crank retired by default (F7.5) — refresh-on-sign + `oracle-monitor` keep feeds fresh at signing time | `PYTH_ADAPTER_PROGRAM_ID` + `PYTH_ADAPTER_AUTHORITY_KEY` + `SOLANA_RPC_URL` set | leader-elected |
| `metrics-scraper` | 15s | Sample runtime gauges (pool, breaker, audit outbox, webhook backlog) | metrics enabled | safe (per-replica) |

Leader election uses Postgres advisory locks (`pg_try_advisory_lock`) on a dedicated pool connection
with a 30s heartbeat. When a leader dies, another replica picks up within ~30s. Workers marked
"safe" run on every replica because their per-row claim (`SKIP LOCKED` + lease) is the authoritative
dedup primitive.

The pricing-history applier, admin bootstrap, mailer/quota/pricing notification workers, the Stripe
service and the gift observer moved to the `backend/` service (architecture split M1–M4).

## Input validation

Every gateway-native handler binds JSON bodies via `httpx.BindAndValidate(w, r, &dto, maxBytes)`:

- `http.MaxBytesReader` enforces the per-call byte cap (413 on overflow).
- `json.NewDecoder` runs in **strict mode** — unknown fields and trailing JSON are 400.
- `go-playground/validator/v10` runs after decode using struct tags.

Reusable tags (in addition to the built-in `required`, `min`, `max`, `oneof`, `len`, `url`, ...):

| Tag | Meaning |
|---|---|
| `solana_pubkey` | base58 Solana pubkey (32 bytes) |
| `base64` | any valid standard base64 |
| `base64_len=N` | base64 that decodes to exactly N bytes |
| `hex_len=N` | hex that decodes to exactly N bytes |

Validator errors land on the canonical `{error, code}` envelope with `code ∈ {invalid_body,
unknown_field, payload_too_large, invalid_field}`. Authors of new handlers should add the tags
on the DTO and call `BindAndValidate` — avoid hand-rolled per-field `if req.X == ""` chains.

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
| `ALLOWED_ORIGINS` | CSV of dashboard origins (e.g. `https://app.andromedainfra.pro`). Production refuses to boot if empty or `*` — without it a malicious site could exfil JSON via fetch. |
| `TRUSTED_PROXY_CIDRS` | Behind the Railway edge proxy this **must** contain the proxy's range, otherwise API keys with an `ip_allowlist` are rejected with `ip_allowlist_unsupported`. A malformed CIDR is fatal in production. |

### Recommended
| Var | Notes |
|-----|-------|
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
| `ANDROMEDA_AUDIT_SIGNER` | `env` (default, dev) or `vault` (HashiCorp Vault Transit, ed25519). In `production` with `env`, a loud warning is logged — migrate to `vault`. With `vault`: the gateway never holds the private key; each audit entry is signed via Vault Transit `sign/<key-name>/sha2-256` calls (`andromeda-audit` key, ed25519). Required envs: `ANDROMEDA_AUDIT_VAULT_{ADDR,TOKEN,KEY_NAME,PUBKEY_B64}` (all-or-nothing — see below). The tenant's audit public key is returned by `GET /v1/audit/log/verify` so external verifiers can replay the chain. |
| `ANDROMEDA_AUDIT_PRIVATE_KEY` | Base64 ed25519 (32-byte seed or 64-byte key). Used only when signer = `env`. Falls back to an ephemeral key if empty in dev. |
| `ANDROMEDA_AUDIT_VAULT_{ADDR,TOKEN,KEY_NAME,PUBKEY_B64}` | Required (all-or-nothing) when signer = `vault`. Every signature is locally re-verified against `PUBKEY_B64`. |

**Hot path note (outbox model).** `Recorder.Append` no longer signs inline — it computes
`prev_hash + entry_hash` and inserts the row with `signature = NULL`. The `audit-signer-worker`
drains the queue out-of-band (`FOR UPDATE SKIP LOCKED`), signs each row, and updates the
signature. The chain integrity is preserved because the chain is defined by `prev_hash +
entry_hash`; the signature is an external proof attached afterwards. Hot path therefore never
blocks on Vault, and a Vault outage shows up as a growing `gateway_audit_outbox_depth` /
`outbox_oldest_age_seconds` instead of failing requests.

Worker tunables (env, optional): `AUDIT_SIGNER_BATCH=100`, `AUDIT_SIGNER_TICK_MS=500`,
`AUDIT_SIGNER_DEGRADED_AGE_SEC=30` (flip `gateway_audit_degraded=1` above this).

### Oracle (Pyth adapter + price triggers)
| Var | Default | Notes |
|-----|---------|-------|
| `PYTH_ADAPTER_PROGRAM_ID` | empty | Deployed `pyth-adapter` program id (devnet `A6xjw8jkJTFjpjHCRSFxVt1d1KbBZdh3XBNYvTfLZxP2`). Enables refresh-on-sign + the `/v1/oracle/*` admin surface + the Hermes catalog. |
| `PYTH_ADAPTER_AUTHORITY_KEY` | empty | 64-byte solana-keygen JSON array for the adapter authority — signs the one-shot FeedCache bootstrap (init) + the kill-switch (pause/transfer). NOT needed for refresh-on-sign (the gas sponsor pays; refresh is permissionless). |
| `PYTH_ADAPTER_CLUSTER` | `devnet` | Cluster label for feed rows + the price-trigger registry. |
| `PYTH_ADAPTER_FEEDS` | empty | JSON array of feeds to bootstrap, e.g. `[{"label":"SOL/USD","feedIdHex":"ef0d8b6f…","pythAccount":"7UVimffx…","pythAccountKind":"price_feed"}]`. Feeds can also be registered at runtime via `POST /v1/oracle/feeds`. |
| `PYTH_HERMES_URL` | `https://hermes.pyth.network` | Pyth Hermes endpoint — used by `GET /v1/oracle/catalog` and by the price-trigger monitor's live-price reads. |
| `PYTH_ADAPTER_CRANK_ENABLED` | `false` | Periodic refresh crank. **Retired by default (F7.5)** — refresh-on-sign + the monitor keep feeds fresh on demand. Set `true` only if a feed must stay warm for reads outside a signing tx. Bootstrap + admin routes run regardless. |
| `ORACLE_MONITOR_TICK_SECONDS` | `10` | How often the managed price-trigger monitor scans armed triggers + reads Hermes. The monitor runs only when the policy-engine + gas sponsor (`ANDROMEDA_GAS_SPONSOR_KEYPAIR`) + `SOLANA_RPC_URL` are all configured. |

The price-trigger monitor (`/v1/oracle/triggers`) and refresh-on-sign reuse the PolicyEngine signing wiring (`ANDROMEDA_POLICY_ENGINE_PROGRAM_ID`, `ANDROMEDA_GAS_SPONSOR_KEYPAIR`, `SOLANA_RPC_URL`); the gas sponsor pays both the refresh and the fired `request_signature`, so a dev needs no SOL.

### Oracle price-trigger metrics & alerts (F7.5/F7.6)

The managed monitor + feed relay export (bounded labels, no per-feed/per-tenant cardinality):

| Metric | Type | Meaning |
|--------|------|---------|
| `gateway_oracle_monitor_trigger_fires_total{result}` | counter | fires by `result` (`fired` = `request_signature` landed, `failed` = fire errored) |
| `gateway_oracle_monitor_triggers_expired_total` | counter | armed triggers reaped at expiry without firing |
| `gateway_oracle_monitor_errors_total{stage}` | counter | loop errors by `stage` (`tick`/`hermes`/`claim`/`reap`) |
| `gateway_oracle_monitor_armed_triggers` | gauge | armed triggers (sampled every 15s) |
| `gateway_oracle_relay_feed_refresh_total{result}` | counter | FeedCache refresh outcomes (`success`/`skipped`/`stale`/`error`) |

Recommended alerts (PromQL):

- **Fire failure rate** — `rate(gateway_oracle_monitor_trigger_fires_total{result="failed"}[10m]) / clamp_min(rate(gateway_oracle_monitor_trigger_fires_total[10m]), 1e-9) > 0.1` for 10 min → page (triggers failing to land; a stop-loss may not be executing).
- **Hermes outage** — `increase(gateway_oracle_monitor_errors_total{stage="hermes"}[5m]) > 0` sustained → warning (no live prices ⇒ no fires; HA the monitor / check Hermes).
- **Monitor stalled** — the `oracle-monitor` worker is leader-elected; if the leader dies, armed triggers stop firing. Alert on absence of `gateway_oracle_monitor_armed_triggers` samples (scrape gap) or on a stuck non-zero `armed_triggers` with zero fires during known price moves.

Per-feed gauges (`feed_age_seconds{feed}`, `feed_price{feed}`) and a latency histogram are deferred (F7.6) — they need per-feed sampling against on-chain `FeedCache` state.

### Audit snapshot to R2/S3 (opt-in, DR defence-in-depth)
| Var | Default | Notes |
|-----|---------|-------|
| `AUDIT_SNAPSHOT_ENABLED` | `false` | Master flag for the snapshot worker. |
| `AUDIT_SNAPSHOT_S3_ENDPOINT` | empty | S3-compatible endpoint, e.g. `https://<account>.r2.cloudflarestorage.com`. |
| `AUDIT_SNAPSHOT_S3_BUCKET` | empty | Bucket name. |
| `AUDIT_SNAPSHOT_S3_REGION` | `auto` | `auto` for R2; `us-east-1`/etc for AWS. |
| `AUDIT_SNAPSHOT_S3_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` | empty | API token credentials (SigV4). |
| `AUDIT_SNAPSHOT_S3_PREFIX` | `audit/` | Object key prefix. |
| `AUDIT_SNAPSHOT_INTERVAL_HOURS` | `24` | Tick cadence. |
| `AUDIT_SNAPSHOT_MAX_ROWS` | `100000` | Cap per upload batch. |
| `AUDIT_SNAPSHOT_MAX_BYTES_MB` | `512` | Cap per upload batch. |

Worker is leader-elected and writes one NDJSON.gz per tick to `<prefix>/<date>-<first>-<last>.ndjson.gz`.
Each upload is recorded in the `audit_snapshot_log` table — point-in-time lookups are cheap.

### Solana / PolicyEngine v3
| Var | Notes |
|-----|-------|
| `SOLANA_RPC_URL` | Enables the on-chain event listener. Also required by the PolicyEngine v3 `/submit` endpoints — the gateway builds the Solana tx in-process, signs as gas sponsor, and broadcasts via this RPC. Empty → admin/recover submits return `503 no_rpc`. |
| `IKA_PROGRAM_ID` | Ika dWallet program (must match the ika-backend's). Referenced by the `KIND_RECOVERY` / `KIND_PASSKEY` dispatchers when building the CPI to `approve_message`. |
| `ANDROMEDA_POLICY_ENGINE_PROGRAM_ID` | Deployed `policy-engine` Quasar program. Devnet: `ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL`. Empty → the local `/v1/policy/*` routes are not mounted. |
| `ANDROMEDA_GAS_SPONSOR_KEYPAIR` | JSON byte array (64 B, `solana-keygen` format). Gateway pays gas for every PolicyEngine v3 Solana tx so users never need a Solana wallet. Empty → `/submit` endpoints return `503 no_gas_sponsor`. Never commit it; keep it funded. |

### OAuth broker — Login Social (opt-in)

Mounts `GET /v1/oauth/authorize`, `GET /v1/oauth/callback` and `POST /v1/oauth/token-exchange`. Boot fails if `OAUTH_BROKER_ENABLED=true` without `BASE_URL` (`https://` in production), `STATE_HMAC_SECRET` (≥32 bytes), `REDIS_URL`, and at least one provider configured.

| Var | Default | Notes |
|-----|---------|-------|
| `OAUTH_BROKER_ENABLED` | `false` | Master flag. |
| `OAUTH_BROKER_BASE_URL` | empty | Public base URL of the gateway (used to build the callback URI). Must start with `https://` in production. |
| `OAUTH_BROKER_STATE_HMAC_SECRET` | empty | ≥32 bytes. HMAC over the OAuth `state` payload (CSRF + replay protection). |
| `OAUTH_BROKER_CODE_TTL_SECONDS` | `60` | Lifetime of the short-lived gateway code returned to the tenant app. Allowed range `[30, 300]`. |
| `OAUTH_BROKER_GOOGLE_ENABLED` | `false` | Accept Google. |
| `OAUTH_BROKER_GOOGLE_CLIENT_ID` / `OAUTH_BROKER_GOOGLE_CLIENT_SECRET` | empty | Google OAuth client. Required when Google is enabled. |
| `OAUTH_BROKER_APPLE_ENABLED` | `false` | Accept Apple. |
| `OAUTH_BROKER_APPLE_SERVICE_ID` / `OAUTH_BROKER_APPLE_TEAM_ID` / `OAUTH_BROKER_APPLE_KEY_ID` / `OAUTH_BROKER_APPLE_PRIVATE_KEY` | empty | Apple Sign-In credentials. All four required when Apple is enabled. `TEAM_ID` / `KEY_ID` are typically 10 chars. |

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
| `GATEWAY_MAX_BODY_BYTES` | `10485760` | Global body cap (10 MiB). Per-route caps (1 MiB for signing/mutating) still apply at the handler. |
| `TRUSTED_PROXY_CIDRS` | empty | CIDRs of reverse proxies whose `X-Forwarded-For` / `X-Real-IP` may be trusted for API-key IP allowlists. Empty = trust only the socket peer. **Required behind an edge proxy** (see *Required in production*); a malformed CIDR is fatal in production, a warning in dev. |
| `IKA_PRESIGN_PREFETCH_ENABLED` | `false` | Async presign prefetch (Update 2 Part A): the signing challenge (`request-signature` / `recover-as-primary`) fires the presign in the background; the matching submit returns it as `presign_session_id_hex` for `/v1/dwallet/sign` to reuse. Single-use, tenant-scoped, short TTL — not a pool. Fully non-fatal (the `/sign` inline allocation is the fallback). Keep `false` in pre-alpha (mock signer = no latency to hide); flip on at Alpha. Needs `REDIS_URL` + the ika upstream. |
| `IKA_PRESIGN_PREFETCH_TTL_SECONDS` | `120` | TTL of the ephemeral presign cache (align to challenge validity). |

#### Postgres pool
| Var | Default | Notes |
|-----|---------|-------|
| `PG_MAX_CONNS` | `20` | Pool ceiling. Calculate cluster budget = replicas × pool. Default Railway Postgres allows 100-150 conns. |
| `PG_MIN_CONNS` | `2` | Warm idle pool. |
| `PG_MAX_CONN_LIFETIME_SEC` | `1800` | Rotate connections after this age. |
| `PG_MAX_CONN_IDLE_SEC` | `300` | Drop idle conns after N seconds. |
| `PG_HEALTH_CHECK_SEC` | `30` | pgxpool health-check period. |
| `PG_STATEMENT_TIMEOUT_MS` | `30000` | Postgres `statement_timeout` applied on every new connection. |
| `PG_IDLE_IN_TX_TIMEOUT_MS` | `60000` | Postgres `idle_in_transaction_session_timeout`. Frees stuck conns. |
| `PG_STATEMENT_CACHE_MODE` | (pgx default) | Set to `describe` under PgBouncer transaction-pool mode (named prepared statements break otherwise). |
| `MIGRATION_DATABASE_URL` | `DATABASE_URL` | Direct Postgres DSN used for migrations only — bypass PgBouncer so the transactional advisory lock survives across statements. |

#### Upstream HTTP transport
| Var | Default | Notes |
|-----|---------|-------|
| `UPSTREAM_MAX_IDLE_CONNS` | `2000` | Per-process idle conn pool ceiling. |
| `UPSTREAM_MAX_IDLE_CONNS_PER_HOST` | `300` | Idle conns per engine host. |
| `UPSTREAM_MAX_CONNS_PER_HOST` | `500` | Hard ceiling per engine host. |
| `UPSTREAM_IDLE_CONN_TIMEOUT_SEC` | `90` | Drop idle conns after N seconds. |

#### Webhook dispatcher
| Var | Default | Notes |
|-----|---------|-------|
| `WEBHOOK_DISPATCHER_BATCH` | `100` | Rows claimed per tick. |
| `WEBHOOK_DISPATCHER_TICK_MS` | `1000` | Claim cadence. |
| `WEBHOOK_DISPATCHER_WORKERS` | `20` | Concurrent deliveries in flight. |
| `WEBHOOK_DISPATCHER_LEASE_SEC` | `60` | Lease duration on each claim. |
| `WEBHOOK_RECOVER_TICK_SEC` | `30` | Stuck-claim sweep cadence. |
| `WEBHOOK_PER_ENDPOINT_RPS` | `50` | Per-destination token bucket refill rate. |
| `WEBHOOK_PER_ENDPOINT_BURST` | `100` | Per-destination burst. |
| `WEBHOOK_ENDPOINT_LIMITER_IDLE_SEC` | `600` | Drop limiter from map when endpoint goes quiet. |

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
