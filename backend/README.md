# andromeda-backend

Product-side service of Andromeda. Handles signup/login, API key management, billing (Stripe), gift cards, customer endpoints (`/v1/me/*`), tenant configuration for Login Social (`/v1/oauth/redirects`), and the admin console (`/admin/*`).

Stack: Go 1.25 · chi · pgx · JWT · bcrypt · Stripe · OAuth (Google/GitHub) · TOTP · Railway.

## Communicates with

- **`dashboard/`** — consumes every customer route (`/v1/auth/*`, `/v1/me/*`, `/v1/api-keys`, `/v1/billing/*`, `/v1/gifts/*`) and the admin console (`/admin/*`).
- **`gateway/`** — shares the same Postgres pool. Schema is owned by the gateway; the backend reads/writes through the same DB. The `tenant_oauth_redirects` table (Login Social) is one such shared table: backend manages CRUD for tenants, gateway reads it at `/v1/oauth/authorize` time.
- **Stripe** — Checkout, Customer Portal, metered overage, webhooks.
- **SMTP provider** — password reset and notification emails.

Does **not** talk to `ika-backend` or `encrypt-backend` — those are reached only through the gateway.

## Project layout

```
backend/
├── cmd/server/             # main.go entrypoint
├── internal/
│   ├── api/                # HTTP handlers (customer + admin)
│   ├── auth/               # JWT, bcrypt, OAuth, TOTP, refresh tokens
│   ├── apikeys/            # API key minting + revocation
│   ├── billing/            # Stripe checkout, portal, metered overage
│   ├── notifications/      # Quota / pricing-change / overage workers
│   ├── pricing/            # Pricing applier (writes to gateway tables)
│   ├── store/              # Postgres store + migrations
│   ├── webhooks/           # Stripe webhook ingestion
│   └── config/             # Env loader
├── Dockerfile
├── railway.toml
└── go.mod
```

## Customer endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET    | `/health` | — | Liveness probe |
| GET    | `/metrics` | — | Prometheus (Railway private network only). HTTP request counts/latency, pgxpool stats, auth rate-limit blocked counter, worker tick counts. |
| POST   | `/v1/auth/signup` | — | Create account, return access JWT + refresh cookie |
| POST   | `/v1/auth/login` | — | Login, same shape as signup |
| POST   | `/v1/auth/refresh` | refresh cookie | Rotate access JWT |
| POST   | `/v1/auth/logout` | refresh cookie | Revoke all refresh tokens |
| POST   | `/v1/auth/forgot-password` | — | Send reset email (anti-enumeration) |
| POST   | `/v1/auth/reset-password` | reset token | Apply new password |
| GET    | `/v1/auth/oauth/{provider}/start` | — | Begin OAuth (Google/GitHub) |
| GET    | `/v1/auth/oauth/{provider}/callback` | — | OAuth callback |
| GET    | `/v1/auth/providers` | — | List enabled OAuth providers |
| GET    | `/v1/me` | Bearer | Current user |
| PATCH  | `/v1/me` | Bearer | Update profile |
| DELETE | `/v1/me` | Bearer | Soft-delete account |
| PATCH  | `/v1/me/password` | Bearer | Change password |
| GET    | `/v1/me/balance` | Bearer | Token balance per bucket |
| GET    | `/v1/me/usage` | Bearer | Usage chart + top routes |
| GET    | `/v1/api-keys` | Bearer | List user's API keys |
| POST   | `/v1/api-keys` | Bearer | Create API key (raw key shown once). Accepts optional `allowedOrigins` |
| PATCH  | `/v1/api-keys/{id}` | Bearer | Update name and/or `allowedOrigins` |
| DELETE | `/v1/api-keys/{id}` | Bearer | Revoke API key |
| GET    | `/v1/oauth/redirects` | Bearer | List the tenant's OAuth redirect URIs (Login Social broker allowlist) |
| POST   | `/v1/oauth/redirects` | Bearer | Add a redirect URI (HTTPS-only in prod, max 20 per tenant). Consumed by the gateway broker at `/v1/oauth/authorize` |
| DELETE | `/v1/oauth/redirects?redirectUri=<uri>` | Bearer | Remove a redirect URI |
| GET    | `/v1/pricing/plans` | — | Public plan catalogue |
| GET    | `/v1/gifts/preview/{token}` | — | Preview gift card |
| POST   | `/v1/gifts/redeem` | Bearer | Redeem gift card |
| POST   | `/v1/gifts/checkout` | — | Stripe Checkout for paid gifts |
| POST   | `/v1/billing/checkout` | Bearer | Stripe Checkout for plan upgrade |
| POST   | `/v1/billing/portal` | Bearer | Open Stripe Customer Portal |
| POST   | `/v1/billing/overage/enable` | Bearer | Enable metered overage |
| POST   | `/v1/billing/overage/disable` | Bearer | Disable metered overage |
| POST   | `/v1/billing/stripe/webhook` | Stripe-Signature | Stripe webhook ingestion |

## Admin endpoints (`/admin/*`)

JWT-gated operator console with TOTP MFA and audit log.

| Method | Path | Purpose |
|--------|------|---------|
| POST   | `/admin/auth/login` | Email + password (+ TOTP) → admin JWT |
| GET    | `/admin/auth/me` | Current operator |
| POST   | `/admin/auth/totp/setup`, `verify` | TOTP enrollment |
| GET/POST | `/admin/admin-users` | Manage operators (super_admin) |
| GET    | `/admin/audit` | Audit log tail |
| GET/PATCH | `/admin/plans`, `plans/{code}` | Manage plans |
| GET/PATCH | `/admin/request-costs`, `request-costs/{routeKey}` | Per-route token cost |
| POST   | `/admin/users` | Find-or-create user |
| POST/GET/PATCH/DELETE | `/admin/api-keys`, `users/{userId}/api-keys/{id}` | Manage user keys |
| POST/GET/PATCH | `/admin/subscriptions`, `subscriptions/{id}/overage` | Manage subscriptions |
| POST   | `/admin/credits` | Grant credits |
| GET/POST | `/admin/coupons`, `coupons/{id}/refund` | Gift card management |
| GET/POST/DELETE | `/admin/pricing-changes` | Schedule price changes |

## Environment variables

### Required (production)
| Var | Notes |
|-----|-------|
| `JWT_SECRET` | `openssl rand -hex 32`. Service refuses to boot in production without it. |
| `DATABASE_URL` | Postgres DSN. Same plugin used by the gateway. |
| `ALLOWED_ORIGINS` | Comma-separated CORS allowlist (dashboard origin). |
| `ENV` | `production` or `development`. |
| `ADMIN_JWT_SECRET` | `openssl rand -hex 32`. Required for `/admin/*`. |
| `REDIS_URL` | Backs OAuth state replay (`SET NX EX` per nonce) and the auth rate limiter (token bucket cross-replica). Service refuses to boot in production without it — multi-replica deploys can otherwise be brute-forced because per-replica memory doesn't share state. |

### Bootstrap admin (first deploy only)
| Var | Notes |
|-----|-------|
| `ANDROMEDA_BOOTSTRAP_ADMIN_EMAIL` | Initial super_admin email. |
| `ANDROMEDA_BOOTSTRAP_ADMIN_PASSWORD` | Initial password. Must be ≥12 chars **and** contain at least two of: uppercase letter, digit, special character. Service refuses to boot if shorter; admin row creation also fails if the entropy rule is not met. Clear after first login. |

### OAuth (opt-in)
| Var | Notes |
|-----|-------|
| `OAUTH_REDIRECT_BASE` | e.g. `https://api.andromeda.shinka.dev`. Required when any provider is enabled. |
| `OAUTH_STATE_SECRET` | `openssl rand -hex 32`. Required in production. |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Enables Google OAuth. |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | Enables GitHub OAuth. |
| `DASHBOARD_URL` | Post-login redirect target. |

### Stripe billing (opt-in)
| Var | Notes |
|-----|-------|
| `STRIPE_SECRET_KEY` | `sk_live_...` or `sk_test_...`. |
| `STRIPE_WEBHOOK_SECRET` | `whsec_...`. |
| `STRIPE_PRICES_JSON` | Map of plan/cycle/overage/gift → Stripe price IDs. |
| `STRIPE_CHECKOUT_SUCCESS_URL` / `STRIPE_CHECKOUT_CANCEL_URL` | Return URLs. |

### SMTP (opt-in)
| Var | Notes |
|-----|-------|
| `SMTP_HOST` / `SMTP_PORT` | 587 (STARTTLS) or 465 (TLS). Empty `SMTP_HOST` disables email; a non-numeric `SMTP_PORT` is fatal at boot (no silent fallback). |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | Provider creds. |
| `SMTP_FROM` | `Andromeda <noreply@shinkalabs.com>`. Validated with `mail.ParseAddress` and stripped of CR/LF before every send (header-injection defense). |

### Redis tuning (opt-in)
| Var | Default | Notes |
|-----|---------|-------|
| `RATE_LIMIT_FAIL_OPEN` | `false` | When Redis is unreachable: `false` (default) falls back to per-replica memory bucket; `true` allows unrestricted traffic + warns at boot. Production should leave it `false`. |
| `TRUSTED_PROXIES` | empty | CSV of proxies whose `X-Forwarded-For` may be honoured. Empty = use direct peer IP (correct behind Railway + Cloudflare). |

### Postgres pool tuning (opt-in)
| Var | Default | Notes |
|-----|---------|-------|
| `PG_MAX_CONNS` | `10` | Upper bound on pgx pool size. Raise to match Railway plan limits when the gateway and backend share the same database. |
| `PG_MIN_CONNS` | `1` | Idle connections kept warm. |
| `PG_HEALTH_CHECK_SEC` | `30` | pgxpool health-check period. |
| `PG_CONN_MAX_LIFETIME_SEC` | `3600` | Hard recycle to refresh DNS / pgbouncer state. |
| `PG_CONN_MAX_IDLE_SEC` | `600` | Drop connections idle for longer than this. |
| `PG_STATEMENT_TIMEOUT_MS` | `30000` | Postgres `statement_timeout` applied on every new connection. Frees stuck queries from the pool. |
| `PG_IDLE_IN_TX_TIMEOUT_MS` | `60000` | Postgres `idle_in_transaction_session_timeout`. |
| `PG_STATEMENT_CACHE_MODE` | (pgx default) | Set to `describe` under PgBouncer transaction-pool mode. |
| `MIGRATION_DATABASE_URL` | `DATABASE_URL` | Direct Postgres DSN for migrations only — bypass PgBouncer so the session-level advisory lock survives across statements. |

`PORT` is injected by Railway — do not set it.

## Database migrations

SQL files live under `internal/store/migrations/` and are embedded in the binary. On boot the service:

1. Connects to `MIGRATION_DATABASE_URL` (or `DATABASE_URL` if not set). The migration connection
   is opened **directly** with `pgx.Connect`, NOT via the pool — required so the session-level
   advisory lock survives across statements. Behind PgBouncer in transaction-pool mode you MUST
   set `MIGRATION_DATABASE_URL` to a direct Postgres DSN.
2. Acquires a session-level `pg_advisory_lock` (id `0x416E64726F6D6564`). Concurrent boots — blue/green deploys, two replicas restarting in lockstep — serialise here instead of double-applying a migration.
3. Creates `backend_schema_migrations` if missing.
4. Applies any file whose name is not yet recorded, each inside its own transaction. The
   `INSERT ... ON CONFLICT DO NOTHING` is defence-in-depth in case a previous run committed the
   migration but failed to record it.

Latest file: `005_admin_totp_replay.sql` (adds `admin_users.mfa_last_window` for TOTP single-use). Apply before rolling out the binary that depends on it.

The schema is co-owned with the gateway: tables the gateway creates (users, plans, subscriptions, webhook tables, etc.) live in the gateway's migration set. Backend's migrations only add columns the product surface needs.

## Background workers

Workers that have cross-replica side effects (Stripe meter events, emails, pricing rollout) run
under a leader runner that takes a Postgres advisory lock on a dedicated pool connection with a 30s
heartbeat. Multi-replica deploys never duplicate emails, meter events, or pricing applies.

| Worker | Lock ID | Purpose |
|--------|--------:|---------|
| `overage` | `0x416E64726F6501` | Stripe meter events every 5 min (active overage subs). |
| `quota` | `0x416E64726F6502` | Quota threshold email + webhook fan-out. |
| `pricing_notify` | `0x416E64726F6503` | Pricing-change announcement emails + webhooks. |
| `pricing_apply` | `0x416E64726F6504` | Apply due `pricing_history` rows to live `request_costs` / `plans`. |

The follower replicas log `leader lock unavailable` and re-try every 30s; takeover happens within
~30s of a leader dying.

## Security hardening (what to expect)

| Area | Control |
|------|---------|
| Refresh tokens | Single-use rotation with family-revocation on reuse. Hashed SHA-256 at rest. Cookie is `HttpOnly`, `Secure`+`SameSite=None` in production. |
| Password reset | Atomic `UPDATE ... RETURNING` consume; failed refresh-token revocation BLOCKS the success response. |
| Admin JWT | HS256, 8 h TTL, `jwt.WithLeeway(60s)`, mandatory `role` claim, random 16-byte `jti`. |
| TOTP | Single-use per window. `mfa_last_window` advances atomically — concurrent logins consuming the same code lose the race and get 401. |
| Admin password | bcrypt cost 12 + entropy gate (length ≥12, 2-of-3 upper/digit/special). |
| User password | bcrypt cost 12. Login feeds a real bcrypt hash on miss so response time does not leak email existence. |
| OAuth state | HMAC-signed `(nonce, expiry)`; verified state is marked consumed in-memory so the same value cannot be replayed inside its 10 min TTL. |
| OAuth profiles | Validated with `mail.ParseAddress` before persisting. |
| Scopes | `*` must appear alone; mixed `[ "*", "read" ]` is rejected. |
| Rate limit | Per-IP token bucket on `/v1/auth/*` and `/admin/auth/{login,totp/verify}`. Hard ceiling of 50 k buckets with LRU eviction. |
| Mailer | `\r\n\x00` stripped from From/To/Subject. TCP/TLS handshake bounded by a 10 s timeout, full SMTP exchange by 60 s. |
| Stripe overage | `Idempotency-Key` derived from `(subscription, baseline, delta)` — a crash between Stripe ack and DB update never double-bills. |
| Stripe customer | `Idempotency-Key` per user id — duplicate customers cannot be created. |
| Stripe refund | 3 attempts with exponential backoff for 429 / 5xx / `api_error`. |
| Webhooks | Outbound payloads >100 KiB are rejected before any DB write. |
| Account deletion | `SoftDeleteUser` anonymises email/name, deletes OAuth links, revokes API keys, revokes refresh tokens, and drops password-reset tokens in one transaction. |
| Background tasks | Goroutines spawned by handlers go through `Server.goBackground` and are awaited by the shutdown path (15 s drain window). |

## Run locally

```bash
cp .env.example .env
go mod download
go run ./cmd/server
```

API listens on `:8080`.
