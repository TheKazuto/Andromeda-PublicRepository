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

### Bootstrap admin (first deploy only)
| Var | Notes |
|-----|-------|
| `ANDROMEDA_BOOTSTRAP_ADMIN_EMAIL` | Initial super_admin email. |
| `ANDROMEDA_BOOTSTRAP_ADMIN_PASSWORD` | Initial password (≥12 chars). Empty after first login. |

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
| `SMTP_HOST` / `SMTP_PORT` | 587 (STARTTLS) or 465 (TLS). Empty disables email. |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | Provider creds. |
| `SMTP_FROM` | `Andromeda <noreply@shinkalabs.com>`. |

`PORT` is injected by Railway — do not set it.

## Run locally

```bash
cp .env.example .env
go mod download
go run ./cmd/server
```

API listens on `:8080`.
