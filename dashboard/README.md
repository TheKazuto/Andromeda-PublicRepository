# andromeda-dashboard

Next.js dashboard for Andromeda. Static export, deployed to Cloudflare Pages.

Three surfaces share the codebase:

- **Public** — landing, pricing, gift purchase/redeem, login/signup.
- **Customer dashboard** (`/dashboard/*`) — API keys, OAuth redirects (Login Social), usage, billing, MCP setup, settings, support.
- **Admin console** (`/admin/*`) — operator-only, separate JWT + TOTP + RBAC.

Stack: Next.js 16 (App Router, `output: "export"`) · React 19 · TypeScript 6 · Tailwind 4 · lucide-react · clsx · wrangler · Cloudflare Pages.

## Communicates with

- **`backend/`** (`NEXT_PUBLIC_API_URL`) — every customer and admin endpoint (auth, API keys, billing, gifts, admin console).
- **`gateway/`** (`NEXT_PUBLIC_GATEWAY_URL`) — public pricing catalogue (`/v1/pricing`, `/v1/pricing/estimate`) and the hosted MCP endpoint (`/mcp`) shown to users on the MCP Server page.

Both URLs are read at build time. Changing them in Cloudflare requires a redeploy.

## Project layout

```
dashboard/
├── app/
│   ├── page.tsx                    # Landing
│   ├── pricing/                    # Public plan catalogue
│   ├── login/, signup/             # Customer auth (with ?next= support)
│   ├── auth/                       # forgot, reset, OAuth callback
│   ├── gifts/, redeem/             # Gift card flows
│   ├── billing/                    # Stripe success/cancel landings
│   ├── dashboard/                  # Customer dashboard (8 pages)
│   └── admin/                      # Admin console (10 pages)
├── components/
│   ├── Sidebar, Topbar, Logo, …    # Shell + design-system primitives
│   ├── Modal.tsx                   # Reusable overlay (focus trap, ESC, scroll lock)
│   ├── ConfirmDialog.tsx           # Replaces window.confirm() across the app
│   ├── OAuthButtons.tsx            # Provider buttons with redirect-loading state
│   └── admin/                      # AdminSidebar, PageHeader
├── lib/
│   ├── api.ts                      # Customer client (in-memory JWT, pub/sub session-lost)
│   ├── admin-api.ts                # Admin client (sessionStorage)
│   ├── format.ts                   # formatNumber, formatDate, timeAgo, errorMessage
│   ├── clipboard.ts                # copyToClipboard() with permission failure handling
│   ├── use-normalized-pathname.ts  # Strips trailing slash for active-link checks
│   └── user-context.tsx            # UserProvider + useUser() — single /v1/me fetch
├── public/                         # Logo, _headers (CSP/HSTS)
├── next.config.js                  # output: "export"
├── tsconfig.json
└── wrangler.jsonc                  # Cloudflare Pages config
```

## Pages

### Public
| Route | Purpose |
|-------|---------|
| `/` | Landing |
| `/pricing` | Plan catalogue |
| `/login`, `/signup` | Customer authentication (accept `?next=` for post-login redirect; only same-origin paths are honoured) |
| `/auth/forgot`, `/auth/reset` | Password recovery |
| `/auth/callback` | OAuth fragment handler — validates the token shape (JWT) before storing it |
| `/gifts/buy`, `/redeem` | Gift card buy + redeem |
| `/billing/success`, `/billing/cancel` | Stripe checkout returns |

### Customer (`/dashboard/*`)
| Route | Purpose |
|-------|---------|
| `/dashboard` | Overview |
| `/dashboard/api-keys` | Create, edit (name + allowed origins), revoke keys. Newly minted key triggers a `beforeunload` guard so the user can't navigate away before copying it. |
| `/dashboard/settings/oauth-redirects` | Tenant-managed redirect URI allowlist for Login Social. Lists / adds / removes URIs the gateway broker accepts at `/v1/oauth/authorize` |
| `/dashboard/mcp-server` | MCP install config + tool catalog. The URL is derived from `NEXT_PUBLIC_GATEWAY_URL + /mcp`. |
| `/dashboard/usage` | 30-day usage chart |
| `/dashboard/billing` | Plan + Stripe Portal + overage |
| `/dashboard/settings` | Profile + security + danger zone. OAuth-only accounts are detected by `err.code` (not message text). |
| `/dashboard/support` | FAQ + contact |
| `/dashboard/documentation` | Docs landing |

### Admin (`/admin/*`)
| Route | Purpose |
|-------|---------|
| `/admin/login` | Login + optional TOTP |
| `/admin` | Operator overview |
| `/admin/users` | Lookup, credits, plan, keys |
| `/admin/plans` | Edit plans |
| `/admin/costs` | Per-route token cost |
| `/admin/coupons` | Gift cards |
| `/admin/pricing-changes` | Versioned pricing changes (the `datetime-local` input enforces the ≥30-day floor client-side) |
| `/admin/audit` | Audit log viewer |
| `/admin/admin-users` | Manage operators (super_admin) |
| `/admin/security` | TOTP setup |

## Auth model

- **Customer** — short-lived access JWT in memory + HttpOnly refresh cookie (14d). XSS in the dashboard cannot exfiltrate either credential.
  - On every `401`, `lib/api.ts` calls `/v1/auth/refresh` once (with concurrent callers sharing the same in-flight promise) and retries. If the refresh fails it wipes local state, fires the `session-lost` listeners, and throws an `APIError` with `code: "session_lost"` — callers never receive a confusing "Request failed (401)" body.
  - `registerSessionLostHandler(fn)` is pub/sub and returns an `unsubscribe()`. The dashboard layout subscribes on mount and unsubscribes on unmount, so navigating between `/dashboard` and `/admin` never leaves a dangling redirect handler.
  - A localStorage migration shim (`andromeda.token`) covers users carrying a pre-Wave-3 token; it is wiped on first read and on every `setToken()` call.
- **Admin** — JWT in `sessionStorage` (8h, no refresh). Closing the tab forces re-login. (A move to HttpOnly cookies is on the roadmap and requires coordinated backend changes.)

## Shared building blocks

- **`<Modal>`** (`components/Modal.tsx`) — overlay with focus trap, ESC handling, scroll lock and focus restore. Every confirmation and form modal in the app sits on top of this — never call `window.confirm()` / `window.alert()` directly.
- **`<ConfirmDialog>`** (`components/ConfirmDialog.tsx`) — destructive-action prompt built on `<Modal>`. Use it for revoke/delete/refund/cancel flows so they stay inside the design system and the focus trap.
- **`<UserProvider>` + `useUser()`** (`lib/user-context.tsx`) — provides the current `/v1/me` payload to every page under `/dashboard/*`. Topbar and Settings read from the context instead of issuing duplicate fetches.
- **`copyToClipboard(text)`** (`lib/clipboard.ts`) — always returns `Promise<boolean>` so the UI can fall back to "copy manually" messaging when the browser blocks the permission (insecure context, cross-origin iframe, user denied prompt).
- **`errorMessage(e, fallback)`** (`lib/format.ts`) — narrows an `unknown` rejection to a string. Use this instead of inlining `e instanceof Error ? e.message : "X failed"`.
- **`useNormalizedPathname()`** (`lib/use-normalized-pathname.ts`) — strips the trailing slash that `trailingSlash: true` adds to `usePathname()` so active-link checks against `/dashboard`, `/admin`, etc. still match.

## Environment variables

All env vars are read at **build time** — changing them in Cloudflare requires a redeploy.

| Var | Required | Default | Notes |
|-----|----------|---------|-------|
| `NEXT_PUBLIC_API_URL` | yes | `http://localhost:8080` | Backend service URL (auth, billing, admin, customer). e.g. `https://api.shinkalabs.com`. |
| `NEXT_PUBLIC_GATEWAY_URL` | yes | `http://localhost:8081` | Gateway service URL (pricing catalogue + MCP base). e.g. `https://gateway.shinkalabs.com`. |
| `NEXT_PUBLIC_NETWORK` | no | `Devnet` | Label shown in the Sidebar's "Network" badge. |
| `NEXT_PUBLIC_NETWORK_TIER` | no | `Pre-alpha` | Tier shown under the network label. Flip to e.g. `Mainnet` / `Beta` when ready. |

## Run locally

```bash
cp .env.local.example .env.local
npm install
npm run dev
```

Open http://localhost:3000. Backend on `:8080` and gateway on `:8081` must be running.

## Quality gates

```bash
npm run typecheck   # tsc --noEmit
npm run lint        # next lint
npm run build       # next build (also exercises the static export)
```

Notes:

- `any` is forbidden in `app/`, `components/`, `lib/`. Use `unknown` and narrow.
- Every `useEffect` that issues network I/O must use a cancellation flag (or `AbortController`) so a stale response cannot call `setState` after unmount.
- New destructive actions must go through `<ConfirmDialog>`. Inline error toasts and form-level errors are fine — `window.confirm()` / `window.alert()` are not.
- All clipboard writes go through `copyToClipboard()` so the failure case is observable.

## Deploy

Cloudflare Pages with **build command** `npm run build` and **output** `out/`. Set the env vars above.
