# andromeda-dashboard

Next.js dashboard for Andromeda. Static export, deployed to Cloudflare Pages.

Three surfaces share the codebase:

- **Public** — landing, pricing, gift purchase/redeem, login/signup.
- **Customer dashboard** (`/dashboard/*`) — API keys, usage, billing, MCP setup, settings, support.
- **Admin console** (`/admin/*`) — operator-only, separate JWT + TOTP + RBAC.

Stack: Next.js 16 (App Router, `output: "export"`) · React 19 · TypeScript 6 · Tailwind 4 · lucide-react · wrangler · Cloudflare Pages.

## Communicates with

- **`backend/`** (`NEXT_PUBLIC_API_URL`) — every customer and admin endpoint (auth, API keys, billing, gifts, admin console).
- **`gateway/`** (`NEXT_PUBLIC_GATEWAY_URL`) — public pricing catalogue (`/v1/pricing`, `/v1/pricing/estimate`).

Both URLs are read at build time. Changing them in Cloudflare requires a redeploy.

## Project layout

```
dashboard/
├── app/
│   ├── page.tsx              # Landing
│   ├── pricing/              # Public plan catalogue
│   ├── login/, signup/       # Customer auth
│   ├── auth/                 # forgot, reset, OAuth callback
│   ├── gifts/, redeem/       # Gift card flows
│   ├── billing/              # Stripe success/cancel landings
│   ├── dashboard/            # Customer dashboard (8 pages)
│   └── admin/                # Admin console (10 pages)
├── components/               # Sidebar, Topbar, Logo, OAuth buttons, admin/
├── lib/
│   ├── api.ts                # Customer client (in-memory JWT)
│   └── admin-api.ts          # Admin client (sessionStorage)
├── public/                   # Logo, _headers (CSP/HSTS)
├── next.config.js            # output: "export"
├── tsconfig.json
└── wrangler.jsonc            # Cloudflare Pages config
```

## Pages

### Public
| Route | Purpose |
|-------|---------|
| `/` | Landing |
| `/pricing` | Plan catalogue |
| `/login`, `/signup` | Customer authentication |
| `/auth/forgot`, `/auth/reset` | Password recovery |
| `/gifts/buy`, `/redeem` | Gift card buy + redeem |
| `/billing/success`, `/billing/cancel` | Stripe checkout returns |

### Customer (`/dashboard/*`)
| Route | Purpose |
|-------|---------|
| `/dashboard` | Overview |
| `/dashboard/api-keys` | Create, edit (name + allowed origins), revoke keys |
| `/dashboard/mcp-server` | MCP install config + tool catalog |
| `/dashboard/usage` | 30-day usage chart |
| `/dashboard/billing` | Plan + Stripe Portal + overage |
| `/dashboard/settings` | Profile + security + danger zone |
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
| `/admin/pricing-changes` | Versioned pricing changes |
| `/admin/audit` | Audit log viewer |
| `/admin/admin-users` | Manage operators (super_admin) |
| `/admin/security` | TOTP setup |

## Auth model

- **Customer** — short-lived access JWT in memory + HttpOnly refresh cookie (14d). XSS in the dashboard cannot exfiltrate either credential.
- **Admin** — JWT in `sessionStorage` (8h, no refresh). Closing the tab forces re-login.

## Environment variables

Both vars are read at **build time** — changing them in Cloudflare requires a redeploy.

| Var | Notes |
|-----|-------|
| `NEXT_PUBLIC_API_URL` | Backend service URL (auth, billing, admin, customer). e.g. `https://api.shinkalabs.com`. |
| `NEXT_PUBLIC_GATEWAY_URL` | Gateway service URL (pricing catalogue). e.g. `https://gateway.shinkalabs.com`. |

## Run locally

```bash
cp .env.local.example .env.local
npm install
npm run dev
```

Open http://localhost:3000. Backend on `:8080` and gateway on `:8081` must be running.

## Deploy

Cloudflare Pages with **build command** `npm run build` and **output** `out/`. Set the env vars above.
