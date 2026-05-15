// Two backends after the M1–M3 architecture split:
//
//   * BACKEND_BASE — customer-facing product (auth, api keys, billing,
//     gifts: preview/redeem/checkout, /v1/me/*, /v1/pricing/plans).
//     Default 8080. Set via NEXT_PUBLIC_API_URL.
//   * GATEWAY_BASE — hot-path API (proxy to ika/encrypt) + the
//     route-level pricing surface (/v1/pricing, /v1/pricing/estimate).
//     Default 8081. Set via NEXT_PUBLIC_GATEWAY_URL.
//
// When the two URLs are equal (e.g. behind a reverse proxy), the
// distinction is invisible — both helpers hit the same host.
//
// ----- Session model (post-Wave-3 hardening) -----
//
// The access JWT lives in memory only — never `localStorage`, never
// `sessionStorage`. The refresh side is an HttpOnly cookie set by the
// backend (scoped to /v1/auth) and is therefore unreadable by JS.
// XSS in the dashboard can no longer exfiltrate a long-lived credential.
//
// Bootstrap on page load: nothing in memory yet — `bootstrapSession()`
// calls /v1/auth/refresh which, if the cookie is still valid, hands back
// a fresh JWT. On 401 anywhere in the app, `doFetch()` does the same
// refresh-and-retry once before giving up.
//
// A short-lived `localStorage` migration shim (LEGACY_TOKEN_KEY) reads any
// pre-Wave-3 token left behind by older builds, copies it to memory,
// and immediately wipes the entry. Triggered from the boot path *and*
// from `setToken`, so any OAuth/login that lands first still cleans the
// stale entry.

const BACKEND_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";
const GATEWAY_BASE = process.env.NEXT_PUBLIC_GATEWAY_URL || "http://localhost:8081";
const LEGACY_TOKEN_KEY = "andromeda.token";

export const API_BASE = BACKEND_BASE;
export const GATEWAY_API_BASE = GATEWAY_BASE;

export function oauthStartURL(provider: "google" | "github"): string {
  return `${BACKEND_BASE}/v1/auth/oauth/${provider}/start`;
}

export type AuthProviders = {
  google: boolean;
  github: boolean;
};

export class APIError extends Error {
  status: number;
  code: string;
  constructor(status: number, message: string, code = "") {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// ----- In-memory access token -----

let memoryToken: string | null = null;
let migrationDone = false;

function clearLegacyToken(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(LEGACY_TOKEN_KEY);
  } catch {
    /* localStorage unavailable in restricted contexts — ignore */
  }
}

function migrateLegacyToken(): void {
  if (migrationDone || typeof window === "undefined") return;
  migrationDone = true;
  try {
    const legacy = window.localStorage.getItem(LEGACY_TOKEN_KEY);
    if (legacy) {
      memoryToken = legacy;
      window.localStorage.removeItem(LEGACY_TOKEN_KEY);
    }
  } catch {
    /* localStorage unavailable in restricted contexts — ignore */
  }
}

function getToken(): string | null {
  migrateLegacyToken();
  return memoryToken;
}

export function setToken(token: string): void {
  // Mark migration as done and proactively scrub the legacy entry so a
  // fresh login (e.g. OAuth callback) can never leave a stale long-lived
  // token sitting in localStorage.
  migrationDone = true;
  clearLegacyToken();
  memoryToken = token;
}

export function clearToken(): void {
  memoryToken = null;
}

export function hasToken(): boolean {
  return Boolean(getToken());
}

// ----- Refresh / logout -----

let refreshInflight: Promise<boolean> | null = null;

type SessionLostListener = () => void;
const sessionLostListeners = new Set<SessionLostListener>();

/** registerSessionLostHandler lets one or more views (root layout, admin
 * console, etc.) react when the refresh attempt fails. Returns an
 * unsubscribe function so the caller can clean up on unmount — required
 * to avoid stale handlers redirecting users to the wrong route. */
export function registerSessionLostHandler(fn: SessionLostListener): () => void {
  sessionLostListeners.add(fn);
  return () => {
    sessionLostListeners.delete(fn);
  };
}

function emitSessionLost(): void {
  sessionLostListeners.forEach((fn) => {
    try {
      fn();
    } catch {
      /* one bad listener should not break the others */
    }
  });
}

/** refreshSession swaps the HttpOnly cookie for a new access JWT. Returns
 * true on success. Concurrent callers share a single in-flight promise so
 * a flurry of 401s never produces a flurry of /v1/auth/refresh requests. */
export async function refreshSession(): Promise<boolean> {
  if (refreshInflight) return refreshInflight;
  refreshInflight = (async () => {
    try {
      const res = await fetch(`${BACKEND_BASE}/v1/auth/refresh`, {
        method: "POST",
        credentials: "include",
        cache: "no-store",
      });
      if (!res.ok) return false;
      const data = (await res.json()) as { token?: string };
      if (!data.token) return false;
      setToken(data.token);
      return true;
    } catch {
      return false;
    } finally {
      refreshInflight = null;
    }
  })();
  return refreshInflight;
}

/** bootstrapSession is called once on app load (and after legacy migration)
 * so the dashboard knows whether the visitor is signed in before any
 * authenticated fetch happens. Resolves to true if a session exists. */
export async function bootstrapSession(): Promise<boolean> {
  if (getToken()) return true;
  return refreshSession();
}

/** logoutSession revokes the refresh cookie server-side and clears the
 * in-memory access token. */
export async function logoutSession(): Promise<void> {
  try {
    await fetch(`${BACKEND_BASE}/v1/auth/logout`, {
      method: "POST",
      credentials: "include",
      cache: "no-store",
    });
  } catch {
    /* best-effort — even if the request fails we still clear memory */
  }
  clearToken();
}

// ----- forgot / reset password -----

export const passwords = {
  forgot: (email: string): Promise<{ ok: true }> =>
    api<{ ok: true }>("/v1/auth/forgot-password", {
      method: "POST",
      auth: false,
      body: { email },
    }),
  reset: (token: string, newPassword: string): Promise<void> =>
    api("/v1/auth/reset-password", {
      method: "POST",
      auth: false,
      body: { token, newPassword },
    }),
};

// ----- core fetch helper -----

type FetchOpts = {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  auth?: boolean;
  // Lets callers cancel a request when their component unmounts.
  signal?: AbortSignal;
};

// Narrow an `unknown` response body to the standard `{ error, code }` shape
// without trusting arbitrary fields.
function readErrorBody(data: unknown): { message?: string; code?: string } {
  if (typeof data !== "object" || data === null) return {};
  const obj = data as Record<string, unknown>;
  const out: { message?: string; code?: string } = {};
  if (typeof obj.error === "string") out.message = obj.error;
  if (typeof obj.code === "string") out.code = obj.code;
  return out;
}

async function doFetch<T>(
  base: string,
  path: string,
  opts: FetchOpts,
  attempted = false,
): Promise<T> {
  const headers: Record<string, string> = {};

  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  if (opts.auth !== false) {
    const tok = getToken();
    if (tok) headers["Authorization"] = `Bearer ${tok}`;
  }

  const res = await fetch(`${base}${path}`, {
    method: opts.method || "GET",
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    cache: "no-store",
    // include the HttpOnly refresh cookie on every call so /v1/auth/refresh
    // can rotate it transparently when the access JWT is stale.
    credentials: "include",
    signal: opts.signal,
  });

  // 401 with auth=true: try the refresh once, then retry. If refresh fails,
  // wipe local state, notify listeners, and throw — never fall through to
  // the JSON parse below, which would yield a confusing "Request failed
  // (401)" while the router is already redirecting to /login.
  if (res.status === 401 && opts.auth !== false && !attempted) {
    const refreshed = await refreshSession();
    if (refreshed) {
      return doFetch<T>(base, path, opts, true);
    }
    clearToken();
    emitSessionLost();
    throw new APIError(401, "Session expired", "session_lost");
  }

  if (res.status === 204) return undefined as T;

  let data: unknown = null;
  try {
    data = await res.json();
  } catch {
    /* empty body */
  }

  if (!res.ok) {
    const body = readErrorBody(data);
    const msg = body.message ?? `Request failed (${res.status})`;
    throw new APIError(res.status, msg, body.code ?? "");
  }
  return data as T;
}

// api() targets the backend (auth, api keys, billing, gifts.checkout).
export async function api<T>(path: string, opts: FetchOpts = {}): Promise<T> {
  return doFetch<T>(BACKEND_BASE, path, opts);
}

// gatewayApi() targets the gateway (read-only data the dashboard reads:
// pricing, balance, usage, gift preview/redeem).
export async function gatewayApi<T>(path: string, opts: FetchOpts = {}): Promise<T> {
  return doFetch<T>(GATEWAY_BASE, path, opts);
}

// ---- Typed shapes ----

export type User = {
  id: string;
  email: string;
  name: string;
  plan: string;
  createdAt: string;
};

export type APIKey = {
  id: string;
  userId: string;
  name: string;
  prefix: string;
  scopes: string[];
  ipAllowlist?: string[];
  allowedOrigins?: string[];
  createdAt: string;
  lastUsedAt?: string;
  revokedAt?: string;
};

export type AuthResp = {
  token: string;
  expiresAt: string;
  user: User;
};

// Login Social — one redirect URI registered by the tenant for the
// gateway OAuth broker. Backend at GET/POST/DELETE /v1/oauth/redirects.
export type OAuthRedirect = {
  redirectUri: string;
  description?: string;
  createdAt: string;
};

export type UsageDay = { date: string; signs: number; reads: number };
export type Usage = {
  period: string;
  totalSigns: number;
  totalReads: number;
  includedSigns: number;
  overagePct: number;
  medianLatencyMs: number;
  successRate: number;
  daily: UsageDay[];
};

export type Invoice = { id: string; date: string; amount: number; status: string };
export type Billing = {
  plan: string;
  nextRenewal: string;
  monthToDateUsd: number;
  paymentLast4: string;
  invoices: Invoice[];
};

// ---- Gift cards (public preview + authenticated redeem) ----

export type GiftPreview = {
  planCode: string;
  durationMonths: number;
  source: "paid" | "promo";
  message?: string;
  expiresAt: string;
  status: "redeemable" | "redeemed" | "refunded" | "expired";
};

export type GiftRedeemResp = {
  action: "created" | "extended" | "upgraded";
  addedTokens: number;
  addedDays: number;
  subscription: unknown; // shape mirrors the gateway store.Subscription
  gift: GiftPreview;
};

export const gifts = {
  // All gift card endpoints live on the backend after M3.
  preview: (token: string): Promise<GiftPreview> =>
    api<GiftPreview>(`/v1/gifts/preview/${encodeURIComponent(token)}`, { auth: false }),
  redeem: (token: string): Promise<GiftRedeemResp> =>
    api<GiftRedeemResp>("/v1/gifts/redeem", { method: "POST", body: { token } }),
  checkout: (body: {
    planCode: string;
    durationMonths: 1 | 12;
    message?: string;
  }): Promise<{ url: string; sessionId: string }> =>
    api("/v1/gifts/checkout", { method: "POST", auth: false, body }),
};

// ---- Pricing (public) ----

export interface PublicPlan {
  code: string;
  name: string;
  monthlyTokens: number;
  priceCents: number;
  annualPriceCents: number;
  overagePer1kCents: number;
  readRps: number;
  readBurst: number;
  txRps: number;
  txBurst: number;
  features: Record<string, unknown>;
  isGiftable: boolean;
  sortOrder: number;
}

export interface PricingPlansResp {
  plans: PublicPlan[];
  generatedAt: string;
}

export interface PricingRouteCost {
  method: string;
  path: string;
  key: string;
  upstream: string;
  rateClass: string;
  idempotent: boolean;
  costTokens: number;
}

export interface PricingCatalogResp {
  service: string;
  tokenSymbol: string;
  rate: { balconCentsPer1k: number; balconUsdPer1k: string; note: string };
  defaultCostTokens: number;
  totalRoutes: number;
  routes: PricingRouteCost[];
  generatedAt: string;
}

// Pricing surface is split: /plans is product info hosted by the
// backend; /catalog and /estimate are route-aware and stay on the
// gateway because they depend on the gateway's compile-time route
// registry.
export const pricing = {
  plans: (): Promise<PricingPlansResp> =>
    api<PricingPlansResp>("/v1/pricing/plans", { auth: false }),
  catalog: (): Promise<PricingCatalogResp> =>
    gatewayApi<PricingCatalogResp>("/v1/pricing", { auth: false }),
  estimate: (
    routes: Array<{ key: string; count?: number }>,
  ): Promise<{
    items: Array<{ key: string; count: number; costTokens: number; subtotal: number }>;
    totalTokens: number;
    estimatedUsdCents: number;
  }> => gatewayApi("/v1/pricing/estimate", { method: "POST", auth: false, body: { routes } }),
};

// ---- Me (authenticated user) ----

export interface MeBalance {
  userId: string;
  email: string;
  balance: {
    subscription?: {
      id: string;
      planCode: string;
      status: string;
      billingCycle: string;
      currentPeriodEnd: string;
      tokensUsed: number;
      tokensLimit: number;
      overageEnabled: boolean;
      overageCardPresent: boolean;
      overageUsedTokens: number;
      overageCapTokens: number;
      stripeCustomerId?: string;
      stripeSubscriptionId?: string;
      stripeOverageItemId?: string;
    };
    credits: number;
    monthlyRemaining: number;
    overageAvailable: number;
    totalRemaining: number;
    periodEnd?: string;
  };
  plan?: { code: string; billingCycle: string; status: string };
  generatedAt: string;
}

export interface MeUsage {
  userId: string;
  range: string;
  since: string;
  until: string;
  tokens: number;
  calls: number;
  daily: Array<{ date: string; tokens: number; calls: number }>;
  topRoutes: Array<{ routeKey: string; tokens: number; calls: number }>;
  generatedAt: string;
}

// /v1/me/balance and /v1/me/usage moved to the backend in M3 — both
// services share the same Postgres pool so the data is identical.
export const me = {
  balance: (): Promise<MeBalance> => api<MeBalance>("/v1/me/balance"),
  usage: (range = "30d"): Promise<MeUsage> =>
    api<MeUsage>(`/v1/me/usage?range=${encodeURIComponent(range)}`),
  changePassword: (body: {
    currentPassword: string;
    newPassword: string;
  }): Promise<void> => api("/v1/me/password", { method: "PATCH", body }),
  deleteAccount: (body: { password?: string; confirmEmail?: string }): Promise<void> =>
    api("/v1/me", { method: "DELETE", body }),
};

// ---- Billing (authenticated) ----

export const billing = {
  checkout: (body: {
    planCode: string;
    cycle?: "monthly" | "annual";
  }): Promise<{ url: string; sessionId: string }> =>
    api("/v1/billing/checkout", { method: "POST", body }),
  portal: (returnUrl?: string): Promise<{ url: string }> =>
    api("/v1/billing/portal", { method: "POST", body: returnUrl ? { returnUrl } : {} }),
  enableOverage: (): Promise<{ enabled: boolean; itemId: string }> =>
    api("/v1/billing/overage/enable", { method: "POST", body: {} }),
  disableOverage: (): Promise<void> =>
    api("/v1/billing/overage/disable", { method: "POST", body: {} }),
};
