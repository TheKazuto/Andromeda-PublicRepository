// Admin API client — completely separate from the customer-facing
// `lib/api.ts`. Different token, different storage, different endpoints.
//
// Storage uses sessionStorage so closing the tab logs the admin out.
// localStorage would persist across browser restarts; for an operator
// console that's a bigger blast radius than we want.
//
// Admin moved to the backend service in M4 — this points at the same
// host as the customer auth flow (NEXT_PUBLIC_API_URL).

const BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";
const ADMIN_TOKEN_KEY = "andromeda.admin.token";
const ADMIN_EXPIRY_KEY = "andromeda.admin.expiresAt";

export const ADMIN_API_BASE = BASE;

export class AdminAPIError extends Error {
  status: number;
  code: string;

  constructor(status: number, message: string, code = "") {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// ----- token storage -----

export function getAdminToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.sessionStorage.getItem(ADMIN_TOKEN_KEY);
}

export function setAdminToken(token: string, expiresAt: string): void {
  if (typeof window === "undefined") return;
  window.sessionStorage.setItem(ADMIN_TOKEN_KEY, token);
  window.sessionStorage.setItem(ADMIN_EXPIRY_KEY, expiresAt);
}

export function clearAdminToken(): void {
  if (typeof window === "undefined") return;
  window.sessionStorage.removeItem(ADMIN_TOKEN_KEY);
  window.sessionStorage.removeItem(ADMIN_EXPIRY_KEY);
}

export function getAdminTokenExpiry(): Date | null {
  if (typeof window === "undefined") return null;
  const v = window.sessionStorage.getItem(ADMIN_EXPIRY_KEY);
  if (!v) return null;
  const d = new Date(v);
  return isNaN(d.getTime()) ? null : d;
}

export function hasAdminToken(): boolean {
  const t = getAdminToken();
  if (!t) return false;
  const exp = getAdminTokenExpiry();
  if (exp && exp.getTime() <= Date.now()) {
    clearAdminToken();
    return false;
  }
  return true;
}

// ----- fetch wrapper -----

type FetchOpts = {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  // Defaults to true. Set false for /admin/auth/login.
  auth?: boolean;
  query?: Record<string, string | number | undefined>;
};

export async function adminApi<T>(path: string, opts: FetchOpts = {}): Promise<T> {
  const headers: Record<string, string> = {};

  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  if (opts.auth !== false) {
    const tok = getAdminToken();
    if (tok) headers["Authorization"] = `Bearer ${tok}`;
  }

  let url = `${BASE}${path}`;
  if (opts.query) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(opts.query)) {
      if (v !== undefined && v !== null && v !== "") {
        qs.set(k, String(v));
      }
    }
    const enc = qs.toString();
    if (enc) url += `?${enc}`;
  }

  const res = await fetch(url, {
    method: opts.method || "GET",
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    cache: "no-store",
  });

  if (res.status === 204) return undefined as T;

  let data: unknown = null;
  try {
    data = await res.json();
  } catch {
    /* empty body */
  }

  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    let code = "";
    if (data && typeof data === "object") {
      const obj = data as Record<string, unknown>;
      if (typeof obj.error === "string") msg = obj.error;
      if (typeof obj.code === "string") code = obj.code;
    }
    if (res.status === 401) {
      // Token rejected — wipe and let the caller re-route to login.
      clearAdminToken();
    }
    throw new AdminAPIError(res.status, msg, code);
  }

  return data as T;
}

// ----- typed responses -----

export type AdminRole = "super_admin" | "support" | "billing";

export interface AdminMe {
  id: string;
  email: string;
  role: AdminRole;
  mfaRequired: boolean;
  mfaEnabled: boolean;
  lastLoginAt?: string;
  lastLoginIp?: string;
  createdAt: string;
}

export interface AdminLoginResp {
  token: string;
  expiresAt: string;
  admin: AdminMe;
}

export interface AdminAuditEntry {
  id: number;
  adminId: string;
  adminEmail: string;
  action: string;
  target?: string;
  payload: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  createdAt: string;
}

export interface AdminPlan {
  id: string;
  code: string;
  name: string;
  monthlyTokens: number;
  priceCents: number;
  annualPriceCents: number;
  overagePer1kCents: number;
  rateLimitRps: number;
  rateLimitBurst: number;
  readRps: number;
  readBurst: number;
  txRps: number;
  txBurst: number;
  features: Record<string, unknown>;
  isActive: boolean;
  isGiftable: boolean;
  sortOrder: number;
  createdAt: string;
  updatedAt: string;
}

export interface AdminRequestCost {
  routeKey: string;
  costTokens: number;
  description: string;
  updatedAt: string;
}

export interface AdminGiftCard {
  id: string;
  redeemToken: string;
  planCode: string;
  durationMonths: 1 | 12;
  source: "paid" | "promo";
  buyerUserId?: string;
  buyerEmail?: string;
  paidAmountCents?: number;
  stripePaymentId?: string;
  grantedBy?: string;
  message: string;
  expiresAt: string;
  redeemedAt?: string;
  redeemedBy?: string;
  refundedAt?: string;
  createdAt: string;
}

export interface AdminPricingChange {
  id: number;
  changeType: string;
  targetKey: string;
  oldValue?: number;
  newValue: number;
  effectiveAt: string;
  appliedAt?: string;
  cancelledAt?: string;
  notificationSentAt?: string;
  createdBy: string;
  reason: string;
  createdAt: string;
}

export interface AdminCredit {
  id: string;
  userId: string;
  amount: number;
  consumed: number;
  reason: string;
  grantedBy: string;
  expiresAt: string;
  exhaustedAt?: string;
  createdAt: string;
}

// ----- typed endpoint helpers -----

export const adminAuth = {
  login: (body: { email: string; password: string; totpCode?: string }) =>
    adminApi<AdminLoginResp>("/admin/auth/login", { method: "POST", auth: false, body }),
  me: () => adminApi<AdminMe>("/admin/auth/me"),
  totpSetup: () =>
    adminApi<{ secret: string; uri: string }>("/admin/auth/totp/setup", { method: "POST" }),
  totpVerify: (code: string) =>
    adminApi<void>("/admin/auth/totp/verify", { method: "POST", body: { code } }),
  totpDisable: () => adminApi<void>("/admin/auth/totp", { method: "DELETE" }),
};

export const adminUsers = {
  list: () => adminApi<{ items: AdminMe[]; total: number }>("/admin/admin-users/"),
  create: (body: {
    email: string;
    password: string;
    role: AdminRole;
    mfaRequired?: boolean;
  }) => adminApi<AdminMe>("/admin/admin-users/", { method: "POST", body }),
};

export const adminAudit = {
  list: () =>
    adminApi<{ items: AdminAuditEntry[]; total: number }>("/admin/audit/"),
};

// ----- Plans -----

export interface AdminPlanUpdate {
  name?: string;
  monthlyTokens?: number;
  priceCents?: number;
  annualPriceCents?: number;
  overagePer1kCents?: number;
  rateLimitRps?: number;
  rateLimitBurst?: number;
  readRps?: number;
  readBurst?: number;
  txRps?: number;
  txBurst?: number;
  features?: Record<string, unknown>;
  isActive?: boolean;
  isGiftable?: boolean;
  sortOrder?: number;
}

export const adminPlans = {
  list: () =>
    adminApi<{ items: AdminPlan[] }>("/admin/plans"),
  update: (code: string, body: AdminPlanUpdate) =>
    adminApi<AdminPlan>(`/admin/plans/${encodeURIComponent(code)}`, { method: "PATCH", body }),
};

// ----- Request costs -----

export const adminCosts = {
  list: () =>
    adminApi<{ items: AdminRequestCost[] }>("/admin/request-costs"),
  upsert: (routeKey: string, body: { costTokens: number; description?: string }) =>
    adminApi<AdminRequestCost>(`/admin/request-costs/${encodeURIComponent(routeKey)}`, {
      method: "PATCH",
      body,
    }),
};

// ----- Coupons / gift cards -----

export type GiftCardSource = "paid" | "promo" | "";
export type GiftCardStatus = "active" | "redeemed" | "refunded" | "expired" | "";

export const adminCoupons = {
  list: (filter: { source?: GiftCardSource; status?: GiftCardStatus }) =>
    adminApi<{ items: AdminGiftCard[]; total: number }>("/admin/coupons", {
      query: { source: filter.source, status: filter.status },
    }),
  createPromo: (body: {
    planCode: string;
    durationMonths: 1 | 12;
    grantedBy: string;
    message?: string;
  }) =>
    adminApi<{ giftCard: AdminGiftCard; redeemUrl: string }>("/admin/coupons", {
      method: "POST",
      body,
    }),
  refund: (id: string) =>
    adminApi<AdminGiftCard>(`/admin/coupons/${encodeURIComponent(id)}/refund`, {
      method: "POST",
    }),
};

// ----- Pricing changes -----

export type PricingChangeStatus = "pending" | "by-target";

export const adminPricingChanges = {
  list: (filter: { status?: PricingChangeStatus; type?: string; target?: string }) =>
    adminApi<{ items: AdminPricingChange[]; total: number }>("/admin/pricing-changes", {
      query: { status: filter.status, type: filter.type, target: filter.target },
    }),
  create: (body: {
    changeType: string;
    targetKey: string;
    newValue: number;
    effectiveAt: string; // ISO
    createdBy?: string;
    reason?: string;
  }) =>
    adminApi<AdminPricingChange>("/admin/pricing-changes", {
      method: "POST",
      body,
    }),
  cancel: (id: number) =>
    adminApi<void>(`/admin/pricing-changes/${id}`, { method: "DELETE" }),
};

// ----- Users / subscriptions / credits -----

export interface AdminUser {
  id: string;
  email: string;
  name: string;
  createdAt: string;
}

export interface AdminUserSubscription {
  id: string;
  userId: string;
  planId: string;
  planCode: string;
  status: string;
  billingCycle: string;
  currentPeriodStart: string;
  currentPeriodEnd: string;
  tokensUsed: number;
  tokensLimit: number;
  overageEnabled: boolean;
  overageCardPresent: boolean;
  overageUsedTokens: number;
  overageCapTokens: number;
  readRps: number;
  readBurst: number;
  txRps: number;
  txBurst: number;
  rateLimitRps: number;
  rateLimitBurst: number;
  stripeCustomerId?: string;
  stripeSubscriptionId?: string;
  createdAt: string;
  updatedAt: string;
}

export interface AdminUserAPIKey {
  id: string;
  userId: string;
  name: string;
  prefix: string;
  scopes: string[];
  createdAt: string;
  lastUsedAt?: string;
  revokedAt?: string;
}

export const adminCustomers = {
  /** Find-or-create. Backend returns existing user when email already exists. */
  findOrCreate: (body: { email: string; name?: string }) =>
    adminApi<AdminUser>("/admin/users", { method: "POST", body }),
  listKeys: (userId: string) =>
    adminApi<{ items: AdminUserAPIKey[] }>(`/admin/users/${encodeURIComponent(userId)}/api-keys`),
  getSubscription: (userId: string) =>
    adminApi<AdminUserSubscription>(
      `/admin/users/${encodeURIComponent(userId)}/subscription`
    ),
  assignPlan: (body: { userId?: string; email?: string; planCode: string }) =>
    adminApi<AdminUserSubscription>("/admin/subscriptions", { method: "POST", body }),
  updateOverage: (
    subscriptionId: string,
    body: { enabled?: boolean; cardPresent?: boolean; capTokens?: number }
  ) =>
    adminApi<AdminUserSubscription>(
      `/admin/subscriptions/${encodeURIComponent(subscriptionId)}/overage`,
      { method: "PATCH", body }
    ),
};

export const adminCredits = {
  grant: (body: {
    userId?: string;
    email?: string;
    amount: number;
    reason: "trial" | "support" | "promo" | "hackathon" | "partner";
    grantedBy?: string;
    expiresAt?: string;
  }) => adminApi<AdminCredit>("/admin/credits", { method: "POST", body }),
};
