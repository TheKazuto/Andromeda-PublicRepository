"use client";

import { useState } from "react";
import { Search } from "lucide-react";
import { PageHeader } from "@/components/admin/PageHeader";
import {
  adminCustomers,
  adminCredits,
  adminPlans,
  AdminAPIError,
  type AdminUser,
  type AdminUserSubscription,
  type AdminUserAPIKey,
  type AdminPlan,
} from "@/lib/admin-api";
import { errorMessage } from "@/lib/format";
import { copyToClipboard } from "@/lib/clipboard";

export default function AdminCustomersPage() {
  const [email, setEmail] = useState("");
  const [user, setUser] = useState<AdminUser | null>(null);
  const [sub, setSub] = useState<AdminUserSubscription | null>(null);
  const [keys, setKeys] = useState<AdminUserAPIKey[]>([]);
  const [plans, setPlans] = useState<AdminPlan[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  async function lookup(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setMessage(null);
    setLoading(true);
    setUser(null);
    setSub(null);
    setKeys([]);
    try {
      const u = await adminCustomers.findOrCreate({ email: email.trim().toLowerCase() });
      setUser(u);
      // load subscription + keys + plans in parallel
      const [subRes, keysRes, plansRes] = await Promise.allSettled([
        adminCustomers.getSubscription(u.id),
        adminCustomers.listKeys(u.id),
        adminPlans.list(),
      ]);
      if (subRes.status === "fulfilled") setSub(subRes.value);
      else if (subRes.reason instanceof AdminAPIError && subRes.reason.status !== 404) {
        setError(subRes.reason.message);
      }
      if (keysRes.status === "fulfilled") setKeys(keysRes.value.items);
      if (plansRes.status === "fulfilled") setPlans(plansRes.value.items);
    } catch (err) {
      setError(errorMessage(err, "Lookup failed"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="flex-1 px-6 lg:px-10 py-8">
      <PageHeader
        title="Customers"
        description="Look up by email, view subscription and API keys, grant credits, change plan, toggle overage."
      />

      <form onSubmit={lookup} className="card p-4 mb-6 max-w-2xl flex items-stretch gap-2">
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="input-base flex-1"
          placeholder="alice@example.com"
        />
        <button type="submit" disabled={loading} className="btn-primary">
          <Search size={14} strokeWidth={1.8} />
          {loading ? "Searching…" : "Look up"}
        </button>
      </form>

      {error && (
        <div className="mb-4 text-xs text-ember-soft bg-ember/10 border border-ember/20 rounded-lg px-3 py-2">
          {error}
        </div>
      )}
      {message && (
        <div className="mb-4 text-xs text-emerald-300 bg-emerald-500/10 border border-emerald-500/20 rounded-lg px-3 py-2">
          {message}
        </div>
      )}

      {user && (
        <>
          <UserSummary user={user} sub={sub} />
          <SubscriptionPanel
            user={user}
            sub={sub}
            plans={plans}
            onChange={async () => {
              const s = await adminCustomers.getSubscription(user.id).catch(() => null);
              setSub(s);
              setMessage("Subscription updated.");
            }}
          />
          <CreditsPanel
            user={user}
            onGranted={() => setMessage("Credit granted.")}
          />
          <KeysPanel
            keys={keys}
            user={user}
            onMinted={async () => {
              const list = await adminCustomers.listKeys(user.id).catch(() => null);
              if (list) setKeys(list.items);
              setMessage("API key minted.");
            }}
          />
        </>
      )}
    </main>
  );
}

function UserSummary({
  user,
  sub,
}: {
  user: AdminUser;
  sub: AdminUserSubscription | null;
}) {
  return (
    <div className="card p-5 mb-6 grid grid-cols-1 md:grid-cols-3 gap-4">
      <div>
        <div className="text-[11px] uppercase tracking-wider text-slate-400 mb-1">User ID</div>
        <code className="text-xs text-snow font-mono">{user.id}</code>
      </div>
      <div>
        <div className="text-[11px] uppercase tracking-wider text-slate-400 mb-1">Email</div>
        <div className="text-sm text-snow">{user.email}</div>
      </div>
      <div>
        <div className="text-[11px] uppercase tracking-wider text-slate-400 mb-1">Plan</div>
        {sub ? (
          <div className="text-sm text-snow">
            {sub.planCode}{" "}
            <span className="text-xs text-slate-400">
              ({sub.tokensUsed.toLocaleString()} / {sub.tokensLimit.toLocaleString()} tokens)
            </span>
          </div>
        ) : (
          <div className="text-sm text-slate-400">no active subscription</div>
        )}
      </div>
    </div>
  );
}

function SubscriptionPanel({
  user,
  sub,
  plans,
  onChange,
}: {
  user: AdminUser;
  sub: AdminUserSubscription | null;
  plans: AdminPlan[];
  onChange: () => Promise<void>;
}) {
  const [planCode, setPlanCode] = useState(sub?.planCode || "");
  const [busy, setBusy] = useState(false);
  const [overageEnabled, setOverageEnabled] = useState(sub?.overageEnabled || false);
  const [cardPresent, setCardPresent] = useState(sub?.overageCardPresent || false);
  const [cap, setCap] = useState(sub?.overageCapTokens || 0);
  const [err, setErr] = useState<string | null>(null);

  async function assign() {
    if (!planCode) return;
    setBusy(true);
    setErr(null);
    try {
      await adminCustomers.assignPlan({ userId: user.id, planCode });
      await onChange();
    } catch (e) {
      setErr(errorMessage(e, "Assign failed"));
    } finally {
      setBusy(false);
    }
  }

  async function saveOverage() {
    if (!sub) return;
    if (!Number.isFinite(cap) || cap < 0) {
      setErr("Overage cap must be a non-negative number.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await adminCustomers.updateOverage(sub.id, {
        enabled: overageEnabled,
        cardPresent,
        capTokens: cap,
      });
      await onChange();
    } catch (e) {
      setErr(errorMessage(e, "Save failed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card p-5 mb-6">
      <h3 className="text-sm font-semibold text-snow mb-4">Subscription</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <label className="label-base mb-1.5 block">Plan</label>
          <select
            value={planCode}
            onChange={(e) => setPlanCode(e.target.value)}
            className="input-base"
          >
            <option value="">Select plan…</option>
            {plans
              .filter((p) => p.isActive)
              .map((p) => (
                <option key={p.code} value={p.code}>
                  {p.name}
                </option>
              ))}
          </select>
          <button type="button" disabled={busy || !planCode} onClick={assign} className="btn-secondary mt-2 text-xs">
            Assign / replace
          </button>
        </div>

        {sub && (
          <>
            <div>
              <label className="flex items-center gap-2 text-sm text-slate-300 mb-2">
                <input
                  type="checkbox"
                  checked={overageEnabled}
                  onChange={(e) => setOverageEnabled(e.target.checked)}
                  className="accent-ember"
                />
                Overage enabled
              </label>
              <label className="flex items-center gap-2 text-sm text-slate-300">
                <input
                  type="checkbox"
                  checked={cardPresent}
                  onChange={(e) => setCardPresent(e.target.checked)}
                  className="accent-ember"
                />
                Card on file
              </label>
            </div>
            <div>
              <label className="label-base mb-1.5 block">Overage cap (tokens)</label>
              <input
                type="number"
                min={0}
                value={cap}
                onChange={(e) => {
                  const n = Number(e.target.value);
                  if (e.target.value !== "" && !Number.isFinite(n)) return;
                  setCap(n);
                }}
                className="input-base"
              />
              <button type="button" disabled={busy} onClick={saveOverage} className="btn-secondary mt-2 text-xs">
                Save overage
              </button>
            </div>
          </>
        )}
      </div>
      {err && <div className="mt-3 text-xs text-ember-soft">{err}</div>}
    </section>
  );
}

function CreditsPanel({
  user,
  onGranted,
}: {
  user: AdminUser;
  onGranted: () => void;
}) {
  const [amount, setAmount] = useState(1000);
  const [reason, setReason] = useState<"trial" | "support" | "promo" | "hackathon" | "partner">("support");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function grant() {
    setError(null);
    if (!Number.isFinite(amount) || amount <= 0) {
      setError("Amount must be a positive number.");
      return;
    }
    setBusy(true);
    try {
      await adminCredits.grant({
        userId: user.id,
        amount,
        reason,
      });
      onGranted();
    } catch (err) {
      setError(errorMessage(err, "Grant failed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card p-5 mb-6">
      <h3 className="text-sm font-semibold text-snow mb-1">Grant credit</h3>
      <p className="text-xs text-slate-400 mb-4">Free tokens for this user. Expires in 30 days.</p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-xl">
        <div>
          <label className="label-base mb-1.5 block">Amount</label>
          <input
            type="number"
            min={1}
            value={amount}
            onChange={(e) => {
              const n = Number(e.target.value);
              if (e.target.value !== "" && !Number.isFinite(n)) return;
              setAmount(n);
            }}
            className="input-base"
          />
        </div>
        <div>
          <label className="label-base mb-1.5 block">Reason</label>
          <select
            value={reason}
            onChange={(e) => setReason(e.target.value as typeof reason)}
            className="input-base"
          >
            <option value="support">support</option>
            <option value="trial">trial</option>
            <option value="promo">promo</option>
            <option value="hackathon">hackathon</option>
            <option value="partner">partner</option>
          </select>
        </div>
        <div className="flex items-end">
          <button type="button" disabled={busy || amount <= 0} onClick={grant} className="btn-primary w-full">
            {busy ? "Granting…" : "Grant"}
          </button>
        </div>
      </div>
      {error && <div className="mt-2 text-xs text-ember-soft">{error}</div>}
    </section>
  );
}

function KeysPanel({
  keys,
  user,
  onMinted,
}: {
  keys: AdminUserAPIKey[];
  user: AdminUser;
  onMinted: () => Promise<void>;
}) {
  const [name, setName] = useState("");
  const [scopeRead, setScopeRead] = useState(true);
  const [scopeWrite, setScopeWrite] = useState(true);
  const [scopeAdmin, setScopeAdmin] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<string | null>(null);

  async function onMint(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setRevealed(null);
    const scopes: Array<"read" | "write" | "admin"> = [];
    if (scopeRead) scopes.push("read");
    if (scopeWrite) scopes.push("write");
    if (scopeAdmin) scopes.push("admin");
    if (scopes.length === 0) {
      setErr("Pick at least one scope.");
      return;
    }
    setBusy(true);
    try {
      const resp = await adminCustomers.mintKey({
        userId: user.id,
        name: name.trim() || "Admin-minted key",
        scopes,
      });
      setRevealed(resp.key);
      setName("");
      await onMinted();
    } catch (e) {
      setErr(errorMessage(e, "Mint failed"));
    } finally {
      setBusy(false);
    }
  }

  async function copyKey() {
    if (!revealed) return;
    const ok = await copyToClipboard(revealed);
    if (!ok) {
      setErr("Clipboard blocked — copy the key manually.");
    }
  }

  return (
    <section className="card p-5">
      <h3 className="text-sm font-semibold text-snow mb-4">API keys</h3>
      <form onSubmit={onMint} className="mb-5 flex flex-wrap items-end gap-3">
        <div className="flex-1 min-w-[200px]">
          <label className="block text-[11px] uppercase tracking-wider text-slate-400 mb-1">
            Name
          </label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Smoke E2E key"
            className="input-base w-full"
          />
        </div>
        <div>
          <label className="block text-[11px] uppercase tracking-wider text-slate-400 mb-1">
            Scopes
          </label>
          <div className="flex items-center gap-3 text-xs text-snow">
            <label className="inline-flex items-center gap-1">
              <input
                type="checkbox"
                checked={scopeRead}
                onChange={(e) => setScopeRead(e.target.checked)}
              />
              read
            </label>
            <label className="inline-flex items-center gap-1">
              <input
                type="checkbox"
                checked={scopeWrite}
                onChange={(e) => setScopeWrite(e.target.checked)}
              />
              write
            </label>
            <label className="inline-flex items-center gap-1">
              <input
                type="checkbox"
                checked={scopeAdmin}
                onChange={(e) => setScopeAdmin(e.target.checked)}
              />
              admin
            </label>
          </div>
        </div>
        <button type="submit" disabled={busy} className="btn-primary">
          {busy ? "Minting…" : "Mint key"}
        </button>
      </form>
      {err && <div className="mb-3 text-xs text-ember-soft">{err}</div>}
      {revealed && (
        <div className="mb-4 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2">
          <div className="text-[11px] uppercase tracking-wider text-emerald-200 mb-1">
            Key — shown once
          </div>
          <code className="block text-xs font-mono text-emerald-100 break-all">
            {revealed}
          </code>
          <button
            type="button"
            onClick={copyKey}
            className="mt-2 text-[11px] text-emerald-300 hover:text-emerald-100"
          >
            Copy to clipboard
          </button>
        </div>
      )}
      <table className="min-w-full text-sm">
        <thead className="text-[11px] uppercase tracking-wider text-slate-400 border-b border-white/[0.06]">
          <tr>
            <th className="px-2 py-2 text-left font-medium">Name</th>
            <th className="px-2 py-2 text-left font-medium">Prefix</th>
            <th className="px-2 py-2 text-left font-medium">Scopes</th>
            <th className="px-2 py-2 text-left font-medium">Last used</th>
            <th className="px-2 py-2 text-left font-medium">State</th>
          </tr>
        </thead>
        <tbody>
          {keys.map((k) => (
            <tr key={k.id} className="border-b border-white/[0.04] last:border-0">
              <td className="px-2 py-2 text-xs text-snow">{k.name}</td>
              <td className="px-2 py-2 text-xs text-slate-300 font-mono">{k.prefix}</td>
              <td className="px-2 py-2 text-xs text-slate-400">{k.scopes.join(", ")}</td>
              <td className="px-2 py-2 text-xs text-slate-400 font-mono">
                {k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleString() : "—"}
              </td>
              <td className="px-2 py-2 text-xs">
                {k.revokedAt ? (
                  <span className="text-ember-soft">revoked</span>
                ) : (
                  <span className="text-emerald-300">active</span>
                )}
              </td>
            </tr>
          ))}
          {keys.length === 0 && (
            <tr>
              <td colSpan={5} className="px-2 py-6 text-center text-xs text-slate-400">
                No API keys.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </section>
  );
}
