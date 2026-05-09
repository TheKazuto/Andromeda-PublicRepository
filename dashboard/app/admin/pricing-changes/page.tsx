"use client";

import { useEffect, useState } from "react";
import { Plus, X } from "lucide-react";
import { PageHeader } from "@/components/admin/PageHeader";
import {
  adminPricingChanges,
  type AdminPricingChange,
} from "@/lib/admin-api";

const CHANGE_TYPES = [
  { value: "route_cost", label: "Route cost (request_costs.cost_tokens)" },
  { value: "plan_price", label: "Plan price (plans.price_cents)" },
  { value: "plan_annual_price", label: "Plan annual price" },
  { value: "plan_tokens", label: "Plan monthly tokens" },
  { value: "plan_read_rps", label: "Plan read RPS" },
  { value: "plan_tx_rps", label: "Plan tx RPS" },
  { value: "plan_overage", label: "Plan overage rate" },
];

export default function AdminPricingChangesPage() {
  const [items, setItems] = useState<AdminPricingChange[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);

  const [changeType, setChangeType] = useState<string>(CHANGE_TYPES[0].value);
  const [targetKey, setTargetKey] = useState("");
  const [newValue, setNewValue] = useState<number>(0);
  const [effectiveAt, setEffectiveAt] = useState<string>(defaultEffectiveAt());
  const [reason, setReason] = useState("");
  const [createdBy, setCreatedBy] = useState("admin");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    try {
      const data = await adminPricingChanges.list({ status: "pending" });
      setItems(data.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Load failed");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function onCreate(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    setBusy(true);
    try {
      await adminPricingChanges.create({
        changeType,
        targetKey: targetKey.trim(),
        newValue,
        effectiveAt: new Date(effectiveAt).toISOString(),
        createdBy: createdBy.trim() || "admin",
        reason: reason.trim(),
      });
      setShowForm(false);
      setTargetKey("");
      setNewValue(0);
      setReason("");
      setEffectiveAt(defaultEffectiveAt());
      await load();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Create failed");
    } finally {
      setBusy(false);
    }
  }

  async function cancel(id: number) {
    if (!confirm("Cancel this scheduled change? Cannot be undone.")) return;
    setBusyId(id);
    try {
      await adminPricingChanges.cancel(id);
      await load();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Cancel failed");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <main className="flex-1 px-6 lg:px-10 py-8">
      <PageHeader
        title="Pricing changes"
        description="Schedule grandfathered changes with ≥30 days notice. The applier worker copies new_value into the live tables on effective_at."
        actions={
          <button
            type="button"
            className="btn-primary"
            onClick={() => setShowForm((s) => !s)}
          >
            <Plus size={14} strokeWidth={1.8} />
            {showForm ? "Cancel" : "Schedule change"}
          </button>
        }
      />

      {showForm && (
        <form onSubmit={onCreate} className="card p-5 mb-6 grid grid-cols-1 md:grid-cols-2 gap-4 max-w-3xl">
          <div className="md:col-span-2">
            <label className="label-base mb-1.5 block">Change type</label>
            <select
              value={changeType}
              onChange={(e) => setChangeType(e.target.value)}
              className="input-base"
            >
              {CHANGE_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label-base mb-1.5 block">Target key</label>
            <input
              type="text"
              required
              value={targetKey}
              onChange={(e) => setTargetKey(e.target.value)}
              className="input-base font-mono"
              placeholder={
                changeType === "route_cost"
                  ? "ika.sign.submit"
                  : "pro / business / premium / enterprise"
              }
            />
          </div>
          <div>
            <label className="label-base mb-1.5 block">New value</label>
            <input
              type="number"
              required
              value={newValue}
              onChange={(e) => setNewValue(Number(e.target.value))}
              className="input-base"
            />
            <p className="text-[11px] text-slate-400 mt-1">
              {hintFor(changeType)}
            </p>
          </div>
          <div>
            <label className="label-base mb-1.5 block">Effective at</label>
            <input
              type="datetime-local"
              required
              value={effectiveAt}
              onChange={(e) => setEffectiveAt(e.target.value)}
              className="input-base"
            />
            <p className="text-[11px] text-slate-400 mt-1">Must be ≥30 days from now.</p>
          </div>
          <div>
            <label className="label-base mb-1.5 block">Created by</label>
            <input
              type="text"
              value={createdBy}
              onChange={(e) => setCreatedBy(e.target.value)}
              className="input-base"
            />
          </div>
          <div className="md:col-span-2">
            <label className="label-base mb-1.5 block">Reason (visible in audit log)</label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="input-base h-20"
              placeholder="Engine rebalance — upstream cost increased per upstream metrics."
            />
          </div>
          <div className="md:col-span-2 flex items-center gap-3">
            <button type="submit" disabled={busy || !targetKey} className="btn-primary">
              {busy ? "Scheduling…" : "Schedule change"}
            </button>
            {formError && <span className="text-xs text-ember-soft">{formError}</span>}
          </div>
        </form>
      )}

      {loading && <div className="text-sm text-slate-400">Loading…</div>}
      {error && <div className="text-xs text-ember-soft">{error}</div>}

      {!loading && !error && (
        <div className="card overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead className="text-[11px] uppercase tracking-wider text-slate-400 border-b border-white/[0.06]">
              <tr>
                <th className="px-4 py-3 text-left font-medium">Type</th>
                <th className="px-4 py-3 text-left font-medium">Target</th>
                <th className="px-4 py-3 text-right font-medium">Old → New</th>
                <th className="px-4 py-3 text-left font-medium">Effective at</th>
                <th className="px-4 py-3 text-left font-medium">By</th>
                <th className="px-4 py-3 text-right font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {items.map((c) => (
                <tr key={c.id} className="border-b border-white/[0.04] last:border-0">
                  <td className="px-4 py-3 text-xs">
                    <code className="bg-graphite-700/60 px-1.5 py-0.5 rounded">{c.changeType}</code>
                  </td>
                  <td className="px-4 py-3 text-xs text-snow font-mono">{c.targetKey}</td>
                  <td className="px-4 py-3 text-xs text-right font-mono">
                    {c.oldValue ?? "—"} → <span className="text-ember">{c.newValue}</span>
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-300 font-mono">
                    {new Date(c.effectiveAt).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-400">{c.createdBy}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      disabled={busyId === c.id}
                      onClick={() => cancel(c.id)}
                      className="btn-secondary text-xs"
                    >
                      <X size={12} strokeWidth={2} />
                      {busyId === c.id ? "…" : "Cancel"}
                    </button>
                  </td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-xs text-slate-400">
                    No pending changes.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}

function defaultEffectiveAt(): string {
  // 31 days from now to stay above the 30-day floor.
  const d = new Date(Date.now() + 31 * 24 * 60 * 60 * 1000);
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); // local timezone
  return d.toISOString().slice(0, 16);
}

function hintFor(changeType: string): string {
  switch (changeType) {
    case "route_cost":
      return "tokens (e.g. 60)";
    case "plan_price":
    case "plan_annual_price":
    case "plan_overage":
      return "cents (e.g. 4900 for $49.00)";
    case "plan_tokens":
      return "tokens (e.g. 15000)";
    case "plan_read_rps":
    case "plan_tx_rps":
      return "requests per second";
    default:
      return "";
  }
}
