"use client";

import { useEffect, useMemo, useState } from "react";
import { Plus, X } from "lucide-react";
import { PageHeader } from "@/components/admin/PageHeader";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import {
  adminPricingChanges,
  type AdminPricingChange,
} from "@/lib/admin-api";
import { errorMessage } from "@/lib/format";

const CHANGE_TYPES = [
  { value: "route_cost", label: "Route cost (request_costs.cost_tokens)" },
  { value: "plan_price", label: "Plan price (plans.price_cents)" },
  { value: "plan_annual_price", label: "Plan annual price" },
  { value: "plan_tokens", label: "Plan monthly tokens" },
  { value: "plan_read_rps", label: "Plan read RPS" },
  { value: "plan_tx_rps", label: "Plan tx RPS" },
  { value: "plan_overage", label: "Plan overage rate" },
];

// The backend enforces a 30-day notice window; we mirror it in the UI so the
// admin can't even pick a sooner date.
const NOTICE_DAYS = 30;

export default function AdminPricingChangesPage() {
  const [items, setItems] = useState<AdminPricingChange[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [toCancel, setToCancel] = useState<AdminPricingChange | null>(null);

  const [changeType, setChangeType] = useState<string>(CHANGE_TYPES[0].value);
  const [targetKey, setTargetKey] = useState("");
  const [newValue, setNewValue] = useState<number>(0);
  const [effectiveAt, setEffectiveAt] = useState<string>(defaultEffectiveAt());
  const [reason, setReason] = useState("");
  const [createdBy, setCreatedBy] = useState("admin");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // `min` for the date input — recomputed on mount so the form is always
  // comparing against the current clock, not a build-time constant.
  const minEffective = useMemo(() => minEffectiveAt(), []);

  async function load() {
    setLoading(true);
    try {
      const data = await adminPricingChanges.list({ status: "pending" });
      setItems(data.items);
    } catch (err) {
      setError(errorMessage(err, "Load failed"));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const data = await adminPricingChanges.list({ status: "pending" });
        if (!cancelled) setItems(data.items);
      } catch (err) {
        if (!cancelled) setError(errorMessage(err, "Load failed"));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function onCreate(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    if (!Number.isFinite(newValue) || newValue < 0) {
      setFormError("New value must be a non-negative number.");
      return;
    }
    const effectiveDate = new Date(effectiveAt);
    if (Number.isNaN(effectiveDate.getTime())) {
      setFormError("Pick a valid effective date.");
      return;
    }
    const earliest = new Date(Date.now() + NOTICE_DAYS * 24 * 60 * 60 * 1000);
    if (effectiveDate.getTime() < earliest.getTime()) {
      setFormError(`Effective date must be at least ${NOTICE_DAYS} days from now.`);
      return;
    }
    setBusy(true);
    try {
      await adminPricingChanges.create({
        changeType,
        targetKey: targetKey.trim(),
        newValue,
        effectiveAt: effectiveDate.toISOString(),
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
      setFormError(errorMessage(err, "Create failed"));
    } finally {
      setBusy(false);
    }
  }

  async function confirmCancel() {
    if (!toCancel) return;
    try {
      await adminPricingChanges.cancel(toCancel.id);
      setToCancel(null);
      await load();
    } catch (err) {
      setError(errorMessage(err, "Cancel failed"));
      throw err;
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
              min={0}
              value={newValue}
              onChange={(e) => {
                const n = Number(e.target.value);
                if (e.target.value !== "" && !Number.isFinite(n)) return;
                setNewValue(n);
              }}
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
              min={minEffective}
              value={effectiveAt}
              onChange={(e) => setEffectiveAt(e.target.value)}
              className="input-base"
            />
            <p className="text-[11px] text-slate-400 mt-1">
              Must be ≥{NOTICE_DAYS} days from now.
            </p>
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
                      onClick={() => setToCancel(c)}
                      className="btn-secondary text-xs"
                    >
                      <X size={12} strokeWidth={2} />
                      Cancel
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

      <ConfirmDialog
        open={toCancel !== null}
        title="Cancel scheduled change"
        description={
          toCancel ? (
            <>
              Cancel the scheduled change to{" "}
              <span className="font-mono text-snow">{toCancel.targetKey}</span>?
              The applier worker will skip this entry and the live value stays unchanged.
              This action cannot be undone.
            </>
          ) : null
        }
        confirmLabel="Cancel change"
        busyLabel="Cancelling…"
        danger
        onConfirm={confirmCancel}
        onCancel={() => setToCancel(null)}
      />
    </main>
  );
}

function defaultEffectiveAt(): string {
  // 31 days from now to stay above the 30-day floor.
  const d = new Date(Date.now() + (NOTICE_DAYS + 1) * 24 * 60 * 60 * 1000);
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); // local timezone
  return d.toISOString().slice(0, 16);
}

function minEffectiveAt(): string {
  // The exact 30-day floor for the `min` attribute. Browsers reject any
  // earlier pick before the form even submits.
  const d = new Date(Date.now() + NOTICE_DAYS * 24 * 60 * 60 * 1000);
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
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
