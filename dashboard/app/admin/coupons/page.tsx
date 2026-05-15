"use client";

import { useEffect, useState } from "react";
import { Plus, Copy, Check } from "lucide-react";
import { PageHeader } from "@/components/admin/PageHeader";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import {
  adminCoupons,
  adminPlans,
  type AdminGiftCard,
  type AdminPlan,
  type GiftCardSource,
  type GiftCardStatus,
} from "@/lib/admin-api";
import { errorMessage } from "@/lib/format";
import { copyToClipboard } from "@/lib/clipboard";

export default function AdminCouponsPage() {
  const [items, setItems] = useState<AdminGiftCard[]>([]);
  const [plans, setPlans] = useState<AdminPlan[]>([]);
  const [filterSource, setFilterSource] = useState<GiftCardSource>("");
  const [filterStatus, setFilterStatus] = useState<GiftCardStatus>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [newRedeem, setNewRedeem] = useState<string | null>(null);
  const [toRefund, setToRefund] = useState<AdminGiftCard | null>(null);

  // form state
  const [planCode, setPlanCode] = useState("");
  const [duration, setDuration] = useState<1 | 12>(1);
  const [grantedBy, setGrantedBy] = useState("admin");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Plans are immutable for the duration of this view — fetch them once and
  // never refetch when the user toggles the gift-card filters.
  useEffect(() => {
    let cancelled = false;
    adminPlans
      .list()
      .then((p) => {
        if (cancelled) return;
        const giftable = p.items.filter((x) => x.isGiftable);
        setPlans(giftable);
        if (giftable.length > 0) setPlanCode(giftable[0].code);
      })
      .catch((err) => {
        if (!cancelled) setError(errorMessage(err, "Failed to load plans"));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Gift cards depend on the active filter — refetch whenever it changes.
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    adminCoupons
      .list({ source: filterSource, status: filterStatus })
      .then((c) => {
        if (!cancelled) setItems(c.items);
      })
      .catch((err) => {
        if (!cancelled) setError(errorMessage(err, "Failed to load coupons"));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [filterSource, filterStatus]);

  async function reloadCoupons() {
    setLoading(true);
    try {
      const c = await adminCoupons.list({
        source: filterSource,
        status: filterStatus,
      });
      setItems(c.items);
    } catch (err) {
      setError(errorMessage(err, "Failed to load coupons"));
    } finally {
      setLoading(false);
    }
  }

  async function onCreate(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    setBusy(true);
    try {
      const data = await adminCoupons.createPromo({
        planCode,
        durationMonths: duration,
        grantedBy: grantedBy.trim() || "admin",
        message: message.trim(),
      });
      setNewRedeem(data.redeemUrl);
      setShowForm(false);
      setMessage("");
      await reloadCoupons();
    } catch (err) {
      setFormError(errorMessage(err, "Create failed"));
    } finally {
      setBusy(false);
    }
  }

  async function confirmRefund() {
    if (!toRefund) return;
    try {
      await adminCoupons.refund(toRefund.id);
      setToRefund(null);
      await reloadCoupons();
    } catch (err) {
      setError(errorMessage(err, "Refund failed"));
      throw err;
    }
  }

  async function copyLink(text: string) {
    const ok = await copyToClipboard(text);
    if (!ok) {
      setError("Clipboard blocked — copy manually.");
      return;
    }
    setCopied(text);
    setTimeout(() => setCopied(null), 2000);
  }

  return (
    <main className="flex-1 px-6 lg:px-10 py-8">
      <PageHeader
        title="Coupons & gift cards"
        description="Create promotional coupons (free, by Andromeda) and review paid gift cards. Promo cards use the same redeem URL flow as paid ones."
        actions={
          <button
            type="button"
            className="btn-primary"
            onClick={() => setShowForm((s) => !s)}
          >
            <Plus size={14} strokeWidth={1.8} />
            {showForm ? "Cancel" : "New coupon"}
          </button>
        }
      />

      {newRedeem && (
        <div className="card p-4 mb-6 border-emerald-500/30 bg-emerald-500/[0.04]">
          <div className="text-xs text-emerald-300 mb-2">Coupon ready — share this link with the recipient:</div>
          <div className="flex items-stretch gap-2">
            <input readOnly value={newRedeem} className="input-base flex-1 font-mono text-xs" />
            <button
              type="button"
              onClick={() => copyLink(newRedeem)}
              className="btn-secondary text-xs"
            >
              {copied === newRedeem ? <><Check size={13} /> Copied</> : <><Copy size={13} /> Copy</>}
            </button>
          </div>
        </div>
      )}

      {showForm && (
        <form onSubmit={onCreate} className="card p-5 mb-6 grid grid-cols-1 md:grid-cols-2 gap-4 max-w-3xl">
          <div>
            <label className="label-base mb-1.5 block">Plan</label>
            <select
              required
              value={planCode}
              onChange={(e) => setPlanCode(e.target.value)}
              className="input-base"
            >
              <option value="">Select plan…</option>
              {plans.map((p) => (
                <option key={p.code} value={p.code}>
                  {p.name} ({p.code})
                </option>
              ))}
            </select>
            {plans.length === 0 && (
              <p className="text-[11px] text-amber-300 mt-1.5">
                No giftable plans — set <code>isGiftable</code> on a plan first.
              </p>
            )}
          </div>
          <div>
            <label className="label-base mb-1.5 block">Duration</label>
            <select
              value={duration}
              onChange={(e) => setDuration(Number(e.target.value) as 1 | 12)}
              className="input-base"
            >
              <option value={1}>1 month</option>
              <option value={12}>12 months (annual)</option>
            </select>
          </div>
          <div>
            <label className="label-base mb-1.5 block">Granted by</label>
            <input
              type="text"
              value={grantedBy}
              onChange={(e) => setGrantedBy(e.target.value)}
              className="input-base"
              placeholder="hackathon-organizer / kazuto"
            />
          </div>
          <div>
            <label className="label-base mb-1.5 block">Message (optional)</label>
            <input
              type="text"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              className="input-base"
              placeholder="Hackathon 2026 prize"
            />
          </div>
          <div className="md:col-span-2 flex items-center gap-3">
            <button type="submit" disabled={busy || !planCode} className="btn-primary">
              {busy ? "Creating…" : "Create coupon"}
            </button>
            {formError && <span className="text-xs text-ember-soft">{formError}</span>}
          </div>
        </form>
      )}

      <div className="mb-4 flex items-center gap-3 flex-wrap">
        <FilterSelect
          label="Source"
          value={filterSource}
          options={[
            { value: "", label: "All" },
            { value: "paid", label: "Paid" },
            { value: "promo", label: "Promo" },
          ]}
          onChange={(v) => setFilterSource(v as GiftCardSource)}
        />
        <FilterSelect
          label="Status"
          value={filterStatus}
          options={[
            { value: "", label: "All" },
            { value: "active", label: "Active" },
            { value: "redeemed", label: "Redeemed" },
            { value: "refunded", label: "Refunded" },
            { value: "expired", label: "Expired" },
          ]}
          onChange={(v) => setFilterStatus(v as GiftCardStatus)}
        />
      </div>

      {loading && <div className="text-sm text-slate-400">Loading…</div>}
      {error && <div className="text-xs text-ember-soft">{error}</div>}

      {!loading && !error && (
        <div className="card overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead className="text-[11px] uppercase tracking-wider text-slate-400 border-b border-white/[0.06]">
              <tr>
                <th className="px-4 py-3 text-left font-medium">Plan</th>
                <th className="px-4 py-3 text-left font-medium">Duration</th>
                <th className="px-4 py-3 text-left font-medium">Source</th>
                <th className="px-4 py-3 text-left font-medium">State</th>
                <th className="px-4 py-3 text-left font-medium">Created</th>
                <th className="px-4 py-3 text-right font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {items.map((g) => {
                const state = giftState(g);
                return (
                  <tr key={g.id} className="border-b border-white/[0.04] last:border-0">
                    <td className="px-4 py-3 text-xs">
                      <code className="bg-graphite-700/60 px-1.5 py-0.5 rounded">{g.planCode}</code>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-300">{g.durationMonths}m</td>
                    <td className="px-4 py-3 text-xs text-slate-300">{g.source}</td>
                    <td className="px-4 py-3 text-xs">
                      <span className={stateClass(state)}>{state}</span>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400 font-mono">
                      {new Date(g.createdAt).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {g.source === "paid" && state === "active" && (
                        <button
                          type="button"
                          onClick={() => setToRefund(g)}
                          className="btn-secondary text-xs"
                        >
                          Refund
                        </button>
                      )}
                      {state === "active" && (
                        <button
                          type="button"
                          onClick={() => copyLink(redeemPathFor(g.redeemToken))}
                          className="btn-secondary text-xs ml-2"
                        >
                          {copied === redeemPathFor(g.redeemToken) ? "Copied" : "Copy link"}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
              {items.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-xs text-slate-400">
                    No coupons match the filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      <ConfirmDialog
        open={toRefund !== null}
        title="Refund gift card"
        description="Refund this paid gift card? Only allowed within 7 days of purchase and only when the card has not been redeemed."
        confirmLabel="Refund"
        busyLabel="Refunding…"
        danger
        onConfirm={confirmRefund}
        onCancel={() => setToRefund(null)}
      />
    </main>
  );
}

function giftState(g: AdminGiftCard): "active" | "redeemed" | "refunded" | "expired" {
  if (g.redeemedAt) return "redeemed";
  if (g.refundedAt) return "refunded";
  if (new Date(g.expiresAt).getTime() <= Date.now()) return "expired";
  return "active";
}

function stateClass(state: string): string {
  switch (state) {
    case "active":
      return "text-emerald-300";
    case "redeemed":
      return "text-slate-300";
    case "refunded":
      return "text-amber-300";
    case "expired":
      return "text-slate-500";
    default:
      return "text-slate-400";
  }
}

function redeemPathFor(token: string): string {
  return `/redeem?token=${encodeURIComponent(token)}`;
}

interface FilterSelectProps {
  label: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
}

function FilterSelect({ label, value, options, onChange }: FilterSelectProps) {
  return (
    <label className="flex items-center gap-2 text-xs text-slate-300">
      <span className="text-slate-400">{label}:</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="input-base text-xs h-8 py-0"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}
