"use client";

import { useEffect, useState } from "react";
import { Save } from "lucide-react";
import { PageHeader } from "@/components/admin/PageHeader";
import {
  adminPlans,
  type AdminPlan,
  type AdminPlanUpdate,
} from "@/lib/admin-api";

export default function AdminPlansPage() {
  const [plans, setPlans] = useState<AdminPlan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    try {
      const data = await adminPlans.list();
      setPlans(data.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Load failed");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <main className="flex-1 px-6 lg:px-10 py-8">
      <PageHeader
        title="Plans"
        description="Token allowance, RPS buckets, pricing and gift eligibility per plan. Direct edits go live immediately — for grandfathered changes, use the pricing scheduler."
      />

      {loading && <div className="text-sm text-slate-400">Loading…</div>}
      {error && <div className="text-xs text-ember-soft">{error}</div>}

      <div className="space-y-6">
        {plans.map((plan) => (
          <PlanCard key={plan.id} plan={plan} onSaved={load} />
        ))}
      </div>
    </main>
  );
}

interface PlanCardProps {
  plan: AdminPlan;
  onSaved: () => void;
}

function PlanCard({ plan, onSaved }: PlanCardProps) {
  const [draft, setDraft] = useState<AdminPlanUpdate>({});
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: "ok" | "error"; text: string } | null>(null);

  function set<K extends keyof AdminPlanUpdate>(key: K, value: AdminPlanUpdate[K]) {
    setDraft((d) => ({ ...d, [key]: value }));
  }

  async function save() {
    if (Object.keys(draft).length === 0) return;
    setBusy(true);
    setMessage(null);
    try {
      await adminPlans.update(plan.code, draft);
      setMessage({ tone: "ok", text: "Saved." });
      setDraft({});
      onSaved();
    } catch (err) {
      setMessage({
        tone: "error",
        text: err instanceof Error ? err.message : "Save failed",
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card p-5">
      <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <span className="text-lg font-semibold text-snow">{plan.name}</span>
          <code className="text-xs text-slate-400 bg-graphite-700/60 px-2 py-0.5 rounded font-mono">
            {plan.code}
          </code>
          {!plan.isActive && (
            <span className="text-xs text-amber-300">inactive</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button type="button" className="btn-primary" disabled={busy} onClick={save}>
            <Save size={14} strokeWidth={1.8} />
            {busy ? "Saving…" : "Save changes"}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <NumberField
          label="Monthly tokens"
          base={plan.monthlyTokens}
          onChange={(v) => set("monthlyTokens", v)}
        />
        <NumberField
          label="Price (cents)"
          base={plan.priceCents}
          onChange={(v) => set("priceCents", v)}
        />
        <NumberField
          label="Annual price (cents)"
          base={plan.annualPriceCents}
          onChange={(v) => set("annualPriceCents", v)}
        />
        <NumberField
          label="Overage rate ($/1k cents)"
          base={plan.overagePer1kCents}
          onChange={(v) => set("overagePer1kCents", v)}
        />
        <NumberField
          label="Read RPS"
          base={plan.readRps}
          onChange={(v) => set("readRps", v)}
        />
        <NumberField
          label="Read burst"
          base={plan.readBurst}
          onChange={(v) => set("readBurst", v)}
        />
        <NumberField
          label="Tx RPS"
          base={plan.txRps}
          onChange={(v) => set("txRps", v)}
        />
        <NumberField
          label="Tx burst"
          base={plan.txBurst}
          onChange={(v) => set("txBurst", v)}
        />
        <BoolField
          label="Active"
          base={plan.isActive}
          onChange={(v) => set("isActive", v)}
        />
        <BoolField
          label="Giftable"
          base={plan.isGiftable}
          onChange={(v) => set("isGiftable", v)}
        />
      </div>

      {message && (
        <div
          className={`mt-3 text-xs rounded-lg px-3 py-2 border ${
            message.tone === "ok"
              ? "text-emerald-300 bg-emerald-500/10 border-emerald-500/20"
              : "text-ember-soft bg-ember/10 border-ember/20"
          }`}
        >
          {message.text}
        </div>
      )}
    </div>
  );
}

interface NumberFieldProps {
  label: string;
  base: number;
  onChange: (v: number | undefined) => void;
}

function NumberField({ label, base, onChange }: NumberFieldProps) {
  const [val, setVal] = useState<string>(String(base));

  function handle(v: string) {
    setVal(v);
    if (v === "" || v === String(base)) {
      onChange(undefined);
      return;
    }
    const n = Number(v);
    if (!Number.isFinite(n)) return;
    onChange(n);
  }

  return (
    <div>
      <label className="label-base mb-1.5 block">{label}</label>
      <input
        type="number"
        value={val}
        onChange={(e) => handle(e.target.value)}
        className="input-base"
      />
    </div>
  );
}

interface BoolFieldProps {
  label: string;
  base: boolean;
  onChange: (v: boolean) => void;
}

function BoolField({ label, base, onChange }: BoolFieldProps) {
  const [val, setVal] = useState(base);
  return (
    <div className="flex items-end pb-1">
      <label className="flex items-center gap-2 text-sm text-slate-300">
        <input
          type="checkbox"
          checked={val}
          onChange={(e) => {
            setVal(e.target.checked);
            onChange(e.target.checked);
          }}
          className="accent-ember"
        />
        {label}
      </label>
    </div>
  );
}
