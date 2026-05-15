"use client";

import { useEffect, useState } from "react";
import clsx from "clsx";
import {
  CreditCard,
  Sparkles,
  Building2,
  ExternalLink,
  AlertCircle,
  Check,
  Zap,
} from "lucide-react";
import { Topbar } from "@/components/Topbar";
import { PageTitle } from "@/components/PageTitle";
import {
  pricing,
  me,
  billing,
  type PublicPlan,
  type MeBalance,
  APIError,
} from "@/lib/api";
import { errorMessage } from "@/lib/format";

type Cycle = "monthly" | "annual";

export default function BillingPage() {
  const [plans, setPlans] = useState<PublicPlan[]>([]);
  const [balance, setBalance] = useState<MeBalance | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [cycle, setCycle] = useState<Cycle>("monthly");
  const [busyAction, setBusyAction] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const [plansResp, balResp] = await Promise.all([
        pricing.plans(),
        me.balance(),
      ]);
      setPlans(plansResp.plans);
      setBalance(balResp);
    } catch (err) {
      setError(errorMessage(err, "Failed to load billing"));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const [plansResp, balResp] = await Promise.all([
          pricing.plans(),
          me.balance(),
        ]);
        if (cancelled) return;
        setPlans(plansResp.plans);
        setBalance(balResp);
      } catch (err) {
        if (!cancelled) setError(errorMessage(err, "Failed to load billing"));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function startCheckout(planCode: string, c: Cycle) {
    if (planCode === "free") return;
    setBusyAction(planCode + ":" + c);
    try {
      const { url } = await billing.checkout({ planCode, cycle: c });
      window.location.href = url;
    } catch (err) {
      const msg =
        err instanceof APIError
          ? err.code === "billing_disabled"
            ? "Billing is not yet enabled in this environment."
            : err.message
          : "Checkout failed";
      setError(msg);
      setBusyAction(null);
    }
  }

  async function openPortal() {
    setBusyAction("portal");
    try {
      const { url } = await billing.portal();
      window.location.href = url;
    } catch (err) {
      const msg =
        err instanceof APIError
          ? err.code === "no_stripe_customer"
            ? "Subscribe to a paid plan first to access the billing portal."
            : err.message
          : "Could not open portal";
      setError(msg);
      setBusyAction(null);
    }
  }

  async function toggleOverage(target: boolean) {
    setBusyAction("overage");
    setError(null);
    try {
      if (target) {
        await billing.enableOverage();
      } else {
        await billing.disableOverage();
      }
      await load();
    } catch (err) {
      setError(errorMessage(err, "Could not change overage"));
    } finally {
      setBusyAction(null);
    }
  }

  const currentPlan = balance?.plan?.code ?? "free";
  const sub = balance?.balance.subscription;

  return (
    <>
      <Topbar pageTitle="Billing" />
      <main className="flex-1 px-6 py-8 overflow-auto">
        <div className="max-w-[1200px] mx-auto">
          <PageTitle
            eyebrow="// billing"
            title="Billing"
            description="Manage your subscription, payment method, and overage settings."
          />

          {error && (
            <div className="mb-4 text-xs text-ember-soft bg-ember/10 border border-ember/20 rounded-lg px-3 py-2 flex items-center gap-2">
              <AlertCircle size={14} strokeWidth={1.6} />
              {error}
            </div>
          )}

          {loading ? (
            <div className="text-sm text-slate-400">Loading…</div>
          ) : (
            <>
              <CurrentPlanCard
                balance={balance}
                onPortal={openPortal}
                portalBusy={busyAction === "portal"}
                onToggleOverage={toggleOverage}
                overageBusy={busyAction === "overage"}
              />

              <CycleToggle cycle={cycle} onChange={setCycle} />

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
                {plans
                  .filter((p) => p.code !== "enterprise")
                  .map((p) => (
                    <PlanCard
                      key={p.code}
                      plan={p}
                      cycle={cycle}
                      currentPlan={currentPlan}
                      busy={busyAction === p.code + ":" + cycle}
                      onChoose={() => startCheckout(p.code, cycle)}
                    />
                  ))}
              </div>

              <EnterpriseCard
                plan={plans.find((p) => p.code === "enterprise")}
                isCurrent={currentPlan === "enterprise"}
              />

              <UsageSummary sub={sub} />
            </>
          )}
        </div>
      </main>
    </>
  );
}

interface CurrentPlanCardProps {
  balance: MeBalance | null;
  onPortal: () => void;
  portalBusy: boolean;
  onToggleOverage: (target: boolean) => void;
  overageBusy: boolean;
}

function CurrentPlanCard({
  balance,
  onPortal,
  portalBusy,
  onToggleOverage,
  overageBusy,
}: CurrentPlanCardProps) {
  const sub = balance?.balance.subscription;
  const plan = balance?.plan;

  return (
    <div className="card p-6 mb-6">
      <div className="flex items-start justify-between gap-6 flex-wrap">
        <div>
          <div className="label-base mb-1">Current plan</div>
          <div className="flex items-center gap-2 mt-0.5">
            <span className="text-[22px] font-semibold tracking-tight capitalize">
              {plan?.code ?? "free"}
            </span>
            {plan?.status === "active" && <span className="badge-ember">active</span>}
            {plan?.status === "past_due" && (
              <span className="badge-ember bg-amber-500/10 text-amber-300 border-amber-500/20">
                past due
              </span>
            )}
            {plan?.status === "trialing" && <span className="badge-mint">trialing</span>}
            {plan?.billingCycle === "annual" && (
              <span className="badge text-slate-300">annual</span>
            )}
          </div>
          <div className="text-xs text-slate-300 mt-2">
            {sub?.currentPeriodEnd
              ? `Renews ${new Date(sub.currentPeriodEnd).toLocaleDateString("en-US", {
                  month: "short",
                  day: "numeric",
                  year: "numeric",
                })}`
              : "—"}
          </div>
        </div>

        <div>
          <div className="label-base mb-1">Tokens</div>
          <div className="text-[22px] font-semibold tracking-tight font-mono">
            {balance?.balance.totalRemaining.toLocaleString() ?? "—"}
          </div>
          <div className="text-xs text-slate-400 mt-2">
            of {sub ? sub.tokensLimit.toLocaleString() : "—"} this period
          </div>
        </div>

        <div>
          <div className="label-base mb-1">Overage</div>
          <div className="flex items-center gap-2 mt-0.5">
            <Zap size={16} strokeWidth={1.6} className={sub?.overageEnabled ? "text-ember" : "text-slate-500"} />
            <span className="text-sm text-snow capitalize">
              {sub?.overageEnabled ? "Enabled" : "Disabled"}
            </span>
          </div>
          {sub && sub.stripeSubscriptionId ? (
            <button
              type="button"
              onClick={() => onToggleOverage(!sub.overageEnabled)}
              disabled={overageBusy}
              className="text-xs text-ember-soft hover:text-ember mt-2 transition-colors"
            >
              {overageBusy
                ? "Updating…"
                : sub.overageEnabled
                ? "Disable overage"
                : "Enable overage"}
            </button>
          ) : (
            <div className="text-xs text-slate-500 mt-2">Subscribe to a paid plan first</div>
          )}
        </div>

        <div>
          <div className="label-base mb-1">Payment</div>
          <div className="flex items-center gap-2 mt-0.5">
            <CreditCard size={16} strokeWidth={1.6} className="text-slate-300" />
            <span className="text-sm text-snow">
              {sub?.stripeCustomerId ? "On file" : "—"}
            </span>
          </div>
          {sub?.stripeCustomerId ? (
            <button
              type="button"
              onClick={onPortal}
              disabled={portalBusy}
              className="text-xs text-ember-soft hover:text-ember mt-2 transition-colors flex items-center gap-1"
            >
              {portalBusy ? "Opening…" : "Manage billing"}
              <ExternalLink size={11} strokeWidth={1.8} />
            </button>
          ) : (
            <div className="text-xs text-slate-500 mt-2">No card yet</div>
          )}
        </div>
      </div>
    </div>
  );
}

function CycleToggle({ cycle, onChange }: { cycle: Cycle; onChange: (c: Cycle) => void }) {
  return (
    <div className="flex items-center justify-between mb-3">
      <h3 className="text-[15px] font-semibold tracking-tight">Change plan</h3>
      <div className="flex items-center bg-graphite-700/40 border border-white/[0.05] rounded-lg p-0.5">
        <button
          type="button"
          onClick={() => onChange("monthly")}
          className={clsx(
            "px-3 py-1.5 text-xs rounded-md transition-colors",
            cycle === "monthly"
              ? "bg-charcoal text-snow"
              : "text-slate-400 hover:text-snow",
          )}
        >
          Monthly
        </button>
        <button
          type="button"
          onClick={() => onChange("annual")}
          className={clsx(
            "px-3 py-1.5 text-xs rounded-md transition-colors flex items-center gap-1.5",
            cycle === "annual"
              ? "bg-charcoal text-snow"
              : "text-slate-400 hover:text-snow",
          )}
        >
          Annual
          <span className="text-[10px] text-emerald-300 font-mono">−16.7%</span>
        </button>
      </div>
    </div>
  );
}

interface PlanCardProps {
  plan: PublicPlan;
  cycle: Cycle;
  currentPlan: string;
  busy: boolean;
  onChoose: () => void;
}

function PlanCard({ plan, cycle, currentPlan, busy, onChoose }: PlanCardProps) {
  const isCurrent = plan.code === currentPlan;
  const isFree = plan.code === "free";
  const isHighlight = plan.code === "pro";

  const priceCents =
    cycle === "annual" ? plan.annualPriceCents : plan.priceCents;
  const cadence = cycle === "annual" ? "/year" : "/mo";

  return (
    <div
      className={clsx(
        "card p-6 flex flex-col",
        isHighlight && "border-ember/30 shadow-ember",
      )}
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm font-semibold tracking-tight">{plan.name}</span>
        {isHighlight && (
          <span className="badge-ember">
            <Sparkles size={10} strokeWidth={1.8} /> Popular
          </span>
        )}
      </div>
      <div className="mb-4">
        <span className="text-[26px] font-semibold tracking-display">
          ${(priceCents / 100).toLocaleString()}
        </span>
        <span className="text-sm text-slate-400 ml-1">{isFree ? "" : cadence}</span>
        {!isFree && cycle === "annual" && plan.priceCents > 0 && (
          <div className="text-[11px] text-slate-400 mt-1 font-mono">
            ≈ ${Math.round(priceCents / 12 / 100).toLocaleString()}/mo
          </div>
        )}
      </div>
      <ul className="flex flex-col gap-2 mb-6 text-xs text-slate-300">
        <Feature label={`${plan.monthlyTokens.toLocaleString()} tokens / month`} />
        <Feature label={`${plan.readRps} read RPS / ${plan.txRps} tx RPS`} />
        {boolFeature(plan.features, "webhooks") && <Feature label="Webhooks" />}
        {boolFeature(plan.features, "audit") && <Feature label="Signed audit log" />}
        {boolFeature(plan.features, "policies") && <Feature label="Policy templates" />}
        {boolFeature(plan.features, "recovery_quorum") && <Feature label="Recovery quorum" />}
        {boolFeature(plan.features, "mainnet") && <Feature label="Mainnet ready" />}
        {boolFeature(plan.features, "priority_support") && <Feature label="Priority support" />}
        {boolFeature(plan.features, "sla_99_9") && <Feature label="SLA 99.9%" />}
      </ul>
      <button
        type="button"
        disabled={isCurrent || isFree || busy}
        onClick={onChoose}
        className={clsx(
          isHighlight ? "btn-primary" : "btn-secondary",
          "mt-auto disabled:opacity-50",
        )}
      >
        {isCurrent ? "Current plan" : isFree ? "Free tier" : busy ? "Redirecting…" : "Choose"}
      </button>
    </div>
  );
}

function Feature({ label }: { label: string }) {
  return (
    <li className="flex items-start gap-2">
      <Check size={12} strokeWidth={2} className="text-emerald-300 mt-0.5 shrink-0" />
      <span>{label}</span>
    </li>
  );
}

function boolFeature(f: Record<string, unknown> | undefined, key: string): boolean {
  return Boolean(f && f[key] === true);
}

function EnterpriseCard({ plan, isCurrent }: { plan?: PublicPlan; isCurrent: boolean }) {
  if (!plan) return null;
  return (
    <div className="card p-6 mb-8 border-white/10">
      <div className="grid grid-cols-1 lg:grid-cols-[1.2fr_1fr] gap-8 items-center">
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Building2 size={16} strokeWidth={1.6} className="text-ember-soft" />
            <span className="text-sm font-semibold tracking-tight">Enterprise</span>
            <span className="badge">custom</span>
            {isCurrent && <span className="badge-ember">active</span>}
          </div>
          <div className="mb-4">
            <span className="text-[26px] font-semibold tracking-display">From $1,999</span>
            <span className="text-sm text-slate-400 ml-1">one-time · token pack</span>
          </div>
          <p className="text-sm text-slate-300 mb-4 max-w-xl">
            Pre-purchase token packs for high-volume workloads. Choose the amount that fits
            your usage — minimum $1,999. Includes everything in Premium plus dedicated infra,
            99.99% SLA, SOC 2 reports, and 24/7 priority support.
          </p>
          <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-xs text-slate-300">
            <Feature label="Custom token rate (down from $2/1k)" />
            <Feature label="Dedicated infra + private endpoints" />
            <Feature label="99.99% SLA + SOC 2 reports" />
            <Feature label="24/7 priority support" />
          </ul>
        </div>
        <div className="rounded-lg border border-white/[0.06] bg-black/20 p-5 text-center">
          <div className="text-sm text-slate-300 mb-3">
            Enterprise contracts are negotiated directly. Reach out for a quote.
          </div>
          <a
            href="mailto:sales@shinkalabs.com"
            className="btn-primary inline-flex"
          >
            Contact sales
          </a>
        </div>
      </div>
    </div>
  );
}

function UsageSummary({
  sub,
}: {
  sub?: MeBalance["balance"]["subscription"];
}) {
  if (!sub) return null;
  const pct = sub.tokensLimit > 0 ? Math.round((sub.tokensUsed * 100) / sub.tokensLimit) : 0;
  const overagePct =
    sub.overageCapTokens > 0
      ? Math.round((sub.overageUsedTokens * 100) / sub.overageCapTokens)
      : 0;

  return (
    <div className="card p-6">
      <h3 className="text-[15px] font-semibold tracking-tight mb-4">This period</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-400">Monthly tokens</span>
            <span className="text-xs font-mono text-snow">
              {sub.tokensUsed.toLocaleString()} / {sub.tokensLimit.toLocaleString()}
            </span>
          </div>
          <div className="h-2 bg-graphite-700/60 rounded-full overflow-hidden">
            <div
              className="h-full bg-ember"
              style={{ width: `${Math.min(pct, 100)}%` }}
            />
          </div>
          <div className="text-[11px] text-slate-400 mt-1 font-mono">{pct}% used</div>
        </div>
        {sub.overageEnabled && (
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-slate-400">Overage</span>
              <span className="text-xs font-mono text-snow">
                {sub.overageUsedTokens.toLocaleString()} /{" "}
                {sub.overageCapTokens.toLocaleString()}
              </span>
            </div>
            <div className="h-2 bg-graphite-700/60 rounded-full overflow-hidden">
              <div
                className="h-full bg-amber-300"
                style={{ width: `${Math.min(overagePct, 100)}%` }}
              />
            </div>
            <div className="text-[11px] text-slate-400 mt-1 font-mono">
              {overagePct}% of cap · billed at next invoice
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
