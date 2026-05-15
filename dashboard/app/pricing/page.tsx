"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import clsx from "clsx";
import { Sparkles, Building2, Check, Gift } from "lucide-react";
import { Logo } from "@/components/Logo";
import { pricing, type PublicPlan } from "@/lib/api";
import { errorMessage } from "@/lib/format";

type Cycle = "monthly" | "annual";

export default function PublicPricingPage() {
  const [plans, setPlans] = useState<PublicPlan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [cycle, setCycle] = useState<Cycle>("monthly");

  useEffect(() => {
    let cancelled = false;
    pricing
      .plans()
      .then((data) => {
        if (!cancelled) setPlans(data.plans);
      })
      .catch((err) => {
        if (!cancelled) setError(errorMessage(err, "Failed to load plans"));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const enterprise = plans.find((p) => p.code === "enterprise");

  return (
    <main className="min-h-screen bg-void">
      <header className="px-6 py-5 border-b border-white/[0.05]">
        <div className="max-w-[1200px] mx-auto flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2.5">
            <Logo size={26} />
            <span className="text-[15px] font-semibold tracking-tight">Andromeda</span>
          </Link>
          <nav className="flex items-center gap-6 text-sm">
            <Link href="/login" className="text-slate-300 hover:text-snow transition-colors">
              Sign in
            </Link>
            <Link href="/signup" className="btn-primary">
              Get started
            </Link>
          </nav>
        </div>
      </header>

      <section className="px-6 py-16 atmosphere-ember">
        <div className="max-w-[1200px] mx-auto text-center">
          <p className="text-[11px] font-mono uppercase tracking-[0.18em] text-ember mb-3">
            Pricing
          </p>
          <h1 className="text-4xl md:text-5xl font-semibold tracking-tight mb-4">
            Simple, transparent token pricing.
          </h1>
          <p className="text-base text-slate-300 max-w-2xl mx-auto">
            Pay for what you use. 1,000 tokens ≈ $4 at the standard rate.
            Plans give you discounted token packages with feature unlocks; overage
            is opt-in and only charges what you spend above the plan.
          </p>

          <div className="flex justify-center mt-8">
            <div className="inline-flex items-center bg-graphite-700/40 border border-white/[0.05] rounded-lg p-0.5">
              <button
                type="button"
                onClick={() => setCycle("monthly")}
                className={clsx(
                  "px-4 py-2 text-sm rounded-md transition-colors",
                  cycle === "monthly"
                    ? "bg-charcoal text-snow"
                    : "text-slate-400 hover:text-snow",
                )}
              >
                Monthly
              </button>
              <button
                type="button"
                onClick={() => setCycle("annual")}
                className={clsx(
                  "px-4 py-2 text-sm rounded-md transition-colors flex items-center gap-2",
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
        </div>
      </section>

      <section className="px-6 pb-16">
        <div className="max-w-[1200px] mx-auto">
          {loading && <p className="text-center text-sm text-slate-400">Loading plans…</p>}
          {error && (
            <p className="text-center text-xs text-ember-soft">{error}</p>
          )}

          {!loading && !error && (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                {plans
                  .filter((p) => p.code !== "enterprise")
                  .map((p) => (
                    <PublicPlanCard key={p.code} plan={p} cycle={cycle} />
                  ))}
              </div>

              {enterprise && <EnterpriseCard plan={enterprise} />}

              <GiftBanner />
            </>
          )}
        </div>
      </section>
    </main>
  );
}

function PublicPlanCard({ plan, cycle }: { plan: PublicPlan; cycle: Cycle }) {
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
      <div className="mb-5">
        <span className="text-[28px] font-semibold tracking-display">
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
      <Link
        href={isFree ? "/signup" : `/signup?plan=${plan.code}&cycle=${cycle}`}
        className={clsx(
          isHighlight ? "btn-primary" : "btn-secondary",
          "mt-auto",
        )}
      >
        {isFree ? "Start free" : "Get started"}
      </Link>
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

function EnterpriseCard({ plan }: { plan: PublicPlan }) {
  return (
    <div className="card p-6 mt-6">
      <div className="grid grid-cols-1 lg:grid-cols-[1.2fr_1fr] gap-8 items-center">
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Building2 size={16} strokeWidth={1.6} className="text-ember-soft" />
            <span className="text-sm font-semibold tracking-tight">{plan.name}</span>
            <span className="badge">custom</span>
          </div>
          <div className="mb-4">
            <span className="text-[28px] font-semibold tracking-display">From $1,999</span>
            <span className="text-sm text-slate-400 ml-1">one-time · token pack</span>
          </div>
          <p className="text-sm text-slate-300 mb-4 max-w-xl">
            Pre-purchase token packs for high-volume workloads. Token rate as low as
            $2/1,000 — 50% off the standard rate. Includes everything in Premium plus
            dedicated infra, 99.99% SLA, SOC 2 reports, and 24/7 priority support.
          </p>
          <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-xs text-slate-300">
            <Feature label="Custom token rate (down to $2/1k)" />
            <Feature label="Dedicated infra + private endpoints" />
            <Feature label="99.99% SLA + SOC 2 reports" />
            <Feature label="24/7 priority support" />
          </ul>
        </div>
        <div className="rounded-lg border border-white/[0.06] bg-black/20 p-5 text-center">
          <div className="text-sm text-slate-300 mb-3">
            Enterprise contracts are negotiated directly. Reach out for a quote.
          </div>
          <a href="mailto:sales@shinkalabs.com" className="btn-primary inline-flex">
            Contact sales
          </a>
        </div>
      </div>
    </div>
  );
}

function GiftBanner() {
  return (
    <div className="card p-6 mt-6 border-ember/20 bg-ember/[0.04]">
      <div className="flex items-start gap-4">
        <div className="w-10 h-10 rounded-md bg-ember/10 border border-ember/20 grid place-items-center shrink-0">
          <Gift size={18} strokeWidth={1.8} className="text-ember" />
        </div>
        <div className="flex-1">
          <h3 className="text-sm font-semibold text-snow mb-1">Gift Andromeda</h3>
          <p className="text-xs text-slate-300 mb-3 max-w-2xl">
            Buy a 1-month or 12-month gift card for any paid plan. The recipient
            redeems it on their account — gifts extend or upgrade their existing
            subscription.
          </p>
          <Link href="/gifts/buy" className="btn-secondary inline-flex">
            Buy a gift
          </Link>
        </div>
      </div>
    </div>
  );
}
