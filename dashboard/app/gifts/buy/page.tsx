"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Gift, ArrowRight } from "lucide-react";
import { Logo } from "@/components/Logo";
import { gifts, pricing, type PublicPlan, APIError } from "@/lib/api";

type Cycle = 1 | 12;

export default function GiftBuyPage() {
  const [plans, setPlans] = useState<PublicPlan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [planCode, setPlanCode] = useState<string>("");
  const [duration, setDuration] = useState<Cycle>(1);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    pricing
      .plans()
      .then((data) => {
        const giftable = data.plans.filter((p) => p.isGiftable);
        setPlans(giftable);
        if (giftable.length > 0) setPlanCode(giftable[0].code);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load"))
      .finally(() => setLoading(false));
  }, []);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!planCode) return;
    setBusy(true);
    setError(null);
    try {
      const { url } = await gifts.checkout({
        planCode,
        durationMonths: duration,
        message: message.trim(),
      });
      window.location.href = url;
    } catch (err) {
      const msg =
        err instanceof APIError
          ? err.code === "billing_disabled"
            ? "Gift purchases are not yet enabled."
            : err.message
          : "Could not start checkout";
      setError(msg);
      setBusy(false);
    }
  }

  const selected = plans.find((p) => p.code === planCode);
  const priceCents = selected
    ? duration === 12
      ? selected.annualPriceCents
      : selected.priceCents
    : 0;

  return (
    <main className="min-h-screen bg-void">
      <header className="px-6 py-5 border-b border-white/[0.05]">
        <div className="max-w-[800px] mx-auto flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2.5">
            <Logo size={26} />
            <span className="text-[15px] font-semibold tracking-tight">Andromeda</span>
          </Link>
          <Link href="/pricing" className="text-sm text-slate-300 hover:text-snow transition-colors">
            Pricing
          </Link>
        </div>
      </header>

      <section className="px-6 py-12 atmosphere-ember">
        <div className="max-w-[640px] mx-auto">
          <div className="flex items-center gap-3 mb-3">
            <Gift size={24} strokeWidth={1.6} className="text-ember" />
            <h1 className="text-3xl font-semibold tracking-tight">Buy a gift</h1>
          </div>
          <p className="text-sm text-slate-300 mb-8">
            Send an Andromeda subscription to anyone. Gift links can be redeemed
            on any account; we'll email the link to you after payment.
          </p>

          {loading && <div className="text-sm text-slate-400">Loading…</div>}

          {!loading && plans.length === 0 && !error && (
            <div className="card p-6 text-center text-sm text-slate-300">
              No giftable plans are available right now.
            </div>
          )}

          {!loading && plans.length > 0 && (
            <form onSubmit={onSubmit} className="card p-6 flex flex-col gap-5">
              <div>
                <label className="label-base mb-2 block">Plan</label>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  {plans.map((p) => (
                    <button
                      key={p.code}
                      type="button"
                      onClick={() => setPlanCode(p.code)}
                      className={
                        "rounded-lg border px-4 py-3 text-left transition-colors " +
                        (planCode === p.code
                          ? "border-ember/40 bg-ember/[0.06] text-snow"
                          : "border-white/[0.05] bg-graphite-700/40 text-slate-300 hover:border-white/[0.1]")
                      }
                    >
                      <div className="text-sm font-semibold">{p.name}</div>
                      <div className="text-[11px] text-slate-400 font-mono">
                        {p.monthlyTokens.toLocaleString()} tokens/mo
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="label-base mb-2 block">Duration</label>
                <div className="grid grid-cols-2 gap-2">
                  <DurationOption
                    label="1 month"
                    selected={duration === 1}
                    onClick={() => setDuration(1)}
                  />
                  <DurationOption
                    label="12 months (saves 16.7%)"
                    selected={duration === 12}
                    onClick={() => setDuration(12)}
                  />
                </div>
              </div>

              <div>
                <label className="label-base mb-2 block">Message (optional)</label>
                <textarea
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  className="input-base h-20"
                  placeholder="Happy birthday! Hope this helps with your project."
                  maxLength={500}
                />
                <p className="text-[11px] text-slate-400 mt-1">
                  Shown to the recipient when they open the gift link.
                </p>
              </div>

              <div className="border-t border-white/[0.05] pt-4">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <div className="text-xs text-slate-400">Total</div>
                    <div className="text-2xl font-semibold tracking-tight font-mono">
                      ${(priceCents / 100).toLocaleString()}
                    </div>
                  </div>
                  <div className="text-right text-[11px] text-slate-400">
                    <div>One-time payment</div>
                    <div>via Stripe</div>
                  </div>
                </div>

                {error && (
                  <div className="text-xs text-ember-soft bg-ember/10 border border-ember/20 rounded-lg px-3 py-2 mb-3">
                    {error}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={busy || !planCode}
                  className="btn-primary w-full"
                >
                  {busy ? (
                    "Redirecting to checkout…"
                  ) : (
                    <>
                      Continue to payment <ArrowRight size={14} strokeWidth={1.8} />
                    </>
                  )}
                </button>
                <p className="text-[11px] text-slate-500 text-center mt-3">
                  Refundable within 7 days if not redeemed. Gift links are valid for 12 months.
                </p>
              </div>
            </form>
          )}
        </div>
      </section>
    </main>
  );
}

function DurationOption({
  label,
  selected,
  onClick,
}: {
  label: string;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={
        "rounded-lg border px-4 py-3 text-sm text-left transition-colors " +
        (selected
          ? "border-ember/40 bg-ember/[0.06] text-snow"
          : "border-white/[0.05] bg-graphite-700/40 text-slate-300 hover:border-white/[0.1]")
      }
    >
      {label}
    </button>
  );
}
