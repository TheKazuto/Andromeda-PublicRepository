"use client";

import Link from "next/link";
import { Sparkles } from "lucide-react";
import { Logo } from "@/components/Logo";

export default function CheckoutSuccessPage() {
  return (
    <main className="min-h-screen flex items-center justify-center px-4 atmosphere-ember bg-void">
      <div className="w-full max-w-[440px] animate-fade-up text-center">
        <div className="flex items-center justify-center mb-8">
          <Logo size={36} />
        </div>
        <div className="card p-7">
          <div className="flex items-center justify-center mb-3">
            <Sparkles className="text-ember" size={32} strokeWidth={1.6} />
          </div>
          <h1 className="text-[22px] font-semibold tracking-tight mb-2">
            Subscription confirmed
          </h1>
          <p className="text-sm text-slate-300 mb-5">
            Your plan is active. Stripe is processing the first invoice now —
            it may take a few seconds for the new tokens to appear in your
            balance.
          </p>
          <Link href="/dashboard/billing" className="btn-primary inline-flex">
            View billing
          </Link>
        </div>
      </div>
    </main>
  );
}
