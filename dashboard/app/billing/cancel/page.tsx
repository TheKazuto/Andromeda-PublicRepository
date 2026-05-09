"use client";

import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { Logo } from "@/components/Logo";

export default function CheckoutCancelPage() {
  return (
    <main className="min-h-screen flex items-center justify-center px-4 atmosphere-ember bg-void">
      <div className="w-full max-w-[440px] animate-fade-up text-center">
        <div className="flex items-center justify-center mb-8">
          <Logo size={36} />
        </div>
        <div className="card p-7">
          <h1 className="text-[22px] font-semibold tracking-tight mb-2">
            Checkout cancelled
          </h1>
          <p className="text-sm text-slate-300 mb-5">
            No payment was processed. Your current plan is unchanged.
          </p>
          <Link href="/dashboard/billing" className="btn-secondary inline-flex">
            <ArrowLeft size={14} strokeWidth={1.6} />
            Back to billing
          </Link>
        </div>
      </div>
    </main>
  );
}
