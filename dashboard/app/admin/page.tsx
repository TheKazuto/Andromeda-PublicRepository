"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  Users,
  Tag,
  Coins,
  Calendar,
  ScrollText,
  ShieldCheck,
} from "lucide-react";
import { adminAuth, type AdminMe } from "@/lib/admin-api";

interface ShortcutCard {
  href: string;
  label: string;
  description: string;
  Icon: typeof Users;
  /** Only show for these roles. Empty = always. */
  roles?: AdminMe["role"][];
}

const SHORTCUTS: ShortcutCard[] = [
  {
    href: "/admin/users",
    label: "Users",
    description: "Look up customers, manage API keys, change plan.",
    Icon: Users,
  },
  {
    href: "/admin/plans",
    label: "Plans",
    description: "Edit price, tokens, RPS limits and features.",
    Icon: Tag,
  },
  {
    href: "/admin/costs",
    label: "Request costs",
    description: "Tune token cost per route. Pricing changes go through the schedule.",
    Icon: Coins,
  },
  {
    href: "/admin/coupons",
    label: "Coupons & gifts",
    description: "Issue promo gift cards, view paid gift cards, refund recent purchases.",
    Icon: Tag,
  },
  {
    href: "/admin/pricing-changes",
    label: "Pricing changes",
    description: "Schedule versioned price adjustments with 30-day notice.",
    Icon: Calendar,
  },
  {
    href: "/admin/audit",
    label: "Audit log",
    description: "Review every admin action with IP and timestamp.",
    Icon: ScrollText,
  },
  {
    href: "/admin/admin-users",
    label: "Admin accounts",
    description: "Provision new operators with role-based access.",
    Icon: ShieldCheck,
    roles: ["super_admin"],
  },
];

export default function AdminOverviewPage() {
  const [me, setMe] = useState<AdminMe | null>(null);

  useEffect(() => {
    let cancelled = false;
    adminAuth
      .me()
      .then((data) => {
        if (!cancelled) setMe(data);
      })
      .catch(() => {
        // Errors are surfaced by the layout's `me()` call; swallow here so a
        // transient failure doesn't leak unhandledrejection into the console.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const shortcuts = SHORTCUTS.filter((s) => {
    if (!s.roles) return true;
    if (!me) return false;
    return s.roles.includes(me.role);
  });

  return (
    <main className="flex-1 px-6 lg:px-10 py-8">
      <header className="mb-8">
        <p className="text-[11px] font-mono uppercase tracking-[0.18em] text-ember">
          Operator console
        </p>
        <h1 className="text-3xl font-semibold tracking-tight mt-1">
          {me ? `Welcome, ${formatGreeting(me.email)}.` : "Admin overview"}
        </h1>
        <p className="text-sm text-slate-300 mt-2 max-w-2xl">
          Use the shortcuts below to manage the Andromeda token economy. Every
          mutation is recorded in the audit log with your identity, IP and
          user-agent.
        </p>
      </header>

      <section>
        <h2 className="text-xs uppercase tracking-[0.14em] text-slate-400 font-mono mb-3">
          Shortcuts
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {shortcuts.map(({ href, label, description, Icon }) => (
            <Link
              key={href}
              href={href}
              className="card p-5 hover:border-ember/30 hover:bg-charcoal/80 transition-colors group"
            >
              <div className="flex items-center gap-3 mb-2">
                <div className="w-9 h-9 rounded-md bg-ember/10 border border-ember/20 grid place-items-center group-hover:bg-ember/15">
                  <Icon size={18} strokeWidth={1.8} className="text-ember" />
                </div>
                <h3 className="text-sm font-semibold text-snow">{label}</h3>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">{description}</p>
            </Link>
          ))}
        </div>
      </section>

      <section className="mt-10">
        <h2 className="text-xs uppercase tracking-[0.14em] text-slate-400 font-mono mb-3">
          Heads-up
        </h2>
        <div className="card p-5 text-sm text-slate-300 max-w-3xl">
          <ul className="list-disc list-inside space-y-1.5">
            <li>
              All <strong className="text-snow">pricing changes</strong> require ≥30 days notice;
              the worker applies them automatically at the effective date.
            </li>
            <li>
              Promotional <strong className="text-snow">coupons</strong> are emitted free of
              charge; paid gift cards arrive via Stripe checkout (5.7).
            </li>
            <li>
              Token <strong className="text-snow">credits</strong> always expire in 30 days. Top-up
              packs do not exist — only plans and overage.
            </li>
          </ul>
        </div>
      </section>
    </main>
  );
}

function formatGreeting(email: string): string {
  const local = email.split("@")[0] ?? "";
  if (!local) return email;
  // String.prototype.toUpperCase() is unicode-aware in modern engines, but
  // codepoint splitting via `Array.from` keeps accented or compound letters
  // intact (e.g. `émile` doesn't lose its accent).
  const chars = Array.from(local);
  const first = chars[0]?.toUpperCase() ?? "";
  return first + chars.slice(1).join("");
}
