"use client";

import Link from "next/link";
import clsx from "clsx";
import {
  Home,
  KeyRound,
  Server,
  Activity,
  CreditCard,
  Settings,
  LifeBuoy,
  BookOpen,
  Link2,
} from "lucide-react";
import { useNormalizedPathname } from "@/lib/use-normalized-pathname";

const NETWORK_LABEL = process.env.NEXT_PUBLIC_NETWORK || "Devnet";
const NETWORK_TIER = process.env.NEXT_PUBLIC_NETWORK_TIER || "Pre-alpha";

type Item = { href: string; label: string; Icon: typeof Home };

const NAV: Item[] = [
  { href: "/dashboard", label: "Home", Icon: Home },
  { href: "/dashboard/api-keys", label: "API Keys", Icon: KeyRound },
  { href: "/dashboard/settings/oauth-redirects", label: "OAuth Redirects", Icon: Link2 },
  { href: "/dashboard/mcp-server", label: "MCP Server", Icon: Server },
  { href: "/dashboard/usage", label: "Usage", Icon: Activity },
  { href: "/dashboard/billing", label: "Billing", Icon: CreditCard },
  { href: "/dashboard/settings", label: "Settings", Icon: Settings },
  { href: "/dashboard/support", label: "Support", Icon: LifeBuoy },
  { href: "/dashboard/documentation", label: "Documentation", Icon: BookOpen },
];

export function Sidebar() {
  const pathname = useNormalizedPathname();

  return (
    <aside className="hidden md:flex md:w-60 lg:w-64 shrink-0 flex-col bg-charcoal border-r border-white/[0.05] sticky top-0 h-screen">
      <div className="h-[60px] px-5 flex items-center border-b border-white/[0.04]">
        <span
          className="text-ember"
          style={{
            fontFamily: "'Instrument Serif', ui-serif, Georgia, 'Times New Roman', serif",
            fontStyle: "italic",
            fontWeight: 400,
            fontSize: "24px",
            lineHeight: 1,
            letterSpacing: "-0.03em",
          }}
        >
          Andromeda
        </span>
      </div>

      <nav className="flex-1 px-3 py-4 flex flex-col gap-0.5">
        {NAV.map(({ href, label, Icon }) => {
          const active = href === "/dashboard" ? pathname === href : pathname.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              className={clsx(
                "group flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors",
                active
                  ? "bg-ember/10 text-snow border border-ember/20"
                  : "text-slate-300 hover:bg-white/[0.04] hover:text-snow border border-transparent"
              )}
            >
              <Icon
                size={16}
                strokeWidth={1.6}
                className={clsx("shrink-0", active ? "text-ember" : "text-slate-400 group-hover:text-snow")}
              />
              <span>{label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="px-5 py-4 border-t border-white/[0.04]">
        <div className="rounded-card bg-graphite-700/60 border border-white/[0.05] p-3">
          <div className="text-[11px] uppercase tracking-[0.12em] text-slate-400 font-mono">
            Network
          </div>
          <div className="mt-1.5 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-signal-mint shadow-[0_0_8px_var(--tw-shadow-color)] shadow-signal-mint" />
            <span className="text-xs text-snow">{NETWORK_LABEL}</span>
          </div>
          <div className="mt-1 text-[11px] text-slate-400 font-mono">{NETWORK_TIER}</div>
        </div>
      </div>
    </aside>
  );
}
