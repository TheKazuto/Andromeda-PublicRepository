"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import clsx from "clsx";
import { useNormalizedPathname } from "@/lib/use-normalized-pathname";
import {
  LayoutDashboard,
  Users,
  ShieldCheck,
  Coins,
  Tag,
  Calendar,
  History,
  ScrollText,
  LogOut,
} from "lucide-react";
import { Logo } from "../Logo";
import { clearAdminToken, type AdminMe } from "@/lib/admin-api";

interface NavItem {
  href: string;
  label: string;
  Icon: typeof LayoutDashboard;
  /** When set, only shown for these roles. */
  roles?: AdminMe["role"][];
}

const NAV: NavItem[] = [
  { href: "/admin", label: "Overview", Icon: LayoutDashboard },
  { href: "/admin/users", label: "Users", Icon: Users },
  { href: "/admin/plans", label: "Plans", Icon: Tag },
  { href: "/admin/costs", label: "Request costs", Icon: Coins },
  { href: "/admin/coupons", label: "Coupons & gifts", Icon: Tag },
  { href: "/admin/pricing-changes", label: "Pricing changes", Icon: Calendar },
  { href: "/admin/audit", label: "Audit log", Icon: ScrollText },
  { href: "/admin/admin-users", label: "Admins", Icon: ShieldCheck, roles: ["super_admin"] },
];

interface AdminSidebarProps {
  me: AdminMe | null;
}

export function AdminSidebar({ me }: AdminSidebarProps) {
  const pathname = useNormalizedPathname();
  const router = useRouter();

  const items = NAV.filter((item) => {
    if (!item.roles) return true;
    if (!me) return false;
    return item.roles.includes(me.role);
  });

  function onSignOut() {
    clearAdminToken();
    router.replace("/admin/login");
  }

  return (
    <aside className="hidden md:flex md:w-60 lg:w-64 shrink-0 flex-col bg-charcoal border-r border-white/[0.05] sticky top-0 h-screen">
      <div className="px-5 py-5 flex items-center gap-2.5 border-b border-white/[0.04]">
        <Logo size={26} />
        <div className="flex flex-col leading-tight">
          <span className="text-[15px] font-semibold tracking-tight">Andromeda</span>
          <span className="text-[10px] text-ember font-mono uppercase tracking-[0.18em]">
            Admin Console
          </span>
        </div>
      </div>

      <nav className="flex-1 px-3 py-4 flex flex-col gap-0.5 overflow-y-auto">
        {items.map(({ href, label, Icon }) => {
          const active = href === "/admin" ? pathname === href : pathname.startsWith(href);
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
                className={clsx(
                  "shrink-0",
                  active ? "text-ember" : "text-slate-400 group-hover:text-snow"
                )}
              />
              <span>{label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="px-5 py-4 border-t border-white/[0.04] space-y-3">
        {me && (
          <div className="rounded-card bg-graphite-700/60 border border-white/[0.05] p-3">
            <div className="text-[11px] uppercase tracking-[0.12em] text-slate-400 font-mono">
              Signed in
            </div>
            <div className="mt-1.5 text-xs text-snow truncate" title={me.email}>
              {me.email}
            </div>
            <div className="mt-1 text-[11px] text-slate-400 font-mono uppercase tracking-wide">
              {me.role.replace("_", " ")}
            </div>
            {!me.mfaEnabled && (
              <div className="mt-2 text-[11px] text-amber-300 flex items-center gap-1.5">
                <History size={11} strokeWidth={1.8} />
                <Link href="/admin/security" className="underline">
                  Enable 2FA
                </Link>
              </div>
            )}
          </div>
        )}

        <button
          type="button"
          onClick={onSignOut}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs text-slate-300 hover:bg-white/[0.04] hover:text-snow border border-white/[0.05] transition-colors"
        >
          <LogOut size={14} strokeWidth={1.6} />
          Sign out
        </button>
      </div>
    </aside>
  );
}
