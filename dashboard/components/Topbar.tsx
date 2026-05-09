"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Bell, LogOut, ChevronDown } from "lucide-react";
import { api, logoutSession, type User } from "@/lib/api";

export function Topbar({ pageTitle }: { pageTitle: string }) {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api<User>("/v1/me")
      .then((u) => {
        if (!cancelled) setUser(u);
      })
      .catch(() => {
        void logoutSession();
        router.replace("/login");
      });
    return () => {
      cancelled = true;
    };
  }, [router]);

  const onLogout = async () => {
    await logoutSession();
    router.push("/login");
  };

  const initials = (user?.name || user?.email || "?")
    .split(/[\s@]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((s) => s[0]?.toUpperCase())
    .join("");

  return (
    <header className="h-[60px] border-b border-white/[0.05] bg-charcoal/80 backdrop-blur-md sticky top-0 z-30 flex items-center px-6 justify-between">
      <div className="flex items-center gap-3">
        <h1 className="text-[15px] font-semibold tracking-tight">{pageTitle}</h1>
      </div>

      <div className="flex items-center gap-2">
        <button
          type="button"
          aria-label="Notifications"
          className="w-9 h-9 grid place-items-center rounded-lg text-slate-300 hover:text-snow hover:bg-white/[0.04] transition-colors"
        >
          <Bell size={16} strokeWidth={1.6} />
        </button>

        <div className="relative">
          <button
            type="button"
            onClick={() => setOpen((o) => !o)}
            className="flex items-center gap-2 pl-1.5 pr-2.5 py-1.5 rounded-pill bg-graphite-700/60 border border-white/[0.06] hover:bg-graphite-700 transition-colors"
          >
            <span className="w-7 h-7 rounded-full bg-ember/20 border border-ember/30 grid place-items-center text-[11px] font-semibold text-ember-soft">
              {initials || "··"}
            </span>
            <span className="text-xs text-snow max-w-[120px] truncate">
              {user?.name || user?.email || "Loading…"}
            </span>
            <ChevronDown size={14} strokeWidth={1.6} className="text-slate-400" />
          </button>

          {open && (
            <div className="absolute right-0 mt-2 w-56 card p-2 z-50">
              <div className="px-3 py-2">
                <div className="text-xs text-slate-400">Signed in as</div>
                <div className="text-sm text-snow truncate">{user?.email}</div>
              </div>
              <div className="border-t border-white/[0.05] my-1" />
              <button
                type="button"
                onClick={onLogout}
                className="w-full flex items-center gap-2 px-3 py-2 text-sm text-slate-300 hover:text-snow hover:bg-white/[0.04] rounded-lg transition-colors"
              >
                <LogOut size={14} strokeWidth={1.6} /> Log out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
