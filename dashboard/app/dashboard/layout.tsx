"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/Sidebar";
import { bootstrapSession, registerSessionLostHandler } from "@/lib/api";
import { UserProvider } from "@/lib/user-context";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let cancelled = false;

    // `registerSessionLostHandler` now returns an unsubscribe function so we
    // can safely scope the redirect handler to this layout instance — no
    // dangling listeners trying to navigate after unmount.
    const unsubscribe = registerSessionLostHandler(() => {
      router.replace("/login");
    });

    (async () => {
      const ok = await bootstrapSession();
      if (cancelled) return;
      if (!ok) {
        router.replace("/login");
        return;
      }
      setReady(true);
    })();

    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, [router]);

  if (!ready) {
    return (
      <main className="min-h-screen grid place-items-center">
        <div className="text-sm text-slate-400">Loading…</div>
      </main>
    );
  }

  return (
    <UserProvider>
      <div className="flex min-h-screen bg-void">
        <Sidebar />
        <div className="flex-1 min-w-0 flex flex-col">{children}</div>
      </div>
    </UserProvider>
  );
}
