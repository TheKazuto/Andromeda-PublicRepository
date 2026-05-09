"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { AdminSidebar } from "@/components/admin/AdminSidebar";
import {
  hasAdminToken,
  adminAuth,
  clearAdminToken,
  AdminAPIError,
  type AdminMe,
} from "@/lib/admin-api";

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const isLoginPage = pathname === "/admin/login";

  const [me, setMe] = useState<AdminMe | null>(null);
  const [ready, setReady] = useState(isLoginPage);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isLoginPage) {
      setReady(true);
      return;
    }
    if (!hasAdminToken()) {
      router.replace("/admin/login");
      return;
    }

    let cancelled = false;
    adminAuth
      .me()
      .then((data) => {
        if (cancelled) return;
        setMe(data);
        setReady(true);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        if (err instanceof AdminAPIError && err.status === 401) {
          clearAdminToken();
          router.replace("/admin/login");
          return;
        }
        const message = err instanceof Error ? err.message : "Failed to load admin profile";
        setError(message);
        setReady(true);
      });

    return () => {
      cancelled = true;
    };
  }, [router, isLoginPage]);

  if (isLoginPage) {
    return <>{children}</>;
  }

  if (!ready) {
    return (
      <main className="min-h-screen grid place-items-center bg-void">
        <div className="text-sm text-slate-400">Loading admin console…</div>
      </main>
    );
  }

  if (error) {
    return (
      <main className="min-h-screen grid place-items-center px-4 bg-void">
        <div className="card p-6 max-w-md text-center">
          <div className="text-snow font-semibold mb-2">Admin console unavailable</div>
          <div className="text-sm text-slate-300 mb-4">{error}</div>
          <button
            type="button"
            className="btn-primary mx-auto"
            onClick={() => {
              clearAdminToken();
              router.replace("/admin/login");
            }}
          >
            Sign in again
          </button>
        </div>
      </main>
    );
  }

  return (
    <div className="flex min-h-screen bg-void">
      <AdminSidebar me={me} />
      <div className="flex-1 min-w-0 flex flex-col">{children}</div>
    </div>
  );
}
