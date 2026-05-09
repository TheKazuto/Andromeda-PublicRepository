"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { bootstrapSession } from "@/lib/api";

export default function Home() {
  const router = useRouter();

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const ok = await bootstrapSession();
      if (cancelled) return;
      router.replace(ok ? "/dashboard" : "/login");
    })();
    return () => {
      cancelled = true;
    };
  }, [router]);

  return null;
}
