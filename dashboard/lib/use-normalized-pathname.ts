"use client";

import { usePathname } from "next/navigation";

// `next.config.js` uses `trailingSlash: true`, so `/dashboard/` is the
// canonical path — strip the trailing slash so comparisons against the
// route table (`/dashboard`, `/admin`, …) line up.
export function useNormalizedPathname(): string {
  const raw = usePathname();
  return (raw ?? "").replace(/\/+$/, "") || "/";
}
