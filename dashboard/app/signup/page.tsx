"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import dynamic from "next/dynamic";
import { ArrowRight } from "lucide-react";
import { OAuthButtons } from "@/components/OAuthButtons";
import { api, bootstrapSession, setToken, type AuthResp } from "@/lib/api";
import { errorMessage } from "@/lib/format";

const SpacetimeBackground = dynamic(
  () => import("@/components/SpacetimeBackground").then((m) => m.SpacetimeBackground),
  { ssr: false },
);

function safeNext(raw: string | null): string {
  if (!raw) return "/dashboard";
  if (!raw.startsWith("/") || raw.startsWith("//")) return "/dashboard";
  return raw;
}

export default function SignupPage() {
  return (
    <Suspense
      fallback={
        <main className="min-h-screen grid place-items-center bg-void">
          <div className="text-sm text-slate-400">Loading…</div>
        </main>
      }
    >
      <SignupPageInner />
    </Suspense>
  );
}

function SignupPageInner() {
  const router = useRouter();
  const search = useSearchParams();
  const next = useMemo(() => safeNext(search?.get("next") ?? null), [search]);

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const ok = await bootstrapSession();
      if (cancelled) return;
      if (ok) router.replace(next);
    })();
    return () => {
      cancelled = true;
    };
  }, [router, next]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const data = await api<AuthResp>("/v1/auth/signup", {
        method: "POST",
        auth: false,
        body: { email, password, name },
      });
      setToken(data.token);
      router.push(next);
    } catch (err) {
      setError(errorMessage(err, "Signup failed"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="relative min-h-screen flex items-center justify-center px-4">
      <SpacetimeBackground />
      <div className="relative w-full max-w-[400px] animate-fade-up" style={{ zIndex: 10 }}>
        <div className="card p-7">
          <h1 className="text-[22px] font-semibold tracking-tight mb-1">Create your account</h1>
          <p className="text-sm text-slate-300 mb-6">Start with the free Explorer plan — no credit card required.</p>

          <OAuthButtons intent="signup" />

          <form onSubmit={onSubmit} className="flex flex-col gap-4">
            <div>
              <label className="label-base mb-1.5 block" htmlFor="name">Name</label>
              <input
                id="name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="input-base"
                placeholder="Ada Lovelace"
              />
            </div>
            <div>
              <label className="label-base mb-1.5 block" htmlFor="email">Email</label>
              <input
                id="email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="input-base"
                placeholder="you@company.com"
              />
            </div>
            <div>
              <label className="label-base mb-1.5 block" htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="input-base"
                placeholder="At least 8 characters"
              />
            </div>
            {error && (
              <div className="text-xs text-ember-soft bg-ember/10 border border-ember/20 rounded-lg px-3 py-2">
                {error}
              </div>
            )}
            <button type="submit" disabled={loading} className="btn-primary mt-2">
              {loading ? "Creating account…" : (<>Create account <ArrowRight size={14} strokeWidth={1.6} /></>)}
            </button>
          </form>
        </div>

        <p className="text-center text-sm text-slate-300 mt-5">
          Already have an account?{" "}
          <Link href="/login" className="text-snow hover:text-ember transition-colors">
            Sign in
          </Link>
        </p>
      </div>
    </main>
  );
}
