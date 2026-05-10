"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import dynamic from "next/dynamic";
import { ArrowRight } from "lucide-react";
import { OAuthButtons } from "@/components/OAuthButtons";
import { api, bootstrapSession, setToken, type AuthResp } from "@/lib/api";

const SpacetimeBackground = dynamic(
  () => import("@/components/SpacetimeBackground").then((m) => m.SpacetimeBackground),
  { ssr: false },
);

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const ok = await bootstrapSession();
      if (cancelled) return;
      if (ok) router.replace("/dashboard");
    })();
    return () => {
      cancelled = true;
    };
  }, [router]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const data = await api<AuthResp>("/v1/auth/login", {
        method: "POST",
        auth: false,
        body: { email, password },
      });
      setToken(data.token);
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="relative min-h-screen flex items-center justify-center px-4">
      <SpacetimeBackground />
      <div className="relative w-full max-w-[400px] animate-fade-up" style={{ zIndex: 10 }}>
        <div className="card p-7">
          <h1 className="text-[22px] font-semibold tracking-tight mb-1">Welcome back</h1>
          <p className="text-sm text-slate-300 mb-6">Sign in to your Andromeda dashboard.</p>

          <OAuthButtons intent="signin" />

          <form onSubmit={onSubmit} className="flex flex-col gap-4">
            <div>
              <label className="label-base mb-1.5 block" htmlFor="email">Email</label>
              <input
                id="email"
                type="email"
                required
                autoComplete="email"
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
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="input-base"
                placeholder="••••••••"
                minLength={8}
              />
            </div>
            {error && (
              <div className="text-xs text-ember-soft bg-ember/10 border border-ember/20 rounded-lg px-3 py-2">
                {error}
              </div>
            )}
            <button type="submit" disabled={loading} className="btn-primary mt-2">
              {loading ? "Signing in…" : (<>Sign in <ArrowRight size={14} strokeWidth={1.6} /></>)}
            </button>
            <div className="text-center mt-1">
              <Link
                href="/auth/forgot"
                className="text-xs text-slate-400 hover:text-snow transition-colors"
              >
                Forgot your password?
              </Link>
            </div>
          </form>
        </div>

        <p className="text-center text-sm text-slate-300 mt-5">
          Don&apos;t have an account?{" "}
          <Link href="/signup" className="text-snow hover:text-ember transition-colors">
            Create one
          </Link>
        </p>
      </div>
    </main>
  );
}
