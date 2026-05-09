"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { Logo } from "@/components/Logo";
import { OAuthButtons } from "@/components/OAuthButtons";
import { api, bootstrapSession, setToken, type AuthResp } from "@/lib/api";

export default function SignupPage() {
  const router = useRouter();
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
      const data = await api<AuthResp>("/v1/auth/signup", {
        method: "POST",
        auth: false,
        body: { email, password, name },
      });
      setToken(data.token);
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Signup failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="min-h-screen flex items-center justify-center px-4 atmosphere-ember">
      <div className="w-full max-w-[400px] animate-fade-up">
        <div className="flex items-center justify-center mb-8">
          <Logo size={36} />
        </div>
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
