"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, ShieldCheck, KeyRound } from "lucide-react";
import { Logo } from "@/components/Logo";
import {
  adminAuth,
  setAdminToken,
  hasAdminToken,
  AdminAPIError,
} from "@/lib/admin-api";

type Stage = "credentials" | "totp";

export default function AdminLoginPage() {
  const router = useRouter();

  const [stage, setStage] = useState<Stage>("credentials");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (hasAdminToken()) router.replace("/admin");
  }, [router]);

  async function handleLogin(code?: string) {
    setError(null);
    setLoading(true);
    try {
      const data = await adminAuth.login({
        email: email.trim().toLowerCase(),
        password,
        totpCode: code,
      });
      setAdminToken(data.token, data.expiresAt);
      router.push("/admin");
    } catch (err: unknown) {
      if (err instanceof AdminAPIError) {
        if (err.code === "totp_required") {
          setStage("totp");
          setError(null);
          return;
        }
        if (err.code === "invalid_totp") {
          setError("Invalid 2FA code. Try again.");
          return;
        }
        setError(err.message || "Sign in failed");
        return;
      }
      setError("Sign in failed");
    } finally {
      setLoading(false);
    }
  }

  function onSubmitCredentials(e: React.FormEvent) {
    e.preventDefault();
    handleLogin();
  }

  function onSubmitTOTP(e: React.FormEvent) {
    e.preventDefault();
    handleLogin(totpCode.trim());
  }

  function backToCredentials() {
    setStage("credentials");
    setTotpCode("");
    setError(null);
  }

  return (
    <main className="min-h-screen flex items-center justify-center px-4 atmosphere-ember bg-void">
      <div className="w-full max-w-[420px] animate-fade-up">
        <div className="flex items-center justify-center gap-2 mb-8">
          <Logo size={36} />
          <span className="text-[11px] font-mono uppercase tracking-[0.18em] text-ember">
            Admin Console
          </span>
        </div>

        <div className="card p-7">
          <div className="flex items-center gap-3 mb-1">
            {stage === "totp" ? (
              <ShieldCheck size={22} className="text-ember" strokeWidth={1.8} />
            ) : (
              <KeyRound size={22} className="text-ember" strokeWidth={1.8} />
            )}
            <h1 className="text-[22px] font-semibold tracking-tight">
              {stage === "totp" ? "Two-factor required" : "Admin sign in"}
            </h1>
          </div>
          <p className="text-sm text-slate-300 mb-6">
            {stage === "totp"
              ? "Enter the 6-digit code from your authenticator app."
              : "Restricted access — Andromeda operators only."}
          </p>

          {stage === "credentials" && (
            <form onSubmit={onSubmitCredentials} className="flex flex-col gap-4">
              <div>
                <label className="label-base mb-1.5 block" htmlFor="email">
                  Email
                </label>
                <input
                  id="email"
                  type="email"
                  required
                  autoComplete="email"
                  autoFocus
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input-base"
                  placeholder="admin@shinkalabs.com"
                />
              </div>
              <div>
                <label className="label-base mb-1.5 block" htmlFor="password">
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  required
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input-base"
                  placeholder="••••••••"
                  minLength={12}
                />
              </div>

              {error && (
                <div className="text-xs text-ember-soft bg-ember/10 border border-ember/20 rounded-lg px-3 py-2">
                  {error}
                </div>
              )}

              <button type="submit" disabled={loading} className="btn-primary mt-2">
                {loading ? (
                  "Signing in…"
                ) : (
                  <>
                    Continue <ArrowRight size={14} strokeWidth={1.6} />
                  </>
                )}
              </button>
            </form>
          )}

          {stage === "totp" && (
            <form onSubmit={onSubmitTOTP} className="flex flex-col gap-4">
              <div>
                <label className="label-base mb-1.5 block" htmlFor="totp">
                  Authenticator code
                </label>
                <input
                  id="totp"
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  required
                  autoFocus
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ""))}
                  className="input-base font-mono tracking-[0.4em] text-center text-lg"
                  placeholder="000000"
                  autoComplete="one-time-code"
                />
                <p className="text-[11px] text-slate-400 mt-2">
                  Six digits from your TOTP app (1Password, Authy, Google Authenticator).
                </p>
              </div>

              {error && (
                <div className="text-xs text-ember-soft bg-ember/10 border border-ember/20 rounded-lg px-3 py-2">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading || totpCode.length !== 6}
                className="btn-primary mt-1"
              >
                {loading ? (
                  "Verifying…"
                ) : (
                  <>
                    Verify <ArrowRight size={14} strokeWidth={1.6} />
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={backToCredentials}
                className="text-xs text-slate-400 hover:text-snow transition-colors"
              >
                ← Use a different account
              </button>
            </form>
          )}
        </div>

        <p className="text-center text-[11px] text-slate-500 mt-5 font-mono">
          v1 admin gate · sessions expire after 8 hours
        </p>
      </div>
    </main>
  );
}
