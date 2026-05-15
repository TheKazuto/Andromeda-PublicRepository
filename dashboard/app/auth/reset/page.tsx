"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { Logo } from "@/components/Logo";
import { passwords, APIError } from "@/lib/api";
import { errorMessage } from "@/lib/format";

const MIN_PASSWORD_LEN = 8;

export default function ResetPasswordPage() {
  return (
    <Suspense
      fallback={
        <main className="min-h-screen grid place-items-center bg-void">
          <div className="text-sm text-slate-400">Loading…</div>
        </main>
      }
    >
      <ResetPasswordPageInner />
    </Suspense>
  );
}

function ResetPasswordPageInner() {
  const router = useRouter();
  const search = useSearchParams();
  const token = useMemo(() => (search?.get("token") ?? "").trim(), [search]);

  const [pw1, setPw1] = useState("");
  const [pw2, setPw2] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) {
      setError("This reset link is missing its token. Request a new one.");
    }
  }, [token]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (pw1.length < MIN_PASSWORD_LEN) {
      setError(`Password must be at least ${MIN_PASSWORD_LEN} characters.`);
      return;
    }
    if (pw1 !== pw2) {
      setError("Passwords do not match.");
      return;
    }
    setSubmitting(true);
    try {
      await passwords.reset(token, pw1);
      setDone(true);
      setTimeout(() => router.replace("/login"), 1500);
    } catch (err) {
      setError(
        err instanceof APIError
          ? err.message
          : errorMessage(err, "Could not reset password. Please try again."),
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="min-h-screen flex items-center justify-center px-4 atmosphere-ember">
      <div className="w-full max-w-[400px] animate-fade-up">
        <div className="flex items-center justify-center mb-8">
          <Logo size={36} />
        </div>
        <div className="card p-7">
          <h1 className="text-[22px] font-semibold tracking-tight mb-1">
            Choose a new password
          </h1>
          <p className="text-sm text-slate-300 mb-6">
            Pick something memorable. The reset link is single-use and stops
            working once you submit.
          </p>

          {done ? (
            <div className="text-sm text-slate-200">
              Your password has been updated. Taking you back to the sign-in
              page…
            </div>
          ) : (
            <form onSubmit={onSubmit} className="flex flex-col gap-4">
              <div>
                <label className="label-base mb-1.5 block" htmlFor="pw1">
                  New password
                </label>
                <input
                  id="pw1"
                  type="password"
                  required
                  autoComplete="new-password"
                  value={pw1}
                  onChange={(e) => setPw1(e.target.value)}
                  className="input-base"
                  placeholder="••••••••"
                  minLength={MIN_PASSWORD_LEN}
                />
              </div>
              <div>
                <label className="label-base mb-1.5 block" htmlFor="pw2">
                  Confirm password
                </label>
                <input
                  id="pw2"
                  type="password"
                  required
                  autoComplete="new-password"
                  value={pw2}
                  onChange={(e) => setPw2(e.target.value)}
                  className="input-base"
                  placeholder="••••••••"
                  minLength={MIN_PASSWORD_LEN}
                />
              </div>
              {error && (
                <div className="text-xs text-ember-soft bg-ember/10 border border-ember/20 rounded-lg px-3 py-2">
                  {error}
                </div>
              )}
              <button
                type="submit"
                disabled={submitting || !token}
                className="btn-primary mt-2"
              >
                {submitting ? "Saving…" : "Reset password"}
              </button>
              <div className="text-center mt-1">
                <Link
                  href="/login"
                  className="text-xs text-slate-400 hover:text-snow transition-colors"
                >
                  Back to sign in
                </Link>
              </div>
            </form>
          )}
        </div>
      </div>
    </main>
  );
}
