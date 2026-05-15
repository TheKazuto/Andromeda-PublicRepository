"use client";

import { useState } from "react";
import Link from "next/link";
import { Logo } from "@/components/Logo";
import { passwords, APIError } from "@/lib/api";
import { errorMessage } from "@/lib/format";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await passwords.forgot(email.trim());
      setDone(true);
    } catch (err) {
      // The backend always returns 200 for /forgot-password, so the only
      // way we end up here is a network error. Show a generic message.
      setError(
        err instanceof APIError
          ? err.message
          : errorMessage(err, "Could not reach the server. Please try again."),
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
            Reset your password
          </h1>
          <p className="text-sm text-slate-300 mb-6">
            Enter the email associated with your Andromeda account. We will
            send you a link to set a new password.
          </p>

          {done ? (
            <div className="text-sm text-slate-200">
              <p>
                If an account exists for that email, a reset link is on its way.
                The link expires in 30 minutes — check your inbox (and your
                spam folder) and follow the instructions to choose a new
                password.
              </p>
              <p className="mt-4">
                <Link
                  href="/login"
                  className="text-snow hover:text-ember transition-colors"
                >
                  Back to sign in
                </Link>
              </p>
            </div>
          ) : (
            <form onSubmit={onSubmit} className="flex flex-col gap-4">
              <div>
                <label className="label-base mb-1.5 block" htmlFor="email">
                  Email
                </label>
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
              {error && (
                <div className="text-xs text-ember-soft bg-ember/10 border border-ember/20 rounded-lg px-3 py-2">
                  {error}
                </div>
              )}
              <button
                type="submit"
                disabled={submitting}
                className="btn-primary mt-2"
              >
                {submitting ? "Sending…" : "Send reset link"}
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
