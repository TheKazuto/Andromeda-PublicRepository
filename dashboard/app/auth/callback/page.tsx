"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Logo } from "@/components/Logo";
import { setToken } from "@/lib/api";

const ERROR_MESSAGES: Record<string, string> = {
  invalid_state: "Your sign-in session expired. Please try again.",
  exchange_failed: "We couldn't complete sign-in with the provider.",
  account_error: "We couldn't link or create your account.",
  token_error: "We couldn't issue a session token.",
  missing_params: "The provider response was incomplete.",
  provider_not_enabled: "This sign-in method isn't enabled.",
};

export default function AuthCallbackPage() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (typeof window === "undefined") return;

    const fragment = window.location.hash.startsWith("#")
      ? window.location.hash.slice(1)
      : window.location.hash;
    const params = new URLSearchParams(fragment);

    const token = params.get("token");
    const errorCode = params.get("error");

    if (token) {
      setToken(token);
      window.history.replaceState(null, "", window.location.pathname);
      router.replace("/dashboard");
      return;
    }

    if (errorCode) {
      setError(ERROR_MESSAGES[errorCode] || `Sign-in failed (${errorCode}).`);
      return;
    }

    setError("No sign-in result was returned. Please try again.");
  }, [router]);

  return (
    <main className="min-h-screen flex items-center justify-center px-4 atmosphere-ember">
      <div className="w-full max-w-[400px] animate-fade-up">
        <div className="flex items-center justify-center mb-8">
          <Logo size={36} />
        </div>
        <div className="card p-7 text-center">
          {error ? (
            <>
              <h1 className="text-[20px] font-semibold tracking-tight mb-2">
                Sign-in failed
              </h1>
              <p className="text-sm text-slate-300 mb-5">{error}</p>
              <button
                type="button"
                className="btn-primary w-full"
                onClick={() => router.replace("/login")}
              >
                Back to sign in
              </button>
            </>
          ) : (
            <>
              <h1 className="text-[20px] font-semibold tracking-tight mb-2">
                Signing you in…
              </h1>
              <p className="text-sm text-slate-300">
                Hold tight while we finish the handshake.
              </p>
            </>
          )}
        </div>
      </div>
    </main>
  );
}
