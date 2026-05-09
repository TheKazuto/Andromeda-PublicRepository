"use client";

import { useEffect, useState } from "react";
import { api, oauthStartURL, type AuthProviders } from "@/lib/api";

function GoogleIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 18 18" aria-hidden="true">
      <path fill="#4285F4" d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 0 1-1.8 2.72v2.26h2.92c1.7-1.57 2.68-3.88 2.68-6.62z" />
      <path fill="#34A853" d="M9 18c2.43 0 4.47-.81 5.96-2.18l-2.92-2.26c-.81.54-1.84.86-3.04.86-2.34 0-4.32-1.58-5.03-3.7H.96v2.32A9 9 0 0 0 9 18z" />
      <path fill="#FBBC05" d="M3.97 10.72A5.4 5.4 0 0 1 3.68 9c0-.6.1-1.18.29-1.72V4.96H.96A9 9 0 0 0 0 9c0 1.45.35 2.83.96 4.04l3.01-2.32z" />
      <path fill="#EA4335" d="M9 3.58c1.32 0 2.5.45 3.43 1.34l2.58-2.58A9 9 0 0 0 9 0 9 9 0 0 0 .96 4.96l3.01 2.32C4.68 5.16 6.66 3.58 9 3.58z" />
    </svg>
  );
}

function GitHubIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M8 0a8 8 0 0 0-2.53 15.59c.4.07.55-.17.55-.38v-1.46c-2.22.48-2.69-.95-2.69-.95-.36-.92-.89-1.16-.89-1.16-.73-.5.05-.49.05-.49.8.06 1.23.83 1.23.83.72 1.23 1.88.87 2.34.67.07-.52.28-.87.5-1.07-1.77-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.01.08-2.12 0 0 .67-.21 2.2.82A7.6 7.6 0 0 1 8 4.07c.68 0 1.36.09 2 .27 1.53-1.03 2.2-.82 2.2-.82.44 1.11.16 1.92.08 2.12.51.56.82 1.28.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48v2.19c0 .21.15.46.55.38A8 8 0 0 0 8 0z" />
    </svg>
  );
}

type Props = {
  intent: "signin" | "signup";
};

export function OAuthButtons({ intent }: Props) {
  const [providers, setProviders] = useState<AuthProviders | null>(null);

  useEffect(() => {
    let cancelled = false;
    api<AuthProviders>("/v1/auth/providers", { auth: false })
      .then((data) => {
        if (!cancelled) setProviders(data);
      })
      .catch(() => {
        if (!cancelled) setProviders({ google: false, github: false });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const verbGoogle = intent === "signup" ? "Sign up with Google" : "Continue with Google";
  const verbGitHub = intent === "signup" ? "Sign up with GitHub" : "Continue with GitHub";

  if (!providers) {
    return (
      <div className="flex flex-col gap-2.5">
        <div className="h-[42px] rounded-lg bg-graphite-700/40 animate-pulse" />
        <div className="h-[42px] rounded-lg bg-graphite-700/40 animate-pulse" />
      </div>
    );
  }

  if (!providers.google && !providers.github) return null;

  return (
    <div className="flex flex-col gap-2.5">
      {providers.google && (
        <a href={oauthStartURL("google")} className="btn-secondary">
          <GoogleIcon />
          {verbGoogle}
        </a>
      )}
      {providers.github && (
        <a href={oauthStartURL("github")} className="btn-secondary">
          <GitHubIcon />
          {verbGitHub}
        </a>
      )}
      <div className="flex items-center gap-3 my-3">
        <div className="flex-1 h-px bg-white/[0.06]" />
        <span className="text-[11px] uppercase tracking-[0.12em] text-slate-400">or</span>
        <div className="flex-1 h-px bg-white/[0.06]" />
      </div>
    </div>
  );
}
