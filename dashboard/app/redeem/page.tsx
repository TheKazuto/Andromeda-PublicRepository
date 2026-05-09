"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { Gift, Sparkles, ShieldCheck, Clock, AlertCircle } from "lucide-react";
import { Logo } from "@/components/Logo";
import {
  bootstrapSession,
  APIError,
  gifts,
  type GiftPreview,
  type GiftRedeemResp,
} from "@/lib/api";

export default function RedeemPage() {
  return (
    <Suspense
      fallback={
        <main className="min-h-screen grid place-items-center bg-void">
          <div className="text-sm text-slate-400">Loading…</div>
        </main>
      }
    >
      <RedeemPageInner />
    </Suspense>
  );
}

type Stage = "loading" | "preview" | "redeemed" | "error";

function RedeemPageInner() {
  const router = useRouter();
  const search = useSearchParams();
  const token = useMemo(() => (search?.get("token") ?? "").trim(), [search]);

  const [stage, setStage] = useState<Stage>("loading");
  const [preview, setPreview] = useState<GiftPreview | null>(null);
  const [redemption, setRedemption] = useState<GiftRedeemResp | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [signedIn, setSignedIn] = useState<boolean>(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const ok = await bootstrapSession();
      if (!cancelled) setSignedIn(ok);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!token) {
      setError("Missing redeem token. Please use the full link you received.");
      setStage("error");
      return;
    }
    let cancelled = false;
    gifts
      .preview(token)
      .then((p) => {
        if (cancelled) return;
        setPreview(p);
        setStage("preview");
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const message =
          err instanceof APIError
            ? err.status === 404
              ? "This gift link is invalid."
              : err.message
            : "Could not load gift card";
        setError(message);
        setStage("error");
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  async function onRedeem() {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      const data = await gifts.redeem(token);
      setRedemption(data);
      setStage("redeemed");
    } catch (err: unknown) {
      if (err instanceof APIError) {
        if (err.status === 401) {
          setError("Sign in required.");
        } else {
          setError(err.message);
        }
      } else {
        setError("Redeem failed");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen flex items-center justify-center px-4 atmosphere-ember bg-void">
      <div className="w-full max-w-[480px] animate-fade-up">
        <div className="flex items-center justify-center gap-2 mb-8">
          <Logo size={36} />
          <span className="text-[11px] font-mono uppercase tracking-[0.18em] text-ember">
            Gift Redemption
          </span>
        </div>

        {stage === "loading" && (
          <div className="card p-7 text-center">
            <div className="text-sm text-slate-400">Loading gift card…</div>
          </div>
        )}

        {stage === "error" && (
          <div className="card p-7 text-center">
            <div className="flex items-center justify-center mb-3">
              <AlertCircle className="text-ember" size={32} strokeWidth={1.6} />
            </div>
            <h1 className="text-[20px] font-semibold tracking-tight mb-2">
              Gift unavailable
            </h1>
            <p className="text-sm text-slate-300">{error}</p>
            <Link href="/" className="btn-secondary mt-5 inline-flex">
              Go back
            </Link>
          </div>
        )}

        {stage === "preview" && preview && (
          <PreviewCard
            preview={preview}
            signedIn={signedIn}
            busy={busy}
            error={error}
            onRedeem={onRedeem}
            onSignIn={() =>
              router.push(`/login?next=${encodeURIComponent(`/redeem?token=${token}`)}`)
            }
          />
        )}

        {stage === "redeemed" && redemption && (
          <RedeemedCard redemption={redemption} />
        )}
      </div>
    </main>
  );
}

interface PreviewCardProps {
  preview: GiftPreview;
  signedIn: boolean;
  busy: boolean;
  error: string | null;
  onRedeem: () => void;
  onSignIn: () => void;
}

function PreviewCard({
  preview,
  signedIn,
  busy,
  error,
  onRedeem,
  onSignIn,
}: PreviewCardProps) {
  if (preview.status !== "redeemable") {
    return (
      <div className="card p-7 text-center">
        <div className="flex items-center justify-center mb-3">
          <AlertCircle className="text-amber-300" size={32} strokeWidth={1.6} />
        </div>
        <h1 className="text-[20px] font-semibold tracking-tight mb-2">
          {preview.status === "redeemed"
            ? "Already redeemed"
            : preview.status === "refunded"
            ? "Refunded"
            : "Expired"}
        </h1>
        <p className="text-sm text-slate-300">
          {preview.status === "redeemed" && "This gift has already been used."}
          {preview.status === "refunded" && "The buyer refunded this gift."}
          {preview.status === "expired" && "This gift has expired."}
        </p>
      </div>
    );
  }

  return (
    <div className="card p-7">
      <div className="flex items-center gap-3 mb-3">
        <Gift size={26} strokeWidth={1.6} className="text-ember" />
        <h1 className="text-[22px] font-semibold tracking-tight">
          You&apos;ve received a gift
        </h1>
      </div>

      <div className="rounded-card bg-graphite-700/40 border border-white/[0.05] p-4 mb-5">
        <div className="text-[11px] uppercase tracking-[0.14em] text-slate-400 font-mono">
          Andromeda subscription
        </div>
        <div className="mt-1 text-2xl font-semibold tracking-tight text-snow capitalize">
          {preview.planCode}
        </div>
        <div className="mt-1 text-sm text-slate-300">
          {preview.durationMonths === 1
            ? "1 month"
            : `${preview.durationMonths} months`}{" "}
          — {preview.source === "promo" ? "promotional" : "paid"} gift
        </div>
        {preview.message && (
          <div className="mt-3 pt-3 border-t border-white/[0.05]">
            <div className="text-[11px] uppercase tracking-[0.14em] text-slate-400 font-mono mb-1">
              Message
            </div>
            <p className="text-sm text-slate-200 italic">&ldquo;{preview.message}&rdquo;</p>
          </div>
        )}
      </div>

      <div className="flex items-center gap-2 text-xs text-slate-400 mb-5">
        <Clock size={12} strokeWidth={1.8} />
        Redeem before {new Date(preview.expiresAt).toLocaleDateString()}
      </div>

      {signedIn ? (
        <button
          type="button"
          disabled={busy}
          onClick={onRedeem}
          className="btn-primary w-full"
        >
          {busy ? (
            "Applying gift…"
          ) : (
            <>
              <Sparkles size={14} strokeWidth={1.8} />
              Apply to my account
            </>
          )}
        </button>
      ) : (
        <>
          <button type="button" onClick={onSignIn} className="btn-primary w-full">
            <ShieldCheck size={14} strokeWidth={1.8} />
            Sign in to redeem
          </button>
          <p className="text-center text-xs text-slate-400 mt-3">
            Don&apos;t have an account?{" "}
            <Link href="/signup" className="text-snow hover:text-ember transition-colors">
              Create one
            </Link>
          </p>
        </>
      )}

      {error && (
        <div className="mt-4 text-xs text-ember-soft bg-ember/10 border border-ember/20 rounded-lg px-3 py-2">
          {error}
        </div>
      )}
    </div>
  );
}

function RedeemedCard({ redemption }: { redemption: GiftRedeemResp }) {
  const verb =
    redemption.action === "created"
      ? "Plan activated"
      : redemption.action === "upgraded"
      ? "Plan upgraded"
      : "Subscription extended";

  return (
    <div className="card p-7 text-center">
      <div className="flex items-center justify-center mb-3">
        <Sparkles className="text-ember" size={32} strokeWidth={1.6} />
      </div>
      <h1 className="text-[22px] font-semibold tracking-tight mb-2">{verb}</h1>
      <p className="text-sm text-slate-300 mb-5">
        {formatRedemptionMessage(redemption)}
      </p>
      <Link href="/dashboard" className="btn-primary inline-flex">
        Go to dashboard
      </Link>
    </div>
  );
}

function formatRedemptionMessage(r: GiftRedeemResp): string {
  const tokens = r.addedTokens.toLocaleString();
  const months = Math.round(r.addedDays / 30);
  switch (r.action) {
    case "created":
      return `Your account is now active on ${r.gift.planCode} for ${months} ${
        months === 1 ? "month" : "months"
      } (${tokens} tokens).`;
    case "upgraded":
      return `Welcome to ${r.gift.planCode} — your plan has been upgraded and the period extended by ${months} ${
        months === 1 ? "month" : "months"
      } (${tokens} tokens added).`;
    case "extended":
    default:
      return `Your subscription has been extended by ${months} ${
        months === 1 ? "month" : "months"
      } and ${tokens} tokens were added to the period.`;
  }
}
