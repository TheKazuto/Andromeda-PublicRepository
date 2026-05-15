"use client";

import { useEffect, useState } from "react";
import { ShieldCheck, ShieldAlert, Copy, Check } from "lucide-react";
import { PageHeader } from "@/components/admin/PageHeader";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { adminAuth, type AdminMe } from "@/lib/admin-api";
import { errorMessage } from "@/lib/format";
import { copyToClipboard } from "@/lib/clipboard";

export default function AdminSecurityPage() {
  const [me, setMe] = useState<AdminMe | null>(null);
  const [setupSecret, setSetupSecret] = useState<string | null>(null);
  const [setupURI, setSetupURI] = useState<string | null>(null);
  const [verifyCode, setVerifyCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const [copied, setCopied] = useState<"secret" | "uri" | null>(null);
  const [askDisable, setAskDisable] = useState(false);

  async function loadMe() {
    const data = await adminAuth.me();
    setMe(data);
  }

  useEffect(() => {
    let cancelled = false;
    loadMe().catch((err) => {
      if (!cancelled) {
        setMessage({ tone: "error", text: errorMessage(err, "Load failed") });
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  async function startSetup() {
    setBusy(true);
    setMessage(null);
    try {
      const data = await adminAuth.totpSetup();
      setSetupSecret(data.secret);
      setSetupURI(data.uri);
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(err, "Could not start setup") });
    } finally {
      setBusy(false);
    }
  }

  async function verify() {
    if (verifyCode.length !== 6) return;
    setBusy(true);
    setMessage(null);
    try {
      await adminAuth.totpVerify(verifyCode);
      setSetupSecret(null);
      setSetupURI(null);
      setVerifyCode("");
      setMessage({ tone: "ok", text: "Two-factor authentication enabled." });
      await loadMe();
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(err, "Verification failed") });
    } finally {
      setBusy(false);
    }
  }

  async function confirmDisable() {
    setBusy(true);
    setMessage(null);
    try {
      await adminAuth.totpDisable();
      setAskDisable(false);
      setMessage({ tone: "ok", text: "Two-factor authentication disabled." });
      await loadMe();
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(err, "Disable failed") });
      throw err;
    } finally {
      setBusy(false);
    }
  }

  async function copyText(value: string, kind: "secret" | "uri") {
    const ok = await copyToClipboard(value);
    if (!ok) {
      setMessage({ tone: "error", text: "Clipboard blocked — copy manually." });
      return;
    }
    setCopied(kind);
    setTimeout(() => setCopied(null), 2000);
  }

  return (
    <main className="flex-1 px-6 lg:px-10 py-8 max-w-3xl">
      <PageHeader
        title="Security"
        description="Manage two-factor authentication on your admin account."
      />

      {me && (
        <div className="card p-5 mb-6 flex items-start gap-3">
          {me.mfaEnabled ? (
            <ShieldCheck className="text-emerald-400 mt-0.5 shrink-0" size={20} strokeWidth={1.8} />
          ) : (
            <ShieldAlert className="text-amber-300 mt-0.5 shrink-0" size={20} strokeWidth={1.8} />
          )}
          <div>
            <div className="text-sm text-snow font-medium">
              2FA is {me.mfaEnabled ? "enabled" : "disabled"}
              {me.mfaRequired && " (required)"}
            </div>
            <div className="text-xs text-slate-400 mt-1">
              {me.mfaEnabled
                ? "You will be asked for a TOTP code on every sign in."
                : "Enable 2FA to protect this admin account against credential leaks."}
            </div>
          </div>
        </div>
      )}

      {!setupSecret && me && !me.mfaEnabled && (
        <button type="button" className="btn-primary" disabled={busy} onClick={startSetup}>
          {busy ? "Starting…" : "Set up two-factor authentication"}
        </button>
      )}

      {!setupSecret && me?.mfaEnabled && (
        <button
          type="button"
          className="btn-secondary"
          disabled={busy}
          onClick={() => setAskDisable(true)}
        >
          Disable 2FA
        </button>
      )}

      {setupSecret && setupURI && (
        <div className="card p-6 space-y-5">
          <div>
            <div className="text-sm font-medium text-snow mb-1">1. Add account to authenticator</div>
            <p className="text-xs text-slate-400 mb-3">
              Open 1Password / Authy / Google Authenticator and either scan the URI or enter the
              setup key manually.
            </p>
            <div className="space-y-3">
              <CopyField
                label="Setup key (manual entry)"
                value={formatSecret(setupSecret)}
                onCopy={() => copyText(setupSecret, "secret")}
                copied={copied === "secret"}
              />
              <CopyField
                label="otpauth:// URI"
                value={setupURI}
                onCopy={() => copyText(setupURI, "uri")}
                copied={copied === "uri"}
                code
              />
            </div>
          </div>

          <div>
            <div className="text-sm font-medium text-snow mb-1">2. Confirm the code</div>
            <p className="text-xs text-slate-400 mb-3">
              Enter the current 6-digit code to finalise activation.
            </p>
            <div className="flex items-center gap-2">
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                value={verifyCode}
                onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, ""))}
                className="input-base font-mono tracking-[0.4em] text-center w-44"
                placeholder="000000"
              />
              <button
                type="button"
                className="btn-primary"
                disabled={busy || verifyCode.length !== 6}
                onClick={verify}
              >
                {busy ? "Verifying…" : "Verify & enable"}
              </button>
            </div>
          </div>
        </div>
      )}

      {message && (
        <div
          className={`mt-4 text-xs rounded-lg px-3 py-2 border ${
            message.tone === "ok"
              ? "text-emerald-300 bg-emerald-500/10 border-emerald-500/20"
              : "text-ember-soft bg-ember/10 border-ember/20"
          }`}
        >
          {message.text}
        </div>
      )}

      <ConfirmDialog
        open={askDisable}
        title="Disable two-factor authentication"
        description="Disable 2FA on your admin account? You will be able to sign in with just your password until you re-enable it. You can turn 2FA back on at any time."
        confirmLabel="Disable 2FA"
        busyLabel="Disabling…"
        danger
        onConfirm={confirmDisable}
        onCancel={() => setAskDisable(false)}
      />
    </main>
  );
}

interface CopyFieldProps {
  label: string;
  value: string;
  onCopy: () => void;
  copied: boolean;
  code?: boolean;
}

function CopyField({ label, value, onCopy, copied, code }: CopyFieldProps) {
  return (
    <div>
      <label className="label-base mb-1 block">{label}</label>
      <div className="flex items-stretch gap-2">
        <input
          readOnly
          value={value}
          className={`input-base flex-1 ${code ? "font-mono text-xs" : "font-mono text-sm"}`}
        />
        <button
          type="button"
          onClick={onCopy}
          className="px-3 py-2 rounded-lg border border-white/10 hover:bg-white/[0.04] text-slate-300 hover:text-snow text-xs transition-colors flex items-center gap-1.5"
          aria-label="Copy"
        >
          {copied ? (
            <>
              <Check size={13} strokeWidth={2} /> Copied
            </>
          ) : (
            <>
              <Copy size={13} strokeWidth={1.6} /> Copy
            </>
          )}
        </button>
      </div>
    </div>
  );
}

function formatSecret(s: string): string {
  // Group in chunks of 4 for readability.
  return s.replace(/(.{4})/g, "$1 ").trim();
}
