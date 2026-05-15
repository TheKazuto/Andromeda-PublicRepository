"use client";

import { useEffect, useState } from "react";
import { Save, AlertTriangle, ShieldCheck } from "lucide-react";
import { Topbar } from "@/components/Topbar";
import { PageTitle } from "@/components/PageTitle";
import { Modal } from "@/components/Modal";
import { api, me, type User, logoutSession, APIError } from "@/lib/api";
import { errorMessage } from "@/lib/format";
import { useUser } from "@/lib/user-context";
import { useRouter } from "next/navigation";

const MIN_PASSWORD_LEN = 8;

export default function SettingsPage() {
  const router = useRouter();
  const { user, refresh, setUser } = useUser();
  const [name, setName] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [showPwForm, setShowPwForm] = useState(false);
  const [showDelete, setShowDelete] = useState(false);

  // Mirror the context's user into the local `name` field on first load and
  // whenever the upstream value changes (e.g. after profile refresh).
  useEffect(() => {
    if (user) setName(user.name || "");
  }, [user]);

  async function onSave(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      const u = await api<User>("/v1/me", { method: "PATCH", body: { name } });
      setUser(u);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      setError(errorMessage(err, "Failed to save"));
    } finally {
      setSaving(false);
    }
  }

  async function onLogout() {
    await logoutSession();
    router.push("/login");
  }

  async function onDeleted() {
    await logoutSession();
    router.push("/login");
  }

  return (
    <>
      <Topbar pageTitle="Settings" />
      <main className="flex-1 px-6 py-8 overflow-auto">
        <div className="max-w-[840px] mx-auto">
          <PageTitle
            eyebrow="// account"
            title="Settings"
            description="Manage your profile, security, and account preferences."
          />

          {/* Profile */}
          <div className="card p-6 mb-6">
            <h3 className="text-[15px] font-semibold tracking-tight mb-1">Profile</h3>
            <p className="text-sm text-slate-300 mb-5">Your name and contact details.</p>
            <form onSubmit={onSave} className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="label-base mb-1.5 block" htmlFor="s-name">Name</label>
                <input
                  id="s-name"
                  className="input-base"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div>
                <label className="label-base mb-1.5 block" htmlFor="s-email">Email</label>
                <input
                  id="s-email"
                  className="input-base bg-graphite-700/30"
                  value={user?.email || ""}
                  disabled
                />
                <p className="text-[11px] text-slate-400 mt-1.5">
                  Contact support to change your email.
                </p>
              </div>
              <div className="sm:col-span-2 flex items-center justify-between">
                {error && <div className="text-xs text-ember-soft">{error}</div>}
                {saved && <div className="text-xs text-signal-mint">Saved</div>}
                <button type="submit" disabled={saving} className="btn-primary ml-auto">
                  <Save size={14} strokeWidth={1.6} />
                  {saving ? "Saving…" : "Save changes"}
                </button>
              </div>
            </form>
          </div>

          {/* Security */}
          <div className="card p-6 mb-6">
            <h3 className="text-[15px] font-semibold tracking-tight mb-1">Security</h3>
            <p className="text-sm text-slate-300 mb-5">Password and authenticator settings.</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <button
                type="button"
                className="btn-secondary justify-start"
                onClick={() => setShowPwForm((v) => !v)}
              >
                {showPwForm ? "Cancel" : "Change password"}
              </button>
              <button
                type="button"
                className="btn-secondary justify-start"
                disabled
                title="Coming soon"
              >
                Two-factor authentication (soon)
              </button>
            </div>
            {showPwForm && (
              <ChangePasswordForm
                onDone={() => {
                  setShowPwForm(false);
                  void refresh();
                }}
              />
            )}
          </div>

          {/* Sessions */}
          <div className="card p-6 mb-6">
            <h3 className="text-[15px] font-semibold tracking-tight mb-1">Active session</h3>
            <p className="text-sm text-slate-300 mb-5">You can sign out from this device any time.</p>
            <button onClick={onLogout} className="btn-secondary">
              Log out of this device
            </button>
          </div>

          {/* Danger */}
          <div className="card p-6 border-ember/15">
            <div className="flex items-start gap-3">
              <div className="w-9 h-9 rounded-lg bg-ember/12 border border-ember/25 grid place-items-center text-ember-soft shrink-0">
                <AlertTriangle size={16} strokeWidth={1.6} />
              </div>
              <div className="flex-1">
                <h3 className="text-[15px] font-semibold tracking-tight mb-1">Delete account</h3>
                <p className="text-sm text-slate-300 mb-4">
                  This permanently anonymizes your account, revokes every API key, and removes
                  linked OAuth providers. Stripe and historical billing records are retained for
                  compliance. This cannot be undone.
                </p>
                <button
                  type="button"
                  className="btn-danger"
                  onClick={() => setShowDelete(true)}
                >
                  Delete account
                </button>
              </div>
            </div>
          </div>
        </div>
      </main>

      {user && (
        <DeleteAccountModal
          open={showDelete}
          user={user}
          onClose={() => setShowDelete(false)}
          onDeleted={onDeleted}
        />
      )}
    </>
  );
}

// -----------------------------------------------------------------------------
// Change password — inline form
// -----------------------------------------------------------------------------

function ChangePasswordForm({ onDone }: { onDone: () => void }) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    if (newPassword.length < MIN_PASSWORD_LEN) {
      setErr(`New password must be at least ${MIN_PASSWORD_LEN} characters.`);
      return;
    }
    if (newPassword !== confirmPassword) {
      setErr("New password and confirmation do not match.");
      return;
    }
    if (newPassword === currentPassword) {
      setErr("New password must differ from the current one.");
      return;
    }
    setBusy(true);
    try {
      await me.changePassword({ currentPassword, newPassword });
      setOk(true);
      setTimeout(onDone, 1200);
    } catch (e) {
      setErr(errorMessage(e, "Failed to change password"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      onSubmit={onSubmit}
      className="mt-5 grid grid-cols-1 sm:grid-cols-2 gap-4 p-4 rounded-card border border-white/[0.06] bg-graphite-700/30"
    >
      <div className="sm:col-span-2 flex items-center gap-2 text-xs text-slate-300">
        <ShieldCheck size={14} strokeWidth={1.6} className="text-ember-soft" />
        Choose a strong password — at least {MIN_PASSWORD_LEN} characters.
      </div>
      <div className="sm:col-span-2">
        <label className="label-base mb-1.5 block" htmlFor="pw-current">
          Current password
        </label>
        <input
          id="pw-current"
          type="password"
          className="input-base"
          autoComplete="current-password"
          value={currentPassword}
          onChange={(e) => setCurrentPassword(e.target.value)}
          required
        />
      </div>
      <div>
        <label className="label-base mb-1.5 block" htmlFor="pw-new">
          New password
        </label>
        <input
          id="pw-new"
          type="password"
          className="input-base"
          autoComplete="new-password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          required
          minLength={MIN_PASSWORD_LEN}
        />
      </div>
      <div>
        <label className="label-base mb-1.5 block" htmlFor="pw-confirm">
          Confirm new password
        </label>
        <input
          id="pw-confirm"
          type="password"
          className="input-base"
          autoComplete="new-password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          required
          minLength={MIN_PASSWORD_LEN}
        />
      </div>
      <div className="sm:col-span-2 flex items-center justify-between">
        {err && <div className="text-xs text-ember-soft">{err}</div>}
        {ok && <div className="text-xs text-signal-mint">Password updated</div>}
        <button
          type="submit"
          disabled={busy || ok}
          className="btn-primary ml-auto"
        >
          {busy ? "Updating…" : ok ? "Updated" : "Update password"}
        </button>
      </div>
    </form>
  );
}

// -----------------------------------------------------------------------------
// Delete account — confirmation modal
// -----------------------------------------------------------------------------

function DeleteAccountModal({
  open,
  user,
  onClose,
  onDeleted,
}: {
  open: boolean;
  user: User;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const [password, setPassword] = useState("");
  const [confirmEmail, setConfirmEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Whether the account has a local password is not exposed by /v1/me — the
  // backend signals it via `code: "oauth_only"` (or "password_required") on
  // the first delete attempt. We branch off that code, not the message text,
  // so backend i18n changes never break this flow.
  const [needsEmail, setNeedsEmail] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      await me.deleteAccount(needsEmail ? { confirmEmail } : { password });
      onDeleted();
    } catch (e) {
      if (e instanceof APIError) {
        const oauthOnly =
          e.code === "oauth_only" || e.code === "password_required";
        if (!needsEmail && oauthOnly) {
          setNeedsEmail(true);
          setErr("This account has no password. Confirm by typing your email.");
        } else {
          setErr(e.message);
        }
      } else {
        setErr(errorMessage(e, "Failed to delete account"));
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Delete account"
      description={user.email}
      tone="danger"
      maxWidth={480}
    >
      <p className="text-sm text-slate-300 mb-5">
        This will anonymize your profile, revoke every API key, and disconnect any linked OAuth
        provider. Subscriptions and Stripe records are retained for compliance. This is
        irreversible.
      </p>

      <form onSubmit={onSubmit} className="flex flex-col gap-4">
        {!needsEmail ? (
          <div>
            <label className="label-base mb-1.5 block" htmlFor="del-pw">
              Confirm with your password
            </label>
            <input
              id="del-pw"
              type="password"
              className="input-base"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
        ) : (
          <div>
            <label className="label-base mb-1.5 block" htmlFor="del-email">
              Type your email to confirm
            </label>
            <input
              id="del-email"
              type="email"
              className="input-base"
              placeholder={user.email}
              value={confirmEmail}
              onChange={(e) => setConfirmEmail(e.target.value)}
              required
            />
          </div>
        )}

        {err && <div className="text-xs text-ember-soft">{err}</div>}

        <div className="flex items-center justify-end gap-2 pt-1">
          <button type="button" onClick={onClose} className="btn-ghost" disabled={busy}>
            Cancel
          </button>
          <button type="submit" disabled={busy} className="btn-danger">
            {busy ? "Deleting…" : "Delete account permanently"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
