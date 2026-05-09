"use client";

import { useEffect, useState } from "react";
import { Plus } from "lucide-react";
import { PageHeader } from "@/components/admin/PageHeader";
import {
  adminUsers,
  AdminAPIError,
  type AdminMe,
  type AdminRole,
} from "@/lib/admin-api";

export default function AdminUsersPage() {
  const [items, setItems] = useState<AdminMe[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showForm, setShowForm] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<AdminRole>("support");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  async function load() {
    try {
      const data = await adminUsers.list();
      setItems(data.items);
    } catch (err) {
      if (err instanceof AdminAPIError && err.status === 403) {
        setError("Only super_admin can manage admin accounts.");
        return;
      }
      setError(err instanceof Error ? err.message : "Load failed");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function onCreate(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    setBusy(true);
    try {
      await adminUsers.create({
        email: email.trim().toLowerCase(),
        password,
        role,
        mfaRequired,
      });
      setSuccess(`Admin ${email} created.`);
      setEmail("");
      setPassword("");
      setRole("support");
      setMfaRequired(false);
      setShowForm(false);
      await load();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Create failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex-1 px-6 lg:px-10 py-8">
      <PageHeader
        title="Admin accounts"
        description="Operators with access to /admin endpoints. Only super_admin can manage this list."
        actions={
          !error && (
            <button
              type="button"
              className="btn-primary"
              onClick={() => setShowForm((s) => !s)}
            >
              <Plus size={14} strokeWidth={1.8} />
              {showForm ? "Cancel" : "New admin"}
            </button>
          )
        }
      />

      {error && (
        <div className="card p-5 text-sm text-ember-soft">
          {error}
        </div>
      )}

      {success && (
        <div className="mb-4 text-xs text-emerald-300 bg-emerald-500/10 border border-emerald-500/20 rounded-lg px-3 py-2">
          {success}
        </div>
      )}

      {showForm && !error && (
        <form
          onSubmit={onCreate}
          className="card p-5 mb-6 grid grid-cols-1 md:grid-cols-2 gap-4 max-w-3xl"
        >
          <div>
            <label className="label-base mb-1.5 block">Email</label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="input-base"
              placeholder="ops@shinkalabs.com"
            />
          </div>
          <div>
            <label className="label-base mb-1.5 block">Password</label>
            <input
              type="password"
              required
              minLength={12}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="input-base"
              placeholder="≥12 characters"
            />
          </div>
          <div>
            <label className="label-base mb-1.5 block">Role</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as AdminRole)}
              className="input-base"
            >
              <option value="support">support</option>
              <option value="billing">billing</option>
              <option value="super_admin">super_admin</option>
            </select>
          </div>
          <div className="flex items-end gap-2 pb-1">
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input
                type="checkbox"
                checked={mfaRequired}
                onChange={(e) => setMfaRequired(e.target.checked)}
                className="accent-ember"
              />
              MFA required
            </label>
          </div>
          <div className="md:col-span-2 flex items-center gap-3">
            <button type="submit" disabled={busy} className="btn-primary">
              {busy ? "Creating…" : "Create admin"}
            </button>
            {formError && <span className="text-xs text-ember-soft">{formError}</span>}
          </div>
        </form>
      )}

      {!loading && !error && (
        <div className="card overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead className="text-[11px] uppercase tracking-wider text-slate-400 border-b border-white/[0.06]">
              <tr>
                <th className="px-4 py-3 text-left font-medium">Email</th>
                <th className="px-4 py-3 text-left font-medium">Role</th>
                <th className="px-4 py-3 text-left font-medium">MFA</th>
                <th className="px-4 py-3 text-left font-medium">Last login</th>
                <th className="px-4 py-3 text-left font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {items.map((a) => (
                <tr key={a.id} className="border-b border-white/[0.04] last:border-0">
                  <td className="px-4 py-3 text-xs text-snow">{a.email}</td>
                  <td className="px-4 py-3 text-xs text-slate-300">
                    <code className="bg-graphite-700/60 px-1.5 py-0.5 rounded">{a.role}</code>
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {a.mfaEnabled ? (
                      <span className="text-emerald-300">enabled</span>
                    ) : a.mfaRequired ? (
                      <span className="text-amber-300">required, not set</span>
                    ) : (
                      <span className="text-slate-400">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-400 font-mono">
                    {a.lastLoginAt ? new Date(a.lastLoginAt).toLocaleString() : "—"}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-400 font-mono">
                    {new Date(a.createdAt).toLocaleDateString()}
                  </td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-xs text-slate-400">
                    No admins yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}
