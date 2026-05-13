"use client";

import { useEffect, useState } from "react";
import { Plus, Trash2, X, Link2, AlertCircle } from "lucide-react";
import { Topbar } from "@/components/Topbar";
import { PageTitle } from "@/components/PageTitle";
import { api, type OAuthRedirect } from "@/lib/api";
import { formatDate, timeAgo } from "@/lib/format";

// Login Social — tenant-managed redirect URI allowlist for the gateway
// OAuth broker. Mirrors the backend at /v1/oauth/redirects (CRUD).
// The gateway's /v1/oauth/authorize rejects any URI not in this list.

export default function OAuthRedirectsPage() {
  const [items, setItems] = useState<OAuthRedirect[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Add modal state.
  const [showAdd, setShowAdd] = useState(false);
  const [newUri, setNewUri] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [adding, setAdding] = useState(false);

  function refresh() {
    setLoading(true);
    api<{ items: OAuthRedirect[] }>("/v1/oauth/redirects")
      .then((r) => setItems(r.items || []))
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load"))
      .finally(() => setLoading(false));
  }
  useEffect(() => {
    refresh();
  }, []);

  async function onAdd(e: React.FormEvent) {
    e.preventDefault();
    setAdding(true);
    setError(null);
    try {
      await api("/v1/oauth/redirects", {
        method: "POST",
        body: {
          redirectUri: newUri.trim(),
          description: newDescription.trim(),
        },
      });
      setShowAdd(false);
      setNewUri("");
      setNewDescription("");
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to add");
    } finally {
      setAdding(false);
    }
  }

  async function onDelete(uri: string) {
    if (!confirm(`Remove this redirect URI?\n\n${uri}\n\nApps using it will fail at /v1/oauth/authorize until re-added.`)) {
      return;
    }
    try {
      await api(`/v1/oauth/redirects?redirectUri=${encodeURIComponent(uri)}`, {
        method: "DELETE",
      });
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete");
    }
  }

  return (
    <>
      <Topbar pageTitle="OAuth Redirects" />
      <main className="flex-1 px-6 py-8 overflow-auto">
        <div className="max-w-[1200px] mx-auto">
          <PageTitle
            eyebrow="// login social"
            title="OAuth Redirect URIs"
            description="Allowlist of redirect URIs your app uses with the Andromeda OAuth broker. The /v1/oauth/authorize endpoint rejects any redirect_uri not registered here. Add the URI exactly as it appears in your app — Google and Apple match strictly (no trailing slash differences, no scheme variants)."
            actions={
              <button onClick={() => setShowAdd(true)} className="btn-primary">
                <Plus size={14} strokeWidth={1.6} /> Add redirect URI
              </button>
            }
          />

          {error && (
            <div className="card p-4 mb-6 border-red-500/20 bg-red-500/[0.04] flex items-start gap-3">
              <AlertCircle size={16} className="text-red-400 mt-0.5 flex-shrink-0" />
              <div className="text-sm text-red-200">{error}</div>
            </div>
          )}

          {loading ? (
            <div className="card p-6 text-sm text-slate-400">Loading…</div>
          ) : items.length === 0 ? (
            <div className="card p-8 text-center">
              <Link2 size={32} className="mx-auto mb-3 text-slate-500" strokeWidth={1.4} />
              <h3 className="text-sm font-medium mb-1">No redirect URIs registered</h3>
              <p className="text-xs text-slate-400 mb-4">
                Your app cannot use Andromeda&apos;s Login Social until at least one URI is added.
              </p>
              <button onClick={() => setShowAdd(true)} className="btn-primary">
                <Plus size={14} strokeWidth={1.6} /> Add your first URI
              </button>
            </div>
          ) : (
            <div className="card overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-white/[0.02] text-xs text-slate-400 uppercase tracking-wide">
                  <tr>
                    <th className="px-5 py-3 text-left font-medium">Redirect URI</th>
                    <th className="px-5 py-3 text-left font-medium">Description</th>
                    <th className="px-5 py-3 text-left font-medium">Added</th>
                    <th className="px-5 py-3 w-12"></th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item) => (
                    <tr key={item.redirectUri} className="border-t border-white/[0.04]">
                      <td className="px-5 py-3.5 font-mono text-[13px] break-all">{item.redirectUri}</td>
                      <td className="px-5 py-3.5 text-slate-300">{item.description || "—"}</td>
                      <td className="px-5 py-3.5 text-slate-400 text-xs" title={formatDate(item.createdAt)}>
                        {timeAgo(item.createdAt)}
                      </td>
                      <td className="px-5 py-3.5">
                        <button
                          onClick={() => onDelete(item.redirectUri)}
                          className="text-slate-500 hover:text-red-400 transition-colors"
                          title="Remove"
                          aria-label="Remove redirect URI"
                        >
                          <Trash2 size={14} strokeWidth={1.6} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className="mt-8 text-xs text-slate-500 max-w-2xl">
            <p className="mb-2"><strong className="text-slate-300">Limits:</strong> max 20 URIs per account. Each URI must be <code className="font-mono">https://</code>, except <code className="font-mono">http://localhost</code> (dev only).</p>
            <p>
              <strong className="text-slate-300">Tip:</strong> the URI you register here must match{" "}
              <strong>byte-for-byte</strong> the redirect URI configured in your app and registered at Google / Apple. Trailing slashes, schemes, port numbers — all are checked exactly.
            </p>
          </div>
        </div>
      </main>

      {showAdd && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="card w-full max-w-lg">
            <div className="flex items-center justify-between px-5 py-4 border-b border-white/[0.06]">
              <h2 className="text-sm font-medium">Add redirect URI</h2>
              <button onClick={() => setShowAdd(false)} className="text-slate-500 hover:text-white">
                <X size={16} />
              </button>
            </div>
            <form onSubmit={onAdd} className="p-5 space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                  Redirect URI <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={newUri}
                  onChange={(e) => setNewUri(e.target.value)}
                  placeholder="https://app.example.com/oauth/callback"
                  className="input w-full font-mono text-[13px]"
                  required
                  autoFocus
                />
                <p className="text-xs text-slate-500 mt-1.5">
                  Must be exactly the same URI your app sends to <code className="font-mono">/v1/oauth/authorize</code>.
                </p>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Description</label>
                <input
                  type="text"
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  placeholder="Production web app"
                  maxLength={200}
                  className="input w-full"
                />
                <p className="text-xs text-slate-500 mt-1.5">Optional. Helps you identify which app uses this URI.</p>
              </div>
              <div className="flex items-center justify-end gap-2 pt-2">
                <button type="button" onClick={() => setShowAdd(false)} className="btn-secondary">
                  Cancel
                </button>
                <button type="submit" disabled={adding || !newUri.trim()} className="btn-primary">
                  {adding ? "Adding…" : "Add"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
