"use client";

import { useEffect, useState } from "react";
import { Plus, Trash2, Link2, AlertCircle } from "lucide-react";
import { Topbar } from "@/components/Topbar";
import { PageTitle } from "@/components/PageTitle";
import { Modal } from "@/components/Modal";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { api, type OAuthRedirect } from "@/lib/api";
import { errorMessage, formatDate, timeAgo } from "@/lib/format";

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

  // Delete confirmation state.
  const [uriToDelete, setUriToDelete] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const ac = new AbortController();
    setLoading(true);
    api<{ items: OAuthRedirect[] }>("/v1/oauth/redirects", { signal: ac.signal })
      .then((r) => {
        if (!cancelled) setItems(r.items || []);
      })
      .catch((e) => {
        if (cancelled || (e instanceof DOMException && e.name === "AbortError")) {
          return;
        }
        setError(errorMessage(e, "Failed to load"));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
      ac.abort();
    };
  }, []);

  async function refresh() {
    setLoading(true);
    try {
      const r = await api<{ items: OAuthRedirect[] }>("/v1/oauth/redirects");
      setItems(r.items || []);
    } catch (e) {
      setError(errorMessage(e, "Failed to load"));
    } finally {
      setLoading(false);
    }
  }

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
      await refresh();
    } catch (e) {
      setError(errorMessage(e, "Failed to add"));
    } finally {
      setAdding(false);
    }
  }

  async function confirmDelete() {
    if (!uriToDelete) return;
    try {
      await api(
        `/v1/oauth/redirects?redirectUri=${encodeURIComponent(uriToDelete)}`,
        { method: "DELETE" },
      );
      setUriToDelete(null);
      await refresh();
    } catch (e) {
      setError(errorMessage(e, "Failed to delete"));
      throw e;
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
            <div className="card p-4 mb-6 border-ember/20 bg-ember/[0.04] flex items-start gap-3">
              <AlertCircle size={16} className="text-ember-soft mt-0.5 flex-shrink-0" />
              <div className="text-sm text-ember-soft">{error}</div>
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
                          onClick={() => setUriToDelete(item.redirectUri)}
                          className="text-slate-500 hover:text-ember-soft transition-colors"
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

      <Modal
        open={showAdd}
        onClose={() => setShowAdd(false)}
        title="Add redirect URI"
        maxWidth={520}
      >
        <form onSubmit={onAdd} className="space-y-4">
          <div>
            <label className="label-base mb-1.5 block" htmlFor="oauth-uri">
              Redirect URI <span className="text-ember-soft">*</span>
            </label>
            <input
              id="oauth-uri"
              type="text"
              value={newUri}
              onChange={(e) => setNewUri(e.target.value)}
              placeholder="https://app.example.com/oauth/callback"
              className="input-base font-mono text-[13px]"
              required
              autoFocus
            />
            <p className="text-xs text-slate-500 mt-1.5">
              Must be exactly the same URI your app sends to <code className="font-mono">/v1/oauth/authorize</code>.
            </p>
          </div>
          <div>
            <label className="label-base mb-1.5 block" htmlFor="oauth-desc">
              Description
            </label>
            <input
              id="oauth-desc"
              type="text"
              value={newDescription}
              onChange={(e) => setNewDescription(e.target.value)}
              placeholder="Production web app"
              maxLength={200}
              className="input-base"
            />
            <p className="text-xs text-slate-500 mt-1.5">Optional. Helps you identify which app uses this URI.</p>
          </div>
          <div className="flex items-center justify-end gap-2 pt-2">
            <button type="button" onClick={() => setShowAdd(false)} className="btn-ghost">
              Cancel
            </button>
            <button type="submit" disabled={adding || !newUri.trim()} className="btn-primary">
              {adding ? "Adding…" : "Add"}
            </button>
          </div>
        </form>
      </Modal>

      <ConfirmDialog
        open={uriToDelete !== null}
        title="Remove redirect URI"
        description={
          <>
            Remove <span className="font-mono text-snow break-all">{uriToDelete}</span>?
            Apps using this URI will start failing at <code>/v1/oauth/authorize</code> until you re-add it.
          </>
        }
        confirmLabel="Remove URI"
        busyLabel="Removing…"
        danger
        onConfirm={confirmDelete}
        onCancel={() => setUriToDelete(null)}
      />
    </>
  );
}
