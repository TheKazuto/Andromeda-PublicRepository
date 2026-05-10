"use client";

import { useEffect, useState } from "react";
import { Plus, KeyRound, Copy, Check, Trash2, X, Pencil, Globe, Link2 } from "lucide-react";
import { Topbar } from "@/components/Topbar";
import { PageTitle } from "@/components/PageTitle";
import { api, type APIKey } from "@/lib/api";
import { formatDate, timeAgo } from "@/lib/format";

const API_ENDPOINT =
  process.env.NEXT_PUBLIC_GATEWAY_URL || "https://api.andromedainfra.pro";

// Convert a textarea value (one origin per line) to a clean string array.
function parseOriginsInput(raw: string): string[] {
  return raw
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

// Pretty-print an origins list for display.
function originsCount(key: APIKey): number {
  return key.allowedOrigins?.length ?? 0;
}

export default function ApiKeysPage() {
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [loading, setLoading] = useState(true);

  // Create modal state.
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newOrigins, setNewOrigins] = useState("");
  const [creating, setCreating] = useState(false);

  // Edit modal state.
  const [editingKey, setEditingKey] = useState<APIKey | null>(null);
  const [editName, setEditName] = useState("");
  const [editOrigins, setEditOrigins] = useState("");
  const [saving, setSaving] = useState(false);

  const [revealedKey, setRevealedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [endpointCopied, setEndpointCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function copyEndpoint() {
    navigator.clipboard.writeText(API_ENDPOINT);
    setEndpointCopied(true);
    setTimeout(() => setEndpointCopied(false), 1500);
  }

  function refresh() {
    setLoading(true);
    api<{ items: APIKey[] }>("/v1/api-keys")
      .then((r) => setKeys(r.items || []))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }
  useEffect(() => {
    refresh();
  }, []);

  async function onCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    setError(null);
    try {
      const allowedOrigins = parseOriginsInput(newOrigins);
      const resp = await api<{ key: string; item: APIKey }>("/v1/api-keys", {
        method: "POST",
        body: {
          name: newName || "Untitled key",
          ...(allowedOrigins.length > 0 ? { allowedOrigins } : {}),
        },
      });
      setRevealedKey(resp.key);
      setShowCreate(false);
      setNewName("");
      setNewOrigins("");
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed");
    } finally {
      setCreating(false);
    }
  }

  function openEdit(key: APIKey) {
    setEditingKey(key);
    setEditName(key.name);
    setEditOrigins((key.allowedOrigins ?? []).join("\n"));
    setError(null);
  }

  function closeEdit() {
    setEditingKey(null);
    setEditName("");
    setEditOrigins("");
  }

  async function onSaveEdit(e: React.FormEvent) {
    e.preventDefault();
    if (!editingKey) return;
    setSaving(true);
    setError(null);
    try {
      const allowedOrigins = parseOriginsInput(editOrigins);
      await api<{ item: APIKey }>(`/v1/api-keys/${editingKey.id}`, {
        method: "PATCH",
        body: {
          name: editName.trim() || editingKey.name,
          allowedOrigins,
        },
      });
      closeEdit();
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed");
    } finally {
      setSaving(false);
    }
  }

  async function onRevoke(id: string) {
    if (!confirm("Revoke this API key? This action cannot be undone.")) return;
    try {
      await api(`/v1/api-keys/${id}`, { method: "DELETE" });
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed");
    }
  }

  function copy(text: string) {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <>
      <Topbar pageTitle="API Keys" />
      <main className="flex-1 px-6 py-8 overflow-auto">
        <div className="max-w-[1200px] mx-auto">
          <PageTitle
            eyebrow="// credentials"
            title="API Keys"
            description="Generate and manage keys to authenticate against the Andromeda API. Each key carries scopes — keep them secret and rotate when needed."
            actions={
              <button onClick={() => setShowCreate(true)} className="btn-primary">
                <Plus size={14} strokeWidth={1.6} /> New key
              </button>
            }
          />

          {revealedKey && (
            <div className="card p-5 mb-6 border-ember/20 bg-ember/[0.04]">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <div className="text-xs text-ember-soft font-medium tracking-wide mb-1">
                    YOUR NEW KEY — COPY IT NOW
                  </div>
                  <p className="text-xs text-slate-300 mb-3">
                    This key will not be shown again. Store it in a secure location.
                  </p>
                  <div className="font-mono text-[13px] bg-void border border-white/[0.06] rounded-lg px-3 py-2.5 break-all">
                    {revealedKey}
                  </div>
                </div>
                <div className="flex flex-col gap-2 shrink-0">
                  <button onClick={() => copy(revealedKey)} className="btn-secondary">
                    {copied ? <Check size={14} strokeWidth={1.6} /> : <Copy size={14} strokeWidth={1.6} />}
                    {copied ? "Copied" : "Copy"}
                  </button>
                  <button onClick={() => setRevealedKey(null)} className="btn-ghost">
                    <X size={14} strokeWidth={1.6} /> Dismiss
                  </button>
                </div>
              </div>
            </div>
          )}

          {error && (
            <div className="text-xs text-ember-soft bg-ember/10 border border-ember/20 rounded-lg px-3 py-2 mb-4">
              {error}
            </div>
          )}

          <div className="card p-5 mb-6">
            <div className="flex items-start gap-4">
              <div className="w-10 h-10 grid place-items-center rounded-lg bg-ember/10 border border-ember/20 shrink-0">
                <Link2 size={16} strokeWidth={1.6} className="text-ember-soft" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-[13px] font-medium text-snow mb-0.5">API endpoint</div>
                <p className="text-xs text-slate-400 mb-3">
                  Point your HTTPS requests to this base URL. Authenticate with any active key below using the <code className="font-mono text-slate-300">X-Api-Key</code> header.
                </p>
                <div className="flex items-stretch gap-2">
                  <div className="flex-1 font-mono text-[13px] bg-void border border-white/[0.06] rounded-lg px-3 py-2.5 break-all">
                    {API_ENDPOINT}
                  </div>
                  <button
                    onClick={copyEndpoint}
                    className="btn-secondary shrink-0"
                    aria-label="Copy API endpoint"
                  >
                    {endpointCopied ? <Check size={14} strokeWidth={1.6} /> : <Copy size={14} strokeWidth={1.6} />}
                    {endpointCopied ? "Copied" : "Copy"}
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div className="card overflow-hidden">
            <div className="grid grid-cols-[1.4fr_1.5fr_1fr_1fr_100px] gap-4 px-5 py-3 border-b border-white/[0.05] text-[11px] uppercase tracking-[0.12em] text-slate-400 font-medium">
              <div>Name</div>
              <div>Prefix</div>
              <div>Created</div>
              <div>Status</div>
              <div></div>
            </div>

            {loading && <div className="px-5 py-8 text-sm text-slate-400">Loading…</div>}

            {!loading && keys.length === 0 && (
              <div className="px-5 py-12 text-center">
                <KeyRound size={28} strokeWidth={1.4} className="mx-auto text-slate-400 mb-3" />
                <div className="text-sm text-snow mb-1">No API keys yet</div>
                <div className="text-xs text-slate-400 mb-4">Create your first key to start using the API.</div>
                <button onClick={() => setShowCreate(true)} className="btn-secondary">
                  <Plus size={14} strokeWidth={1.6} /> Create key
                </button>
              </div>
            )}

            {!loading &&
              keys.map((k) => {
                const originsN = originsCount(k);
                return (
                  <div
                    key={k.id}
                    className="grid grid-cols-[1.4fr_1.5fr_1fr_1fr_100px] gap-4 px-5 py-4 border-b border-white/[0.04] last:border-b-0 items-center"
                  >
                    <div>
                      <div className="text-sm text-snow font-medium">{k.name}</div>
                      <div className="text-[11px] text-slate-400 mt-0.5 flex items-center gap-2">
                        <span>{k.scopes.slice(0, 3).join(" · ")}</span>
                        {originsN > 0 && (
                          <span className="inline-flex items-center gap-1 text-slate-300">
                            <Globe size={10} strokeWidth={1.6} />
                            {originsN} origin{originsN === 1 ? "" : "s"}
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="font-mono text-xs text-slate-200 truncate">{k.prefix}</div>
                    <div className="text-xs text-slate-300">
                      {formatDate(k.createdAt)}
                      <div className="text-[11px] text-slate-400">{timeAgo(k.createdAt)}</div>
                    </div>
                    <div>
                      {k.revokedAt ? (
                        <span className="badge text-slate-400">revoked</span>
                      ) : (
                        <span className="badge-mint">active</span>
                      )}
                    </div>
                    <div className="flex justify-end gap-1">
                      {!k.revokedAt && (
                        <>
                          <button
                            onClick={() => openEdit(k)}
                            className="w-8 h-8 grid place-items-center rounded-lg text-slate-400 hover:text-snow hover:bg-white/[0.05] transition-colors"
                            aria-label="Edit"
                          >
                            <Pencil size={14} strokeWidth={1.6} />
                          </button>
                          <button
                            onClick={() => onRevoke(k.id)}
                            className="w-8 h-8 grid place-items-center rounded-lg text-slate-400 hover:text-ember-soft hover:bg-ember/10 transition-colors"
                            aria-label="Revoke"
                          >
                            <Trash2 size={14} strokeWidth={1.6} />
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                );
              })}
          </div>
        </div>
      </main>

      {/* Create modal */}
      {showCreate && (
        <div
          className="fixed inset-0 z-50 grid place-items-center bg-black/60 backdrop-blur-sm px-4"
          onClick={() => setShowCreate(false)}
        >
          <div
            className="card w-full max-w-[480px] p-6 animate-fade-up"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-[17px] font-semibold mb-1">Create API key</h3>
            <p className="text-sm text-slate-300 mb-5">
              Pick a name and optionally restrict which web origins can use this key.
            </p>
            <form onSubmit={onCreate} className="flex flex-col gap-4">
              <div>
                <label className="label-base mb-1.5 block" htmlFor="kname">Name</label>
                <input
                  id="kname"
                  type="text"
                  autoFocus
                  className="input-base"
                  placeholder="Production · Backend"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                />
              </div>
              <div>
                <label className="label-base mb-1.5 block" htmlFor="korigins">
                  Allowed origins <span className="text-slate-400 font-normal">(optional)</span>
                </label>
                <textarea
                  id="korigins"
                  rows={4}
                  className="input-base font-mono text-[12px] resize-none"
                  placeholder={"https://app.example.com\nhttps://staging.example.com"}
                  value={newOrigins}
                  onChange={(e) => setNewOrigins(e.target.value)}
                />
                <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">
                  One origin per line, in the form <code>scheme://host[:port]</code>. Leave empty to
                  accept any origin (server-to-server calls are unaffected).
                </p>
              </div>
              <div className="flex justify-end gap-2 mt-2">
                <button type="button" onClick={() => setShowCreate(false)} className="btn-ghost">
                  Cancel
                </button>
                <button type="submit" disabled={creating} className="btn-primary">
                  {creating ? "Creating…" : "Create key"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit modal */}
      {editingKey && (
        <div
          className="fixed inset-0 z-50 grid place-items-center bg-black/60 backdrop-blur-sm px-4"
          onClick={closeEdit}
        >
          <div
            className="card w-full max-w-[480px] p-6 animate-fade-up"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-[17px] font-semibold mb-1">Edit API key</h3>
            <p className="text-sm text-slate-300 mb-5">
              Change the name or update the allowed origins. The key value itself never changes.
            </p>
            <form onSubmit={onSaveEdit} className="flex flex-col gap-4">
              <div>
                <label className="label-base mb-1.5 block" htmlFor="ename">Name</label>
                <input
                  id="ename"
                  type="text"
                  autoFocus
                  className="input-base"
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                />
              </div>
              <div>
                <label className="label-base mb-1.5 block" htmlFor="eorigins">
                  Allowed origins
                </label>
                <textarea
                  id="eorigins"
                  rows={5}
                  className="input-base font-mono text-[12px] resize-none"
                  placeholder={"https://app.example.com"}
                  value={editOrigins}
                  onChange={(e) => setEditOrigins(e.target.value)}
                />
                <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">
                  One origin per line. Empty = accept any origin (browser-only restriction;
                  server-side calls are unaffected).
                </p>
              </div>
              <div className="flex justify-end gap-2 mt-2">
                <button type="button" onClick={closeEdit} className="btn-ghost">
                  Cancel
                </button>
                <button type="submit" disabled={saving} className="btn-primary">
                  {saving ? "Saving…" : "Save changes"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
