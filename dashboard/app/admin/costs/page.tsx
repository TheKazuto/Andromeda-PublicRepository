"use client";

import { useEffect, useMemo, useState } from "react";
import { Search, Save } from "lucide-react";
import { PageHeader } from "@/components/admin/PageHeader";
import { adminCosts, type AdminRequestCost } from "@/lib/admin-api";
import { errorMessage } from "@/lib/format";

export default function AdminCostsPage() {
  const [items, setItems] = useState<AdminRequestCost[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [pending, setPending] = useState<Record<string, number>>({});
  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    try {
      const data = await adminCosts.list();
      const sorted = [...data.items].sort((a, b) =>
        a.routeKey.localeCompare(b.routeKey)
      );
      setItems(sorted);
    } catch (err) {
      setError(errorMessage(err, "Load failed"));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const data = await adminCosts.list();
        if (cancelled) return;
        const sorted = [...data.items].sort((a, b) =>
          a.routeKey.localeCompare(b.routeKey)
        );
        setItems(sorted);
      } catch (err) {
        if (!cancelled) setError(errorMessage(err, "Load failed"));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const filtered = useMemo(() => {
    if (!search) return items;
    const q = search.toLowerCase();
    return items.filter(
      (i) =>
        i.routeKey.toLowerCase().includes(q) ||
        i.description.toLowerCase().includes(q)
    );
  }, [items, search]);

  async function save(routeKey: string) {
    const v = pending[routeKey];
    if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) return;
    setSavingKey(routeKey);
    setMessage(null);
    try {
      await adminCosts.upsert(routeKey, { costTokens: v });
      setPending((p) => {
        const cp = { ...p };
        delete cp[routeKey];
        return cp;
      });
      setMessage(`Saved cost for ${routeKey}.`);
      await load();
    } catch (err) {
      setMessage(errorMessage(err, "Save failed"));
    } finally {
      setSavingKey(null);
    }
  }

  return (
    <main className="flex-1 px-6 lg:px-10 py-8">
      <PageHeader
        title="Request costs"
        description="Token cost per route. Direct edits go live immediately. For grandfathered changes, schedule via Pricing changes (route_cost type)."
      />

      <div className="mb-4 flex items-center gap-2 max-w-md">
        <Search size={16} strokeWidth={1.8} className="text-slate-400" />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter by route key or description…"
          className="input-base"
        />
      </div>

      {loading && <div className="text-sm text-slate-400">Loading…</div>}
      {error && <div className="text-xs text-ember-soft">{error}</div>}
      {message && (
        <div className="mb-4 text-xs text-emerald-300 bg-emerald-500/10 border border-emerald-500/20 rounded-lg px-3 py-2">
          {message}
        </div>
      )}

      {!loading && !error && (
        <div className="card overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead className="text-[11px] uppercase tracking-wider text-slate-400 border-b border-white/[0.06]">
              <tr>
                <th className="px-4 py-3 text-left font-medium">Route</th>
                <th className="px-4 py-3 text-left font-medium">Description</th>
                <th className="px-4 py-3 text-right font-medium">Cost (tokens)</th>
                <th className="px-4 py-3 text-right font-medium">USD ≈</th>
                <th className="px-4 py-3 text-right font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((it) => {
                const draft = pending[it.routeKey];
                const value = draft ?? it.costTokens;
                const dirty = draft !== undefined && draft !== it.costTokens;
                return (
                  <tr key={it.routeKey} className="border-b border-white/[0.04] last:border-0">
                    <td className="px-4 py-3">
                      <code className="text-xs text-snow font-mono">{it.routeKey}</code>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400 max-w-[300px] truncate">
                      {it.description}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <input
                        type="number"
                        min={1}
                        value={value}
                        onChange={(e) => {
                          const n = Number(e.target.value);
                          // Reject NaN so the input never feeds the save guard
                          // with `Number.isFinite === false`.
                          if (e.target.value !== "" && !Number.isFinite(n)) return;
                          setPending((p) => ({ ...p, [it.routeKey]: n }));
                        }}
                        className="input-base w-24 text-right"
                      />
                    </td>
                    <td className="px-4 py-3 text-right text-xs text-slate-400 font-mono">
                      ${(value * 0.004).toFixed(3)}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        disabled={!dirty || savingKey === it.routeKey}
                        onClick={() => save(it.routeKey)}
                        className="btn-secondary text-xs disabled:opacity-40"
                      >
                        <Save size={13} strokeWidth={1.8} />
                        {savingKey === it.routeKey ? "Saving…" : "Save"}
                      </button>
                    </td>
                  </tr>
                );
              })}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-xs text-slate-400">
                    No routes match.
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
