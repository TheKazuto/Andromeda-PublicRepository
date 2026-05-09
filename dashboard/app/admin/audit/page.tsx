"use client";

import { useEffect, useState } from "react";
import { PageHeader } from "@/components/admin/PageHeader";
import { adminAudit, type AdminAuditEntry } from "@/lib/admin-api";

export default function AdminAuditPage() {
  const [items, setItems] = useState<AdminAuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  useEffect(() => {
    adminAudit
      .list()
      .then((data) => setItems(data.items))
      .catch((err) =>
        setError(err instanceof Error ? err.message : "Failed to load audit log")
      )
      .finally(() => setLoading(false));
  }, []);

  const filtered = items.filter((entry) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      entry.action.toLowerCase().includes(q) ||
      entry.adminEmail.toLowerCase().includes(q) ||
      (entry.target ?? "").toLowerCase().includes(q)
    );
  });

  return (
    <main className="flex-1 px-6 lg:px-10 py-8">
      <PageHeader
        title="Audit log"
        description="Every authenticated admin action. Logs are append-only — readable by any admin."
      />

      <div className="mb-4">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter by action, email, target…"
          className="input-base max-w-md"
        />
      </div>

      {loading && <div className="text-sm text-slate-400">Loading…</div>}
      {error && <div className="text-xs text-ember-soft">{error}</div>}

      {!loading && !error && (
        <div className="card overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead className="text-[11px] uppercase tracking-wider text-slate-400 border-b border-white/[0.06]">
              <tr>
                <th className="px-4 py-3 text-left font-medium">When</th>
                <th className="px-4 py-3 text-left font-medium">Admin</th>
                <th className="px-4 py-3 text-left font-medium">Action</th>
                <th className="px-4 py-3 text-left font-medium">Target</th>
                <th className="px-4 py-3 text-left font-medium">IP</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((entry) => (
                <tr key={entry.id} className="border-b border-white/[0.04] last:border-0">
                  <td className="px-4 py-3 text-xs text-slate-300 font-mono">
                    {formatDateTime(entry.createdAt)}
                  </td>
                  <td className="px-4 py-3 text-xs text-snow">{entry.adminEmail}</td>
                  <td className="px-4 py-3 text-xs">
                    <code className="text-xs bg-graphite-700/60 px-1.5 py-0.5 rounded">
                      {entry.action}
                    </code>
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-300 truncate max-w-[200px]">
                    {entry.target || "—"}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-400 font-mono">
                    {entry.ipAddress || "—"}
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-xs text-slate-400">
                    No audit entries match.
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

function formatDateTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString("en-GB", {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}
