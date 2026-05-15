"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  Activity,
  Zap,
  ArrowUpRight,
  KeyRound,
  ArrowRight,
  Layers,
} from "lucide-react";
import { Topbar } from "@/components/Topbar";
import { PageTitle } from "@/components/PageTitle";
import { Stat } from "@/components/Stat";
import { api, me, type MeUsage, type APIKey } from "@/lib/api";
import { errorMessage, formatNumber } from "@/lib/format";

export default function DashboardHome() {
  const [usage, setUsage] = useState<MeUsage | null>(null);
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const errors: string[] = [];

    me.usage("30d")
      .then((u) => {
        if (!cancelled) setUsage(u);
      })
      .catch((e) => {
        if (cancelled) return;
        errors.push(errorMessage(e, "Failed to load usage"));
        setError(errors.join(" · "));
      });

    api<{ items: APIKey[] }>("/v1/api-keys")
      .then((r) => {
        if (!cancelled) setKeys(r.items || []);
      })
      .catch((e) => {
        if (cancelled) return;
        errors.push(errorMessage(e, "Failed to load API keys"));
        setError(errors.join(" · "));
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const activeKeys = useMemo(
    () => keys.filter((k) => !k.revokedAt).length,
    [keys],
  );
  const topRoute = usage?.topRoutes?.[0];

  return (
    <>
      <Topbar pageTitle="Home" />
      <main className="flex-1 px-6 py-8 overflow-auto">
        <div className="max-w-[1200px] mx-auto">
          <PageTitle
            eyebrow="// overview"
            title="Welcome to Andromeda."
            description="Your control center for Andromeda. Monitor signs, manage API keys, and connect any chain."
            actions={
              <Link href="/dashboard/api-keys" className="btn-primary">
                Create API key <ArrowRight size={14} strokeWidth={1.6} />
              </Link>
            }
          />

          {error && (
            <div className="text-xs text-ember-soft bg-ember/10 border border-ember/20 rounded-lg px-3 py-2 mb-6">
              {error}
            </div>
          )}

          {/* Stats */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <Stat
              label="Tokens (30d)"
              value={usage ? formatNumber(usage.tokens) : "—"}
              sublabel="metered usage"
              Icon={Zap}
            />
            <Stat
              label="Calls (30d)"
              value={usage ? formatNumber(usage.calls) : "—"}
              sublabel="all routes"
              Icon={Activity}
            />
            <Stat
              label="Top route"
              value={topRoute ? formatNumber(topRoute.tokens) : "—"}
              sublabel={topRoute ? topRoute.routeKey : "no traffic yet"}
              Icon={ArrowUpRight}
            />
            <Stat
              label="Active keys"
              value={String(activeKeys)}
              sublabel={keys.length ? `${keys.length} total` : ""}
              Icon={Layers}
            />
          </div>

          {/* Two-column body */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Quick start */}
            <div className="lg:col-span-2 card p-6">
              <h3 className="text-[15px] font-semibold tracking-tight mb-1">Quick start</h3>
              <p className="text-sm text-slate-300 mb-5">
                Sign your first transaction in under a minute.
              </p>

              <ol className="flex flex-col gap-4">
                <Step
                  index={1}
                  title="Create an API key"
                  href="/dashboard/api-keys"
                  body="Generate a key scoped to sign:read, sign:write, dwallet:create."
                />
                <Step
                  index={2}
                  title="Provision a dWallet"
                  body="POST /v1/dwallets with the owner address and curve. Idempotent."
                />
                <Step
                  index={3}
                  title="Sign a transaction"
                  body="POST /v1/sign with the dWalletId and message bytes. Andromeda picks the right presign mode."
                />
                <Step
                  index={4}
                  title="Plug into your AI agent (optional)"
                  href="/dashboard/mcp-server"
                  body="Use the MCP server to expose every endpoint as an agent tool."
                />
              </ol>
            </div>

            {/* Active keys */}
            <div className="card p-6">
              <div className="flex items-center justify-between mb-1">
                <h3 className="text-[15px] font-semibold tracking-tight">API keys</h3>
                <span className="badge-ember">{activeKeys} active</span>
              </div>
              <p className="text-sm text-slate-300 mb-5">Last 5 keys you created.</p>
              <div className="flex flex-col gap-2">
                {keys.length === 0 && (
                  <div className="text-sm text-slate-400 py-6 text-center border border-dashed border-white/[0.08] rounded-lg">
                    No keys yet
                  </div>
                )}
                {keys.slice(0, 5).map((k) => (
                  <div key={k.id} className="flex items-center justify-between gap-2 px-3 py-2.5 rounded-lg bg-graphite-700/50 border border-white/[0.05]">
                    <div className="min-w-0">
                      <div className="text-sm text-snow truncate">{k.name}</div>
                      <div className="text-[11px] font-mono text-slate-400 truncate">{k.prefix}</div>
                    </div>
                    <KeyRound size={14} strokeWidth={1.6} className="text-slate-400 shrink-0" />
                  </div>
                ))}
              </div>
              <Link href="/dashboard/api-keys" className="btn-ghost mt-4 w-full">
                Manage keys <ArrowRight size={14} strokeWidth={1.6} />
              </Link>
            </div>
          </div>
        </div>
      </main>
    </>
  );
}

function Step({
  index,
  title,
  body,
  href,
}: {
  index: number;
  title: string;
  body: string;
  href?: string;
}) {
  const inner = (
    <div className="flex items-start gap-4 p-4 rounded-card border border-white/[0.05] bg-graphite-700/40 hover:border-ember/25 transition-colors">
      <div className="w-7 h-7 rounded-full bg-ember/15 border border-ember/25 grid place-items-center text-[12px] font-mono text-ember-soft shrink-0">
        {index}
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-sm text-snow font-medium">{title}</div>
        <div className="text-xs text-slate-300 mt-0.5">{body}</div>
      </div>
      {href && <ArrowRight size={14} strokeWidth={1.6} className="text-slate-400 mt-2.5" />}
    </div>
  );
  return href ? <Link href={href}>{inner}</Link> : <li>{inner}</li>;
}
