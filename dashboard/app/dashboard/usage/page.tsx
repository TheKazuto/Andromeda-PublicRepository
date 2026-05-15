"use client";

import { useEffect, useState } from "react";
import clsx from "clsx";
import { Activity, Zap, BarChart3, ArrowUpRight } from "lucide-react";
import { Topbar } from "@/components/Topbar";
import { PageTitle } from "@/components/PageTitle";
import { Stat } from "@/components/Stat";
import { me, type MeUsage } from "@/lib/api";
import { errorMessage, formatNumber } from "@/lib/format";

type RangeKey = "7d" | "30d" | "90d";

const RANGE_LABEL: Record<RangeKey, string> = {
  "7d": "7 days",
  "30d": "30 days",
  "90d": "90 days",
};

export default function UsagePage() {
  const [range, setRange] = useState<RangeKey>("30d");
  const [usage, setUsage] = useState<MeUsage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    me.usage(range)
      .then((u) => {
        if (!cancelled) setUsage(u);
      })
      .catch((err) => {
        if (!cancelled) setError(errorMessage(err, "Failed to load usage"));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [range]);

  const max = usage ? Math.max(1, ...usage.daily.map((d) => d.tokens)) : 0;
  const days = usage?.daily ?? [];
  const avgPerDay = usage && days.length > 0 ? Math.round(usage.tokens / days.length) : 0;

  return (
    <>
      <Topbar pageTitle="Usage" />
      <main className="flex-1 px-6 py-8 overflow-auto">
        <div className="max-w-[1200px] mx-auto">
          <PageTitle
            eyebrow="// metrics"
            title="Usage"
            description="Real-time view of tokens, calls, and the routes driving your traffic."
            actions={
              <div className="flex items-center gap-1 p-1 rounded-lg border border-white/[0.08] bg-graphite-700/40">
                {(Object.keys(RANGE_LABEL) as RangeKey[]).map((r) => (
                  <button
                    key={r}
                    type="button"
                    onClick={() => setRange(r)}
                    className={clsx(
                      "px-2.5 py-1 text-xs rounded-md transition-colors",
                      range === r
                        ? "bg-ember/15 text-ember-soft border border-ember/25"
                        : "text-slate-300 hover:text-snow",
                    )}
                  >
                    {RANGE_LABEL[r]}
                  </button>
                ))}
              </div>
            }
          />

          {error && (
            <div className="card p-4 mb-6 border-ember/25 text-sm text-ember-soft">
              {error}
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <Stat
              label="Total tokens"
              value={usage ? formatNumber(usage.tokens) : loading ? "…" : "—"}
              sublabel={`metered, ${RANGE_LABEL[range]}`}
              Icon={Zap}
            />
            <Stat
              label="Total calls"
              value={usage ? formatNumber(usage.calls) : loading ? "…" : "—"}
              sublabel="all routes"
              Icon={Activity}
            />
            <Stat
              label="Avg per day"
              value={usage ? formatNumber(avgPerDay) : loading ? "…" : "—"}
              sublabel="tokens"
              Icon={BarChart3}
            />
            <Stat
              label="Top routes"
              value={String(usage?.topRoutes.length ?? 0)}
              sublabel="tracked"
              Icon={ArrowUpRight}
            />
          </div>

          {/* Bar chart */}
          <div className="card p-6 mb-6">
            <div className="flex items-center justify-between mb-1">
              <h3 className="text-[15px] font-semibold tracking-tight">
                Daily tokens ({RANGE_LABEL[range]})
              </h3>
              <div className="flex items-center gap-3 text-[11px] text-slate-400">
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-sm bg-ember" /> Tokens
                </span>
              </div>
            </div>
            <p className="text-sm text-slate-300 mb-6">Hover a day to see exact volume.</p>

            {days.length === 0 ? (
              <div className="text-sm text-slate-400 py-12 text-center border border-dashed border-white/[0.08] rounded-lg">
                {loading ? "Loading…" : "No traffic in this range yet."}
              </div>
            ) : (
              <>
                <div className="flex items-end gap-1 h-[220px]">
                  {days.map((d) => {
                    const h = Math.max(2, (d.tokens / max) * 200);
                    return (
                      <div
                        key={d.date}
                        className="group relative flex-1 flex items-end h-full"
                        title={`${d.date}: ${d.tokens} tokens · ${d.calls} calls`}
                      >
                        <div
                          className="w-full rounded-t bg-gradient-to-t from-ember-deep/70 to-ember/85 hover:from-ember-deep hover:to-ember-soft transition-colors"
                          style={{ height: `${h}px` }}
                        />
                        <div className="opacity-0 group-hover:opacity-100 absolute -top-9 left-1/2 -translate-x-1/2 bg-graphite-700 border border-white/[0.08] rounded-md px-2 py-1 text-[11px] whitespace-nowrap pointer-events-none transition-opacity">
                          <span className="font-mono">{formatNumber(d.tokens)}</span>{" "}
                          <span className="text-slate-400">tokens</span>
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div className="flex justify-between text-[10px] text-slate-400 mt-3 font-mono">
                  <span>{days[0]?.date || ""}</span>
                  <span>{days[days.length - 1]?.date || "Today"}</span>
                </div>
              </>
            )}
          </div>

          {/* Top routes */}
          <div className="card p-6">
            <h3 className="text-[15px] font-semibold tracking-tight mb-1">Top routes</h3>
            <p className="text-sm text-slate-300 mb-5">
              Endpoints driving the most token consumption in this window.
            </p>
            {!usage || usage.topRoutes.length === 0 ? (
              <div className="text-sm text-slate-400 py-6 text-center border border-dashed border-white/[0.08] rounded-lg">
                {loading ? "Loading…" : "No route activity yet."}
              </div>
            ) : (
              <div className="flex flex-col gap-2">
                {usage.topRoutes.map((r) => {
                  const pct = usage.tokens > 0 ? (r.tokens / usage.tokens) * 100 : 0;
                  return (
                    <div
                      key={r.routeKey}
                      className="px-3 py-2.5 rounded-lg bg-graphite-700/50 border border-white/[0.05]"
                    >
                      <div className="flex items-center justify-between gap-3 mb-1.5">
                        <div className="font-mono text-[12px] text-snow truncate">
                          {r.routeKey}
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono shrink-0">
                          {formatNumber(r.tokens)} tokens · {formatNumber(r.calls)} calls
                        </div>
                      </div>
                      <div className="h-1 rounded-full bg-white/[0.05] overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-ember-deep/70 to-ember/85"
                          style={{ width: `${Math.min(100, pct).toFixed(1)}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </main>
    </>
  );
}
