"use client";

import { BookOpen, Code2, Server, Shield, Boxes, Zap, ArrowRight } from "lucide-react";
import Link from "next/link";
import { Topbar } from "@/components/Topbar";
import { PageTitle } from "@/components/PageTitle";

const SECTIONS = [
  {
    Icon: Zap,
    title: "Quick start",
    body: "Provision your first dWallet and sign a transaction in under five minutes.",
    tag: "GUIDE",
  },
  {
    Icon: Code2,
    title: "REST API reference",
    body: "Every endpoint, request shape, and response example. Generated from OpenAPI.",
    tag: "REFERENCE",
  },
  {
    Icon: Server,
    title: "MCP server",
    body: "Wire Andromeda into Claude, Cursor, or any MCP-aware agent with scoped tools.",
    tag: "INTEGRATION",
  },
  {
    Icon: Boxes,
    title: "TypeScript SDK",
    body: "Idiomatic SDK with full type coverage of the Andromeda API.",
    tag: "SDK",
  },
  {
    Icon: Shield,
    title: "Security model",
    body: "Threshold cryptography, on-chain-first recovery, and the trust boundary.",
    tag: "ARCH",
  },
  {
    Icon: BookOpen,
    title: "Cookbook",
    body: "Reusable recipes — Solana sends, EVM signing, future-sign vault flows, share transfer.",
    tag: "RECIPES",
  },
];

export default function DocumentationPage() {
  return (
    <>
      <Topbar pageTitle="Documentation" />
      <main className="flex-1 px-6 py-8 overflow-auto">
        <div className="max-w-[1200px] mx-auto">
          <PageTitle
            eyebrow="// docs"
            title="Documentation"
            description="Everything you need to build on Andromeda — from your first dWallet to running a production-grade signing fleet."
            actions={
              <Link
                href="https://docs.andromeda.shinka.dev"
                target="_blank"
                className="btn-secondary"
              >
                Full docs site <ArrowRight size={14} strokeWidth={1.6} />
              </Link>
            }
          />

          {/* Search-like prompt */}
          <div className="card p-5 mb-8">
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-graphite-700/50 border border-white/[0.05]">
              <BookOpen size={16} strokeWidth={1.6} className="text-slate-400" />
              <input
                type="text"
                placeholder="Search the docs — try “sign Ed25519”, “rebuild cache”, “MCP scopes”…"
                className="bg-transparent flex-1 outline-none text-sm placeholder:text-slate-400"
              />
              <kbd className="text-[11px] text-slate-400 font-mono px-1.5 py-0.5 border border-white/[0.08] rounded">
                ⌘K
              </kbd>
            </div>
          </div>

          {/* Sections grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {SECTIONS.map(({ Icon, title, body, tag }) => (
              <button
                key={title}
                type="button"
                className="card p-5 text-left hover:border-ember/25 transition-colors group"
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="w-9 h-9 rounded-lg bg-ember/10 border border-ember/20 grid place-items-center text-ember">
                    <Icon size={16} strokeWidth={1.6} />
                  </div>
                  <span className="font-mono text-[10px] tracking-wider text-slate-400">
                    {tag}
                  </span>
                </div>
                <h4 className="text-[15px] font-semibold tracking-tight mb-1">{title}</h4>
                <p className="text-xs text-slate-300 mb-4">{body}</p>
                <div className="flex items-center gap-1.5 text-xs text-ember-soft font-medium">
                  Read <ArrowRight size={12} strokeWidth={1.8} className="group-hover:translate-x-0.5 transition-transform" />
                </div>
              </button>
            ))}
          </div>
        </div>
      </main>
    </>
  );
}
