"use client";

import { useState } from "react";
import { Copy, Check, Server, Globe, Sparkles } from "lucide-react";
import { Topbar } from "@/components/Topbar";
import { PageTitle } from "@/components/PageTitle";

const CONFIG = `{
  "mcpServers": {
    "andromeda": {
      "url": "https://api.andromedainfra.pro/mcp",
      "headers": {
        "X-Api-Key": "sk_live_..."
      }
    }
  }
}`;

const TOOLS = [
  { name: "gateway.routes.list", desc: "Discover every tool the agent can call." },
  { name: "ika.dkg.prepare", desc: "Initialize a new dWallet via 2PC-MPC distributed key generation." },
  { name: "ika.sign.submit", desc: "Sign a message with an existing dWallet." },
  { name: "ika.recovery.challenge", desc: "Discover dWallets owned by any external wallet, custody-free." },
  { name: "ika.recovery.primary.submit", desc: "Recover access using a primary credential, gas-sponsored." },
  { name: "encrypt.ciphertext.create", desc: "FHE primitive: register encrypted inputs for confidential operations." },
];

export default function MCPServerPage() {
  const [copied, setCopied] = useState(false);

  function copy(text: string) {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <>
      <Topbar pageTitle="MCP Server" />
      <main className="flex-1 px-6 py-8 overflow-auto">
        <div className="max-w-[1200px] mx-auto">
          <PageTitle
            eyebrow="// model context protocol"
            title="MCP Server"
            description="Drop Andromeda into Claude, Cursor, or any MCP-aware agent. Every API operation becomes a callable tool, gated by the API key's scopes."
          />

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-8">
            <Capability
              Icon={Server}
              title="Hosted endpoint"
              body="No local install. Point any MCP client to https://api.andromedainfra.pro/mcp and authenticate with your API key."
            />
            <Capability
              Icon={Globe}
              title="HTTP Streamable"
              body="Standard MCP transport over HTTPS. Works with Claude Desktop, Cursor, and any client that speaks the spec."
            />
            <Capability
              Icon={Sparkles}
              title="Scoped tools"
              body="Each API key controls which tools are callable. Origin and IP allowlists apply per key."
            />
          </div>

          {/* Config block */}
          <div className="card overflow-hidden mb-6">
            <div className="flex items-center justify-between px-4 py-2.5 border-b border-white/[0.05] bg-white/[0.02]">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-slate-200">claude_desktop_config.json</span>
              </div>
              <button onClick={() => copy(CONFIG)} className="btn-ghost px-2.5 py-1.5 text-xs">
                {copied ? <Check size={12} strokeWidth={1.6} /> : <Copy size={12} strokeWidth={1.6} />}
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <pre className="font-mono text-[13px] leading-relaxed p-5 overflow-x-auto text-[#d6d6d8]">
              <code>
                {`{`}
                {`\n  `}
                <span className="text-[#9cdcfe]">"mcpServers"</span>: {`{`}
                {`\n    `}
                <span className="text-[#9cdcfe]">"andromeda"</span>: {`{`}
                {`\n      `}
                <span className="text-[#9cdcfe]">"url"</span>: <span className="text-[#ce9178]">"https://api.andromedainfra.pro/mcp"</span>,
                {`\n      `}
                <span className="text-[#9cdcfe]">"headers"</span>: {`{`}
                {`\n        `}
                <span className="text-[#9cdcfe]">"X-Api-Key"</span>: <span className="text-[#ce9178]">"sk_live_..."</span>
                {`\n      `}
                {`}`}
                {`\n    `}
                {`}`}
                {`\n  `}
                {`}`}
                {`\n`}
                {`}`}
              </code>
            </pre>
          </div>

          {/* Tools list */}
          <div className="card p-6">
            <h3 className="text-[15px] font-semibold tracking-tight mb-1">Auto-exposed tools</h3>
            <p className="text-sm text-slate-300 mb-5">
              60+ tools auto-generated from the API. Showing 6 of the most common — the full list is returned by tools/list once your client connects.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {TOOLS.map((t) => (
                <div
                  key={t.name}
                  className="rounded-lg border border-white/[0.05] bg-graphite-700/40 p-4 hover:border-ember/25 transition-colors"
                >
                  <div className="font-mono text-[12px] text-ember-soft mb-1">{t.name}</div>
                  <div className="text-xs text-slate-300">{t.desc}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>
    </>
  );
}

function Capability({
  Icon,
  title,
  body,
}: {
  Icon: typeof Server;
  title: string;
  body: string;
}) {
  return (
    <div className="card p-5">
      <div className="w-9 h-9 rounded-lg bg-ember/10 border border-ember/20 grid place-items-center text-ember mb-3">
        <Icon size={16} strokeWidth={1.6} />
      </div>
      <div className="text-[15px] font-semibold tracking-tight mb-1">{title}</div>
      <p className="text-xs text-slate-300 leading-relaxed">{body}</p>
    </div>
  );
}
