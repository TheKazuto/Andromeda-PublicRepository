"use client";

import type { ComponentType } from "react";
import { Mail, MessageSquare, ExternalLink, LifeBuoy } from "lucide-react";
import { Topbar } from "@/components/Topbar";
import { PageTitle } from "@/components/PageTitle";

function Github({ size = 16, strokeWidth = 1.6 }: { size?: number; strokeWidth?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.4 5.4 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4" />
      <path d="M9 18c-4.51 2-5-2-7-2" />
    </svg>
  );
}

const FAQ = [
  {
    q: "How do I rotate an API key?",
    a: "Create a new key on the API Keys page, swap it into your environment, then revoke the old one. Andromeda never invalidates a request mid-flight.",
  },
  {
    q: "Which curves does Andromeda support?",
    a: "Ed25519, Secp256k1 (ECDSA + Schnorr/Taproot), Secp256r1, and Ristretto. That covers Solana, Bitcoin, every EVM chain, Polkadot, Sui and more.",
  },
  {
    q: "What happens if a sign request times out?",
    a: "Retries with the same idempotency key are safe — Andromeda will return the original signature without re-spending the dWallet's presign capacity.",
  },
  {
    q: "How do I rebuild my wallet cache after a network event?",
    a: "POST /v1/users/:owner/rebuild-cache — the on-chain account is the source of truth. Andromeda re-derives state in milliseconds.",
  },
];

export default function SupportPage() {
  return (
    <>
      <Topbar pageTitle="Support" />
      <main className="flex-1 px-6 py-8 overflow-auto">
        <div className="max-w-[1000px] mx-auto">
          <PageTitle
            eyebrow="// help"
            title="Support"
            description="Get unblocked fast. Search the FAQ, open a ticket, or reach an engineer directly."
          />

          {/* Channels */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            <Channel
              Icon={Mail}
              title="Email"
              body="Best for billing questions and account issues."
              cta="support@andromeda.shinka.dev"
              href="mailto:support@andromeda.shinka.dev"
            />
            <Channel
              Icon={MessageSquare}
              title="Live chat"
              body="9–7 UTC weekdays. Avg first response under 6 minutes."
              cta="Open chat"
            />
            <Channel
              Icon={Github}
              title="GitHub"
              body="Bug reports, feature requests, and SDK contributions."
              cta="andromeda/sdk"
              href="https://github.com"
            />
          </div>

          {/* Submit ticket */}
          <div className="card p-6 mb-8">
            <div className="flex items-start gap-3 mb-5">
              <div className="w-9 h-9 rounded-lg bg-ember/10 border border-ember/20 grid place-items-center text-ember">
                <LifeBuoy size={16} strokeWidth={1.6} />
              </div>
              <div>
                <h3 className="text-[15px] font-semibold tracking-tight mb-1">Open a ticket</h3>
                <p className="text-sm text-slate-300">
                  We aim to respond within one business day. Constellation and Galaxy customers get
                  priority routing.
                </p>
              </div>
            </div>
            <form className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="sm:col-span-2">
                <label className="label-base mb-1.5 block" htmlFor="t-subj">Subject</label>
                <input id="t-subj" className="input-base" placeholder="Sign request returns 504" />
              </div>
              <div>
                <label className="label-base mb-1.5 block" htmlFor="t-cat">Category</label>
                <select id="t-cat" className="input-base">
                  <option>Technical issue</option>
                  <option>Billing</option>
                  <option>Account</option>
                  <option>Feature request</option>
                </select>
              </div>
              <div>
                <label className="label-base mb-1.5 block" htmlFor="t-pri">Priority</label>
                <select id="t-pri" className="input-base">
                  <option>Normal</option>
                  <option>High — production impacted</option>
                  <option>Urgent — outage</option>
                </select>
              </div>
              <div className="sm:col-span-2">
                <label className="label-base mb-1.5 block" htmlFor="t-body">Description</label>
                <textarea
                  id="t-body"
                  rows={5}
                  className="input-base resize-none"
                  placeholder="Steps to reproduce, expected behaviour, traceId if available…"
                />
              </div>
              <div className="sm:col-span-2 flex justify-end">
                <button type="submit" className="btn-primary">Submit ticket</button>
              </div>
            </form>
          </div>

          {/* FAQ */}
          <h3 className="text-[15px] font-semibold tracking-tight mb-3">Frequently asked</h3>
          <div className="card divide-y divide-white/[0.05]">
            {FAQ.map((f) => (
              <details key={f.q} className="group p-5">
                <summary className="cursor-pointer flex items-center justify-between text-sm font-medium text-snow list-none">
                  <span>{f.q}</span>
                  <span className="w-5 h-5 rounded-full border border-white/[0.1] grid place-items-center text-slate-400 transition-transform group-open:rotate-45">
                    +
                  </span>
                </summary>
                <p className="text-sm text-slate-300 mt-2.5">{f.a}</p>
              </details>
            ))}
          </div>
        </div>
      </main>
    </>
  );
}

function Channel({
  Icon,
  title,
  body,
  cta,
  href,
}: {
  Icon: ComponentType<{ size?: number; strokeWidth?: number }>;
  title: string;
  body: string;
  cta: string;
  href?: string;
}) {
  const content = (
    <div className="card p-5 hover:border-ember/25 transition-colors h-full flex flex-col">
      <div className="w-9 h-9 rounded-lg bg-ember/10 border border-ember/20 grid place-items-center text-ember mb-3">
        <Icon size={16} strokeWidth={1.6} />
      </div>
      <div className="text-[15px] font-semibold tracking-tight mb-1">{title}</div>
      <p className="text-xs text-slate-300 mb-4 flex-1">{body}</p>
      <div className="flex items-center gap-1.5 text-xs text-ember-soft font-mono">
        {cta} <ExternalLink size={12} strokeWidth={1.8} />
      </div>
    </div>
  );
  return href ? (
    <a href={href} target="_blank" rel="noreferrer">
      {content}
    </a>
  ) : (
    <button type="button" className="text-left">
      {content}
    </button>
  );
}
