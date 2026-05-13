// Andromeda JWK Rotator — off-chain watcher for the on-chain JWK Registry
// (`contracts/jwk-registry/`, program `8xL2mrQ2amDpinQMHJPaEELbgEXWRVGn4PQ7kzDm7vNM`).
//
// Modes:
//   - ROTATE (default): loop fetching provider JWKS, proposes new keys, alerts ops.
//     Usage:  npm start   (loop)   or   npm run once (single pass)
//   - BOOTSTRAP: one-time devnet genesis — fetches JWKS, prints init_registry + bootstrap_jwk
//     instructions (or optionally sends with --send flag).
//     Usage:  npm run bootstrap   or   npm run bootstrap -- --send
//
// Each rotate loop:
//   1. fetches Google / Apple JWKS over TLS, strictly validates each RSA-2048
//      RS256 key, and computes (issuer_hash, audience_hash, kid_hash);
//   2. reads the on-chain JwkRegistry account and decodes its entries;
//   3. for every (iss, aud, kid) that is in the JWKS but has no PENDING/ACTIVE
//      on-chain entry, calls `propose_jwk` with the `authority` keypair;
//   4. alerts ops: a new key was proposed (needs activation after the timelock);
//      an ACTIVE key is nearing `valid_until_ts` with no successor; CRITICAL —
//      an ACTIVE on-chain key is NOT in the provider's JWKS (possible compromise);
//      `propose_jwk` returned RegistryFull.
//
// It NEVER activates / revokes / expires anything — those are human / multisig
// actions (see docs/RUNBOOK_JWK_ROTATION.md).
//
// NOTE — Quasar event-authority PDA seed: this script assumes the standard
// `["__event_authority"]` seed (Anchor/Blueshift convention). If a `propose_jwk`
// tx fails with a PDA-mismatch error, confirm the seed `quasar-lang` actually
// uses and update EVENT_AUTHORITY_SEED below. This is the only on-chain detail
// not yet verified against a deployed program.

import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_CLOCK_PUBKEY,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

// ── Config ─────────────────────────────────────────────────────

const EVENT_AUTHORITY_SEED = Buffer.from("__event_authority");
const REGISTRY_PDA_PREFIX = Buffer.from("jwk_registry");

// Quasar 1-byte instruction discriminators (see contracts/jwk-registry/README.md).
const IX_INIT_REGISTRY = 0;
const IX_PROPOSE_JWK = 1;
const IX_ACTIVATE_JWK = 2;
const IX_BOOTSTRAP_JWK = 5;

// On-chain account layout of JwkRegistry (after the 1-byte Quasar discriminator).
const ACCOUNT_DISC_LEN = 1;
const ENTRY_LEN = 400;
const MAX_JWKS = 8;
// per-entry offsets
const EO_STATUS = 0;
const EO_ALG = 1;
const EO_ISSUER_HASH = 8;
const EO_AUDIENCE_HASH = 40;
const EO_KID_HASH = 72;
const EO_MODULUS = 104;
const EO_EXPONENT = 360;
const EO_PROPOSED_AT = 368;
const EO_VALID_UNTIL = 384;
// statuses
const STATUS_PENDING = 1;
const STATUS_ACTIVE = 2;

const RSA_MODULUS_BYTES = 256;
const RSA_EXPONENT = 65537n;
const ALG_RS256 = 1;

interface ProviderCfg {
  name: "google" | "apple";
  enabled: boolean;
  issuer: string;
  jwksUri: string;
  audience: string;
}

interface Config {
  rpcUrl: string;
  programId: PublicKey;
  registrySeed: Buffer; // 32 bytes
  authority: Keypair;
  // The `AuthorityAction` struct on-chain has authority and payer as SEPARATE
  // Signer slots — if they alias to the same key the framework rejects with
  // "instruction tries to borrow reference for an account which is already
  // borrowed". So propose_jwk / activate_jwk need a distinct payer keypair.
  // Falls back to `authority` when not configured (will fail with aliasing).
  payer: Keypair;
  providers: ProviderCfg[];
  pollIntervalSec: number;
  alertWebhookUrl: string | null;
  successorWarnDays: number;
}

function env(name: string, fallback?: string): string {
  const v = process.env[name];
  if (v === undefined || v === "") {
    if (fallback !== undefined) return fallback;
    throw new Error(`missing required env var ${name}`);
  }
  return v;
}

function loadConfig(): Config {
  const programId = new PublicKey(env("JWK_REGISTRY_PROGRAM_ID"));
  const seedHex = env("JWK_REGISTRY_SEED", "00".repeat(32)).replace(/^0x/, "");
  if (seedHex.length !== 64) throw new Error("JWK_REGISTRY_SEED must be 32 bytes (64 hex chars)");
  const registrySeed = Buffer.from(seedHex, "hex");
  // Authority keypair can be supplied two ways:
  //   - JWK_AUTHORITY_KEYPAIR     → file path (local dev / on-disk secret)
  //   - JWK_AUTHORITY_KEYPAIR_JSON → JSON array of 64 bytes inline (Railway /
  //     other PaaS env-var-only environments). Take precedence is given to the
  //     inline JSON so a deploy override always wins.
  let secret: number[];
  const inlineJson = process.env.JWK_AUTHORITY_KEYPAIR_JSON;
  if (inlineJson && inlineJson.trim().length > 0) {
    try {
      secret = JSON.parse(inlineJson) as number[];
    } catch (e) {
      throw new Error(`JWK_AUTHORITY_KEYPAIR_JSON is not valid JSON: ${(e as Error).message}`);
    }
  } else {
    secret = JSON.parse(readFileSync(env("JWK_AUTHORITY_KEYPAIR"), "utf8")) as number[];
  }
  if (!Array.isArray(secret) || secret.length !== 64) {
    throw new Error("authority keypair must be a JSON array of exactly 64 bytes");
  }
  const authority = Keypair.fromSecretKey(Uint8Array.from(secret));

  // Payer keypair — must be DISTINCT from authority (see Config.payer comment).
  //   - JWK_REGISTRY_PAYER_KEYPAIR_JSON (inline, takes precedence — Railway)
  //   - JWK_REGISTRY_PAYER_KEYPAIR (file path — local dev)
  //   - falls back to `authority` and prints a loud warning (propose/activate
  //     will fail; only useful for read-only / dry-run inspections).
  let payerSecret: number[] | null = null;
  const payerInline = process.env.JWK_REGISTRY_PAYER_KEYPAIR_JSON;
  const payerPath = process.env.JWK_REGISTRY_PAYER_KEYPAIR;
  if (payerInline && payerInline.trim().length > 0) {
    try {
      payerSecret = JSON.parse(payerInline) as number[];
    } catch (e) {
      throw new Error(`JWK_REGISTRY_PAYER_KEYPAIR_JSON is not valid JSON: ${(e as Error).message}`);
    }
  } else if (payerPath && payerPath.trim().length > 0) {
    payerSecret = JSON.parse(readFileSync(payerPath, "utf8")) as number[];
  }
  let payer: Keypair;
  if (payerSecret) {
    if (!Array.isArray(payerSecret) || payerSecret.length !== 64) {
      throw new Error("payer keypair must be a JSON array of exactly 64 bytes");
    }
    payer = Keypair.fromSecretKey(Uint8Array.from(payerSecret));
    if (payer.publicKey.equals(authority.publicKey)) {
      throw new Error("JWK_REGISTRY_PAYER_KEYPAIR must be a DIFFERENT pubkey from JWK_AUTHORITY_KEYPAIR — the framework rejects aliased Signer slots.");
    }
  } else {
    console.warn(
      "[jwk-rotator][WARN] no JWK_REGISTRY_PAYER_KEYPAIR{_JSON} configured — falling back to authority as payer. propose_jwk / activate_jwk WILL FAIL with an aliased-borrow error. Configure a distinct payer keypair before relying on this worker.",
    );
    payer = authority;
  }
  const providers: ProviderCfg[] = [
    {
      name: "google",
      enabled: env("GOOGLE_ENABLED", "true") === "true",
      issuer: "https://accounts.google.com",
      jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
      audience: env("GOOGLE_AUDIENCE", ""),
    },
    {
      name: "apple",
      enabled: env("APPLE_ENABLED", "true") === "true",
      issuer: "https://appleid.apple.com",
      jwksUri: "https://appleid.apple.com/auth/keys",
      audience: env("APPLE_AUDIENCE", ""),
    },
  ];
  for (const p of providers) {
    if (p.enabled && !p.audience) throw new Error(`${p.name} enabled but ${p.name.toUpperCase()}_AUDIENCE not set`);
  }
  return {
    rpcUrl: env("RPC_URL", "https://api.devnet.solana.com"),
    programId,
    registrySeed,
    authority,
    payer,
    providers,
    pollIntervalSec: parseInt(env("POLL_INTERVAL_SECONDS", "3600"), 10),
    alertWebhookUrl: process.env.ALERT_WEBHOOK_URL || null,
    successorWarnDays: parseInt(env("SUCCESSOR_WARN_DAYS", "10"), 10),
  };
}

// ── Helpers ────────────────────────────────────────────────────

const sha256 = (b: Buffer | string): Buffer => createHash("sha256").update(b).digest();

function b64urlDecode(s: string): Buffer {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}

/** Left-pads / validates a JWK modulus to exactly 256 big-endian bytes. */
function normalizeModulus(nB64: string): Buffer | null {
  let n = b64urlDecode(nB64);
  // strip a single leading 0x00 (some encoders prepend it to keep the value positive)
  if (n.length === RSA_MODULUS_BYTES + 1 && n[0] === 0) n = n.subarray(1);
  if (n.length > RSA_MODULUS_BYTES) return null;
  if (n.length < RSA_MODULUS_BYTES) {
    const padded = Buffer.alloc(RSA_MODULUS_BYTES);
    n.copy(padded, RSA_MODULUS_BYTES - n.length);
    n = padded;
  }
  // full 2048-bit (top bit set) and odd — same profile the on-chain program enforces
  if ((n[0]! & 0x80) === 0 || (n[RSA_MODULUS_BYTES - 1]! & 1) === 0) return null;
  return n;
}

function exponentValue(eB64: string): bigint {
  return BigInt("0x" + b64urlDecode(eB64).toString("hex"));
}

interface ProviderKey {
  provider: string;
  issuer: string;
  audience: string;
  kid: string;
  modulus: Buffer; // 256 BE
  issuerHash: Buffer;
  audienceHash: Buffer;
  kidHash: Buffer;
  modulusFp: string; // sha256 hex of modulus, for alerts
}

async function fetchJson(url: string): Promise<unknown> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 10_000);
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: "error", headers: { accept: "application/json" } });
    if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

async function fetchProviderKeys(p: ProviderCfg): Promise<ProviderKey[]> {
  const jwks = (await fetchJson(p.jwksUri)) as { keys?: unknown[] };
  if (!jwks || !Array.isArray(jwks.keys)) throw new Error(`${p.name}: malformed JWKS`);
  const out: ProviderKey[] = [];
  for (const raw of jwks.keys) {
    const k = raw as Record<string, unknown>;
    if (k.kty !== "RSA") continue;
    if (k.alg !== undefined && k.alg !== "RS256") continue; // Google sometimes omits alg
    if (k.use !== undefined && k.use !== "sig") continue;
    if (typeof k.kid !== "string" || typeof k.n !== "string" || typeof k.e !== "string") continue;
    const mod = normalizeModulus(k.n);
    if (!mod) {
      console.warn(`${p.name}: skipping kid=${k.kid} — modulus not a valid RSA-2048 value`);
      continue;
    }
    if (exponentValue(k.e) !== RSA_EXPONENT) {
      console.warn(`${p.name}: skipping kid=${k.kid} — exponent != 65537`);
      continue;
    }
    out.push({
      provider: p.name,
      issuer: p.issuer,
      audience: p.audience,
      kid: k.kid,
      modulus: mod,
      issuerHash: sha256(p.issuer),
      audienceHash: sha256(p.audience),
      kidHash: sha256(k.kid),
      modulusFp: sha256(mod).toString("hex").slice(0, 16),
    });
  }
  return out;
}

// ── On-chain registry ──────────────────────────────────────────

interface OnchainEntry {
  index: number;
  status: number;
  alg: number;
  issuerHash: Buffer;
  audienceHash: Buffer;
  kidHash: Buffer;
  modulus: Buffer; // 256 bytes, BE — used to confirm a PENDING entry's modulus still matches the live JWKS before activating
  proposedAt: bigint;
  validUntil: bigint;
}

interface RegistryState {
  timelockSeconds: bigint;
  gracePeriodSeconds: bigint;
  entries: OnchainEntry[];
}

function deriveRegistryPda(programId: PublicKey, seed: Buffer): PublicKey {
  return PublicKey.findProgramAddressSync([REGISTRY_PDA_PREFIX, seed], programId)[0];
}

function deriveEventAuthority(programId: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync([EVENT_AUTHORITY_SEED], programId)[0];
}

async function readRegistry(conn: Connection, pda: PublicKey): Promise<RegistryState | null> {
  const acc = await conn.getAccountInfo(pda, "confirmed");
  if (!acc) return null;
  const data = acc.data;
  // header layout (after the 1-byte Quasar account discriminator):
  //   disc(1) version(1) entry_count(1) reserved0(6)
  //   authority(32) pending_authority(32) emergency_revoker(32) pending_emergency_revoker(32)
  //   timelock_seconds(8) grace_period_seconds(8)
  //   authority_rotation_ready_at(8) emergency_revoker_rotation_ready_at(8)
  const TIMELOCK_OFFSET = ACCOUNT_DISC_LEN + 1 + 1 + 6 + 32 * 4;
  const GRACE_OFFSET = TIMELOCK_OFFSET + 8;
  const timelockSeconds = data.readBigInt64LE(TIMELOCK_OFFSET);
  const gracePeriodSeconds = data.readBigInt64LE(GRACE_OFFSET);
  const headerLen = ACCOUNT_DISC_LEN + 1 + 1 + 6 + 32 * 4 + 8 * 4;
  const entries: OnchainEntry[] = [];
  for (let i = 0; i < MAX_JWKS; i++) {
    const base = headerLen + i * ENTRY_LEN;
    if (base + ENTRY_LEN > data.length) break;
    const status = data[base + EO_STATUS]!;
    if (status === 0) continue; // EMPTY
    entries.push({
      index: i,
      status,
      alg: data[base + EO_ALG]!,
      issuerHash: data.subarray(base + EO_ISSUER_HASH, base + EO_ISSUER_HASH + 32),
      audienceHash: data.subarray(base + EO_AUDIENCE_HASH, base + EO_AUDIENCE_HASH + 32),
      kidHash: data.subarray(base + EO_KID_HASH, base + EO_KID_HASH + 32),
      modulus: data.subarray(base + EO_MODULUS, base + EO_MODULUS + RSA_MODULUS_BYTES),
      proposedAt: data.readBigInt64LE(base + EO_PROPOSED_AT),
      validUntil: data.readBigInt64LE(base + EO_VALID_UNTIL),
    });
  }
  return { timelockSeconds, gracePeriodSeconds, entries };
}

function tripleEq(e: OnchainEntry, k: ProviderKey): boolean {
  return e.issuerHash.equals(k.issuerHash) && e.audienceHash.equals(k.audienceHash) && e.kidHash.equals(k.kidHash);
}

/**
 * `activate_jwk` instruction. AuthorityAction layout — same accounts as
 * `propose_jwk`. `valid_until_ts` is computed per-provider, see
 * `computeValidUntilTs`.
 */
function activateJwkIx(
  cfg: Config,
  registryPda: PublicKey,
  eventAuthority: PublicKey,
  e: OnchainEntry,
  provider: "google" | "apple",
  gracePeriodSeconds: bigint,
): TransactionInstruction {
  const validUntilTs = computeValidUntilTs(provider, gracePeriodSeconds);
  const data = Buffer.concat([
    Buffer.from([IX_ACTIVATE_JWK]),
    cfg.registrySeed, // 32
    e.issuerHash, // 32
    e.audienceHash, // 32
    e.kidHash, // 32
    (() => {
      const b = Buffer.alloc(8);
      b.writeBigInt64LE(validUntilTs, 0);
      return b;
    })(),
  ]);
  return new TransactionInstruction({
    programId: cfg.programId,
    keys: [
      { pubkey: registryPda, isSigner: false, isWritable: true },
      { pubkey: cfg.authority.publicKey, isSigner: true, isWritable: false },
      { pubkey: cfg.payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
      { pubkey: eventAuthority, isSigner: false, isWritable: false },
      { pubkey: cfg.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

function proposeJwkIx(cfg: Config, registryPda: PublicKey, eventAuthority: PublicKey, k: ProviderKey): TransactionInstruction {
  const data = Buffer.concat([
    Buffer.from([IX_PROPOSE_JWK]),
    cfg.registrySeed, // 32
    k.issuerHash, // 32
    k.audienceHash, // 32
    k.kidHash, // 32
    Buffer.from([ALG_RS256]), // 1
    k.modulus, // 256
    (() => {
      const b = Buffer.alloc(4);
      b.writeUInt32LE(Number(RSA_EXPONENT), 0);
      return b;
    })(),
  ]);
  return new TransactionInstruction({
    programId: cfg.programId,
    keys: [
      { pubkey: registryPda, isSigner: false, isWritable: true },
      { pubkey: cfg.authority.publicKey, isSigner: true, isWritable: false },
      { pubkey: cfg.payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
      { pubkey: eventAuthority, isSigner: false, isWritable: false },
      { pubkey: cfg.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

// ── Alerting ───────────────────────────────────────────────────

type AlertLevel = "info" | "warn" | "critical";
async function alert(cfg: Config, level: AlertLevel, msg: string): Promise<void> {
  const line = `[jwk-rotator][${level.toUpperCase()}] ${msg}`;
  if (level === "critical") console.error(line);
  else console.log(line);
  if (!cfg.alertWebhookUrl) return;
  try {
    await fetch(cfg.alertWebhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text: line, level }),
    });
  } catch (e) {
    console.error(`[jwk-rotator] failed to post alert: ${(e as Error).message}`);
  }
}

// ── One pass ───────────────────────────────────────────────────

async function pass(cfg: Config, conn: Connection): Promise<void> {
  const registryPda = deriveRegistryPda(cfg.programId, cfg.registrySeed);
  const eventAuthority = deriveEventAuthority(cfg.programId);
  const registry = await readRegistry(conn, registryPda);
  if (registry === null) {
    await alert(cfg, "critical", `JwkRegistry account ${registryPda.toBase58()} not found — run init_registry (see RUNBOOK_JWK_ROTATION.md §0)`);
    return;
  }
  const onchain = registry.entries;
  const { timelockSeconds, gracePeriodSeconds } = registry;

  // 1. gather provider keys
  const providerKeys: ProviderKey[] = [];
  for (const p of cfg.providers) {
    if (!p.enabled) continue;
    try {
      const ks = await fetchProviderKeys(p);
      if (ks.length === 0) await alert(cfg, "critical", `${p.name}: JWKS returned no usable RSA-2048/RS256 keys`);
      providerKeys.push(...ks);
    } catch (e) {
      await alert(cfg, "critical", `${p.name}: JWKS fetch failed — ${(e as Error).message}`);
    }
  }

  // 2. CRITICAL — an ACTIVE on-chain entry that is not in any JWKS we just fetched
  //    (only consider providers we successfully fetched, to avoid false positives on a fetch outage)
  const fetchedProviders = new Set(providerKeys.map((k) => k.provider));
  for (const e of onchain) {
    if (e.status !== STATUS_ACTIVE) continue;
    // match by (issuerHash, audienceHash) to a provider we did fetch
    const provForEntry = cfg.providers.find(
      (p) => fetchedProviders.has(p.name) && sha256(p.issuer).equals(e.issuerHash) && sha256(p.audience).equals(e.audienceHash),
    );
    if (!provForEntry) continue; // entry belongs to a provider we didn't fetch this pass, or a different audience — skip
    const stillThere = providerKeys.some((k) => tripleEq(e, k));
    if (!stillThere) {
      await alert(
        cfg,
        "critical",
        `ACTIVE on-chain entry slot=${e.index} (provider=${provForEntry.name}) has a kid that is NOT in the live JWKS — possible key compromise. Investigate and consider emergency revoke (RUNBOOK §4).`,
      );
    }
  }

  // 3. propose any provider key with no PENDING/ACTIVE entry
  let proposed = 0;
  for (const k of providerKeys) {
    const exists = onchain.some((e) => (e.status === STATUS_PENDING || e.status === STATUS_ACTIVE) && tripleEq(e, k));
    if (exists) continue;
    try {
      const ix = proposeJwkIx(cfg, registryPda, eventAuthority, k);
      const tx = new Transaction().add(ix);
      const sig = await conn.sendTransaction(tx, [cfg.authority, cfg.payer], { skipPreflight: false });
      await conn.confirmTransaction(sig, "confirmed");
      proposed++;
      await alert(
        cfg,
        "info",
        `proposed new JWK: provider=${k.provider} kid=${k.kid} modulus_fp=${k.modulusFp} tx=${sig} — NEEDS ACTIVATION after the timelock (RUNBOOK §1).`,
      );
    } catch (e) {
      const m = (e as Error).message || String(e);
      if (m.includes("RegistryFull") || m.includes("0x1b59") /* 7001 hex-ish; adjust if needed */) {
        await alert(cfg, "critical", `propose_jwk failed: registry is full — expire past-grace keys or enlarge the account (RUNBOOK §3). provider=${k.provider} kid=${k.kid}`);
      } else {
        await alert(cfg, "warn", `propose_jwk failed for provider=${k.provider} kid=${k.kid}: ${m}`);
      }
    }
  }

  // 3.5. auto-activate PENDING entries whose timelock has elapsed AND whose
  //      modulus still matches the live JWKS for that provider. The
  //      re-verification is the security wall: even if the authority key were
  //      compromised and proposed a forged JWK, this loop would refuse to
  //      activate it because the live JWKS from Google/Apple cannot be
  //      attacker-controlled.
  const nowForActivate = BigInt(Math.floor(Date.now() / 1000));
  for (const e of onchain) {
    if (e.status !== STATUS_PENDING) continue;
    if (nowForActivate < e.proposedAt + timelockSeconds) continue; // timelock not elapsed yet

    // Match the PENDING entry to a provider via (issuerHash, audienceHash).
    const provForEntry = cfg.providers.find(
      (p) => fetchedProviders.has(p.name) && sha256(p.issuer).equals(e.issuerHash) && sha256(p.audience).equals(e.audienceHash),
    );
    if (!provForEntry) continue; // can't verify against a JWKS we didn't fetch — skip this cycle

    // Find the live JWK with matching kid hash AND matching modulus.
    const liveMatch = providerKeys.find(
      (k) => k.provider === provForEntry.name && tripleEq(e, k) && e.modulus.equals(k.modulus),
    );
    if (!liveMatch) {
      // PENDING entry exists on-chain but does NOT match anything in the live
      // JWKS — either the provider rotated away from this kid already, OR an
      // attacker proposed it. Either way, don't activate. Surface it.
      await alert(
        cfg,
        "warn",
        `PENDING entry slot=${e.index} (provider=${provForEntry.name}) has no matching kid+modulus in the live JWKS — refusing to auto-activate. Investigate before manual action.`,
      );
      continue;
    }

    try {
      const ix = activateJwkIx(cfg, registryPda, eventAuthority, e, provForEntry.name, gracePeriodSeconds);
      const tx = new Transaction().add(ix);
      const sig = await conn.sendTransaction(tx, [cfg.authority, cfg.payer], { skipPreflight: false });
      await conn.confirmTransaction(sig, "confirmed");
      await alert(
        cfg,
        "info",
        `activated PENDING JWK slot=${e.index} provider=${provForEntry.name} modulus_fp=${liveMatch.modulusFp} tx=${sig} (re-verified against live JWKS).`,
      );
    } catch (err) {
      await alert(
        cfg,
        "warn",
        `activate_jwk failed slot=${e.index} provider=${provForEntry.name}: ${(err as Error).message}`,
      );
    }
  }

  // 4. successor warning — an ACTIVE key nearing valid_until with no other ACTIVE/PENDING for the same (iss,aud)
  const nowSec = BigInt(Math.floor(Date.now() / 1000));
  const warnWindow = BigInt(cfg.successorWarnDays * 24 * 3600);
  for (const e of onchain) {
    if (e.status !== STATUS_ACTIVE) continue;
    if (e.validUntil - nowSec > warnWindow) continue;
    const hasSuccessor = onchain.some(
      (o) =>
        o.index !== e.index &&
        (o.status === STATUS_ACTIVE || o.status === STATUS_PENDING) &&
        o.issuerHash.equals(e.issuerHash) &&
        o.audienceHash.equals(e.audienceHash),
    );
    if (!hasSuccessor) {
      await alert(cfg, "warn", `ACTIVE entry slot=${e.index} expires at ${e.validUntil} (~${Number(e.validUntil - nowSec) / 86400 | 0}d) with no ACTIVE/PENDING successor for the same issuer+audience.`);
    }
  }

  console.log(`[jwk-rotator] pass done: ${onchain.length} on-chain entries, ${providerKeys.length} provider keys, ${proposed} proposed.`);
}

// ── Bootstrap (devnet genesis) ─────────────────────────────

interface BootstrapKey {
  provider: string;
  issuer: string;
  audience: string;
  kid: string;
  modulus: Buffer;
  issuerHash: Buffer;
  audienceHash: Buffer;
  kidHash: Buffer;
  validUntilTs: bigint;
}

interface BootstrapInstruction {
  discriminator: number;
  data: string; // hex
  accounts: string[]; // base58 pubkeys
  name: string;
}

/**
 * Per-provider id_token max TTL. The provider issues tokens with `exp - iat`
 * up to this many seconds; an `id_token` cannot validly outlive its issuance
 * by more than this, so we anchor `valid_until_ts` accordingly.
 *
 *   - Google: ~3600s (1h)
 *   - Apple:  ~600s  (10min)
 *
 * Picking the per-provider value (instead of `max(...)`) keeps Apple keys
 * from staying "valid" on-chain long after any plausible Apple token they
 * could have signed has already expired.
 */
const PROVIDER_TOKEN_TTL_SECONDS: Record<"google" | "apple", bigint> = {
  google: BigInt(3600),
  apple: BigInt(600),
};

/**
 * Compute valid_until_ts per RUNBOOK_JWK_ROTATION.md §2:
 * valid_until_ts = last_seen_in_jwks_ts + max_provider_token_ttl + grace_period_seconds
 *
 * For bootstrap (fresh fetch), last_seen_in_jwks_ts = now.
 * `max_provider_token_ttl` is per provider (see `PROVIDER_TOKEN_TTL_SECONDS`).
 * `grace_period_seconds` comes from the registry config.
 */
function computeValidUntilTs(
  provider: "google" | "apple",
  gracePeriodSeconds: bigint,
): bigint {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const maxProviderTokenTtl = PROVIDER_TOKEN_TTL_SECONDS[provider];
  const validUntil = now + maxProviderTokenTtl + gracePeriodSeconds;
  // Sanity cap: contract enforces MAX_VALIDITY_SECONDS = 30 days
  const maxValiditySecs = BigInt(30 * 24 * 3600);
  if (validUntil - now > maxValiditySecs) {
    console.warn(`[jwk-rotator] valid_until_ts computation exceeds MAX_VALIDITY_SECONDS (30d); capping`);
    return now + maxValiditySecs;
  }
  return validUntil;
}

interface BootstrapConfig extends Config {
  payerKeypair?: Keypair; // separate from authority so the two account slots don't alias
  registryAuthority: PublicKey;
  registryEmergencyRevoker: PublicKey;
  timelockSeconds: bigint;
  gracePeriodSeconds: bigint;
  authoritiesKeypair?: Keypair; // only if --send
}

/**
 * Load config for bootstrap mode.
 * Requires additional env vars: JWK_REGISTRY_AUTHORITY, JWK_REGISTRY_EMERGENCY_REVOKER,
 * JWK_REGISTRY_AUTHORITY_KEYPAIR (only if --send).
 */
function loadBootstrapConfig(): BootstrapConfig {
  const cfg = loadConfig();
  const authority = new PublicKey(env("JWK_REGISTRY_AUTHORITY", ""));
  const emergencyRevoker = new PublicKey(env("JWK_REGISTRY_EMERGENCY_REVOKER", ""));
  const timelockSec = BigInt(env("JWK_REGISTRY_TIMELOCK_SECONDS", "3600"));
  const graceSec = BigInt(env("JWK_REGISTRY_GRACE_SECONDS", "604800"));

  let authoritiesKeypair: Keypair | undefined;
  const keypairPath = process.env.JWK_REGISTRY_AUTHORITY_KEYPAIR;
  if (keypairPath) {
    const secret = JSON.parse(readFileSync(keypairPath, "utf8")) as number[];
    authoritiesKeypair = Keypair.fromSecretKey(Uint8Array.from(secret));
  }

  // Optional separate payer (required when --send so authority/payer slots
  // don't point at the same account — the runtime rejects duplicate borrows
  // of a single Signer<…> across two struct fields).
  let payerKeypair: Keypair | undefined;
  const payerPath = process.env.JWK_REGISTRY_PAYER_KEYPAIR;
  if (payerPath) {
    const secret = JSON.parse(readFileSync(payerPath, "utf8")) as number[];
    payerKeypair = Keypair.fromSecretKey(Uint8Array.from(secret));
  }

  return {
    ...cfg,
    registryAuthority: authority,
    registryEmergencyRevoker: emergencyRevoker,
    timelockSeconds: timelockSec,
    gracePeriodSeconds: graceSec,
    authoritiesKeypair,
    payerKeypair,
  };
}

async function bootstrapPass(cfg: BootstrapConfig, conn: Connection): Promise<void> {
  const registryPda = deriveRegistryPda(cfg.programId, cfg.registrySeed);
  const eventAuthority = deriveEventAuthority(cfg.programId);

  // Validate roles
  if (!cfg.registryAuthority || cfg.registryAuthority.equals(PublicKey.default)) {
    throw new Error("JWK_REGISTRY_AUTHORITY not set or invalid");
  }
  if (!cfg.registryEmergencyRevoker || cfg.registryEmergencyRevoker.equals(PublicKey.default)) {
    throw new Error("JWK_REGISTRY_EMERGENCY_REVOKER not set or invalid");
  }
  if (cfg.registryAuthority.equals(cfg.registryEmergencyRevoker)) {
    throw new Error("JWK_REGISTRY_AUTHORITY and JWK_REGISTRY_EMERGENCY_REVOKER must be different");
  }

  console.log(`[jwk-rotator:bootstrap]`);
  console.log(`  Program ID: ${cfg.programId.toBase58()}`);
  console.log(`  Registry PDA: ${registryPda.toBase58()}`);
  console.log(`  Authority: ${cfg.registryAuthority.toBase58()}`);
  console.log(`  Emergency Revoker: ${cfg.registryEmergencyRevoker.toBase58()}`);
  console.log(`  Timelock: ${cfg.timelockSeconds}s`);
  console.log(`  Grace Period: ${cfg.gracePeriodSeconds}s`);

  // Gather provider keys
  const providerKeys: BootstrapKey[] = [];
  for (const p of cfg.providers) {
    if (!p.enabled) continue;
    try {
      const ks = await fetchProviderKeys(p);
      if (ks.length === 0) {
        console.warn(`[jwk-rotator] ${p.name}: JWKS returned no usable RSA-2048/RS256 keys`);
        continue;
      }
      const validUntil = computeValidUntilTs(p.name, cfg.gracePeriodSeconds);
      for (const k of ks) {
        providerKeys.push({
          provider: k.provider,
          issuer: k.issuer,
          audience: k.audience,
          kid: k.kid,
          modulus: k.modulus,
          issuerHash: k.issuerHash,
          audienceHash: k.audienceHash,
          kidHash: k.kidHash,
          validUntilTs: validUntil,
        });
      }
      console.log(`[jwk-rotator] ${p.name}: fetched ${ks.length} keys, valid_until=${new Date(Number(providerKeys[providerKeys.length - 1]!.validUntilTs) * 1000).toISOString()}`);
    } catch (e) {
      throw new Error(`${p.name}: JWKS fetch failed — ${(e as Error).message}`);
    }
  }

  if (providerKeys.length === 0) {
    throw new Error("No provider keys fetched; check provider config and JWKS accessibility");
  }

  console.log(`[jwk-rotator] Fetched ${providerKeys.length} total keys`);

  // Build init_registry instruction
  const initRegData = Buffer.concat([
    Buffer.from([IX_INIT_REGISTRY]),
    cfg.registrySeed, // 32
    cfg.registryAuthority.toBuffer(), // 32
    cfg.registryEmergencyRevoker.toBuffer(), // 32
    (() => {
      const b = Buffer.alloc(8);
      b.writeBigUInt64LE(cfg.timelockSeconds, 0);
      return b;
    })(),
    (() => {
      const b = Buffer.alloc(8);
      b.writeBigUInt64LE(cfg.gracePeriodSeconds, 0);
      return b;
    })(),
  ]);

  // payer defaults to authority (works for the dry-run print + watcher
  // contexts); for --send the separate JWK_REGISTRY_PAYER_KEYPAIR is required
  // and enforced below.
  const payer = (cfg.payerKeypair ?? cfg.authority).publicKey;
  const systemProgram = SystemProgram.programId;
  const rentSysvar = new PublicKey("SysvarRent111111111111111111111111111111111");
  const clockSysvar = new PublicKey("SysvarC1ock11111111111111111111111111111111");

  // Order MUST match the `InitRegistry` Quasar struct in
  // `contracts/jwk-registry/src/lib.rs`:
  //   registry, authority, payer, clock, rent, system_program, event_authority, program.
  const initRegIx: BootstrapInstruction = {
    discriminator: IX_INIT_REGISTRY,
    data: initRegData.toString("hex"),
    accounts: [
      registryPda.toBase58(),
      cfg.registryAuthority.toBase58(),
      payer.toBase58(),
      clockSysvar.toBase58(),
      rentSysvar.toBase58(),
      systemProgram.toBase58(),
      eventAuthority.toBase58(),
      cfg.programId.toBase58(),
    ],
    name: "init_registry",
  };

  // Build bootstrap_jwk instructions (one per key)
  const bootstrapIxs: BootstrapInstruction[] = [];
  for (const k of providerKeys) {
    const bootstrapData = Buffer.concat([
      Buffer.from([IX_BOOTSTRAP_JWK]),
      cfg.registrySeed, // 32
      k.issuerHash, // 32
      k.audienceHash, // 32
      k.kidHash, // 32
      Buffer.from([ALG_RS256]), // 1
      k.modulus, // 256
      (() => {
        const b = Buffer.alloc(4);
        b.writeUInt32LE(Number(RSA_EXPONENT), 0);
        return b;
      })(),
      (() => {
        const b = Buffer.alloc(8);
        b.writeBigInt64LE(k.validUntilTs, 0);
        return b;
      })(),
    ]);

    bootstrapIxs.push({
      discriminator: IX_BOOTSTRAP_JWK,
      data: bootstrapData.toString("hex"),
      accounts: [
        registryPda.toBase58(),
        cfg.registryAuthority.toBase58(),
        payer.toBase58(),
        SYSVAR_CLOCK_PUBKEY.toBase58(),
        eventAuthority.toBase58(),
        cfg.programId.toBase58(),
      ],
      name: `bootstrap_jwk (${k.provider} / ${k.kid.slice(0, 12)}... / expires ${new Date(Number(k.validUntilTs) * 1000).toISOString()})`,
    });
  }

  // Output instructions as JSON
  const instructions = [initRegIx, ...bootstrapIxs];
  const outputJson = {
    programId: cfg.programId.toBase58(),
    registryPda: registryPda.toBase58(),
    instructions,
    summary: {
      initRegistry: 1,
      bootstrapJwk: bootstrapIxs.length,
      totalJwks: bootstrapIxs.length,
    },
  };

  console.log(`\n[jwk-rotator] ── Bootstrap instructions ready ──\n`);
  console.log(JSON.stringify(outputJson, null, 2));

  // Optionally send
  const shouldSend = process.argv.includes("--send");
  if (!shouldSend) {
    console.log(`\n[jwk-rotator] Dry run complete. To actually submit, rerun with --send flag.`);
    console.log(`[jwk-rotator] CAUTION: --send requires JWK_REGISTRY_AUTHORITY_KEYPAIR env var to be set.`);
    return;
  }

  if (!cfg.authoritiesKeypair) {
    throw new Error("--send flag requires JWK_REGISTRY_AUTHORITY_KEYPAIR env var to point to a valid keypair file");
  }

  if (!cfg.authoritiesKeypair.publicKey.equals(cfg.registryAuthority)) {
    throw new Error(`JWK_REGISTRY_AUTHORITY_KEYPAIR pubkey (${cfg.authoritiesKeypair.publicKey.toBase58()}) does not match JWK_REGISTRY_AUTHORITY (${cfg.registryAuthority.toBase58()})`);
  }
  if (!cfg.payerKeypair) {
    throw new Error(
      "--send requires JWK_REGISTRY_PAYER_KEYPAIR — a keypair file DISTINCT from JWK_REGISTRY_AUTHORITY_KEYPAIR. The authority and payer slots cannot alias.",
    );
  }
  if (cfg.payerKeypair.publicKey.equals(cfg.registryAuthority)) {
    throw new Error("JWK_REGISTRY_PAYER_KEYPAIR must be a different pubkey from JWK_REGISTRY_AUTHORITY.");
  }

  // Confirmation banner
  console.log(`\n${"=".repeat(80)}`);
  console.log(`[jwk-rotator] SENDING TO CHAIN IN 3 SECONDS — Press Ctrl+C to abort!`);
  console.log(`  Network: ${cfg.rpcUrl}`);
  console.log(`  1 init_registry + ${bootstrapIxs.length} bootstrap_jwk transactions`);
  console.log(`${"=".repeat(80)}\n`);
  await new Promise((r) => setTimeout(r, 3000));

  // Send init_registry
  try {
    const initTx = new Transaction().add(
      new TransactionInstruction({
        programId: cfg.programId,
        keys: instructions[0]!.accounts.map((addr, idx) => {
          const pubkey = new PublicKey(addr);
          // init_registry accounts:
          //   0 registry (mut, init), 1 authority (signer), 2 payer (signer, mut),
          //   3 clock, 4 rent, 5 system_program, 6 event_authority, 7 program.
          const isWritable = idx === 0 || idx === 2; // registry, payer
          const isSigner = (idx === 1 || idx === 2); // authority, payer
          return { pubkey, isSigner, isWritable };
        }),
        data: Buffer.from(instructions[0]!.data, "hex"),
      }),
    );
    const sig0 = await conn.sendTransaction(initTx, [cfg.authoritiesKeypair, cfg.payerKeypair!], { skipPreflight: false });
    await conn.confirmTransaction(sig0, "confirmed");
    console.log(`[jwk-rotator] ✓ init_registry: ${sig0}`);
  } catch (e) {
    throw new Error(`init_registry failed: ${(e as Error).message}`);
  }

  // Send bootstrap_jwk transactions
  for (let i = 0; i < bootstrapIxs.length; i++) {
    try {
      const ix = instructions[i + 1]!;
      const bootstrapTx = new Transaction().add(
        new TransactionInstruction({
          programId: cfg.programId,
          keys: ix.accounts.map((addr, idx) => {
            const pubkey = new PublicKey(addr);
            // bootstrap_jwk accounts: registry, authority, payer, clock, event_auth, program
            const isWritable = idx === 0 || idx === 2; // registry, payer
            const isSigner = (idx === 1 || idx === 2); // authority, payer
            return { pubkey, isSigner, isWritable };
          }),
          data: Buffer.from(ix.data, "hex"),
        }),
      );
      const sig = await conn.sendTransaction(bootstrapTx, [cfg.authoritiesKeypair, cfg.payerKeypair!], { skipPreflight: false });
      await conn.confirmTransaction(sig, "confirmed");
      console.log(`[jwk-rotator] ✓ bootstrap_jwk[${i}] (${bootstrapIxs[i]!.name}): ${sig}`);
    } catch (e) {
      console.error(`[jwk-rotator] ✗ bootstrap_jwk[${i}] failed: ${(e as Error).message}`);
      throw e;
    }
  }

  console.log(`\n[jwk-rotator] ✓ Genesis bootstrap complete!`);
  console.log(`[jwk-rotator] Registry: ${registryPda.toBase58()}`);
  console.log(`[jwk-rotator] Next: set IKA_OIDC_JWK_REGISTRY_ADDRESS=${registryPda.toBase58()} and start the rotator watcher.`);
}

// ── Main ───────────────────────────────────────────────────────

async function main() {
  const mode = process.argv[2];

  if (mode === "bootstrap") {
    const cfg = loadBootstrapConfig();
    const conn = new Connection(cfg.rpcUrl, "confirmed");
    try {
      await bootstrapPass(cfg, conn);
    } catch (e) {
      console.error(`[jwk-rotator:bootstrap] error: ${(e as Error).message}`);
      process.exit(1);
    }
    return;
  }

  // Default: ROTATE mode
  const cfg = loadConfig();
  const conn = new Connection(cfg.rpcUrl, "confirmed");
  const once = process.argv.includes("--once");
  console.log(
    `[jwk-rotator] program=${cfg.programId.toBase58()} registry=${deriveRegistryPda(cfg.programId, cfg.registrySeed).toBase58()} authority=${cfg.authority.publicKey.toBase58()} interval=${cfg.pollIntervalSec}s ${once ? "(single pass)" : ""}`,
  );
  // graceful shutdown
  let stopping = false;
  for (const s of ["SIGINT", "SIGTERM"] as const) process.on(s, () => { stopping = true; });
  do {
    try {
      await pass(cfg, conn);
    } catch (e) {
      await alert(cfg, "critical", `pass crashed: ${(e as Error).stack || String(e)}`);
    }
    if (once || stopping) break;
    await new Promise((r) => setTimeout(r, cfg.pollIntervalSec * 1000));
  } while (!stopping);
}

main().catch((e) => {
  console.error("[jwk-rotator] fatal:", e);
  process.exit(1);
});
