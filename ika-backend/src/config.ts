import { z } from 'zod'

const truthy = (v: string | undefined): boolean => v === 'true' || v === '1' || v === 'yes'

function csv(value: string | undefined): string[] {
  if (!value) return []
  return value
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}

const baseSchema = z.object({
  port: z.number().int().positive().default(8080),
  nodeEnv: z.enum(['development', 'production', 'test']).default('development'),
  logLevel: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  databaseUrl: z.string().url(),
  pgSslMode: z.string().optional(),
  pgPoolMax: z.number().int().positive().default(20),
  pgConnectionTimeoutMillis: z.number().int().positive().default(3_000),
  ikaGrpcUrl: z.string().url(),
  ikaGrpcTls: z.boolean().default(true),
  ikaProgramId: z.string().min(32),
  solanaRpcUrl: z.string().url(),
  solanaCommitment: z.enum(['processed', 'confirmed', 'finalized']).default('confirmed'),
  // INTERNAL_API_KEY gates traffic from the gateway → ika-backend (private
  // network). 32 char minimum mirrors encrypt-backend and rejects
  // "dev123"/"changeme"-style misconfigurations at boot.
  serviceApiKey: z.string().min(32, 'INTERNAL_API_KEY must be at least 32 chars'),
  adminApiKey: z.string().optional(),
  allowedOrigins: z.array(z.string()).default([]),
})

// ── Login Social (`scheme = 4 = OidcJwt`) — see loginsocial.md §9/§17 ──
//
// Opt-in via IKA_OIDC_ENABLED. When disabled the surface is identical to the
// pre-OIDC backend. The on-chain `rules-policy` (`scheme = 4`) + `jwk-registry`
// remain the source of truth; this config drives the obligatory off-chain
// pre-validation (`POST /v1/oidc/validate`) and the recovery adapters.
const oidcSchema = z.object({
  enabled: z.boolean().default(false),
  googleEnabled: z.boolean().default(false),
  googleClientId: z.string().optional(),
  appleEnabled: z.boolean().default(false),
  appleClientId: z.string().optional(),
  /** CSV — mirrors the hardcoded on-chain allowlist (one `aud` global per env). */
  allowedAudiences: z.array(z.string()).default([]),
  /** Address of the on-chain `JwkRegistry` account (canonical PDA). */
  jwkRegistryAddress: z.string().optional(),
  /** Must equal the contract's `OIDC_VERIFIER_V1`. */
  verifierVersion: z.number().int().positive().default(1),
  /** HMAC key for `subjectHash` in logs/metrics — never reuse another secret. */
  logSubjectHmacSecret: z.string().optional(),
})

const gasSponsorSchema = z.object({
  // Single keypair (back-compat path). Either this or `keypairs` is set;
  // both may be empty, in which case gas sponsor is disabled.
  keypair: z.string().optional(),
  // Pool of N keypairs (production scaling). When set, the engine picks
  // the least-loaded fee payer for each tx. Values are JSON-encoded byte
  // arrays separated by `;` to avoid escaping issues inside Railway env.
  keypairs: z.array(z.string()).optional(),
  minBalanceSol: z.number().nonnegative().default(0.5),
  maxGasPerOpLamports: z.number().int().positive().default(20_000_000),
})

// ── Keyspring Fase 3 — passkey-PRF (D1 Opção A) — see PLAN_KEYSPRING_INTEGRATION_2026_05.md ──
//
// Opt-in via IKA_PASSKEY_ENABLED. When disabled the passkey routes are not
// mounted. The on-chain `rules-policy` (`scheme = 3 = WebAuthn` session
// flow) is the source of truth; this config drives RP ID binding (D2),
// challenge TTL, salt strategy (D3 — `per_credential` only in prod) and
// the off-chain pre-validation done in the routes.
const passkeySchema = z.object({
  enabled: z.boolean().default(false),
  /** D2 — RP ID in production is the apex `andromedainfra.pro`. IMMUTABLE
   *  after the first passkey is registered; rotation would orphan every
   *  credential derived under the old value. */
  rpId: z.string().optional(),
  /** Origin the user's WebAuthn flow runs on (e.g. `https://app.andromedainfra.pro`). */
  rpOrigin: z.string().optional(),
  challengeTtlSeconds: z.number().int().positive().default(120),
  /** D3 — only `per_credential` is accepted in production. The check at
   *  the bottom of `loadConfig` fails-fast on `global`. */
  saltMode: z.enum(['per_credential', 'global']).default('per_credential'),
  /** Mirrors `contracts/rules-policy::SESSION_TTL_SECONDS = 600`. The
   *  contract caps it on-chain anyway; this env exists so tests / dev
   *  envs can shorten it without redeploying. */
  sessionTtlSeconds: z.number().int().positive().default(600),
})

export interface AppConfig {
  base: z.infer<typeof baseSchema>
  oidc: z.infer<typeof oidcSchema>
  passkey: z.infer<typeof passkeySchema>
  gasSponsor: z.infer<typeof gasSponsorSchema>
}

export type OidcConfig = AppConfig['oidc']
export type PasskeyConfig = AppConfig['passkey']

class ConfigError extends Error {
  readonly errors: string[]
  constructor(errors: string[]) {
    super(`Configuration invalid:\n  - ${errors.join('\n  - ')}`)
    this.errors = errors
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const errors: string[] = []

  const baseRaw = {
    port: env.PORT ? Number.parseInt(env.PORT, 10) : 8080,
    nodeEnv: env.NODE_ENV ?? 'development',
    logLevel: env.LOG_LEVEL ?? 'info',
    databaseUrl: env.DATABASE_URL,
    pgSslMode: env.PGSSLMODE,
    pgPoolMax: env.IKA_PG_POOL_MAX ? Number.parseInt(env.IKA_PG_POOL_MAX, 10) : 20,
    pgConnectionTimeoutMillis: env.IKA_PG_CONNECTION_TIMEOUT_MS
      ? Number.parseInt(env.IKA_PG_CONNECTION_TIMEOUT_MS, 10)
      : 3_000,
    ikaGrpcUrl: env.IKA_GRPC_URL,
    ikaGrpcTls: env.IKA_GRPC_TLS === undefined ? true : truthy(env.IKA_GRPC_TLS),
    ikaProgramId: env.IKA_PROGRAM_ID,
    solanaRpcUrl: env.SOLANA_RPC_URL,
    solanaCommitment: env.SOLANA_COMMITMENT ?? 'confirmed',
    serviceApiKey: env.INTERNAL_API_KEY,
    adminApiKey: env.IKA_ADMIN_API_KEY,
    allowedOrigins: csv(env.ALLOWED_ORIGINS),
  }

  const baseParse = baseSchema.safeParse(baseRaw)
  if (!baseParse.success) {
    for (const issue of baseParse.error.issues) {
      errors.push(`base.${issue.path.join('.')}: ${issue.message}`)
    }
  }

  const oidcRaw = {
    enabled: truthy(env.IKA_OIDC_ENABLED),
    googleEnabled: truthy(env.IKA_OIDC_GOOGLE_ENABLED),
    googleClientId: env.IKA_OIDC_GOOGLE_CLIENT_ID,
    appleEnabled: truthy(env.IKA_OIDC_APPLE_ENABLED),
    appleClientId: env.IKA_OIDC_APPLE_CLIENT_ID,
    allowedAudiences: csv(env.IKA_OIDC_ALLOWED_AUDIENCES),
    jwkRegistryAddress: env.IKA_OIDC_JWK_REGISTRY_ADDRESS,
    verifierVersion: env.IKA_OIDC_VERIFIER_VERSION
      ? Number.parseInt(env.IKA_OIDC_VERIFIER_VERSION, 10)
      : 1,
    logSubjectHmacSecret: env.IKA_OIDC_LOG_SUBJECT_HMAC_SECRET,
  }
  const oidcParse = oidcSchema.safeParse(oidcRaw)
  if (!oidcParse.success) {
    for (const issue of oidcParse.error.issues) {
      errors.push(`oidc.${issue.path.join('.')}: ${issue.message}`)
    }
  } else if (oidcParse.data.enabled) {
    // OIDC standalone surface (`/v1/oidc/{nonce,validate}`) — providers,
    // audiences, and the HMAC secret stay required. The legacy on-chain
    // recovery adapter (jwkRegistryAddress / verifierVersion) was deleted
    // in F11b-Phase4b, so those fields are no longer enforced here.
    const o = oidcParse.data
    if (!o.googleEnabled && !o.appleEnabled) {
      errors.push('oidc: at least one provider (IKA_OIDC_GOOGLE_ENABLED / IKA_OIDC_APPLE_ENABLED) must be true when IKA_OIDC_ENABLED=true')
    }
    if (o.googleEnabled && !o.googleClientId) {
      errors.push('oidc.googleClientId (IKA_OIDC_GOOGLE_CLIENT_ID): required when IKA_OIDC_GOOGLE_ENABLED=true')
    }
    if (o.appleEnabled && !o.appleClientId) {
      errors.push('oidc.appleClientId (IKA_OIDC_APPLE_CLIENT_ID): required when IKA_OIDC_APPLE_ENABLED=true')
    }
    if (o.allowedAudiences.length === 0) {
      errors.push('oidc.allowedAudiences (IKA_OIDC_ALLOWED_AUDIENCES): required (CSV, must mirror the on-chain allowlist) when IKA_OIDC_ENABLED=true')
    }
    if (!o.logSubjectHmacSecret) {
      errors.push('oidc.logSubjectHmacSecret (IKA_OIDC_LOG_SUBJECT_HMAC_SECRET): required when IKA_OIDC_ENABLED=true')
    }
  }

  const passkeyRaw = {
    enabled: truthy(env.IKA_PASSKEY_ENABLED),
    rpId: env.IKA_PASSKEY_RP_ID,
    rpOrigin: env.IKA_PASSKEY_RP_ORIGIN,
    challengeTtlSeconds: env.IKA_PASSKEY_CHALLENGE_TTL_SECONDS
      ? Number.parseInt(env.IKA_PASSKEY_CHALLENGE_TTL_SECONDS, 10)
      : 120,
    saltMode: (env.IKA_PASSKEY_SALT_MODE ?? 'per_credential') as 'per_credential' | 'global',
    sessionTtlSeconds: env.IKA_PASSKEY_SESSION_TTL_SECONDS
      ? Number.parseInt(env.IKA_PASSKEY_SESSION_TTL_SECONDS, 10)
      : 600,
  }
  const passkeyParse = passkeySchema.safeParse(passkeyRaw)
  if (!passkeyParse.success) {
    for (const issue of passkeyParse.error.issues) {
      errors.push(`passkey.${issue.path.join('.')}: ${issue.message}`)
    }
  } else if (passkeyParse.data.enabled) {
    const p = passkeyParse.data
    // F11b-Phase4b: legacy passkey routes were deleted. Passkey recovery now
    // flows through the PolicyEngine v3 endpoints on the gateway, which
    // don't read these fields — but keeping the gate so anyone enabling
    // IKA_PASSKEY_ENABLED in the back-end gets a clear error message.
    if (!p.rpId) {
      errors.push(
        'passkey.rpId (IKA_PASSKEY_RP_ID): required when IKA_PASSKEY_ENABLED=true. Production value is "andromedainfra.pro" — IMMUTABLE after first registration (D2).',
      )
    }
    if (!p.rpOrigin) {
      errors.push(
        'passkey.rpOrigin (IKA_PASSKEY_RP_ORIGIN): required when IKA_PASSKEY_ENABLED=true',
      )
    }
    // D3 fail-fast: reject the global-salt mode in production.
    if (p.saltMode !== 'per_credential') {
      errors.push(
        `passkey.saltMode (IKA_PASSKEY_SALT_MODE): only 'per_credential' is accepted in production (got '${p.saltMode}'). See PLAN_KEYSPRING_INTEGRATION_2026_05.md D3.`,
      )
    }
  }

  // Resolution order: ANDROMEDA_GAS_SPONSOR_KEYPAIRS (pool, JSON array
  // of byte-array strings joined by ';'), ANDROMEDA_GAS_SPONSOR_KEYPAIR
  // (single — canonical for one-key deployments), then the legacy
  // IKA_GAS_SPONSOR_KEYPAIR for one release of back-compat.
  let keypairs: string[] | undefined
  const poolRaw = env.ANDROMEDA_GAS_SPONSOR_KEYPAIRS?.trim()
  if (poolRaw && poolRaw.length > 0) {
    // Two accepted formats:
    //  1) JSON: `[[1,2,...],[3,4,...]]` — one outer array of N keypairs.
    //  2) Semicolon-separated: `[1,2,...];[3,4,...]` — each segment is a
    //     standalone JSON byte array. Easier to paste into Railway envs.
    if (poolRaw.startsWith('[[')) {
      try {
        const parsed = JSON.parse(poolRaw) as unknown
        if (Array.isArray(parsed) && parsed.every(Array.isArray)) {
          keypairs = parsed.map((kp) => JSON.stringify(kp))
        }
      } catch {
        // Fall through to error below.
      }
    } else {
      keypairs = poolRaw
        .split(';')
        .map((s) => s.trim())
        .filter((s) => s.length > 0)
    }
    if (!keypairs || keypairs.length === 0) {
      errors.push(
        'gasSponsor.keypairs (ANDROMEDA_GAS_SPONSOR_KEYPAIRS): must be a JSON array of byte arrays OR semicolon-separated JSON byte arrays',
      )
    }
  }
  const gasRaw = {
    keypair: env.ANDROMEDA_GAS_SPONSOR_KEYPAIR ?? env.IKA_GAS_SPONSOR_KEYPAIR,
    keypairs,
    minBalanceSol: env.IKA_GAS_SPONSOR_MIN_BALANCE_SOL
      ? Number.parseFloat(env.IKA_GAS_SPONSOR_MIN_BALANCE_SOL)
      : 0.5,
    maxGasPerOpLamports: env.IKA_GAS_SPONSOR_MAX_GAS_PER_OP_LAMPORTS
      ? Number.parseInt(env.IKA_GAS_SPONSOR_MAX_GAS_PER_OP_LAMPORTS, 10)
      : 20_000_000,
  }
  const gasParse = gasSponsorSchema.safeParse(gasRaw)
  if (!gasParse.success) {
    for (const issue of gasParse.error.issues) {
      errors.push(`gasSponsor.${issue.path.join('.')}: ${issue.message}`)
    }
  }
  // Gas sponsor is initialised by `server.ts` only when the keypair is set
  // (used by /v1/dwallet/transfer-ownership). Boot continues without it,
  // and the route throws a clear error on first call.

  // Risk layer: the EVM RPC for simulation is provided per-request by the
  // client (the dev funds their own RPC); there is no server-side RPC config.

  if (errors.length > 0) throw new ConfigError(errors)

  return {
    base: baseParse.data!,
    oidc: oidcParse.data!,
    passkey: passkeyParse.data!,
    gasSponsor: gasParse.data!,
  }
}
