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
  serviceApiKey: z.string().min(1, 'IKA_SERVICE_API_KEY is required'),
  adminApiKey: z.string().optional(),
  allowedOrigins: z.array(z.string()).default([]),
})

const identitySchema = z.object({
  enabled: z.boolean().default(false),
  jwtSecret: z.string().optional(),
  jwtIssuer: z.string().default('ika-backend'),
  jwtAudience: z.string().default('andromeda-client'),
  jwtTtlSeconds: z.number().int().positive().default(900),
  refreshTokenTtlDays: z.number().int().positive().default(7),
  auditLogEnabled: z.boolean().default(false),
  persistEmail: z.boolean().default(false),
  persistDisplayName: z.boolean().default(false),
})

const recoverySchema = z.object({
  enabled: z.boolean().default(false),
  policyEnabled: z.boolean().default(false),
  policyProgramId: z.string().optional(),
  ikaCoordinatorAddress: z.string().optional(),
  challengeTtlSeconds: z.number().int().positive().default(300),
  quorumSessionTtlSeconds: z.number().int().positive().default(600),
  defaultCooldownSeconds: z.number().int().positive().default(604800),
  minCooldownSeconds: z.number().int().positive().default(3600),
  version: z.string().default('andromeda-ika-recovery-v1'),
})

const gasSponsorSchema = z.object({
  keypair: z.string().optional(),
  minBalanceSol: z.number().nonnegative().default(0.5),
  maxGasPerOpLamports: z.number().int().positive().default(20_000_000),
})

export interface AppConfig {
  base: z.infer<typeof baseSchema>
  identity: z.infer<typeof identitySchema>
  recovery: z.infer<typeof recoverySchema>
  gasSponsor: z.infer<typeof gasSponsorSchema>
}

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
    serviceApiKey: env.IKA_SERVICE_API_KEY,
    adminApiKey: env.IKA_ADMIN_API_KEY,
    allowedOrigins: csv(env.ALLOWED_ORIGINS),
  }

  const baseParse = baseSchema.safeParse(baseRaw)
  if (!baseParse.success) {
    for (const issue of baseParse.error.issues) {
      errors.push(`base.${issue.path.join('.')}: ${issue.message}`)
    }
  }

  const identityRaw = {
    enabled: truthy(env.IKA_IDENTITY_ENABLED),
    jwtSecret: env.IKA_IDENTITY_JWT_SECRET,
    jwtIssuer: env.IKA_IDENTITY_JWT_ISSUER,
    jwtAudience: env.IKA_IDENTITY_JWT_AUDIENCE,
    jwtTtlSeconds: env.IKA_IDENTITY_JWT_TTL_SECONDS
      ? Number.parseInt(env.IKA_IDENTITY_JWT_TTL_SECONDS, 10)
      : 900,
    refreshTokenTtlDays: env.IKA_IDENTITY_REFRESH_TOKEN_TTL_DAYS
      ? Number.parseInt(env.IKA_IDENTITY_REFRESH_TOKEN_TTL_DAYS, 10)
      : 7,
    auditLogEnabled: truthy(env.IKA_IDENTITY_AUDIT_LOG_ENABLED),
    persistEmail: truthy(env.IKA_IDENTITY_PERSIST_EMAIL),
    persistDisplayName: truthy(env.IKA_IDENTITY_PERSIST_DISPLAY_NAME),
  }

  const identityParse = identitySchema.safeParse(identityRaw)
  if (!identityParse.success) {
    for (const issue of identityParse.error.issues) {
      errors.push(`identity.${issue.path.join('.')}: ${issue.message}`)
    }
  } else if (identityParse.data.enabled && !identityParse.data.jwtSecret) {
    errors.push('identity.jwtSecret: required when IKA_IDENTITY_ENABLED=true')
  }

  const recoveryRaw = {
    enabled: truthy(env.IKA_RECOVERY_ENABLED),
    policyEnabled: truthy(env.IKA_RECOVERY_POLICY_ENABLED),
    policyProgramId: env.IKA_RECOVERY_POLICY_PROGRAM_ID,
    ikaCoordinatorAddress: env.IKA_COORDINATOR_ADDRESS,
    challengeTtlSeconds: env.IKA_RECOVERY_CHALLENGE_TTL_SECONDS
      ? Number.parseInt(env.IKA_RECOVERY_CHALLENGE_TTL_SECONDS, 10)
      : 300,
    quorumSessionTtlSeconds: env.IKA_RECOVERY_QUORUM_SESSION_TTL_SECONDS
      ? Number.parseInt(env.IKA_RECOVERY_QUORUM_SESSION_TTL_SECONDS, 10)
      : 600,
    defaultCooldownSeconds: env.IKA_RECOVERY_POLICY_DEFAULT_COOLDOWN_SECONDS
      ? Number.parseInt(env.IKA_RECOVERY_POLICY_DEFAULT_COOLDOWN_SECONDS, 10)
      : 604_800,
    minCooldownSeconds: env.IKA_RECOVERY_POLICY_MIN_COOLDOWN_SECONDS
      ? Number.parseInt(env.IKA_RECOVERY_POLICY_MIN_COOLDOWN_SECONDS, 10)
      : 3_600,
    version: env.IKA_RECOVERY_VERSION,
  }

  const recoveryParse = recoverySchema.safeParse(recoveryRaw)
  if (!recoveryParse.success) {
    for (const issue of recoveryParse.error.issues) {
      errors.push(`recovery.${issue.path.join('.')}: ${issue.message}`)
    }
  } else if (recoveryParse.data.policyEnabled && !recoveryParse.data.policyProgramId) {
    errors.push('recovery.policyProgramId: required when IKA_RECOVERY_POLICY_ENABLED=true')
  } else if (recoveryParse.data.policyEnabled && !recoveryParse.data.ikaCoordinatorAddress) {
    errors.push(
      'recovery.ikaCoordinatorAddress (IKA_COORDINATOR_ADDRESS): required when IKA_RECOVERY_POLICY_ENABLED=true',
    )
  }

  // Prefer the canonical ANDROMEDA_GAS_SPONSOR_KEYPAIR; fall back to the
  // legacy IKA_GAS_SPONSOR_KEYPAIR for one release for back-compat.
  const gasRaw = {
    keypair: env.ANDROMEDA_GAS_SPONSOR_KEYPAIR ?? env.IKA_GAS_SPONSOR_KEYPAIR,
    minBalanceSol: env.IKA_GAS_SPONSOR_MIN_BALANCE_SOL
      ? Number.parseFloat(env.IKA_GAS_SPONSOR_MIN_BALANCE_SOL)
      : 0.5,
    maxGasPerOpLamports: env.IKA_RECOVERY_MAX_GAS_PER_OP_LAMPORTS
      ? Number.parseInt(env.IKA_RECOVERY_MAX_GAS_PER_OP_LAMPORTS, 10)
      : 20_000_000,
  }
  const gasParse = gasSponsorSchema.safeParse(gasRaw)
  if (!gasParse.success) {
    for (const issue of gasParse.error.issues) {
      errors.push(`gasSponsor.${issue.path.join('.')}: ${issue.message}`)
    }
  } else if (recoveryParse.success && recoveryParse.data.policyEnabled && !gasParse.data.keypair) {
    errors.push('gasSponsor.keypair: required when IKA_RECOVERY_POLICY_ENABLED=true (set ANDROMEDA_GAS_SPONSOR_KEYPAIR)')
  }

  if (errors.length > 0) throw new ConfigError(errors)

  return {
    base: baseParse.data!,
    identity: identityParse.data!,
    recovery: recoveryParse.data!,
    gasSponsor: gasParse.data!,
  }
}
