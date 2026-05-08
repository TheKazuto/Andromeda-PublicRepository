// Identity layer — environment configuration.
//
// All settings are read once at module load. Strict validation when enabled.

const TRUTHY = new Set(['1', 'true', 'yes', 'on'])

function readBool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback
  return TRUTHY.has(value.trim().toLowerCase())
}

function readInt(value: string | undefined, fallback: number): number {
  if (value === undefined || value.trim() === '') return fallback
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback
  return Math.floor(parsed)
}

function readCsv(value: string | undefined): string[] {
  if (!value) return []
  return value.split(',').map((v) => v.trim()).filter(Boolean)
}

export type EmailTransportName = 'smtp' | 'memory'

export interface IdentityConfig {
  readonly enabled: boolean
  readonly jwt: {
    readonly secret: string
    readonly issuer: string
    readonly audience: string
    readonly ttlSeconds: number
    readonly refreshTtlDays: number
  }
  readonly persistence: {
    readonly persistEmail: boolean
    readonly persistDisplayName: boolean
    readonly auditLogEnabled: boolean
  }
  readonly providers: {
    readonly oauthGoogle: boolean
    readonly oauthApple: boolean
    readonly oauthTwitter: boolean
    readonly oauthGithub: boolean
    readonly email: boolean
    readonly passkey: boolean
  }
  readonly email: {
    readonly transport: EmailTransportName
    readonly from: string | null
    readonly smtpUrl: string | null
    readonly tokenTtlSeconds: number
    readonly frontendCallbackUrl: string | null
    readonly rateLimitPerEmailPerHour: number
    readonly rateLimitPerIpPerHour: number
  }
  readonly passkey: {
    readonly rpId: string | null
    readonly rpName: string | null
    readonly origins: string[]
    readonly prfSaltHex: string | null
  }
}

const DEFAULT_ISSUER = 'ika-backend'
const DEFAULT_AUDIENCE = 'andromeda-client'
const DEFAULT_JWT_TTL_SECONDS = 15 * 60
const DEFAULT_REFRESH_TTL_DAYS = 7
const MIN_JWT_SECRET_LENGTH = 32
const PRF_SALT_HEX_LENGTH = 64
const DEFAULT_EMAIL_TOKEN_TTL_SECONDS = 15 * 60
const DEFAULT_EMAIL_RATE_LIMIT_PER_EMAIL = 3
const DEFAULT_EMAIL_RATE_LIMIT_PER_IP = 10
const VALID_EMAIL_TRANSPORTS: ReadonlyArray<EmailTransportName> = ['smtp', 'memory']

function readEmailTransport(value: string | undefined, fallback: EmailTransportName): EmailTransportName {
  const normalized = (value ?? '').trim().toLowerCase() as EmailTransportName
  return VALID_EMAIL_TRANSPORTS.includes(normalized) ? normalized : fallback
}

function loadConfigUnsafe(): IdentityConfig {
  return {
    enabled: readBool(process.env.IKA_IDENTITY_ENABLED, false),
    jwt: {
      secret: process.env.IKA_IDENTITY_JWT_SECRET?.trim() ?? '',
      issuer: process.env.IKA_IDENTITY_JWT_ISSUER?.trim() || DEFAULT_ISSUER,
      audience: process.env.IKA_IDENTITY_JWT_AUDIENCE?.trim() || DEFAULT_AUDIENCE,
      ttlSeconds: readInt(process.env.IKA_IDENTITY_JWT_TTL_SECONDS, DEFAULT_JWT_TTL_SECONDS),
      refreshTtlDays: readInt(process.env.IKA_IDENTITY_REFRESH_TOKEN_TTL_DAYS, DEFAULT_REFRESH_TTL_DAYS),
    },
    persistence: {
      persistEmail: readBool(process.env.IKA_IDENTITY_PERSIST_EMAIL, false),
      persistDisplayName: readBool(process.env.IKA_IDENTITY_PERSIST_DISPLAY_NAME, false),
      auditLogEnabled: readBool(process.env.IKA_IDENTITY_AUDIT_LOG_ENABLED, false),
    },
    providers: {
      oauthGoogle: readBool(process.env.IKA_IDENTITY_OAUTH_GOOGLE_ENABLED, false),
      oauthApple: readBool(process.env.IKA_IDENTITY_OAUTH_APPLE_ENABLED, false),
      oauthTwitter: readBool(process.env.IKA_IDENTITY_OAUTH_TWITTER_ENABLED, false),
      oauthGithub: readBool(process.env.IKA_IDENTITY_OAUTH_GITHUB_ENABLED, false),
      email: readBool(process.env.IKA_IDENTITY_EMAIL_ENABLED, false),
      passkey: readBool(process.env.IKA_IDENTITY_PASSKEY_ENABLED, false),
    },
    email: {
      transport: readEmailTransport(process.env.IKA_IDENTITY_EMAIL_TRANSPORT, 'smtp'),
      from: process.env.IKA_IDENTITY_EMAIL_FROM?.trim() || null,
      smtpUrl: process.env.IKA_IDENTITY_EMAIL_SMTP_URL?.trim() || null,
      tokenTtlSeconds: readInt(process.env.IKA_IDENTITY_EMAIL_TOKEN_TTL_SECONDS, DEFAULT_EMAIL_TOKEN_TTL_SECONDS),
      frontendCallbackUrl: process.env.IKA_IDENTITY_EMAIL_FRONTEND_CALLBACK_URL?.trim() || null,
      rateLimitPerEmailPerHour: readInt(
        process.env.IKA_IDENTITY_EMAIL_RATE_LIMIT_PER_EMAIL_PER_HOUR,
        DEFAULT_EMAIL_RATE_LIMIT_PER_EMAIL,
      ),
      rateLimitPerIpPerHour: readInt(
        process.env.IKA_IDENTITY_EMAIL_RATE_LIMIT_PER_IP_PER_HOUR,
        DEFAULT_EMAIL_RATE_LIMIT_PER_IP,
      ),
    },
    passkey: {
      rpId: process.env.IKA_IDENTITY_PASSKEY_RP_ID?.trim() || null,
      rpName: process.env.IKA_IDENTITY_PASSKEY_RP_NAME?.trim() || null,
      origins: readCsv(process.env.IKA_IDENTITY_PASSKEY_ORIGINS),
      prfSaltHex: process.env.IKA_IDENTITY_PASSKEY_PRF_SALT?.trim() || null,
    },
  }
}

let cached: IdentityConfig | null = null
export function getIdentityConfig(): IdentityConfig {
  if (cached === null) {
    cached = loadConfigUnsafe()
  }
  return cached
}

export function _resetIdentityConfigCache(): void {
  cached = null
}

export function isIdentityEnabled(): boolean {
  return getIdentityConfig().enabled
}

export function validateIdentityConfigOrThrow(config: IdentityConfig = getIdentityConfig()): void {
  if (!config.enabled) return
  const errors: string[] = []

  if (!config.jwt.secret || config.jwt.secret.length < MIN_JWT_SECRET_LENGTH) {
    errors.push(
      `IKA_IDENTITY_JWT_SECRET must be at least ${MIN_JWT_SECRET_LENGTH} characters. ` +
        'Generate one with `openssl rand -hex 32`.',
    )
  }

  if (!process.env.DATABASE_URL?.trim()) {
    errors.push('DATABASE_URL is required when IKA_IDENTITY_ENABLED=true.')
  }

  // PII encryption-at-rest. Reading legacy plaintext rows still works
  // without the key, but writes throw — so we hard-require it at boot
  // to keep production correct by default. Generate with
  // `openssl rand -base64 32`.
  const piiKey = process.env.IKA_IDENTITY_PII_KEY?.trim() ?? ''
  if (!piiKey) {
    errors.push(
      'IKA_IDENTITY_PII_KEY is required when IKA_IDENTITY_ENABLED=true. ' +
        'Generate one with `openssl rand -base64 32` (32 bytes).',
    )
  } else {
    let bytes: Buffer | null = null
    if (/^[0-9a-fA-F]+$/.test(piiKey) && piiKey.length === 64) {
      bytes = Buffer.from(piiKey, 'hex')
    } else {
      try {
        bytes = Buffer.from(piiKey, 'base64')
      } catch {
        bytes = null
      }
    }
    if (!bytes || bytes.length !== 32) {
      errors.push(
        'IKA_IDENTITY_PII_KEY must decode to exactly 32 bytes (base64 of `openssl rand -base64 32`).',
      )
    }
  }

  if (config.providers.passkey) {
    if (!config.passkey.rpId) {
      errors.push('IKA_IDENTITY_PASSKEY_RP_ID is required when IKA_IDENTITY_PASSKEY_ENABLED=true.')
    }
    if (!config.passkey.prfSaltHex) {
      errors.push(
        'IKA_IDENTITY_PASSKEY_PRF_SALT is required when IKA_IDENTITY_PASSKEY_ENABLED=true. ' +
          'Generate once with `openssl rand -hex 32` and NEVER change it.',
      )
    } else if (
      !/^[0-9a-fA-F]+$/.test(config.passkey.prfSaltHex) ||
      config.passkey.prfSaltHex.length !== PRF_SALT_HEX_LENGTH
    ) {
      errors.push(`IKA_IDENTITY_PASSKEY_PRF_SALT must be exactly ${PRF_SALT_HEX_LENGTH} hex characters (32 bytes).`)
    }
  }

  if (config.providers.email) {
    if (!config.email.from) {
      errors.push('IKA_IDENTITY_EMAIL_FROM is required when IKA_IDENTITY_EMAIL_ENABLED=true.')
    }
    if (!config.email.frontendCallbackUrl) {
      errors.push('IKA_IDENTITY_EMAIL_FRONTEND_CALLBACK_URL is required when IKA_IDENTITY_EMAIL_ENABLED=true.')
    } else {
      try {
        const url = new URL(config.email.frontendCallbackUrl)
        if (url.protocol !== 'http:' && url.protocol !== 'https:') {
          errors.push('IKA_IDENTITY_EMAIL_FRONTEND_CALLBACK_URL must be http(s).')
        }
      } catch {
        errors.push('IKA_IDENTITY_EMAIL_FRONTEND_CALLBACK_URL is not a valid URL.')
      }
    }
    if (config.email.transport === 'smtp' && !config.email.smtpUrl) {
      errors.push('IKA_IDENTITY_EMAIL_SMTP_URL is required when IKA_IDENTITY_EMAIL_TRANSPORT=smtp.')
    }
  }

  if (errors.length > 0) {
    throw new Error(`[ika-backend][identity] invalid configuration:\n  - ${errors.join('\n  - ')}`)
  }
}
