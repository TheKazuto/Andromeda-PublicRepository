import 'dotenv/config';
import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().int().positive().default(3010),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

  INTERNAL_API_KEY: z.string().min(16, 'INTERNAL_API_KEY must be at least 16 chars'),

  // Comma-separated list of allowed CORS origins. Empty in production = no
  // cross-origin requests allowed (service is meant to be private).
  ALLOWED_ORIGINS: z
    .string()
    .default('')
    .transform((s) => s.split(',').map((x) => x.trim()).filter(Boolean)),

  ENCRYPT_GRPC_URL: z.url().default('https://pre-alpha-dev-1.encrypt.ika-network.net:443'),
  ENCRYPT_PROGRAM_ID: z.string().default('4ebfzWdKnrnGseuQpezXdG8yCdHqwQ1SSBHD3bWArND8'),
  ENCRYPT_NEK_PUBLIC_KEY_BASE64: z.string().optional().or(z.literal('')),

  SOLANA_RPC_URL: z.url().default('https://api.devnet.solana.com'),
  SOLANA_RPC_WS_URL: z.url().default('wss://api.devnet.solana.com'),
  SOLANA_COMMITMENT: z.enum(['processed', 'confirmed', 'finalized']).default('confirmed'),

  // Default priority fee (microLamports per CU). 0 disables. Per-request
  // overrides via computeUnitPriceMicroLamports continue to work.
  SOLANA_DEFAULT_PRIORITY_FEE_MICROLAMPORTS: z.coerce.number().int().nonnegative().default(0),

  // In-process blockhash cache TTL (ms). Solana blockhashes are valid ~60s,
  // 12s cache cuts ~80%+ of getLatestBlockhash calls without risk.
  BLOCKHASH_CACHE_TTL_MS: z.coerce.number().int().positive().default(12_000),

  // In-process NEK cache TTL (ms). NEK rotates rarely; this avoids hitting
  // Upstash REST on every CreateInput call.
  NEK_INMEM_CACHE_TTL_MS: z.coerce.number().int().positive().default(30_000),

  // Maximum request body size (bytes). Default 4MB accommodates large
  // graphBytes payloads.
  MAX_BODY_BYTES: z.coerce.number().int().positive().default(4 * 1024 * 1024),

  // Graceful shutdown drain timeout (ms).
  SHUTDOWN_TIMEOUT_MS: z.coerce.number().int().positive().default(10_000),
  ENCRYPT_GRPC_TIMEOUT_MS: z.coerce.number().int().positive().default(10_000),
  SOLANA_RPC_TIMEOUT_MS: z.coerce.number().int().positive().default(10_000),
  REDIS_TIMEOUT_MS: z.coerce.number().int().positive().default(2_000),

  UPSTASH_REDIS_REST_URL: z.url().optional().or(z.literal('')),
  UPSTASH_REDIS_REST_TOKEN: z.string().optional().or(z.literal('')),

  // P0.1: when true, mutating routes that require an Idempotency-Key
  // refuse to run unless Redis is reachable (so cross-replica retry
  // de-dup is guaranteed). Default true in production, false in dev so
  // local Upstash-less stacks still boot. Set explicitly to override.
  REQUIRE_IDEMPOTENCY_LOCK: z
    .union([z.boolean(), z.string()])
    .optional()
    .transform((v) => {
      if (v === undefined) return undefined
      return typeof v === 'string' ? v.toLowerCase() === 'true' : v
    }),

  CACHE_TTL_NEK: z.coerce.number().int().positive().default(300),
  CACHE_TTL_CIPHERTEXT: z.coerce.number().int().positive().default(60),

  // When true, after the NEK is set (boot env or first /v1/nek/override call)
  // any subsequent override is rejected. Production should always be `true`
  // — flipping the NEK silently makes existing ciphertexts unreadable.
  ENCRYPT_NEK_IMMUTABLE: z
    .union([z.boolean(), z.string()])
    .default(false)
    .transform((v) => (typeof v === 'string' ? v.toLowerCase() === 'true' : v)),

  // Gas sponsor — Andromeda pays Solana fees for every endpoint, so end
  // users never need a Solana wallet or SOL. JSON byte array of a 64-byte
  // Solana keypair (`solana-keygen` format). Required for gas-sponsored
  // endpoints (graph/wallet/decrypt/etc); the legacy `/private-tx/submit`
  // passthrough is being deprecated.
  ANDROMEDA_GAS_SPONSOR_KEYPAIR: z.string().optional().or(z.literal('')),
});

export type Config = z.infer<typeof envSchema>;

function loadConfig(): Config {
  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    console.error('Invalid environment configuration:');
    console.error(z.flattenError(parsed.error).fieldErrors);
    process.exit(1);
  }
  return parsed.data;
}

export const config = loadConfig();

export const isCacheEnabled = Boolean(
  config.UPSTASH_REDIS_REST_URL && config.UPSTASH_REDIS_REST_TOKEN
);

// Production defaults to require Redis-backed idempotency locks so two
// replicas cannot duplicate a gas-sponsored submit. Override via env
// REQUIRE_IDEMPOTENCY_LOCK=false only with explicit justification.
export const requireIdempotencyLock =
  config.REQUIRE_IDEMPOTENCY_LOCK ?? config.NODE_ENV === 'production'
