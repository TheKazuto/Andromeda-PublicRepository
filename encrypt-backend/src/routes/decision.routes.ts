// Decision-signing route — used by the gateway's /v1/confidential/sign
// endpoint to glue the FHE evaluation pipeline (this service) to the on-chain
// fhe-gated policy template (Andromeda Features Roadmap §3).
//
// Pipeline:
//   1. Caller (gateway) supplies (policy_address, request_hash_hex, operation_name,
//      encrypted_inputs).
//   2. We run the FHE graph via existing /v1/graph routines (caller has
//      already prepared/submitted the relevant ciphertexts upstream).
//   3. The result + binding (policy + request_hash + created_slot + authorize)
//      becomes the canonical EncryptedDecision bytes.
//   4. We ASK Vault Transit to ed25519-sign those bytes — the private key
//      never reaches this process. Mirrors the gateway's audit signer pattern
//      (see `docs/AUDIT_KMS.md`).

import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { address as toAddress, getAddressCodec } from '@solana/kit';
import { rpc, commitment } from '../solana/connection.js';
import { logger } from '../lib/logger.js';
import { loadVaultSignerFromEnv, type VaultSigner } from '../lib/vault.js';

const addressCodec = getAddressCodec();

async function getCurrentSlot(): Promise<number> {
  const slot = await rpc.getSlot({ commitment }).send();
  return Number(slot);
}

export const decisionRoutes = new Hono();

const signBody = z.object({
  policy_address: z.string().min(32),
  request_hash_hex: z.string().regex(/^[0-9a-fA-F]{64}$/, 'expected 64 hex chars'),
  operation_name: z.string().min(1),
  encrypted_inputs: z.array(z.string()).max(16).optional(),
  // Mock-mode override. Honoured only when FHE_MOCK_MODE=true. The on-chain
  // fhe-gated program does not yet verify the ed25519 signature (Quasar
  // pre-alpha gap), so this field is operationally equivalent to a trusted
  // gateway decision until the syscall lands. Documented as devnet-only.
  mock_authorize: z.boolean().optional(),
});

interface DecisionResponse {
  request_hash_hex: string;
  created_slot: number;
  authorize: boolean;
  signature_base64: string;
  fhe_authority_base64: string;
}

// vaultSigner is constructed lazily on the first request and reused. We avoid
// constructing at module load so that:
//   1. unit tests can stub env vars.
//   2. local dev with FHE_DECISION_SIGNING_ENABLED=false never tries to talk
//      to a non-existent Vault.
let vaultSigner: VaultSigner | null = null;
let vaultSignerInitErr: Error | null = null;

function getVaultSigner(): VaultSigner | null {
  if (vaultSigner !== null || vaultSignerInitErr !== null) {
    return vaultSigner;
  }
  try {
    vaultSigner = loadVaultSignerFromEnv('FHE_AUTHORITY');
  } catch (err: unknown) {
    vaultSignerInitErr = err instanceof Error ? err : new Error(String(err));
    logger.error({ err: vaultSignerInitErr.message }, 'FHE Vault signer init failed');
  }
  return vaultSigner;
}

// The pubkey published in `FHEGatedPolicy.fhe_authority`. When Vault is
// configured we derive it from the signer; otherwise fall back to the env
// var for backward-compat with the placeholder mode.
function getFHEAuthorityPubkey(): string {
  const signer = getVaultSigner();
  if (signer) {
    return signer.publicKeyBase64();
  }
  return process.env.FHE_AUTHORITY_PUBKEY_B64 ?? '';
}

decisionRoutes.post('/sign', zValidator('json', signBody), async (c) => {
  if (process.env.FHE_DECISION_SIGNING_ENABLED !== 'true') {
    return c.json(
      {
        error: {
          code: 'fhe_decision_signing_disabled',
          message:
            'Confidential decision signing is disabled until real FHE evaluation and KMS signing are configured.',
        },
      },
      503,
    );
  }

  const body = c.req.valid('json');
  const fheAuthority = getFHEAuthorityPubkey();
  if (!fheAuthority) {
    return c.json(
      {
        error: {
          code: 'fhe_authority_not_configured',
          message:
            'FHE authority signing key not configured. Set FHE_AUTHORITY_VAULT_{ADDR,TOKEN,KEY_NAME,PUBKEY_B64} (see docs/FHE_AUTHORITY_KMS.md) before enabling Confidential Workflows.',
        },
      },
      503,
    );
  }

  let policyBytes: Uint8Array;
  try {
    policyBytes = new Uint8Array(addressCodec.encode(toAddress(body.policy_address)));
  } catch {
    return c.json(
      { error: { code: 'invalid_policy', message: 'policy_address must be a valid base58 32-byte pubkey' } },
      400,
    );
  }
  if (policyBytes.length !== 32) {
    return c.json(
      { error: { code: 'invalid_policy', message: 'policy_address must be a 32-byte base58 pubkey' } },
      400,
    );
  }

  // Run the FHE evaluation. For the MVP we accept the operation name + inputs
  // through the existing /v1/graph routes that the caller already invoked
  // upstream — here we only synthesise the decision binding.
  let evaluation: FHEEvaluation;
  try {
    evaluation = await runFHEEvaluation(
      body.operation_name,
      body.encrypted_inputs ?? [],
      body.mock_authorize,
    );
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'unknown error';
    return c.json(
      {
        error: {
          code: 'fhe_evaluation_failed',
          message: msg,
        },
      },
      503,
    );
  }

  const createdSlot = await getCurrentSlot();

  // Canonical decision bytes the on-chain program expects:
  //   policy(32) || request_hash(32) || created_slot(u64 LE) || authorize(u8)
  // The signature MUST be over EXACTLY these bytes — any drift between the
  // gateway's request_hash and the encrypt-backend's binding causes rejection
  // on-chain (FHEError::DecisionRequestHashMismatch).
  const requestHashBytes = Buffer.from(body.request_hash_hex, 'hex');

  const canonical = Buffer.alloc(32 + 32 + 8 + 1);
  Buffer.from(policyBytes.buffer, policyBytes.byteOffset, policyBytes.byteLength).copy(canonical, 0);
  requestHashBytes.copy(canonical, 32);
  canonical.writeBigUInt64LE(BigInt(createdSlot), 64);
  canonical.writeUInt8(evaluation.authorize ? 1 : 0, 72);

  const signature = await kmsSignEd25519(canonical);
  if (signature.length !== 64) {
    return c.json(
      { error: { code: 'kms_sign_failed', message: 'KMS returned a non-64-byte signature' } },
      502,
    );
  }

  const resp: DecisionResponse = {
    request_hash_hex: body.request_hash_hex,
    created_slot: createdSlot,
    authorize: evaluation.authorize,
    signature_base64: signature.toString('base64'),
    fhe_authority_base64: fheAuthority,
  };
  return c.json(resp);
});

// ---- Helpers ----

interface FHEEvaluation {
  authorize: boolean;
  reason?: string;
}

/**
 * runFHEEvaluation produces the boolean authorisation result for an FHE
 * decision request.
 *
 * Status (2026-05-07): the Encrypt SDK does NOT yet expose a typed decoder
 * for the on-chain `DecryptionRequest` account, so the custody-free async
 * pipeline (caller passes a `decryption_request_account_id` and we read
 * the plaintext result on-chain) cannot be implemented safely without
 * reverse-engineering the Borsh layout. Until the SDK exposes
 * `DecryptionRequest` and `getDecryptionRequestDecoder()`, this function
 * runs in **mock mode**:
 *
 *   - When `FHE_MOCK_MODE=true` AND `mock_authorize` is supplied, the
 *     function returns that boolean. The caller is the trust anchor.
 *   - Otherwise it throws — the caller sees `503 fhe_evaluation_failed`.
 *
 * The on-chain `fhe-gated` program does NOT currently verify the ed25519
 * signature (Quasar pre-alpha gap), so mock-mode is operationally
 * equivalent to a trusted gateway decision today. When Quasar exposes the
 * ed25519 syscall AND the Encrypt SDK exposes the decoder, replace this
 * with a real on-chain read using `pollDecryption`.
 */
async function runFHEEvaluation(
  operationName: string,
  inputs: string[],
  mockAuthorize: boolean | undefined,
): Promise<FHEEvaluation> {
  if (process.env.FHE_MOCK_MODE === 'true') {
    if (typeof mockAuthorize !== 'boolean') {
      throw new Error(
        'FHE_MOCK_MODE=true but caller did not supply mock_authorize. ' +
          'Confidential Workflows are gated until either (a) the Encrypt SDK ' +
          'exposes a DecryptionRequest decoder so we can read the on-chain ' +
          'result, or (b) the caller explicitly mocks the decision via ' +
          'mock_authorize:boolean.',
      );
    }
    logger.warn(
      { operationName, inputCount: inputs.length, mockAuthorize },
      'FHE evaluation served from mock_authorize (FHE_MOCK_MODE=true)',
    );
    return {
      authorize: mockAuthorize,
      reason: `mock-mode (operation=${operationName})`,
    };
  }
  throw new Error(
    'FHE decision evaluation is not implemented — set FHE_MOCK_MODE=true to ' +
      'allow caller-supplied mock_authorize for testing.',
  );
}

/**
 * kmsSignEd25519 signs `canonical` via Vault Transit. The private key never
 * leaves Vault — the signature returned here is locally re-verified against
 * the configured pubkey before being returned to the caller.
 */
async function kmsSignEd25519(canonical: Buffer): Promise<Buffer> {
  const signer = getVaultSigner();
  if (!signer) {
    throw new Error(
      'FHE Vault signer not configured — set FHE_AUTHORITY_VAULT_{ADDR,TOKEN,KEY_NAME,PUBKEY_B64}',
    );
  }
  return signer.sign(canonical);
}
