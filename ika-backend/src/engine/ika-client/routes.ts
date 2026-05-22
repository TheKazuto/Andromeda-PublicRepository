// HTTP routes for the MCP-facing dWallet operations (option A2). Mounted by
// `buildEngineRouter` under `/v1/dwallet`, so:
//   POST /v1/dwallet/create             →  MCP tool `create_dwallet`
//   POST /v1/dwallet/transfer-ownership →  MCP tool `transfer_ownership`
//   POST /v1/dwallet/presign            →  MCP tool `presign`
//   POST /v1/dwallet/sign               →  MCP tool `sign_message`
//   GET  /v1/dwallet/addresses/:addr    →  MCP tool `dwallet_addresses`
//   POST /v1/dwallet/prepare-message    →  MCP tool `prepare_message`
// (the gateway auto-generates the MCP tools from its route catalogue, so
// adding the matching entries to `gateway/internal/routes/routes.go` is all
// that's needed on the gateway side.)
//
// F11b-Phase4b (2026-05-15): `/v1/dwallet/approve` and `/v1/dwallet/admin/add-member`
// are retired. Message authorisation now happens through the PolicyEngine v3
// surface on the gateway (`/v1/policy/recover-as-primary/{challenge,submit}`)
// — the dWallet's authority must be a PolicyEngine v3 attached at create
// time via `attachPolicyEngine: true`.
//
// Auth: the engine trusts the gateway (shared `INTERNAL_API_KEY`) and reads
// the tenant identity from the `X-Andromeda-User-Id` header the gateway
// already forwards. A request without it (i.e. not via the gateway) is
// rejected — these are tenant-scoped operations.
//
// Pre-alpha / devnet only. dWallets created here are wiped at Alpha 1; the
// response carries the disclaimer.

import type { Router, Response } from 'express'
import { z } from 'zod'
import bs58 from 'bs58'
import type { AppConfig } from '../../config.js'
import { ok, fail } from '../../types.js'
import { sanitizeError } from '../../safeError.js'
import { logger } from '../../logger.js'
import {
  createDwallet,
  allocatePresign,
  signMessage,
  transferDwalletOwnership,
  deriveWalletAddresses,
} from './wallet.js'
import { prepareMessage } from '../../chain/index.js'

const HEX = /^[0-9a-fA-F]*$/

const createSchema = z.object({
  passphrase: z.string().min(12, 'passphrase must be at least 12 characters'),
  curve: z.enum(['Curve25519', 'Secp256k1', 'Secp256r1']).optional(),
  /**
   * When true, deploy a `PolicyEngine v3` for the new dWallet and delegate
   * its authority to the engine's CPI authority PDA. The engine starts with
   * zero rules; the caller adds them via `/v1/policy/rules/*` later. Requires
   * `IKA_POLICY_ENGINE_ENABLED=true` + `ANDROMEDA_POLICY_ENGINE_PROGRAM_ID`
   * set on the deployment.
   */
  attachPolicyEngine: z.boolean().optional(),
  /**
   * Optional external primary owner for the auto-attached PolicyEngine.
   * Defaults to the keystore key (Ed25519). Pass this to make a wallet whose
   * primary on-chain owner is e.g. a MetaMask address (Secp256k1) or a passkey
   * (Secp256r1). `identifierBase64` length depends on scheme:
   *   0 (Ed25519)   → 32 bytes pubkey
   *   1 (Secp256k1) → 20 bytes eth_address
   *   2 (Secp256r1) → 33 bytes compressed pubkey
   *   3 (WebAuthn)  → 33 bytes compressed P-256 pubkey
   */
  primaryRecoveryOwner: z
    .object({
      scheme: z.number().int().min(0).max(3),
      identifierBase64: z.string().min(1),
    })
    .optional(),
})

const transferOwnershipSchema = z.object({
  dwalletAddress: z.string().min(32),
  passphrase: z.string().min(12, 'passphrase must be at least 12 characters'),
  /** The new authority (base58). For a rules-policy: PDA(["__ika_cpi_authority"], policyProgramId). */
  newAuthorityBase58: z.string().min(32),
})

const presignSchema = z.object({
  dwalletAddress: z.string().min(32),
})

const signSchema = z.object({
  dwalletAddress: z.string().min(32),
  passphrase: z.string().min(12, 'passphrase must be at least 12 characters'),
  messageHex: z.string().regex(HEX).refine((s) => s.length % 2 === 0 && s.length > 0, 'messageHex must be non-empty even-length hex'),
  messageMetadataHex: z.string().regex(HEX).refine((s) => s.length % 2 === 0, 'messageMetadataHex must be even-length hex').optional(),
  scheme: z.number().int().min(0).max(6),
  presignSessionIdHex: z.string().regex(HEX).refine((s) => s.length % 2 === 0 && s.length > 0, 'presignSessionIdHex must be non-empty even-length hex').optional(),
  approvalTxSignatureBase58: z.string().min(32),
  approvalSlot: z.coerce.bigint().nonnegative(),
})

// 256 K hex chars = 128 KB of payload — generous for any destination-chain tx,
// while bounding the keccak/blake2b work a single request can trigger (DoS).
const PAYLOAD_HEX_MAX = 256 * 1024

const prepareMessageSchema = z.object({
  chainId: z.string().min(3).max(128),
  payloadHex: z
    .string()
    .regex(HEX)
    .max(PAYLOAD_HEX_MAX, 'payloadHex too large')
    .refine((s) => s.length % 2 === 0 && s.length > 0, 'payloadHex must be non-empty even-length hex'),
  kind: z.enum(['transaction', 'message']),
})

function ownerRefOf(headerValue: string | undefined): string {
  if (!headerValue || headerValue.trim() === '') {
    const e = new Error('missing tenant identity — call this endpoint through the Andromeda gateway')
    e.name = 'MissingTenantError'
    throw e
  }
  return headerValue
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'))
}

// Duck-typed so it works across zod minor versions (instanceof can be brittle
// with `verbatimModuleSyntax`/dual-package situations).
function isZodError(err: unknown): err is z.ZodError {
  return (
    err instanceof z.ZodError ||
    (err != null && typeof err === 'object' && Array.isArray((err as { issues?: unknown }).issues))
  )
}

// Named errors → 4xx; everything else → 500 (sanitized + trace id).
const KNOWN_4XX: Record<string, number> = {
  MissingTenantError: 401,
  WeakPassphraseError: 400,
  WrongPassphraseError: 401,
  WalletKeyNotFoundError: 404,
  WalletKeyNotFinalizedError: 409,
  // Multi-chain layer (Update 2 / B2-B3): all are caller input errors.
  ChainIdParseError: 400,
  UnsupportedChainError: 400,
  InvalidPublicKeyError: 400,
}

function respondErr(res: Response, scope: string, err: unknown): void {
  if (isZodError(err)) {
    const msg = err.issues.map((i) => i.message).join('; ') || 'invalid request body'
    res.status(400).json(fail(msg))
    return
  }
  const name = err instanceof Error ? err.name : ''
  const status = KNOWN_4XX[name] ?? 500
  if (status < 500) {
    res.status(status).json(fail(err instanceof Error ? err.message : String(err)))
    return
  }
  // 5xx: never echo the raw message or stack back to the caller (the gateway
  // forwards this response to external clients). `sanitizeError` returns a
  // safe message (verbatim only for the allowlisted patterns) plus a trace id,
  // and logs the full error + stack server-side under that trace id.
  const safe = sanitizeError(scope, err)
  res.status(500).json(fail(safe.message, safe.traceId))
}

export function mountMcpWalletRoutes(router: Router, config: AppConfig): void {
  const policyEngineEnabled =
    process.env.IKA_POLICY_ENGINE_ENABLED === 'true' &&
    !!process.env.ANDROMEDA_POLICY_ENGINE_PROGRAM_ID
  const policyEngineOpts = policyEngineEnabled
    ? { programId: process.env.ANDROMEDA_POLICY_ENGINE_PROGRAM_ID as string }
    : null

  router.post('/create', async (req, res) => {
    try {
      const ownerRef = ownerRefOf(req.header('x-andromeda-user-id'))
      const body = createSchema.parse(req.body)
      if (body.attachPolicyEngine && !policyEngineOpts) {
        res.status(400).json(fail('attachPolicyEngine requested but PolicyEngine v3 is not enabled on this deployment (set IKA_POLICY_ENGINE_ENABLED=true and ANDROMEDA_POLICY_ENGINE_PROGRAM_ID)'))
        return
      }
      const result = await createDwallet({
        ownerRef,
        passphrase: body.passphrase,
        ikaProgramId: config.base.ikaProgramId,
        ...(body.curve ? { curve: body.curve } : {}),
        ...(body.attachPolicyEngine && policyEngineOpts ? { policyEngine: policyEngineOpts } : {}),
        ...(body.primaryRecoveryOwner
          ? {
              primaryRecoveryOwner: {
                scheme: body.primaryRecoveryOwner.scheme,
                identifier: new Uint8Array(Buffer.from(body.primaryRecoveryOwner.identifierBase64, 'base64')),
              },
            }
          : {}),
      })
      res.json(
        ok({
          dwalletAddress: result.dwalletAddress,
          curve: result.curve,
          curveId: result.curveId,
          ownerPubkeyBase58: bs58.encode(result.ownerPubkey),
          // The curve-specific dWallet public key — derive destination-chain
          // addresses from THIS, not from `ownerPubkeyBase58` (Ed25519). See
          // GET /v1/dwallet/addresses for the derived addresses themselves.
          dwalletPublicKeyHex: Buffer.from(result.dwalletPublicKey).toString('hex'),
          committed: result.committed,
          signable: result.signable,
          recoverable: result.recoverable,
          ...(result.policyEngineAddress
            ? { policyEngineAddress: result.policyEngineAddress }
            : {}),
          ...(result.policyEngineInitAuthorityHashBase64
            ? {
                policyEngineInitAuthorityHashBase64:
                  result.policyEngineInitAuthorityHashBase64,
              }
            : {}),
          ...(result.policyEngineAttachWarning
            ? { policyEngineAttachWarning: result.policyEngineAttachWarning }
            : {}),
          disclaimer: result.disclaimer,
        }),
      )
    } catch (err) {
      respondErr(res, 'mcp/dwallet/create', err)
    }
  })

  router.post('/transfer-ownership', async (req, res) => {
    try {
      const ownerRef = ownerRefOf(req.header('x-andromeda-user-id'))
      const body = transferOwnershipSchema.parse(req.body)
      const result = await transferDwalletOwnership({
        ownerRef,
        dwalletAddress: body.dwalletAddress,
        passphrase: body.passphrase,
        ikaProgramId: config.base.ikaProgramId,
        newAuthority: body.newAuthorityBase58,
      })
      res.json(ok({ txSignature: result.txSignature, newAuthority: result.newAuthority }))
    } catch (err) {
      respondErr(res, 'mcp/dwallet/transfer-ownership', err)
    }
  })

  router.post('/presign', async (req, res) => {
    try {
      const ownerRef = ownerRefOf(req.header('x-andromeda-user-id'))
      const body = presignSchema.parse(req.body)
      const { presignSessionId } = await allocatePresign({ ownerRef, dwalletAddress: body.dwalletAddress })
      res.json(ok({ presignSessionIdHex: Buffer.from(presignSessionId).toString('hex') }))
    } catch (err) {
      respondErr(res, 'mcp/dwallet/presign', err)
    }
  })

  router.post('/sign', async (req, res) => {
    try {
      const ownerRef = ownerRefOf(req.header('x-andromeda-user-id'))
      const body = signSchema.parse(req.body)

      // Decode the approval tx signature (base58 → 64 bytes typical).
      let approvalTxSignature: Uint8Array
      try {
        approvalTxSignature = bs58.decode(body.approvalTxSignatureBase58)
      } catch {
        res.status(400).json(fail('approvalTxSignatureBase58 is not valid base58'))
        return
      }

      // Use the supplied presign, or allocate one.
      let presignSessionId: Uint8Array
      if (body.presignSessionIdHex) {
        presignSessionId = hexToBytes(body.presignSessionIdHex)
      } else {
        ;({ presignSessionId } = await allocatePresign({ ownerRef, dwalletAddress: body.dwalletAddress }))
      }

      const result = await signMessage({
        ownerRef,
        dwalletAddress: body.dwalletAddress,
        passphrase: body.passphrase,
        message: hexToBytes(body.messageHex),
        ...(body.messageMetadataHex ? { messageMetadata: hexToBytes(body.messageMetadataHex) } : {}),
        scheme: body.scheme,
        presignSessionId,
        approvalTxSignature,
        approvalSlot: body.approvalSlot,
      })
      res.json(
        ok({
          signatureBase64: result.signatureBase64,
          scheme: result.scheme,
          presignSessionIdHex: Buffer.from(presignSessionId).toString('hex'),
        }),
      )
    } catch (err) {
      respondErr(res, 'mcp/dwallet/sign', err)
    }
  })

  router.get('/addresses/:dwalletAddress', async (req, res) => {
    try {
      const ownerRef = ownerRefOf(req.header('x-andromeda-user-id'))
      const dwalletAddress = req.params.dwalletAddress
      if (!dwalletAddress || dwalletAddress.length < 32) {
        res.status(400).json(fail('dwalletAddress path parameter is required (base58)'))
        return
      }
      const result = await deriveWalletAddresses({ ownerRef, dwalletAddress })
      res.json(ok(result))
    } catch (err) {
      respondErr(res, 'mcp/dwallet/addresses', err)
    }
  })

  // Stateless utility: given a destination chainId + raw payload, return the
  // envelope-applied bytes to sign and the on-chain message digest. No tenant
  // data, no signing — pure compute. Single source of truth for the
  // (preprocessed, digest) pair so approve and sign never drift.
  router.post('/prepare-message', (req, res) => {
    try {
      const body = prepareMessageSchema.parse(req.body)
      const result = prepareMessage(body.chainId, hexToBytes(body.payloadHex), body.kind)
      res.json(ok(result))
    } catch (err) {
      respondErr(res, 'mcp/dwallet/prepare-message', err)
    }
  })

  logger.info(
    { policyEngineEnabled },
    'MCP dWallet routes mounted (/v1/dwallet/{create,transfer-ownership,presign,sign,addresses,prepare-message})',
  )
}
