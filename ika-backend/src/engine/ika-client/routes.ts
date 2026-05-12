// HTTP routes for the MCP-facing dWallet operations (option A2). Mounted by
// `buildEngineRouter` under `/v1/dwallet`, so:
//   POST /v1/dwallet/create             →  MCP tool `create_dwallet`
//   POST /v1/dwallet/transfer-ownership →  MCP tool `transfer_ownership`
//   POST /v1/dwallet/approve            →  MCP tool `approve` (owner authorises a message)
//   POST /v1/dwallet/admin/add-member   →  MCP tool `admin_add_member` (keystore-primary policies only)
//   POST /v1/dwallet/presign            →  MCP tool `presign`
//   POST /v1/dwallet/sign               →  MCP tool `sign_message`
// (the gateway auto-generates the MCP tools from its route catalogue, so
// adding the matching entries to `gateway/internal/routes/routes.go` is all
// that's needed on the gateway side.)
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
  approveAsOwner,
  addAsRecoveryMember,
} from './wallet.js'

const HEX = /^[0-9a-fA-F]*$/
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/
const SCHEME_IDENTIFIER_LEN: Record<number, number> = { 0: 32, 1: 20, 2: 33, 3: 33 }

const createSchema = z.object({
  passphrase: z.string().min(12, 'passphrase must be at least 12 characters'),
  curve: z.enum(['Curve25519', 'Secp256k1', 'Secp256r1']).optional(),
  /**
   * When true, also deploy a `rules-policy` for the new dWallet and delegate
   * its authority to it — the dWallet is then signable (via /v1/dwallet/approve
   * → /v1/dwallet/sign) and socially recoverable. Requires the recovery policy
   * layer to be enabled on this deployment.
   */
  attachRecoveryPolicy: z.boolean().optional(),
  /**
   * Optional external primary owner for the auto-attached `rules-policy`.
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

const approveSchema = z.object({
  dwalletAddress: z.string().min(32),
  passphrase: z.string().min(12, 'passphrase must be at least 12 characters'),
  messageHex: z.string().regex(HEX).refine((s) => s.length % 2 === 0 && s.length > 0, 'messageHex must be non-empty even-length hex'),
  messageMetadataHex: z.string().regex(HEX).refine((s) => s.length % 2 === 0, 'messageMetadataHex must be even-length hex').optional(),
  /** Signature scheme written into the MessageApproval (0..6). */
  signatureScheme: z.number().int().min(0).max(6),
})

const presignSchema = z.object({
  dwalletAddress: z.string().min(32),
})

const addRecoveryMemberSchema = z.object({
  dwalletAddress: z.string().min(32),
  passphrase: z.string().min(12, 'passphrase must be at least 12 characters'),
  /** 0=Ed25519, 1=Secp256k1 (eth_address), 2=Secp256r1, 3=WebAuthn. */
  memberScheme: z.number().int().min(0).max(3),
  /** Identifier bytes (base64). Decoded length must match the scheme (32/20/33/33). */
  memberIdentifierBase64: z.string().min(1),
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
  PolicyNotAttachedError: 409,
  PolicyPrimaryExternalError: 409,
  BadMemberSlotError: 400,
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
  const recoveryPolicyEnabled = config.recovery.policyEnabled && !!config.recovery.policyProgramId
  const recoveryPolicyOpts = recoveryPolicyEnabled
    ? { programId: config.recovery.policyProgramId as string, cooldownSeconds: config.recovery.minCooldownSeconds }
    : null

  router.post('/create', async (req, res) => {
    try {
      const ownerRef = ownerRefOf(req.header('x-andromeda-user-id'))
      const body = createSchema.parse(req.body)
      if (body.attachRecoveryPolicy && !recoveryPolicyOpts) {
        res.status(400).json(fail('attachRecoveryPolicy requested but the recovery policy layer is not enabled on this deployment'))
        return
      }
      const result = await createDwallet({
        ownerRef,
        passphrase: body.passphrase,
        ikaProgramId: config.base.ikaProgramId,
        ...(body.curve ? { curve: body.curve } : {}),
        ...(body.attachRecoveryPolicy && recoveryPolicyOpts ? { recoveryPolicy: recoveryPolicyOpts } : {}),
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
          committed: result.committed,
          signable: result.signable,
          recoverable: result.recoverable,
          ...(result.policyAddress ? { policyAddress: result.policyAddress } : {}),
          ...(result.initAuthorityHashBase64 ? { initAuthorityHashBase64: result.initAuthorityHashBase64 } : {}),
          ...(result.policyAttachWarning ? { policyAttachWarning: result.policyAttachWarning } : {}),
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

  router.post('/approve', async (req, res) => {
    try {
      const ownerRef = ownerRefOf(req.header('x-andromeda-user-id'))
      const body = approveSchema.parse(req.body)
      const result = await approveAsOwner({
        ownerRef,
        dwalletAddress: body.dwalletAddress,
        passphrase: body.passphrase,
        message: hexToBytes(body.messageHex),
        ...(body.messageMetadataHex ? { messageMetadata: hexToBytes(body.messageMetadataHex) } : {}),
        signatureScheme: body.signatureScheme,
      })
      res.json(
        ok({
          approvalTxSignatureBase58: result.approvalTxSignature,
          approvalSlot: result.approvalSlot.toString(),
          messageApprovalAddress: result.messageApprovalAddress,
        }),
      )
    } catch (err) {
      respondErr(res, 'mcp/dwallet/approve', err)
    }
  })

  router.post('/admin/add-member', async (req, res) => {
    try {
      const ownerRef = ownerRefOf(req.header('x-andromeda-user-id'))
      const body = addRecoveryMemberSchema.parse(req.body)
      if (!BASE64.test(body.memberIdentifierBase64)) {
        res.status(400).json(fail('memberIdentifierBase64 must be valid base64'))
        return
      }
      const memberIdentifier = new Uint8Array(Buffer.from(body.memberIdentifierBase64, 'base64'))
      const expectedLen = SCHEME_IDENTIFIER_LEN[body.memberScheme]
      if (memberIdentifier.length !== expectedLen) {
        res
          .status(400)
          .json(fail(`memberIdentifierBase64 must decode to ${expectedLen} bytes for scheme ${body.memberScheme} (got ${memberIdentifier.length})`))
        return
      }
      const result = await addAsRecoveryMember({
        ownerRef,
        dwalletAddress: body.dwalletAddress,
        passphrase: body.passphrase,
        memberScheme: body.memberScheme,
        memberIdentifier,
      })
      res.json(ok({ txSignature: result.txSignature, memberSlotBase64: result.memberSlotBase64 }))
    } catch (err) {
      respondErr(res, 'mcp/dwallet/admin/add-member', err)
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

  logger.info(
    { recoveryPolicyEnabled },
    'MCP dWallet routes mounted (/v1/dwallet/{create,transfer-ownership,approve,admin/add-member,presign,sign})',
  )
}
