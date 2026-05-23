import { Router } from 'express'
import { z } from 'zod'
import type { AppConfig } from '../config.js'
import { fail, ok } from '../types.js'
import { sanitizeError } from '../safeError.js'
import { requireServiceApiKey } from '../http/auth.js'
import { initIkaGrpcClient } from './grpc-client.js'
import { initSolanaRpc } from './solana-rpc.js'
import { prepareDkg, dkgRequestSchema, submitDkg } from './dkg.js'
import { submitSign } from './sign.js'
import { submitPresign, listPresigns } from './presign.js'
import { submitFutureSign, submitSignWithPartialUserSig } from './future-sign.js'
import { submitReEncryptShare, submitMakeSharePublic } from './re-encrypt-share.js'
import { mountMcpWalletRoutes } from './ika-client/routes.js'

const submitSchema = z.object({
  userSignatureBase64: z.string().min(1).max(512).regex(/^[A-Za-z0-9+/]+={0,2}$/),
  signedRequestDataBase64: z.string().min(1).max(1_398_104).regex(/^[A-Za-z0-9+/]+={0,2}$/),
})

function decodeBase64(s: string, maxBytes: number): Uint8Array {
  // Buffer is a Uint8Array subclass — wrap its memory zero-copy instead of
  // allocating a fresh Uint8Array via `Uint8Array.from(buf)`.
  const buf = Buffer.from(s, 'base64')
  if (buf.length > maxBytes) throw new Error('Decoded base64 payload exceeds size limit')
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
}

export function buildEngineRouter(config: AppConfig): Router {
  initIkaGrpcClient({ url: config.base.ikaGrpcUrl, tls: config.base.ikaGrpcTls })
  initSolanaRpc(config.base.solanaRpcUrl)

  const router = Router()
  router.use(requireServiceApiKey)

  // High-level, tenant-scoped dWallet ops (option A2): /create, /presign, /sign
  // → the MCP tools `create_dwallet`, `presign`, `sign_message`.
  mountMcpWalletRoutes(router, config)

  router.post('/dkg/prepare', async (req, res) => {
    try {
      const parsed = dkgRequestSchema.parse(req.body)
      res.json(ok(await prepareDkg(parsed)))
    } catch (err) {
      const safe = sanitizeError('dkg/prepare', err)
      const status = err instanceof z.ZodError || safe.message.startsWith('Invalid ') ? 400 : 500
      res.status(status).json(fail(safe.message, safe.traceId))
    }
  })

  const submitHandlers = new Map<
    string,
    (input: { userSignature: Uint8Array; signedRequestData: Uint8Array }) => Promise<unknown>
  >([
    ['/dkg/submit', submitDkg],
    ['/sign/submit', submitSign],
    ['/presign/submit', submitPresign],
    ['/future-sign/submit', submitFutureSign],
    ['/future-sign/complete/submit', submitSignWithPartialUserSig],
    ['/re-encrypt-share/submit', submitReEncryptShare],
    ['/make-share-public/submit', submitMakeSharePublic],
  ])

  for (const [path, handler] of submitHandlers) {
    router.post(path, async (req, res) => {
      try {
        const { userSignatureBase64, signedRequestDataBase64 } = submitSchema.parse(req.body)
        const userSignature = decodeBase64(userSignatureBase64, 256)
        const signedRequestData = decodeBase64(signedRequestDataBase64, 1 * 1024 * 1024)
        const result = await handler({ userSignature, signedRequestData })
        res.json(ok(result))
      } catch (err) {
        const safe = sanitizeError(`engine${path}`, err)
        const status = err instanceof z.ZodError || safe.message.includes('base64') ? 400 : 500
        res.status(status).json(fail(safe.message, safe.traceId))
      }
    })
  }

  router.get('/presigns/:userPubkey', async (req, res) => {
    try {
      const { userPubkey } = req.params
      if (!userPubkey) {
        res.status(400).json(fail('Missing userPubkey'))
        return
      }
      const bytes = decodeBase64(userPubkey, 128)
      const list = await listPresigns(bytes)
      res.json(ok({ presigns: list }))
    } catch (err) {
      const safe = sanitizeError('presigns/list', err)
      res.status(500).json(fail(safe.message, safe.traceId))
    }
  })

  // Risk simulation endpoint: decode + simulate transaction, verify digest match.
  // Internal use only (`X-Api-Key` required from gateway).
  router.post('/simulate', async (req, res) => {
    try {
      const simulateSchema = z.object({
        chain_id: z.string().min(1),
        payload_hex: z.string().min(1),
        kind: z.enum(['transaction', 'message']),
        expected_digest_hex: z.string().length(64).regex(/^[a-fA-F0-9]+$/),
        dwallet_public_key_hex: z.string().optional(),
        // Client-provided RPC for the destination chain (the dev funds it). SSRF
        // is validated downstream in simulateTransaction before any outbound call.
        rpc_url: z.string().url().optional(),
      })

      const parsed = simulateSchema.parse(req.body)

      const { simulateTransaction } = await import('../risk/simulate.js')
      const result = await simulateTransaction(
        {
          chainId: parsed.chain_id,
          payloadHex: parsed.payload_hex,
          kind: parsed.kind,
          expectedDigestHex: parsed.expected_digest_hex,
          dwalletPublicKeyHex: parsed.dwallet_public_key_hex as string | undefined,
        },
        parsed.rpc_url,
      )

      // Convert response to snake_case for consistency
      const snakeCaseResult = {
        ok: result.ok,
        digest_matches: result.digestMatches,
        actual_digest_hex: result.actualDigestHex,
        destination: result.destination,
        verified: result.verified,
        asset_changes: result.assetChanges,
        approvals: result.approvals,
        calls: result.calls,
        effects_extracted: result.effectsExtracted,
        calldata_risk: result.calldataRisk,
        estimated_gas: result.estimatedGas,
        solana_instructions: result.solanaInstructions,
        will_revert: result.willRevert,
        warnings: result.warnings,
        // Nested simulation object: the gateway risk service reads
        // `respMap["simulation"]` (deriveSimulationRisk → will_revert /
        // approvals.amount / asset_changes.change), and the public
        // POST /v1/policy/risk/evaluate surfaces it to the client.
        simulation: {
          ok: result.ok,
          will_revert: result.willRevert,
          asset_changes: result.assetChanges,
          approvals: result.approvals,
          calls: result.calls,
          estimated_gas: result.estimatedGas,
          warnings: result.warnings,
        },
      }

      res.json(ok(snakeCaseResult))
    } catch (err) {
      const safe = sanitizeError('dwallet/simulate', err)
      const status = err instanceof z.ZodError ? 400 : 500
      res.status(status).json(fail(safe.message, safe.traceId))
    }
  })

  return router
}
