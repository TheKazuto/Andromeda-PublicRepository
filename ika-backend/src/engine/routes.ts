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

  return router
}
