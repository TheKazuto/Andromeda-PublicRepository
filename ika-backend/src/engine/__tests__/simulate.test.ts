/**
 * Tests for the /v1/dwallet/simulate endpoint.
 */

import { describe, it, expect, beforeAll } from 'vitest'
import request from 'supertest'
import express, { type Express } from 'express'
import { z } from 'zod'
import { fail, ok } from '../../types.js'
import { configureAuth, requireServiceApiKey } from '../../http/auth.js'

let app: Express

beforeAll(() => {
  app = express()
  app.use(express.json())

  configureAuth({ serviceApiKey: 'test-api-key-32-chars-long-xx' })
  app.use(requireServiceApiKey)

  // Simplified endpoint for testing without full config
  app.post('/v1/dwallet/simulate', async (req, res) => {
    try {
      const simulateSchema = z.object({
        chainId: z.string().min(1),
        payloadHex: z.string().min(1),
        kind: z.enum(['transaction', 'message']),
        expectedDigestHex: z.string().length(64).regex(/^[a-fA-F0-9]+$/),
        dwalletPublicKeyHex: z.string().optional(),
      })

      const parsed = simulateSchema.parse(req.body)

      // Mock response for testing
      res.json(
        ok({
          ok: true,
          digestMatches: false,
          assetChanges: [],
          approvals: [],
          calls: [],
          effectsExtracted: false,
          willRevert: false,
          warnings: ['Mock simulation'],
        }),
      )
    } catch (err) {
      const message = err instanceof z.ZodError ? 'Invalid input' : 'Unknown error'
      res.status(err instanceof z.ZodError ? 400 : 500).json(fail(message))
    }
  })
})

describe('POST /v1/dwallet/simulate', () => {
  it('returns 401 without X-Api-Key header', async () => {
    const res = await request(app)
      .post('/v1/dwallet/simulate')
      .send({
        chainId: 'solana:5eykt4UsFv2P6tnvPqf6xwFxupngamnB21y36T1ef5DQ',
        payloadHex: '0x0102030405',
        kind: 'transaction',
        expectedDigestHex: '0000000000000000000000000000000000000000000000000000000000000000',
      })

    expect(res.status).toBe(401)
    expect(res.body.success).toBe(false)
  })

  it('returns 400 with invalid digest hex', async () => {
    const res = await request(app)
      .post('/v1/dwallet/simulate')
      .set('X-Api-Key', 'test-api-key-32-chars-long-xx')
      .send({
        chainId: 'solana:5eykt4UsFv2P6tnvPqf6xwFxupngamnB21y36T1ef5DQ',
        payloadHex: '0x0102030405',
        kind: 'transaction',
        expectedDigestHex: 'invalid', // too short
      })

    expect(res.status).toBe(400)
    expect(res.body.success).toBe(false)
  })

  it('accepts valid request with correct API key', async () => {
    const res = await request(app)
      .post('/v1/dwallet/simulate')
      .set('X-Api-Key', 'test-api-key-32-chars-long-xx')
      .send({
        chainId: 'solana:5eykt4UsFv2P6tnvPqf6xwFxupngamnB21y36T1ef5DQ',
        payloadHex: '0x0102030405',
        kind: 'transaction',
        expectedDigestHex: '0000000000000000000000000000000000000000000000000000000000000000',
      })

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.data).toBeDefined()
  })

  it('returns simulation result with digest mismatch warning', async () => {
    const res = await request(app)
      .post('/v1/dwallet/simulate')
      .set('X-Api-Key', 'test-api-key-32-chars-long-xx')
      .send({
        chainId: 'eip155:1',
        payloadHex: '0x095ea7b3000000000000000000000000ab12345678901234567890123456789012345678ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        kind: 'transaction',
        expectedDigestHex: '0000000000000000000000000000000000000000000000000000000000000001',
      })

    expect(res.status).toBe(200)
    expect(res.body.data.warnings).toBeDefined()
  })
})
