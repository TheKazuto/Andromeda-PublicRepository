import { Router } from 'express'
import { z } from 'zod'
import { address as toAddress } from '@solana/kit'
import { fail, ok } from '../../types.js'
import { sanitizeError } from '../../safeError.js'
import { getPolicyAdapter } from '../adapters/SolanaAdapter.js'
import type { AdminAction, MemberSlot } from '../adapters/PolicyAdapter.js'
import {
  SCHEME_ED25519,
  SCHEME_SECP256K1,
  SCHEME_SECP256R1,
  SCHEME_WEBAUTHN,
} from '../../clients/rulesPolicy/index.js'
import type { AppConfig } from '../../config.js'

/**
 * Policy management endpoints. All admin actions are challenge-based + gas
 * sponsored:
 *
 *   POST /v1/recovery/policy/preview
 *   POST /v1/recovery/policy/deploy
 *   GET  /v1/recovery/policy/:dwalletAddress
 *   POST /v1/recovery/policy/admin/challenge   ← returns challenge for a given AdminAction
 *   POST /v1/recovery/policy/admin/submit      ← accepts the off-chain primary signature
 *   POST /v1/recovery/policy/apply-pending     ← anyone, after cooldown elapsed
 */

// ── Member-slot DTO ────────────────────────────────────────────

const memberSlotSchema = z.object({
  scheme: z.number().int().min(0).max(3),
  identifierBase64: z.string(),
  label: z.string().max(32).optional(),
})

function decodeMemberSlot(input: z.infer<typeof memberSlotSchema>): MemberSlot {
  const expectedLen =
    input.scheme === SCHEME_ED25519
      ? 32
      : input.scheme === SCHEME_SECP256K1
        ? 20
        : input.scheme === SCHEME_SECP256R1 || input.scheme === SCHEME_WEBAUTHN
          ? 33
          : -1
  if (expectedLen < 0) throw new Error(`Unsupported scheme ${input.scheme}`)
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(input.identifierBase64)) {
    throw new Error('identifierBase64 must be valid base64')
  }
  const identifier = Uint8Array.from(Buffer.from(input.identifierBase64, 'base64'))
  if (identifier.length !== expectedLen) {
    throw new Error(
      `identifier length ${identifier.length} does not match scheme ${input.scheme} (expected ${expectedLen})`,
    )
  }
  return {
    scheme: input.scheme,
    identifier,
    ...(input.label !== undefined ? { label: input.label } : {}),
  }
}

function decodeBase64Fixed(input: string, size: number, label: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(input)) {
    throw new Error(`${label} must be valid base64`)
  }
  const buf = Buffer.from(input, 'base64')
  if (buf.length !== size) throw new Error(`${label} must be ${size} bytes (got ${buf.length})`)
  return Uint8Array.from(buf)
}

function decodeBase64(input: string, label: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(input)) {
    throw new Error(`${label} must be valid base64`)
  }
  return Uint8Array.from(Buffer.from(input, 'base64'))
}

// ── Policy config DTO ──────────────────────────────────────────

const policyConfigSchema = z.object({
  primary: memberSlotSchema,
  members: z.array(memberSlotSchema).max(16).default([]),
  quorumThreshold: z.number().int().min(1).max(16).default(1),
  dailyLimit: z.coerce.bigint().nullable().default(null),
  allowedDestinationsBase64: z.array(z.string()).nullable().default(null),
  cooldownSeconds: z.number().int().min(3600).default(604_800),
})

// Audit C2 (Opção 4): every deploy carries an init_authority signature
// that's checked on-chain via precompile. The hash of the slot is part of
// the policy PDA seed.
const deploySchema = z.object({
  dwalletAddress: z.string().min(32),
  config: policyConfigSchema,
  initAuthoritySlot: memberSlotSchema,
  initAuthoritySignatureBase64: z.string(),
  initAuthorityWebauthnAuthDataBase64: z.string().optional(),
  initAuthorityWebauthnClientDataJsonBase64: z.string().optional(),
})

// Audit C2: post-deploy operations need init_authority_hash (32 bytes b64)
// to derive the policy PDA. Caller looks it up from its DB.
const initAuthorityHashFieldSchema = z.string()

// ── Admin action DTOs ──────────────────────────────────────────

const adminActionSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('add_member'), member: memberSlotSchema }),
  z.object({ type: z.literal('remove_member'), member: memberSlotSchema }),
  z.object({ type: z.literal('add_destination'), destinationBase64: z.string() }),
  z.object({ type: z.literal('remove_destination'), destinationBase64: z.string() }),
  z.object({ type: z.literal('revoke') }),
  z.object({ type: z.literal('set_primary'), newPrimary: memberSlotSchema }),
  z.object({
    type: z.literal('set_quorum_threshold_immediate'),
    newThreshold: z.number().int().min(1).max(16),
  }),
  z.object({
    type: z.literal('set_daily_limit_immediate'),
    newSome: z.boolean(),
    newLimit: z.coerce.bigint(),
  }),
  z.object({
    type: z.literal('set_cooldown_immediate'),
    newCooldownSeconds: z.coerce.bigint(),
  }),
  z.object({
    type: z.literal('propose_quorum_threshold_change'),
    newThreshold: z.number().int().min(1).max(16),
  }),
  z.object({
    type: z.literal('propose_daily_limit_change'),
    newSome: z.boolean(),
    newLimit: z.coerce.bigint(),
  }),
  z.object({
    type: z.literal('propose_cooldown_change'),
    newCooldownSeconds: z.coerce.bigint(),
  }),
])

type AdminActionInput = z.infer<typeof adminActionSchema>

function adminActionFromInput(input: AdminActionInput): AdminAction {
  switch (input.type) {
    case 'add_member':
      return { type: 'add_member', member: decodeMemberSlot(input.member) }
    case 'remove_member':
      return { type: 'remove_member', member: decodeMemberSlot(input.member) }
    case 'add_destination':
      return {
        type: 'add_destination',
        destination: decodeBase64Fixed(input.destinationBase64, 32, 'destination'),
      }
    case 'remove_destination':
      return {
        type: 'remove_destination',
        destination: decodeBase64Fixed(input.destinationBase64, 32, 'destination'),
      }
    case 'revoke':
      return { type: 'revoke' }
    case 'set_primary':
      return { type: 'set_primary', newPrimary: decodeMemberSlot(input.newPrimary) }
    case 'set_quorum_threshold_immediate':
      return { type: 'set_quorum_threshold_immediate', newThreshold: input.newThreshold }
    case 'set_daily_limit_immediate':
      return {
        type: 'set_daily_limit_immediate',
        newSome: input.newSome,
        newLimit: input.newLimit,
      }
    case 'set_cooldown_immediate':
      return { type: 'set_cooldown_immediate', newCooldownSeconds: input.newCooldownSeconds }
    case 'propose_quorum_threshold_change':
      return { type: 'propose_quorum_threshold_change', newThreshold: input.newThreshold }
    case 'propose_daily_limit_change':
      return {
        type: 'propose_daily_limit_change',
        newSome: input.newSome,
        newLimit: input.newLimit,
      }
    case 'propose_cooldown_change':
      return { type: 'propose_cooldown_change', newCooldownSeconds: input.newCooldownSeconds }
  }
}

const adminChallengeSchema = z.object({
  dwalletAddress: z.string().min(32),
  initAuthorityHashBase64: initAuthorityHashFieldSchema,
  action: adminActionSchema,
})

const adminSubmitSchema = z.object({
  dwalletAddress: z.string().min(32),
  initAuthorityHashBase64: initAuthorityHashFieldSchema,
  action: adminActionSchema,
  primarySignatureBase64: z.string(),
  expectedNonce: z.coerce.bigint(),
})

// ── Router ─────────────────────────────────────────────────────

export function buildPolicyRouter(config: AppConfig): Router {
  const router = Router()

  router.post('/preview', (req, res) => {
    try {
      const parsed = deploySchema.parse(req.body)
      const cfg = parsed.config
      if (cfg.cooldownSeconds < config.recovery.minCooldownSeconds) {
        res
          .status(400)
          .json(fail(`Invalid cooldown: minimum ${config.recovery.minCooldownSeconds}s`))
        return
      }
      if (cfg.quorumThreshold > Math.max(1, cfg.members.length)) {
        res.status(400).json(fail('Invalid quorum threshold for members count'))
        return
      }
      if (cfg.members.length > 0) {
        res.status(400).json(fail('Deploy cannot pre-seed quorum members; use admin actions after deploy'))
        return
      }
      if (cfg.allowedDestinationsBase64 !== null) {
        res.status(400).json(fail('Deploy cannot pre-seed allowed destinations; use admin actions after deploy'))
        return
      }
      const _primary = decodeMemberSlot(cfg.primary)
      const _members = cfg.members.map(decodeMemberSlot)
      void _primary
      void _members
      res.json(ok({ summary: 'Configuration valid.', dwalletAddress: parsed.dwalletAddress }))
    } catch (err) {
      const safe = sanitizeError('recovery/policy/preview', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  router.post('/deploy', async (req, res) => {
    try {
      const parsed = deploySchema.parse(req.body)
      const adapter = getPolicyAdapter()
      const cfg = parsed.config
      // Audit C2 (Opção 4): canonical 34-byte init_authority slot.
      const initAuthSlot = decodeMemberSlot(parsed.initAuthoritySlot)
      const initAuthSlotBytes = new Uint8Array(34)
      initAuthSlotBytes[0] = initAuthSlot.scheme
      initAuthSlotBytes.set(initAuthSlot.identifier, 1)
      const result = await adapter.deployRulesPolicy({
        dwalletAddress: toAddress(parsed.dwalletAddress),
        config: {
          primary: decodeMemberSlot(cfg.primary),
          members: cfg.members.map(decodeMemberSlot),
          quorumThreshold: cfg.quorumThreshold,
          dailyLimit: cfg.dailyLimit,
          allowedDestinations:
            cfg.allowedDestinationsBase64?.map((d) =>
              decodeBase64Fixed(d, 32, 'allowed destination'),
            ) ?? null,
          cooldownSeconds: cfg.cooldownSeconds,
        },
        initAuthoritySlot: initAuthSlotBytes,
        initAuthoritySignature: decodeBase64(parsed.initAuthoritySignatureBase64, 'initAuthoritySignature'),
        ...(parsed.initAuthorityWebauthnAuthDataBase64
          ? { initAuthorityWebauthnAuthData: decodeBase64(parsed.initAuthorityWebauthnAuthDataBase64, 'initAuthorityWebauthnAuthData') }
          : {}),
        ...(parsed.initAuthorityWebauthnClientDataJsonBase64
          ? { initAuthorityWebauthnClientDataJson: decodeBase64(parsed.initAuthorityWebauthnClientDataJsonBase64, 'initAuthorityWebauthnClientDataJson') }
          : {}),
      })
      res.json(
        ok({
          policyAddress: result.policyAddress,
          txSignature: result.txSignature,
          initAuthorityHashBase64: Buffer.from(result.initAuthorityHash).toString('base64'),
        }),
      )
    } catch (err) {
      const safe = sanitizeError('recovery/policy/deploy', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  router.get('/:dwalletAddress', async (req, res) => {
    try {
      const dwallet = req.params.dwalletAddress
      if (!dwallet) {
        res.status(400).json(fail('Missing dwalletAddress'))
        return
      }
      // Audit C2 (Opção 4): need init_authority_hash to derive PDA.
      const hashB64 = req.query.initAuthorityHashBase64
      if (typeof hashB64 !== 'string') {
        res.status(400).json(fail('initAuthorityHashBase64 query param required (Audit C2)'))
        return
      }
      const initAuthorityHash = decodeBase64Fixed(hashB64, 32, 'initAuthorityHashBase64')
      const adapter = getPolicyAdapter()
      const state = await adapter.readStateByHash({
        dwalletAddress: toAddress(dwallet),
        initAuthorityHash,
      })
      if (!state) {
        res.status(404).json(fail('Policy not found'))
        return
      }
      res.json(
        ok({
          policyAddress: state.policyAddress,
          dwalletAddress: state.dwalletAddress,
          primary: {
            scheme: state.primary.scheme,
            identifierBase64: Buffer.from(state.primary.identifier).toString('base64'),
          },
          members: state.members.map((m) => ({
            scheme: m.scheme,
            identifierBase64: Buffer.from(m.identifier).toString('base64'),
          })),
          quorumThreshold: state.quorumThreshold,
          dailyLimit: state.dailyLimit?.toString() ?? null,
          allowedDestinationsBase64:
            state.allowedDestinations?.map((d) => Buffer.from(d).toString('base64')) ?? null,
          cooldownSeconds: state.cooldownSeconds,
          pendingChange: state.pendingChange
            ? {
                kind: state.pendingChange.kind,
                ...(state.pendingChange.newQuorumThreshold !== undefined
                  ? { newQuorumThreshold: state.pendingChange.newQuorumThreshold }
                  : {}),
                ...(state.pendingChange.newDailyLimit !== undefined
                  ? { newDailyLimit: state.pendingChange.newDailyLimit?.toString() ?? null }
                  : {}),
                ...(state.pendingChange.newCooldownSeconds !== undefined
                  ? { newCooldownSeconds: state.pendingChange.newCooldownSeconds }
                  : {}),
                activatesAt: state.pendingChange.activatesAt.toISOString(),
              }
            : null,
          dailyUsed: state.dailyUsed.toString(),
          lastResetTs: state.lastResetTs.toISOString(),
          nextAdminNonce: state.nextAdminNonce.toString(),
          nextPrimaryRecoverNonce: state.nextPrimaryRecoverNonce.toString(),
          nextSessionNonce: state.nextSessionNonce.toString(),
        }),
      )
    } catch (err) {
      const safe = sanitizeError('recovery/policy/get', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  router.post('/admin/challenge', async (req, res) => {
    try {
      const input = adminChallengeSchema.parse(req.body)
      const adapter = getPolicyAdapter()
      const initAuthorityHash = decodeBase64Fixed(
        input.initAuthorityHashBase64,
        32,
        'initAuthorityHashBase64',
      )
      const result = await adapter.prepareAdminAction({
        dwalletAddress: toAddress(input.dwalletAddress),
        initAuthorityHash,
        action: adminActionFromInput(input.action),
      })
      res.json(
        ok({
          challengeBase64: Buffer.from(result.challenge).toString('base64'),
          expectedNonce: result.expectedNonce.toString(),
        }),
      )
    } catch (err) {
      const safe = sanitizeError('recovery/policy/admin/challenge', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  router.post('/admin/submit', async (req, res) => {
    try {
      const input = adminSubmitSchema.parse(req.body)
      const adapter = getPolicyAdapter()
      const initAuthorityHash = decodeBase64Fixed(
        input.initAuthorityHashBase64,
        32,
        'initAuthorityHashBase64',
      )
      const result = await adapter.submitAdminAction({
        dwalletAddress: toAddress(input.dwalletAddress),
        initAuthorityHash,
        action: adminActionFromInput(input.action),
        primarySignature: decodeBase64(input.primarySignatureBase64, 'primarySignature'),
        expectedNonce: input.expectedNonce,
      })
      res.json(ok({ txSignature: result.txSignature }))
    } catch (err) {
      const safe = sanitizeError('recovery/policy/admin/submit', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  router.post('/apply-pending', async (req, res) => {
    try {
      const schema = z.object({
        dwalletAddress: z.string().min(32),
        initAuthorityHashBase64: initAuthorityHashFieldSchema,
      })
      const input = schema.parse(req.body)
      const adapter = getPolicyAdapter()
      const result = await adapter.applyPendingChange({
        dwalletAddress: toAddress(input.dwalletAddress),
        initAuthorityHash: decodeBase64Fixed(input.initAuthorityHashBase64, 32, 'initAuthorityHashBase64'),
      })
      res.json(ok({ txSignature: result.txSignature }))
    } catch (err) {
      const safe = sanitizeError('recovery/policy/apply-pending', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  return router
}
