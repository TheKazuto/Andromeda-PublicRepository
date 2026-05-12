// Request DTOs + decoders for the policy management routes.
//
// Keeps `routes.ts` to just the HTTP wiring (parse → call adapter → respond);
// everything that turns wire JSON into the adapter's typed inputs lives here.

import { z } from 'zod'
import type { AdminAction, MemberSlot } from '../adapters/PolicyAdapter.js'
import {
  SCHEME_ED25519,
  SCHEME_SECP256K1,
  SCHEME_SECP256R1,
  SCHEME_WEBAUTHN,
} from '../../clients/rulesPolicy/index.js'

const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/

// ── Base64 decoders ────────────────────────────────────────────

export function decodeBase64Fixed(input: string, size: number, label: string): Uint8Array {
  if (!BASE64_RE.test(input)) throw new Error(`${label} must be valid base64`)
  const buf = Buffer.from(input, 'base64')
  if (buf.length !== size) throw new Error(`${label} must be ${size} bytes (got ${buf.length})`)
  return Uint8Array.from(buf)
}

export function decodeBase64(input: string, label: string): Uint8Array {
  if (!BASE64_RE.test(input)) throw new Error(`${label} must be valid base64`)
  return Uint8Array.from(Buffer.from(input, 'base64'))
}

// ── Member slot ────────────────────────────────────────────────

export const memberSlotSchema = z.object({
  scheme: z.number().int().min(0).max(3),
  identifierBase64: z.string(),
  label: z.string().max(32).optional(),
})

export function decodeMemberSlot(input: z.infer<typeof memberSlotSchema>): MemberSlot {
  const expectedLen =
    input.scheme === SCHEME_ED25519
      ? 32
      : input.scheme === SCHEME_SECP256K1
        ? 20
        : input.scheme === SCHEME_SECP256R1 || input.scheme === SCHEME_WEBAUTHN
          ? 33
          : -1
  if (expectedLen < 0) throw new Error(`Unsupported scheme ${input.scheme}`)
  if (!BASE64_RE.test(input.identifierBase64)) throw new Error('identifierBase64 must be valid base64')
  const identifier = Uint8Array.from(Buffer.from(input.identifierBase64, 'base64'))
  if (identifier.length !== expectedLen) {
    throw new Error(`identifier length ${identifier.length} does not match scheme ${input.scheme} (expected ${expectedLen})`)
  }
  return { scheme: input.scheme, identifier, ...(input.label !== undefined ? { label: input.label } : {}) }
}

// ── Policy config + deploy ─────────────────────────────────────

export const policyConfigSchema = z.object({
  primary: memberSlotSchema,
  members: z.array(memberSlotSchema).max(16).default([]),
  quorumThreshold: z.number().int().min(1).max(16).default(1),
  dailyLimit: z.coerce.bigint().nullable().default(null),
  allowedDestinationsBase64: z.array(z.string()).nullable().default(null),
  cooldownSeconds: z.number().int().min(3600).default(604_800),
})

// Audit C2 (Opção 4): every deploy carries an init_authority signature checked
// on-chain via precompile; sha256 of the 34-byte slot seeds the policy PDA.
export const deploySchema = z.object({
  dwalletAddress: z.string().min(32),
  config: policyConfigSchema,
  initAuthoritySlot: memberSlotSchema,
  initAuthoritySignatureBase64: z.string(),
  initAuthorityWebauthnAuthDataBase64: z.string().optional(),
  initAuthorityWebauthnClientDataJsonBase64: z.string().optional(),
})

// Audit C2: post-deploy operations need init_authority_hash (32 bytes b64) to
// derive the policy PDA. The caller looks it up from its own DB.
export const initAuthorityHashFieldSchema = z.string()

// ── Admin actions ──────────────────────────────────────────────

export const adminActionSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('add_member'), member: memberSlotSchema }),
  z.object({ type: z.literal('remove_member'), member: memberSlotSchema }),
  z.object({ type: z.literal('add_destination'), destinationBase64: z.string() }),
  z.object({ type: z.literal('remove_destination'), destinationBase64: z.string() }),
  z.object({ type: z.literal('revoke') }),
  z.object({ type: z.literal('set_primary'), newPrimary: memberSlotSchema }),
  z.object({ type: z.literal('set_quorum_threshold_immediate'), newThreshold: z.number().int().min(1).max(16) }),
  z.object({ type: z.literal('set_daily_limit_immediate'), newSome: z.boolean(), newLimit: z.coerce.bigint() }),
  z.object({ type: z.literal('set_cooldown_immediate'), newCooldownSeconds: z.coerce.bigint() }),
  z.object({ type: z.literal('propose_quorum_threshold_change'), newThreshold: z.number().int().min(1).max(16) }),
  z.object({ type: z.literal('propose_daily_limit_change'), newSome: z.boolean(), newLimit: z.coerce.bigint() }),
  z.object({ type: z.literal('propose_cooldown_change'), newCooldownSeconds: z.coerce.bigint() }),
])

type AdminActionInput = z.infer<typeof adminActionSchema>

export function adminActionFromInput(input: AdminActionInput): AdminAction {
  switch (input.type) {
    case 'add_member':
      return { type: 'add_member', member: decodeMemberSlot(input.member) }
    case 'remove_member':
      return { type: 'remove_member', member: decodeMemberSlot(input.member) }
    case 'add_destination':
      return { type: 'add_destination', destination: decodeBase64Fixed(input.destinationBase64, 32, 'destination') }
    case 'remove_destination':
      return { type: 'remove_destination', destination: decodeBase64Fixed(input.destinationBase64, 32, 'destination') }
    case 'revoke':
      return { type: 'revoke' }
    case 'set_primary':
      return { type: 'set_primary', newPrimary: decodeMemberSlot(input.newPrimary) }
    case 'set_quorum_threshold_immediate':
      return { type: 'set_quorum_threshold_immediate', newThreshold: input.newThreshold }
    case 'set_daily_limit_immediate':
      return { type: 'set_daily_limit_immediate', newSome: input.newSome, newLimit: input.newLimit }
    case 'set_cooldown_immediate':
      return { type: 'set_cooldown_immediate', newCooldownSeconds: input.newCooldownSeconds }
    case 'propose_quorum_threshold_change':
      return { type: 'propose_quorum_threshold_change', newThreshold: input.newThreshold }
    case 'propose_daily_limit_change':
      return { type: 'propose_daily_limit_change', newSome: input.newSome, newLimit: input.newLimit }
    case 'propose_cooldown_change':
      return { type: 'propose_cooldown_change', newCooldownSeconds: input.newCooldownSeconds }
  }
}

export const adminChallengeSchema = z.object({
  dwalletAddress: z.string().min(32),
  initAuthorityHashBase64: initAuthorityHashFieldSchema,
  action: adminActionSchema,
})

export const adminSubmitSchema = z.object({
  dwalletAddress: z.string().min(32),
  initAuthorityHashBase64: initAuthorityHashFieldSchema,
  action: adminActionSchema,
  primarySignatureBase64: z.string(),
  expectedNonce: z.coerce.bigint(),
})
