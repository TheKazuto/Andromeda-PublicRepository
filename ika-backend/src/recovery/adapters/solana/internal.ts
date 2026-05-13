/**
 * Shared internals for the Solana `rules-policy` adapter — pure helpers, the
 * resolved context object, and the credential→precompile mapping. Kept separate
 * from the flow modules (`deploy`, `state`, `primary`, `quorum`, `admin`) so
 * each stays small and the byte-layout-critical bits live in one tested place.
 */

import {
  address as toAddress,
  getAddressDecoder,
  getAddressEncoder,
  type Address,
  type Instruction,
} from '@solana/kit'
import { createHash } from 'node:crypto'

import {
  buildEd25519PrecompileInstruction,
  buildSecp256k1PrecompileInstruction,
  buildSecp256r1PrecompileInstruction,
} from '../../../engine/precompiles.js'
import {
  type MemberSlotData,
  type RulesPolicyAccountData,
  PENDING_CHANGE_KIND_NONE,
  PENDING_CHANGE_KIND_QUORUM,
  PENDING_CHANGE_KIND_DAILY_LIMIT,
  PENDING_CHANGE_KIND_COOLDOWN,
  SCHEME_ED25519,
  SCHEME_SECP256K1,
  SCHEME_SECP256R1,
  SCHEME_WEBAUTHN,
} from '../../../clients/rulesPolicy/index.js'
import type { MemberSlot, PendingChange } from '../PolicyAdapter.js'

const addrEncoder = getAddressEncoder()
export const addrDecoder = getAddressDecoder()

// ── Options / context ───────────────────────────────────────────

export interface SolanaAdapterOptions {
  programId: string
  ikaProgramId: string
  ikaCoordinatorAddress: string | undefined
  defaultCooldownSeconds: number
  minCooldownSeconds: number
  /** Login Social — the on-chain `JwkRegistry` account address (canonical PDA). */
  oidcJwkRegistryAddress?: string | undefined
  /** Login Social — must equal the contract's `OIDC_VERIFIER_V1`. */
  oidcVerifierVersion?: number | undefined
}

/** Resolved + validated form of {@link SolanaAdapterOptions}, passed to every flow module. */
export interface SolanaCtx {
  readonly programId: Address
  readonly ikaProgramId: Address
  readonly defaultCooldownSeconds: number
  readonly minCooldownSeconds: number
  /** The Ika coordinator account — throws if not configured. */
  coordinator(): Address
  /** The on-chain `JwkRegistry` account address — throws if Login Social isn't configured. */
  oidcJwkRegistry(): Address
  readonly oidcVerifierVersion: number
}

export function makeSolanaCtx(opts: SolanaAdapterOptions): SolanaCtx {
  const programId = toAddress(opts.programId)
  const ikaProgramId = toAddress(opts.ikaProgramId)
  const coordinatorAddr = opts.ikaCoordinatorAddress ? toAddress(opts.ikaCoordinatorAddress) : null
  const jwkRegistryAddr = opts.oidcJwkRegistryAddress ? toAddress(opts.oidcJwkRegistryAddress) : null
  return {
    programId,
    ikaProgramId,
    defaultCooldownSeconds: opts.defaultCooldownSeconds,
    minCooldownSeconds: opts.minCooldownSeconds,
    coordinator() {
      if (!coordinatorAddr) throw new Error('IKA_COORDINATOR_ADDRESS not configured')
      return coordinatorAddr
    },
    oidcJwkRegistry() {
      if (!jwkRegistryAddr) throw new Error('IKA_OIDC_JWK_REGISTRY_ADDRESS not configured')
      return jwkRegistryAddr
    },
    oidcVerifierVersion: opts.oidcVerifierVersion ?? 1,
  }
}

// ── Pure helpers ────────────────────────────────────────────────

export function addressBytes(addr: Address | string): Uint8Array {
  return addrEncoder.encode(toAddress(addr)) as Uint8Array
}

export function idLen(scheme: number): number {
  switch (scheme) {
    case SCHEME_ED25519:
      return 32
    case SCHEME_SECP256K1:
      return 20
    case SCHEME_SECP256R1:
    case SCHEME_WEBAUTHN:
      return 33
    default:
      throw new Error(`Unsupported scheme: ${scheme}`)
  }
}

export function memberSlotToCanonical(slot: MemberSlot): Uint8Array {
  const expected = idLen(slot.scheme)
  if (slot.identifier.length !== expected) {
    throw new Error(
      `Identifier length ${slot.identifier.length} does not match scheme ${slot.scheme} (expected ${expected})`,
    )
  }
  const out = new Uint8Array(34)
  out[0] = slot.scheme
  out.set(slot.identifier, 1)
  return out
}

export function memberSlotFromCanonical(raw: Uint8Array, label?: string): MemberSlot {
  const scheme = raw[0]!
  const len = idLen(scheme)
  return {
    scheme,
    identifier: raw.slice(1, 1 + len),
    ...(label !== undefined ? { label } : {}),
  }
}

export function memberSlotFromData(data: MemberSlotData, label?: string): MemberSlot {
  return { scheme: data.scheme, identifier: data.identifier, ...(label !== undefined ? { label } : {}) }
}

export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest())
}

/**
 * Builds the precompile instruction that proves `slot` signed `challenge`.
 * For WebAuthn members, the runtime-signed message is
 * `webauthnAuthData || sha256(webauthnClientDataJson)`, not the raw
 * challenge — the on-chain handler reconstructs it the same way and verifies
 * the challenge appears base64url-no-pad inside the clientDataJSON.
 */
export function buildCredentialPrecompile(
  slot: MemberSlot,
  challenge: Uint8Array,
  signature: Uint8Array,
  webauthnAuthData?: Uint8Array,
  webauthnClientDataJson?: Uint8Array,
): Instruction {
  switch (slot.scheme) {
    case SCHEME_ED25519:
      return buildEd25519PrecompileInstruction({
        publicKey: slot.identifier,
        message: challenge,
        signature,
      })
    case SCHEME_SECP256K1:
      return buildSecp256k1PrecompileInstruction({
        ethAddress: slot.identifier,
        message: challenge,
        signature,
      })
    case SCHEME_SECP256R1:
      return buildSecp256r1PrecompileInstruction({
        publicKey: slot.identifier,
        message: challenge,
        signature,
      })
    case SCHEME_WEBAUTHN: {
      if (!webauthnAuthData || !webauthnClientDataJson) {
        throw new Error('WebAuthn member requires authenticatorData and clientDataJSON')
      }
      const cdjHash = sha256(webauthnClientDataJson)
      const signed = new Uint8Array(webauthnAuthData.length + 32)
      signed.set(webauthnAuthData, 0)
      signed.set(cdjHash, webauthnAuthData.length)
      return buildSecp256r1PrecompileInstruction({
        publicKey: slot.identifier,
        message: signed,
        signature,
      })
    }
    default:
      throw new Error(`Unsupported scheme: ${slot.scheme}`)
  }
}

export function pendingChangeFromState(data: RulesPolicyAccountData): PendingChange | null {
  if (data.pendingChangeKind === PENDING_CHANGE_KIND_NONE) return null
  const activatesAt = new Date(Number(data.pendingChange.activatesAt) * 1000)
  if (data.pendingChangeKind === PENDING_CHANGE_KIND_QUORUM) {
    return {
      kind: 'quorum_threshold',
      newQuorumThreshold: data.pendingChange.newQuorumThreshold,
      activatesAt,
    }
  }
  if (data.pendingChangeKind === PENDING_CHANGE_KIND_DAILY_LIMIT) {
    return {
      kind: 'daily_limit',
      newDailyLimit:
        data.pendingChange.newDailyLimitSome === 1 ? data.pendingChange.newDailyLimit : null,
      activatesAt,
    }
  }
  if (data.pendingChangeKind === PENDING_CHANGE_KIND_COOLDOWN) {
    return {
      kind: 'cooldown',
      newCooldownSeconds: Number(data.pendingChange.newCooldownSeconds),
      activatesAt,
    }
  }
  return null
}
