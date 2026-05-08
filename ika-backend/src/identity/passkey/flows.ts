// Passkey-as-identity — registration + authentication handlers.
// Identity-grade passkeys are gated by the PRF extension.

import { createHash, randomBytes } from 'node:crypto'
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server'
import type { Request, Response } from 'express'
import { z } from 'zod'
import { fail, ok } from '../../types.js'
import { sanitizeError } from '../../safeError.js'
import { recordAuditEvent } from '../audit.js'
import { getIdentityConfig } from '../config.js'
import { deriveWalletAddress } from '../derive.js'
import { createSessionForIdentity } from '../session.js'
import {
  PrfNotSupportedError,
  extractPrfFromClientExtensionResults,
  getPrfSaltBytes,
} from './prf.js'
import {
  advanceIdentityPasskeyCounter,
  consumePasskeyChallenge,
  createPasskeyChallenge,
  getIdentityPasskeyByCredentialId,
  listIdentityPasskeysByWallet,
  upsertIdentityPasskey,
} from './store.js'

const CHALLENGE_TTL_MS = 5 * 60 * 1000
const RANDOM_USER_HANDLE_BYTES = 16

const registerOptionsSchema = z.object({
  displayName: z.string().min(1).max(120).optional(),
})

const registerVerifySchema = z.object({
  attestation: z.unknown(),
  clientExtensionResults: z.unknown().optional(),
  deviceLabel: z.string().min(1).max(120).optional(),
})

const authenticateOptionsSchema = z.object({
  walletAddress: z.string().min(3).max(128).optional(),
})

const authenticateVerifySchema = z.object({
  assertion: z.unknown(),
  clientExtensionResults: z.unknown().optional(),
})

function getRpConfig() {
  const config = getIdentityConfig()
  if (!config.passkey.rpId || config.passkey.origins.length === 0) {
    throw new Error('Passkey identity layer is not fully configured')
  }
  return {
    rpId: config.passkey.rpId,
    rpName: config.passkey.rpName ?? 'Andromeda',
    origins: config.passkey.origins,
  }
}

function buildPrfRegistrationExtension(): { prf: { eval: { first: Buffer } } } {
  return { prf: { eval: { first: getPrfSaltBytes() } } }
}

function buildPrfAuthenticationExtension(): { prf: { eval: { first: Buffer } } } {
  return { prf: { eval: { first: getPrfSaltBytes() } } }
}

function readUserAgent(req: Request): string | null {
  const ua = req.headers['user-agent']
  if (typeof ua !== 'string' || ua.length === 0) return null
  return ua.length > 512 ? ua.slice(0, 512) : ua
}

function buildIpHash(req: Request): string | null {
  const ip = req.ip || req.socket?.remoteAddress
  if (!ip) return null
  return createHash('sha256').update(ip).digest('hex').slice(0, 32)
}

interface SimpleAttestationLike {
  response?: { clientDataJSON?: string; transports?: string[] }
  clientExtensionResults?: unknown
}

function readChallengeFromAttestation(attestation: unknown): string | null {
  const att = attestation as SimpleAttestationLike
  const clientDataJSON = att?.response?.clientDataJSON
  if (typeof clientDataJSON !== 'string') return null
  try {
    const decoded = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8')) as {
      challenge?: string
    }
    return typeof decoded.challenge === 'string' ? decoded.challenge : null
  } catch {
    return null
  }
}

// ── Registration ─────────────────────────────────────────────────

export async function handlePasskeyRegisterOptions(req: Request, res: Response): Promise<void> {
  const parsed = registerOptionsSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json(fail('Invalid passkey register options payload'))
    return
  }
  try {
    const { rpId, rpName } = getRpConfig()
    const userHandle = randomBytes(RANDOM_USER_HANDLE_BYTES).toString('base64url')
    const options = await generateRegistrationOptions({
      rpID: rpId,
      rpName,
      userID: Buffer.from(userHandle, 'utf8'),
      userName: parsed.data.displayName ?? userHandle,
      userDisplayName: parsed.data.displayName ?? 'Andromeda user',
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      extensions: buildPrfRegistrationExtension() as unknown as never,
    })
    await createPasskeyChallenge({
      challenge: options.challenge,
      type: 'registration',
      userHandle,
      ttlMs: CHALLENGE_TTL_MS,
      metadata: parsed.data.displayName ? { displayName: parsed.data.displayName } : null,
    })
    res.json(ok(options))
  } catch (err) {
    const sanitized = sanitizeError('passkey.register.options', err, {
      fallbackMessage: 'Failed to generate registration options',
    })
    res.status(500).json(fail(sanitized.message, sanitized.traceId))
  }
}

export async function handlePasskeyRegisterVerify(req: Request, res: Response): Promise<void> {
  const parsed = registerVerifySchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json(fail('Invalid passkey register verify payload'))
    return
  }
  try {
    const { rpId, origins } = getRpConfig()

    const challenge = readChallengeFromAttestation(parsed.data.attestation)
    if (!challenge) {
      res.status(400).json(fail('Attestation is missing or malformed'))
      return
    }
    const challengeRecord = await consumePasskeyChallenge(challenge, 'registration')
    if (!challengeRecord) {
      res.status(400).json(fail('Registration challenge is invalid or expired'))
      return
    }

    const verification = await verifyRegistrationResponse({
      response: parsed.data.attestation as Parameters<typeof verifyRegistrationResponse>[0]['response'],
      expectedChallenge: challengeRecord.challenge,
      expectedOrigin: origins,
      expectedRPID: rpId,
      requireUserVerification: false,
    })

    if (!verification.verified || !verification.registrationInfo) {
      res.status(400).json(fail('Registration verification failed'))
      return
    }

    const clientExt = (parsed.data.clientExtensionResults
      ?? (parsed.data.attestation as SimpleAttestationLike)?.clientExtensionResults) as unknown
    let prfHex: string
    try {
      prfHex = extractPrfFromClientExtensionResults(clientExt)
    } catch (err) {
      const message =
        err instanceof PrfNotSupportedError
          ? err.message
          : 'PRF output could not be read from this device'
      res.status(400).json(fail(message))
      return
    }

    const walletAddress = deriveWalletAddress({ provider: 'passkey-prf', prfOutputHex: prfHex })

    const credentialId = verification.registrationInfo.credential.id
    const publicKeyBase64 = Buffer.from(verification.registrationInfo.credential.publicKey).toString('base64')
    const counter = verification.registrationInfo.credential.counter ?? 0
    const transports =
      parsed.data.attestation &&
      typeof parsed.data.attestation === 'object' &&
      Array.isArray((parsed.data.attestation as SimpleAttestationLike).response?.transports)
        ? ((parsed.data.attestation as SimpleAttestationLike).response!.transports as string[])
        : null

    try {
      await upsertIdentityPasskey({
        credentialId,
        walletAddress,
        publicKeyBase64,
        counter,
        transports,
        deviceLabel: parsed.data.deviceLabel ?? null,
      })
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Passkey credential conflict'
      res.status(409).json(fail(message))
      return
    }

    const ipHash = buildIpHash(req)
    const userAgent = readUserAgent(req)
    const session = await createSessionForIdentity(
      { provider: 'passkey-prf', prfOutputHex: prfHex },
      { ipHash, userAgent },
    )

    void recordAuditEvent({
      walletAddress: session.walletAddress,
      eventType: 'register.passkey',
      provider: 'passkey-prf',
      metadata: { isNew: session.isNew, credentialId },
      ipHash,
      userAgent,
    })

    res.json(ok({ ...session, credentialId }))
  } catch (err) {
    const sanitized = sanitizeError('passkey.register.verify', err, {
      fallbackMessage: 'Registration failed',
    })
    res.status(500).json(fail(sanitized.message, sanitized.traceId))
  }
}

// ── Authentication ───────────────────────────────────────────────

export async function handlePasskeyAuthenticateOptions(req: Request, res: Response): Promise<void> {
  const parsed = authenticateOptionsSchema.safeParse(req.body ?? {})
  if (!parsed.success) {
    res.status(400).json(fail('Invalid passkey authenticate options payload'))
    return
  }
  try {
    const { rpId } = getRpConfig()
    type AllowCredential = { id: string; type: 'public-key'; transports?: AuthenticatorTransport[] }
    const allowCredentials: AllowCredential[] = []
    if (parsed.data.walletAddress) {
      const list = await listIdentityPasskeysByWallet(parsed.data.walletAddress)
      for (const passkey of list) {
        const item: AllowCredential = { id: passkey.credentialId, type: 'public-key' }
        if (passkey.transports) {
          item.transports = passkey.transports as AuthenticatorTransport[]
        }
        allowCredentials.push(item)
      }
    }
    const options = await generateAuthenticationOptions({
      rpID: rpId,
      userVerification: 'preferred',
      ...(allowCredentials.length > 0 ? { allowCredentials } : {}),
      extensions: buildPrfAuthenticationExtension() as unknown as never,
    })
    await createPasskeyChallenge({
      challenge: options.challenge,
      type: 'authentication',
      ttlMs: CHALLENGE_TTL_MS,
      targetWalletAddress: parsed.data.walletAddress ?? null,
    })
    res.json(ok(options))
  } catch (err) {
    const sanitized = sanitizeError('passkey.authenticate.options', err, {
      fallbackMessage: 'Failed to generate authentication options',
    })
    res.status(500).json(fail(sanitized.message, sanitized.traceId))
  }
}

interface SimpleAssertionLike {
  id?: string
  rawId?: string
  response?: { clientDataJSON?: string }
  clientExtensionResults?: unknown
}

export async function handlePasskeyAuthenticateVerify(req: Request, res: Response): Promise<void> {
  const parsed = authenticateVerifySchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json(fail('Invalid passkey authenticate verify payload'))
    return
  }
  try {
    const { rpId, origins } = getRpConfig()

    const assertion = parsed.data.assertion as SimpleAssertionLike
    const credentialId =
      typeof assertion?.id === 'string' && assertion.id.length > 0
        ? assertion.id
        : typeof assertion?.rawId === 'string' && assertion.rawId.length > 0
          ? assertion.rawId
          : null
    if (!credentialId) {
      res.status(400).json(fail('Assertion is missing credential id'))
      return
    }

    const passkey = await getIdentityPasskeyByCredentialId(credentialId)
    if (!passkey) {
      res.status(401).json(fail('Unknown passkey credential'))
      return
    }

    const challenge = readChallengeFromAttestation(parsed.data.assertion)
    if (!challenge) {
      res.status(400).json(fail('Assertion is missing or malformed'))
      return
    }
    const challengeRecord = await consumePasskeyChallenge(challenge, 'authentication')
    if (!challengeRecord) {
      res.status(400).json(fail('Authentication challenge is invalid or expired'))
      return
    }

    const verification = await verifyAuthenticationResponse({
      response: parsed.data.assertion as Parameters<typeof verifyAuthenticationResponse>[0]['response'],
      expectedChallenge: challengeRecord.challenge,
      expectedOrigin: origins,
      expectedRPID: rpId,
      credential: {
        id: passkey.credentialId,
        publicKey: new Uint8Array(Buffer.from(passkey.publicKeyBase64, 'base64')),
        counter: passkey.counter,
      },
      requireUserVerification: false,
    })

    if (!verification.verified) {
      res.status(401).json(fail('Authentication verification failed'))
      return
    }

    const clientExt = (parsed.data.clientExtensionResults
      ?? (parsed.data.assertion as SimpleAssertionLike)?.clientExtensionResults) as unknown
    let prfHex: string
    try {
      prfHex = extractPrfFromClientExtensionResults(clientExt)
    } catch (err) {
      const message =
        err instanceof PrfNotSupportedError
          ? err.message
          : 'PRF output could not be read from this device'
      res.status(400).json(fail(message))
      return
    }

    const derivedWallet = deriveWalletAddress({ provider: 'passkey-prf', prfOutputHex: prfHex })
    if (derivedWallet !== passkey.walletAddress) {
      res.status(401).json(fail('Passkey PRF derivation does not match registered wallet'))
      return
    }

    const advance = await advanceIdentityPasskeyCounter(
      passkey.credentialId,
      verification.authenticationInfo.newCounter ?? 0,
    )
    if (!advance.accepted) {
      res.status(401).json(fail('Passkey counter regression detected — possible cloned authenticator'))
      return
    }

    const ipHash = buildIpHash(req)
    const userAgent = readUserAgent(req)
    const session = await createSessionForIdentity(
      { provider: 'passkey-prf', prfOutputHex: prfHex },
      { ipHash, userAgent },
    )
    void recordAuditEvent({
      walletAddress: session.walletAddress,
      eventType: 'login.passkey',
      provider: 'passkey-prf',
      metadata: { credentialId: passkey.credentialId },
      ipHash,
      userAgent,
    })
    res.json(ok(session))
  } catch (err) {
    const sanitized = sanitizeError('passkey.authenticate.verify', err, {
      fallbackMessage: 'Authentication failed',
    })
    res.status(500).json(fail(sanitized.message, sanitized.traceId))
  }
}
