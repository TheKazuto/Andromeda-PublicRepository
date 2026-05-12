// Account linking — passkey (WebAuthn + PRF) handlers.

import { randomBytes } from 'node:crypto'
import { generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server'
import type { Request, Response } from 'express'
import { z } from 'zod'
import { fail, ok } from '../../types.js'
import { sanitizeError } from '../../safeError.js'
import { recordAuditEvent } from '../audit.js'
import { getIdentityConfig } from '../config.js'
import { deriveWalletAddress } from '../derive.js'
import {
  extractPrfFromClientExtensionResults,
  getPrfSaltBytes,
  PrfNotSupportedError,
} from '../passkey/prf.js'
import { consumePasskeyChallenge, createPasskeyChallenge, upsertIdentityPasskey } from '../passkey/store.js'
import { LinkConflictError } from './conflict.js'
import {
  buildIpHash,
  buildLinkResponse,
  persistLinkOrConflict,
  readUserAgent,
  requireAuthedWallet,
} from './common.js'

const PASSKEY_LINK_CHALLENGE_TTL_MS = 5 * 60 * 1000

const passkeyLinkOptionsSchema = z.object({
  displayName: z.string().min(1).max(120).optional(),
})

const passkeyLinkVerifySchema = z.object({
  attestation: z.unknown(),
  clientExtensionResults: z.unknown().optional(),
  deviceLabel: z.string().min(1).max(120).optional(),
})

interface AttestationLike {
  response?: { clientDataJSON?: string; transports?: string[] }
  clientExtensionResults?: unknown
}

function readChallengeFromAttestation(attestation: unknown): string | null {
  const att = attestation as AttestationLike
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

export async function handleLinkPasskeyRegisterOptions(req: Request, res: Response): Promise<void> {
  const wallet = requireAuthedWallet(req, res)
  if (!wallet) return
  const parsed = passkeyLinkOptionsSchema.safeParse(req.body ?? {})
  if (!parsed.success) {
    res.status(400).json(fail('Invalid passkey link options payload'))
    return
  }
  try {
    const config = getIdentityConfig()
    if (!config.passkey.rpId || config.passkey.origins.length === 0) {
      res.status(400).json(fail('Passkey identity is not configured'))
      return
    }
    const userHandle = randomBytes(16).toString('base64url')
    const options = await generateRegistrationOptions({
      rpID: config.passkey.rpId,
      rpName: config.passkey.rpName ?? 'Andromeda',
      userID: Buffer.from(userHandle, 'utf8'),
      userName: parsed.data.displayName ?? userHandle,
      userDisplayName: parsed.data.displayName ?? 'Andromeda user',
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      extensions: { prf: { eval: { first: getPrfSaltBytes() } } } as unknown as never,
    })
    await createPasskeyChallenge({
      challenge: options.challenge,
      type: 'registration',
      ttlMs: PASSKEY_LINK_CHALLENGE_TTL_MS,
      userHandle,
      targetWalletAddress: wallet,
      metadata: { intent: 'link', displayName: parsed.data.displayName ?? null },
    })
    res.json(ok(options))
  } catch (err) {
    const sanitized = sanitizeError('linking.passkey.options', err, {
      fallbackMessage: 'Failed to generate passkey registration options',
    })
    res.status(500).json(fail(sanitized.message, sanitized.traceId))
  }
}

export async function handleLinkPasskeyRegisterVerify(req: Request, res: Response): Promise<void> {
  const wallet = requireAuthedWallet(req, res)
  if (!wallet) return
  const parsed = passkeyLinkVerifySchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json(fail('Invalid passkey link verify payload'))
    return
  }
  try {
    const config = getIdentityConfig()
    if (!config.passkey.rpId || config.passkey.origins.length === 0) {
      res.status(400).json(fail('Passkey identity is not configured'))
      return
    }
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
    if (challengeRecord.targetWalletAddress !== wallet) {
      res.status(400).json(fail('Challenge was not issued for this wallet'))
      return
    }
    const verification = await verifyRegistrationResponse({
      response: parsed.data.attestation as Parameters<typeof verifyRegistrationResponse>[0]['response'],
      expectedChallenge: challengeRecord.challenge,
      expectedOrigin: config.passkey.origins,
      expectedRPID: config.passkey.rpId,
      requireUserVerification: false,
    })
    if (!verification.verified || !verification.registrationInfo) {
      res.status(400).json(fail('Registration verification failed'))
      return
    }

    const clientExt = (parsed.data.clientExtensionResults
      ?? (parsed.data.attestation as AttestationLike)?.clientExtensionResults) as unknown
    let prfHex: string
    try {
      prfHex = extractPrfFromClientExtensionResults(clientExt)
    } catch (err) {
      const message =
        err instanceof PrfNotSupportedError ? err.message : 'PRF output could not be read from this device'
      res.status(400).json(fail(message))
      return
    }

    const passkeyDerivedWallet = deriveWalletAddress({ provider: 'passkey-prf', prfOutputHex: prfHex })
    const credentialId = verification.registrationInfo.credential.id
    const publicKeyBase64 = Buffer.from(verification.registrationInfo.credential.publicKey).toString('base64')
    const counter = verification.registrationInfo.credential.counter ?? 0
    const transports =
      parsed.data.attestation &&
      typeof parsed.data.attestation === 'object' &&
      Array.isArray((parsed.data.attestation as AttestationLike).response?.transports)
        ? ((parsed.data.attestation as AttestationLike).response!.transports as string[])
        : null

    try {
      await upsertIdentityPasskey({
        credentialId,
        walletAddress: passkeyDerivedWallet,
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

    const { alreadyLinked } = await persistLinkOrConflict({
      provider: 'passkey-prf',
      subject: prfHex,
      primaryWalletAddress: wallet,
    })
    void recordAuditEvent({
      walletAddress: wallet,
      eventType: 'link.passkey',
      provider: 'passkey-prf',
      metadata: { alreadyLinked, credentialId },
      ipHash: buildIpHash(req),
      userAgent: readUserAgent(req),
    })
    res.json(
      ok({
        ...buildLinkResponse({
          walletAddress: wallet,
          aliasProvider: 'passkey-prf',
          aliasSubject: prfHex,
          alreadyLinked,
        }),
        credentialId,
      }),
    )
  } catch (err) {
    if (err instanceof LinkConflictError) {
      res.status(409).json(fail(err.message))
      return
    }
    const sanitized = sanitizeError('linking.passkey.verify', err, {
      fallbackMessage: 'Passkey link failed',
    })
    res.status(500).json(fail(sanitized.message, sanitized.traceId))
  }
}
