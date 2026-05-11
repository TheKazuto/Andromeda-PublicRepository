// A2 keystore — passphrase-wrapped storage of the per-dWallet Ed25519 "signer"
// key (the key whose pubkey is the dWallet owner / `intended_chain_sender`).
//
// Andromeda generates the key, wraps the 32-byte private seed under a key
// derived from the user's passphrase (Argon2id → AES-256-GCM), and persists
// ONLY the ciphertext (table `mcp_wallet_keys`). The passphrase and the
// plaintext seed are never written to disk; the seed lives only on the
// request handler's stack and should be `wipe()`d after use.
//
// Decision B (locked): no Vault double-wrap — the at-rest ciphertext is
// protected by the passphrase only. Argon2id (memory-hard) makes a bare
// DB-dump brute-force expensive. Acceptable for pre-alpha / devnet / no real
// value; revisit before mainnet. Min passphrase length: 12.
//
// Lost passphrase != lost wallet: the dWallet's on-chain `rules-policy`
// recovers it (primary owner / quorum). Surface that in the API error text.

import { randomBytes, randomUUID, createCipheriv, createDecipheriv } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { argon2id } from '@noble/hashes/argon2.js'
import { query } from '../../store/pool.js'

const MIN_PASSPHRASE_LEN = 12

// Argon2id parameters. Server-side, so memory-hard rather than time-heavy:
// m = 64 MiB, t = 3, p = 1, 32-byte output (an AES-256 key). Stored per-record
// in `kdf_params` so these can change without re-wrapping existing records.
const KDF = { alg: 'argon2id' as const, t: 3, m: 65_536, p: 1, dkLen: 32 }

export class WeakPassphraseError extends Error {
  constructor() {
    super(`passphrase must be at least ${MIN_PASSPHRASE_LEN} characters`)
    this.name = 'WeakPassphraseError'
  }
}
export class WrongPassphraseError extends Error {
  constructor() {
    super('wrong passphrase — if you lost it, recover this dWallet via its on-chain rules-policy (primary owner / quorum), not via support')
    this.name = 'WrongPassphraseError'
  }
}
export class WalletKeyNotFoundError extends Error {
  constructor() {
    super('no wallet key for that dWallet under this owner')
    this.name = 'WalletKeyNotFoundError'
  }
}

export function assertPassphraseStrength(passphrase: unknown): asserts passphrase is string {
  if (typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE_LEN) throw new WeakPassphraseError()
}

function deriveWrapKey(passphrase: string, salt: Uint8Array, params: typeof KDF): Uint8Array {
  return argon2id(new TextEncoder().encode(passphrase), salt, {
    t: params.t,
    m: params.m,
    p: params.p,
    dkLen: params.dkLen,
  })
}

/** Best-effort zeroing — not a memory guarantee in a GC'd runtime, but better than nothing. */
export function wipe(buf: Uint8Array | undefined | null): void {
  if (buf) buf.fill(0)
}

export interface CreatedWalletKey {
  id: string
  /** 32-byte Ed25519 public key — the dWallet owner / `intended_chain_sender`. */
  signerPubkey: Uint8Array
  /**
   * PLAINTEXT 32-byte Ed25519 private seed. Use it once for the DKG request,
   * then `wipe()` it and drop the reference. NEVER logged, NEVER persisted.
   */
  signerSecret: Uint8Array
}

/**
 * Generate a fresh Ed25519 keypair, wrap the private seed under the passphrase,
 * insert the record (with `dwallet_address` NULL — call `finalizeWalletKey`
 * once DKG completes and the PDA is derived). Returns the id, the pubkey, and
 * the plaintext seed for the caller's one-time use.
 */
export async function createWrappedWalletKey(opts: {
  ownerRef: string
  passphrase: string
  curve: number
}): Promise<CreatedWalletKey> {
  assertPassphraseStrength(opts.passphrase)
  const secret = ed25519.utils.randomSecretKey() // 32 bytes
  const pubkey = ed25519.getPublicKey(secret) // 32 bytes
  const salt = randomBytes(16)
  const iv = randomBytes(12)
  const wrapKey = deriveWrapKey(opts.passphrase, salt, KDF)
  try {
    const cipher = createCipheriv('aes-256-gcm', Buffer.from(wrapKey), iv)
    const ct = Buffer.concat([cipher.update(Buffer.from(secret)), cipher.final()])
    const tag = cipher.getAuthTag()
    const id = randomUUID()
    await query(
      `INSERT INTO mcp_wallet_keys
         (id, owner_ref, curve, signer_pubkey, wrapped_key, wrap_iv, wrap_tag, kdf_salt, kdf_params)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [id, opts.ownerRef, opts.curve, Buffer.from(pubkey), ct, iv, tag, salt, JSON.stringify(KDF)],
    )
    return { id, signerPubkey: pubkey, signerSecret: secret }
  } finally {
    wipe(wrapKey)
  }
}

/** Record the dWallet address, public key, and network attestation once DKG has completed. */
export async function finalizeWalletKey(opts: {
  id: string
  dwalletAddress: string
  dwalletPublicKey: Uint8Array
  attestationData: Uint8Array
  networkSignature: Uint8Array
  networkPubkey: Uint8Array
}): Promise<void> {
  await query(
    `UPDATE mcp_wallet_keys
        SET dwallet_address = $2,
            dwallet_public_key = $3,
            attestation_data = $4,
            network_signature = $5,
            network_pubkey = $6,
            updated_at = NOW()
      WHERE id = $1`,
    [
      opts.id,
      opts.dwalletAddress,
      Buffer.from(opts.dwalletPublicKey),
      Buffer.from(opts.attestationData),
      Buffer.from(opts.networkSignature),
      Buffer.from(opts.networkPubkey),
    ],
  )
}

/**
 * The `rules-policy` a dWallet's authority was delegated to (auto-attached at
 * `create_dwallet` time, or `null` for a bare dWallet). The keystore key is the
 * policy's `init_authority`; its primary owner is described by `primary*`.
 */
export interface WalletKeyPolicyRef {
  /** The `rules_policy` account address (Audit C2 PDA). */
  address: string
  /** 32-byte sha256 of the 34-byte init_authority slot — re-derives the policy PDA. */
  initAuthorityHash: Uint8Array
  /** 0=Ed25519, 1=Secp256k1, 2=Secp256r1, 3=WebAuthn. */
  primaryScheme: number
  /** Primary owner identifier bytes (Ed25519 = 32-byte pubkey). */
  primaryIdentifier: Uint8Array
}

/**
 * Record the auto-attached rules-policy for a dWallet (called after
 * `deployRulesPolicy` + `transfer_ownership` succeed in `createDwallet`).
 */
export async function setWalletKeyPolicy(opts: {
  id: string
  policyAddress: string
  initAuthorityHash: Uint8Array
  primaryScheme: number
  primaryIdentifier: Uint8Array
}): Promise<void> {
  await query(
    `UPDATE mcp_wallet_keys
        SET policy_address = $2,
            policy_init_authority_hash = $3,
            policy_primary_scheme = $4,
            policy_primary_identifier = $5,
            updated_at = NOW()
      WHERE id = $1`,
    [
      opts.id,
      opts.policyAddress,
      Buffer.from(opts.initAuthorityHash),
      opts.primaryScheme,
      Buffer.from(opts.primaryIdentifier),
    ],
  )
}

export interface WalletKeyMeta {
  id: string
  curve: number
  /** 32-byte Ed25519 pubkey = dWallet owner / `intended_chain_sender`. */
  signerPubkey: Uint8Array
  /** The DKG-produced dWallet public key (≠ signerPubkey). */
  dwalletPublicKey: Uint8Array
  attestationData: Uint8Array
  networkSignature: Uint8Array
  networkPubkey: Uint8Array
  /** The auto-attached rules-policy, or `null` if the dWallet is still bare. */
  policy: WalletKeyPolicyRef | null
}

export interface UnwrappedWalletKey extends WalletKeyMeta {
  /** PLAINTEXT 32-byte Ed25519 private seed. Use, then `wipe()`. */
  signerSecret: Uint8Array
}

interface WalletKeyRow {
  id: string
  curve: number
  signer_pubkey: Buffer
  dwallet_public_key: Buffer | null
  wrapped_key: Buffer
  wrap_iv: Buffer
  wrap_tag: Buffer
  kdf_salt: Buffer
  kdf_params: { t: number; m: number; p: number; dkLen: number }
  attestation_data: Buffer | null
  network_signature: Buffer | null
  network_pubkey: Buffer | null
  policy_address: string | null
  policy_init_authority_hash: Buffer | null
  policy_primary_scheme: number | null
  policy_primary_identifier: Buffer | null
}

class WalletKeyNotFinalizedError extends Error {
  constructor() {
    super('wallet key record is not finalized (DKG did not complete) — cannot sign or presign yet')
    this.name = 'WalletKeyNotFinalizedError'
  }
}

function rowPolicy(row: WalletKeyRow): WalletKeyPolicyRef | null {
  if (
    !row.policy_address ||
    !row.policy_init_authority_hash ||
    row.policy_primary_scheme === null ||
    row.policy_primary_scheme === undefined ||
    !row.policy_primary_identifier
  ) {
    return null
  }
  return {
    address: row.policy_address,
    initAuthorityHash: new Uint8Array(row.policy_init_authority_hash),
    primaryScheme: row.policy_primary_scheme,
    primaryIdentifier: new Uint8Array(row.policy_primary_identifier),
  }
}

function rowMeta(row: WalletKeyRow): WalletKeyMeta {
  if (!row.dwallet_public_key || !row.attestation_data || !row.network_signature || !row.network_pubkey) {
    throw new WalletKeyNotFinalizedError()
  }
  return {
    id: row.id,
    curve: row.curve,
    signerPubkey: new Uint8Array(row.signer_pubkey),
    dwalletPublicKey: new Uint8Array(row.dwallet_public_key),
    attestationData: new Uint8Array(row.attestation_data),
    networkSignature: new Uint8Array(row.network_signature),
    networkPubkey: new Uint8Array(row.network_pubkey),
    policy: rowPolicy(row),
  }
}

const SELECT_COLS =
  'id, curve, signer_pubkey, dwallet_public_key, wrapped_key, wrap_iv, wrap_tag, kdf_salt, kdf_params, ' +
  'attestation_data, network_signature, network_pubkey, ' +
  'policy_address, policy_init_authority_hash, policy_primary_scheme, policy_primary_identifier'

/** Read a wallet key's metadata WITHOUT decrypting — no passphrase needed (used for presign allocation). */
export async function getWalletKeyMeta(opts: { ownerRef: string; dwalletAddress: string }): Promise<WalletKeyMeta> {
  const { rows } = await query<WalletKeyRow>(
    `SELECT ${SELECT_COLS} FROM mcp_wallet_keys WHERE owner_ref = $1 AND dwallet_address = $2`,
    [opts.ownerRef, opts.dwalletAddress],
  )
  const row = rows[0]
  if (!row) throw new WalletKeyNotFoundError()
  return rowMeta(row)
}

/**
 * Load the record for `(ownerRef, dwalletAddress)`, derive the wrap key from
 * the passphrase, and decrypt. A GCM auth-tag mismatch (wrong passphrase) is
 * surfaced as `WrongPassphraseError`. The returned `signerSecret` must be
 * `wipe()`d by the caller after use.
 */
export async function unwrapWalletKey(opts: {
  ownerRef: string
  dwalletAddress: string
  passphrase: string
}): Promise<UnwrappedWalletKey> {
  const { rows } = await query<WalletKeyRow>(
    `SELECT ${SELECT_COLS} FROM mcp_wallet_keys WHERE owner_ref = $1 AND dwallet_address = $2`,
    [opts.ownerRef, opts.dwalletAddress],
  )
  const row = rows[0]
  if (!row) throw new WalletKeyNotFoundError()
  const meta = rowMeta(row) // throws WalletKeyNotFinalizedError if DKG didn't complete

  const params = { alg: 'argon2id' as const, t: row.kdf_params.t, m: row.kdf_params.m, p: row.kdf_params.p, dkLen: row.kdf_params.dkLen }
  const wrapKey = deriveWrapKey(opts.passphrase, new Uint8Array(row.kdf_salt), params)
  try {
    const decipher = createDecipheriv('aes-256-gcm', Buffer.from(wrapKey), new Uint8Array(row.wrap_iv))
    decipher.setAuthTag(new Uint8Array(row.wrap_tag))
    let secret: Buffer
    try {
      secret = Buffer.concat([decipher.update(new Uint8Array(row.wrapped_key)), decipher.final()])
    } catch {
      throw new WrongPassphraseError()
    }
    return { ...meta, signerSecret: new Uint8Array(secret) }
  } finally {
    wipe(wrapKey)
  }
}

/** Sign an arbitrary message with a dWallet's signer key (for `transfer_ownership` etc.). */
export function ed25519Sign(message: Uint8Array, signerSecret: Uint8Array): Uint8Array {
  return ed25519.sign(message, signerSecret)
}
