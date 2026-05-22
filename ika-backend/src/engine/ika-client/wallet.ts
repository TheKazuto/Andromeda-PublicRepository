// Orchestration for the MCP-facing dWallet operations (option A2):
//   createDwallet            — generate + wrap the signer key, run DKG, derive
//                              the on-chain dWallet PDA, persist; optionally
//                              deploy a PolicyEngine v3 + transfer_ownership so
//                              the dWallet is born recoverable.
//   transferDwalletOwnership — delegate a dWallet's authority to a new authority
//                              (e.g. the PolicyEngine v3 CPI PDA), signed by
//                              the passphrase-wrapped keystore key.
//   allocatePresign          — allocate a single-use presign for a dWallet.
//   signMessage              — unwrap the signer key, run the gRPC Sign for an
//                              already on-chain MessageApproval, return the sig.
//
// Wired by POST /v1/dwallet/{create,transfer-ownership,sign,presign} on the
// engine, which the gateway proxies → these surface as the MCP tools.
// Authorisation of individual messages (formerly `/v1/dwallet/approve`) is now
// done by the gateway PolicyEngine v3 surface at /v1/policy/recover-as-primary
// or /v1/policy/request-signature.
//
// PRE-ALPHA NOTES
// - The MPC fields and the gRPC user-signature are zero stubs (see request.ts);
//   the keystore key is generated and stored anyway so the same key is used
//   for real at Alpha and for `transfer_ownership`.
// - No GasDeposit funding step (mock signer, no gas economy in pre-alpha).
// - dWallets created here are wiped at Alpha 1. The API surface says so.

import {
  address as toAddress,
  createKeyPairSignerFromBytes,
  type Address,
  type TransactionSigner,
} from '@solana/kit'
import { logger } from '../../logger.js'
import { getSolanaRpc } from '../solana-rpc.js'
import { signAndSendInstructions, getGasSponsorAddress } from '../gas-sponsor.js'
import {
  createWrappedWalletKey,
  finalizeWalletKey,
  getWalletKeyMeta,
  unwrapWalletKey,
  ed25519Sign,
  wipe,
  assertPassphraseStrength,
} from './keystore.js'
import {
  requestDkg,
  requestPresign,
  requestSign,
  sessionIdentifierFromAttestation,
  deriveDwalletAddress,
  Curve,
  type CurveName,
} from './request.js'
import { deriveAccountsForCurve, type DerivedAccount } from '../../chain/index.js'
import { buildTransferOwnershipInstruction } from '../../clients/ika/transferOwnership.js'
import { buildInitEngineInstruction } from '../../clients/policyEngine/instructions.js'
import {
  policyEngineInitChallenge as policyEngineInitChallengeFn,
} from '../../clients/policyEngine/challenges.js'
import {
  enginePda as policyEnginePda,
  initAuthorityHashFromSlot as policyEngineInitAuthorityHashFromSlot,
  cpiAuthorityPda as policyEngineCpiAuthorityPda,
} from '../../clients/policyEngine/pda.js'
import { buildEd25519PrecompileInstruction } from '../precompiles.js'

const MEMBER_SLOT_LEN = 34
const SCHEME_ED25519 = 0

export const PREALPHA_DISCLAIMER =
  'pre-alpha / Solana devnet only — mock signer, no MPC guarantee yet; this dWallet will be wiped at Alpha 1; do not custody real value'

// Curve names supported on-chain (request.ts has the full set; these are the
// ones the create endpoint accepts as input). Default: Curve25519 (Solana).
const SUPPORTED_CREATE_CURVES = new Set<CurveName>(['Curve25519', 'Secp256k1', 'Secp256r1'])

export interface MemberSlotInput {
  /** 0=Ed25519, 1=Secp256k1, 2=Secp256r1, 3=WebAuthn. */
  scheme: number
  /** Identifier bytes (Ed25519 = 32-byte pubkey, Secp256k1 = 20-byte eth address, ...). */
  identifier: Uint8Array
}

/** Canonical 34-byte member slot: `[scheme, ...identifier, 0-pad]`. */
function canonicalSlot(slot: MemberSlotInput): Uint8Array {
  if (slot.identifier.length > MEMBER_SLOT_LEN - 1) {
    throw new Error(`member identifier too long: ${slot.identifier.length} bytes`)
  }
  const out = new Uint8Array(MEMBER_SLOT_LEN)
  out[0] = slot.scheme
  out.set(slot.identifier, 1)
  return out
}

/** Build a `@solana/kit` signer from a keystore record's 32-byte Ed25519 seed + 32-byte pubkey. */
async function signerFromKeystoreKey(seed: Uint8Array, pubkey: Uint8Array): Promise<TransactionSigner> {
  const kp = new Uint8Array(64)
  kp.set(seed, 0)
  kp.set(pubkey, 32)
  try {
    return await createKeyPairSignerFromBytes(kp)
  } finally {
    wipe(kp)
  }
}

export interface CreateDwalletResult {
  dwalletAddress: string
  curve: CurveName
  curveId: number
  /** 32-byte Ed25519 pubkey = the dWallet's on-chain owner / chain sender. */
  ownerPubkey: Uint8Array
  /**
   * The DKG-produced dWallet public key, on the dWallet's curve (secp256k1
   * compressed for EVM/BTC/etc, ed25519 for Solana/Sui). THIS is the key the
   * destination chain's address derives from — NOT `ownerPubkey` (always
   * Ed25519). See `deriveWalletAddresses` / `GET /v1/dwallet/addresses`.
   */
  dwalletPublicKey: Uint8Array
  /** True once the NOA's `commit_dwallet` has landed and the PDA exists. */
  committed: boolean
  /** True once the dWallet's authority is the PolicyEngine v3 CPI PDA. */
  signable: boolean
  /** True once a PolicyEngine v3 holds the dWallet (recoverable per the engine's rules). */
  recoverable: boolean

  /** PolicyEngine v3 PDA, set when `attachPolicyEngine` succeeded. */
  policyEngineAddress?: string
  /** Base64 of the 32-byte `init_authority_hash` for the auto-attached
   *  PolicyEngine. Required by every later /v1/policy/* admin call to
   *  re-derive the engine PDA. */
  policyEngineInitAuthorityHashBase64?: string
  /** Non-fatal: set when `attachPolicyEngine` was requested but did not
   *  fully complete. */
  policyEngineAttachWarning?: string

  disclaimer: string
}

/**
 * Create a dWallet for `ownerRef`, owned by a freshly generated Ed25519 key
 * that is wrapped under `passphrase`. The plaintext key is used for the DKG
 * (and, when `recoveryPolicy` is set, to sign the policy init challenge and the
 * `transfer_ownership` tx) and then wiped — Andromeda never persists it or the
 * passphrase.
 */
export async function createDwallet(opts: {
  ownerRef: string
  passphrase: string
  ikaProgramId: string
  curve?: CurveName
  /** Poll for the on-chain dWallet PDA after DKG. Default true. */
  waitForCommit?: boolean
  commitTimeoutMs?: number
  /** Optional external primary owner for the auto-attached PolicyEngine. Default: the keystore key. */
  primaryRecoveryOwner?: MemberSlotInput
  /**
   * When set, attach a PolicyEngine v3 to the new dWallet. Deploys an empty
   * engine (no rules yet) via `init_engine`, then `transfer_ownership`s the
   * dWallet to the engine's CPI authority PDA. Caller adds rules later via
   * `/v1/policy/rules/*`. Requires `IKA_POLICY_ENGINE_ENABLED=true` and
   * `ANDROMEDA_POLICY_ENGINE_PROGRAM_ID` at the gateway level.
   */
  policyEngine?: { programId: string }
}): Promise<CreateDwalletResult> {
  assertPassphraseStrength(opts.passphrase)
  const curve: CurveName = opts.curve ?? 'Curve25519'
  if (!SUPPORTED_CREATE_CURVES.has(curve)) {
    throw new Error(`unsupported curve for dWallet creation: ${curve}`)
  }
  const curveId = Curve[curve]
  const ikaProgramId = toAddress(opts.ikaProgramId)

  // 1. Generate + wrap the signer key. `signerSecret` is plaintext — used here, then wiped.
  const created = await createWrappedWalletKey({ ownerRef: opts.ownerRef, passphrase: opts.passphrase, curve: curveId })
  try {
    // 2. DKG via gRPC.
    const dkg = await requestDkg({ curve, senderPubkey: created.signerPubkey })

    // 3. Derive the on-chain dWallet PDA from (curve, public_key).
    const { address: dwalletAddress } = await deriveDwalletAddress(curveId, dkg.publicKey, ikaProgramId)

    // 4. Persist: the address, the dWallet public key, and the attestation.
    await finalizeWalletKey({
      id: created.id,
      dwalletAddress,
      dwalletPublicKey: dkg.publicKey,
      attestationData: dkg.attestationData,
      networkSignature: dkg.networkSignature,
      networkPubkey: dkg.networkPubkey,
    })

    // 5. (Optional) wait for the NOA's commit_dwallet to land the PDA on-chain.
    let committed = false
    if (opts.waitForCommit !== false) {
      committed = await waitForAccount(dwalletAddress, opts.commitTimeoutMs ?? 30_000)
      if (!committed) {
        logger.warn({ dwalletAddress }, 'dWallet PDA not yet on-chain after timeout — commit_dwallet may still be pending')
      }
    }

    const result: CreateDwalletResult = {
      dwalletAddress: String(dwalletAddress),
      curve,
      curveId,
      ownerPubkey: created.signerPubkey,
      dwalletPublicKey: dkg.publicKey,
      committed,
      signable: false,
      recoverable: false,
      disclaimer: PREALPHA_DISCLAIMER,
    }

    // 6. (Optional) attach a PolicyEngine v3 — empty engine + delegation.
    if (opts.policyEngine) {
      if (!committed) {
        result.policyEngineAttachWarning =
          'dWallet not yet committed on-chain — PolicyEngine not attached; once it lands, deploy via /v1/policy/init then delegate via /v1/dwallet/transfer-ownership'
      } else {
        try {
          await attachPolicyEngine({
            created,
            dwalletAddress,
            ikaProgramId,
            policyEngineProgramId: toAddress(opts.policyEngine.programId),
            ...(opts.primaryRecoveryOwner ? { ownerSlotInput: opts.primaryRecoveryOwner } : {}),
            result,
          })
        } catch (err) {
          logger.error(
            { err, dwalletAddress: String(dwalletAddress) },
            'attachPolicyEngine failed (the dWallet itself was created)',
          )
          if (!result.policyEngineAttachWarning) {
            result.policyEngineAttachWarning = result.policyEngineAddress
              ? 'PolicyEngine deployed but transfer_ownership did not complete — call /v1/dwallet/transfer-ownership to finish'
              : 'PolicyEngine could not be deployed — the dWallet is bare; retry the attach'
          }
        }
      }
    }

    return result
  } finally {
    wipe(created.signerSecret)
  }
}

/**
 * PolicyEngine v3 attach. Single-call:
 *   1. derive the deterministic engine PDA from `(dwallet, init_authority_hash)`,
 *   2. sign the canonical init challenge with the keystore key,
 *   3. submit `[Ed25519 precompile, init_engine, transfer_ownership]` in a
 *      single gas-sponsored transaction.
 *
 * After this lands, the dWallet's authority is the engine's CPI authority
 * PDA, so every future signing op flows through the PolicyEngine v3 rules.
 *
 * The keystore key signs both the init challenge AND the `transfer_ownership`
 * authority change. The owner slot defaults to the keystore key unless
 * `ownerSlotInput` is provided (e.g. an external wallet that will be the
 * engine's "owner" for admin actions).
 *
 * Mutates `result.policyEngineAddress` / `policyEngineInitAuthorityHashBase64`
 * / `signable` / `recoverable`. Throws on failure — the dWallet itself was
 * already created, so the caller surfaces a non-fatal warning.
 */
async function attachPolicyEngine(args: {
  created: { id: string; signerPubkey: Uint8Array; signerSecret: Uint8Array }
  dwalletAddress: Address
  ikaProgramId: Address
  policyEngineProgramId: Address
  ownerSlotInput?: MemberSlotInput
  result: CreateDwalletResult
}): Promise<void> {
  const { created, dwalletAddress, ikaProgramId, policyEngineProgramId, result } = args

  // 1. Canonical owner / init-authority slots. Both default to the keystore
  //    key — same pattern as legacy rules-policy attach. The init_authority
  //    must be the keystore key here so we can sign the init challenge
  //    in-process; the owner slot can be external (for admin actions later).
  const ownerSlotIn: MemberSlotInput =
    args.ownerSlotInput ?? { scheme: SCHEME_ED25519, identifier: created.signerPubkey }
  const ownerSlot = canonicalSlot(ownerSlotIn)
  const initAuthSlot = canonicalSlot({ scheme: SCHEME_ED25519, identifier: created.signerPubkey })
  const initAuthHash = policyEngineInitAuthorityHashFromSlot(initAuthSlot)

  // 2. Derive engine PDA + CPI authority PDA (target of transfer_ownership).
  const enginePdaResult = await policyEnginePda(policyEngineProgramId, dwalletAddress, initAuthHash)
  const cpiAuth = await policyEngineCpiAuthorityPda(policyEngineProgramId)

  // 3. Sign the canonical init challenge with the keystore key.
  const challenge = policyEngineInitChallengeFn({
    dwallet: dwalletAddress,
    initAuthoritySlot: initAuthSlot,
    ownerSlot,
    defaultRecoveryPresent: 0,
    defaultRecoveryHash: new Uint8Array(32),
  })
  const initAuthSig = ed25519Sign(challenge, created.signerSecret)

  // 4. Build the three instructions that go into the same tx:
  //    [precompile (validates initAuthSig) | init_engine | transfer_ownership]
  const sponsorAddress = getGasSponsorAddress()
  const initEngineIx = await buildInitEngineInstruction({
    programId: policyEngineProgramId,
    dwallet: dwalletAddress,
    engine: enginePdaResult.address,
    payer: sponsorAddress,
    initAuthoritySlot: initAuthSlot,
    initAuthorityHash: initAuthHash,
    ownerSlot,
    defaultRecoveryPresent: 0,
    defaultRecoveryHash: new Uint8Array(32),
  })
  const precompileIx = buildEd25519PrecompileInstruction({
    publicKey: created.signerPubkey,
    message: challenge,
    signature: initAuthSig,
  })
  const authoritySigner = await signerFromKeystoreKey(created.signerSecret, created.signerPubkey)
  const transferIx = buildTransferOwnershipInstruction({
    ikaProgramId,
    dwallet: dwalletAddress,
    authoritySigner,
    newAuthority: cpiAuth.address,
  })

  // 5. Send. Gas sponsor pays + signs as fee payer; the keystore key cosigns
  //    for the transfer_ownership instruction (authoritySigner above).
  const txSignature = await signAndSendInstructions(
    [precompileIx, initEngineIx, transferIx],
    'policy-engine.attach',
    { dwalletAddress: String(dwalletAddress), engineAddress: String(enginePdaResult.address) },
  )

  result.policyEngineAddress = String(enginePdaResult.address)
  result.policyEngineInitAuthorityHashBase64 = Buffer.from(initAuthHash).toString('base64')
  result.signable = true
  result.recoverable = true

  logger.info(
    { dwalletAddress: String(dwalletAddress), engineAddress: String(enginePdaResult.address), txSignature },
    'PolicyEngine v3 attached',
  )
}

export interface TransferDwalletOwnershipResult {
  txSignature: string
  /** The new authority the dWallet was delegated to (base58). */
  newAuthority: string
}

/**
 * Delegate a dWallet's authority to `newAuthority`. The dWallet's current
 * authority must be this keystore key — the passphrase unwraps it in memory to
 * sign the transaction. Use this to finish a delegation that `createDwallet`
 * couldn't, or to re-delegate. Gas-sponsored.
 */
export async function transferDwalletOwnership(opts: {
  ownerRef: string
  dwalletAddress: string
  passphrase: string
  ikaProgramId: string
  newAuthority: string
}): Promise<TransferDwalletOwnershipResult> {
  const k = await unwrapWalletKey({ ownerRef: opts.ownerRef, dwalletAddress: opts.dwalletAddress, passphrase: opts.passphrase })
  try {
    const authoritySigner = await signerFromKeystoreKey(k.signerSecret, k.signerPubkey)
    const ix = buildTransferOwnershipInstruction({
      ikaProgramId: toAddress(opts.ikaProgramId),
      dwallet: toAddress(opts.dwalletAddress),
      authoritySigner,
      newAuthority: toAddress(opts.newAuthority),
    })
    const txSignature = await signAndSendInstructions([ix], 'ika.transfer-ownership', { dwalletAddress: opts.dwalletAddress })
    return { txSignature, newAuthority: opts.newAuthority }
  } finally {
    wipe(k.signerSecret)
  }
}

/**
 * Allocate one single-use global presign for the dWallet's curve. No passphrase
 * needed — it only reads the record's metadata (curve + owner pubkey).
 */
export async function allocatePresign(opts: {
  ownerRef: string
  dwalletAddress: string
}): Promise<{ presignSessionId: Uint8Array }> {
  const meta = await getWalletKeyMeta(opts)
  const presignSessionId = await requestPresign({
    curve: curveNameFromId(meta.curve),
    senderPubkey: meta.signerPubkey,
    sessionIdentifier: sessionIdentifierFromAttestation(meta.attestationData),
  })
  return { presignSessionId }
}

export interface WalletAddressesResult {
  dwalletAddress: string
  curve: CurveName
  /** Hex of the curve-specific dWallet public key the addresses derive from. */
  dwalletPublicKeyHex: string
  /** Every chain-native address this dWallet's curve can hold. */
  addresses: DerivedAccount[]
}

/**
 * Read-only: derive every chain-native address for an MCP-created dWallet from
 * its stored `dwalletPublicKey` + curve. No passphrase, no gas, no signing —
 * only `getWalletKeyMeta` (which never decrypts). Resolves the §1.3 mismatch by
 * deriving from the curve-specific key, never the Ed25519 signer key.
 */
export async function deriveWalletAddresses(opts: {
  ownerRef: string
  dwalletAddress: string
}): Promise<WalletAddressesResult> {
  const meta = await getWalletKeyMeta(opts)
  const curve = curveNameFromId(meta.curve)
  return {
    dwalletAddress: opts.dwalletAddress,
    curve,
    dwalletPublicKeyHex: Buffer.from(meta.dwalletPublicKey).toString('hex'),
    addresses: deriveAccountsForCurve(meta.dwalletPublicKey, curve),
  }
}

export interface SignMessageResult {
  signatureBase64: string
  scheme: number
}

/**
 * Sign a message with an MCP-created dWallet. The caller must already have an
 * on-chain MessageApproval (`status=Pending`) for `(dwallet, keccak256(message),
 * keccak256(metadata) or 32×0)` and pass its `approvalTxSignature` + `slot` —
 * for a policy-delegated MCP dWallet, get those from `/v1/dwallet/approve`.
 * `message` is RAW — the network applies the hash from `scheme`.
 */
export async function signMessage(opts: {
  ownerRef: string
  dwalletAddress: string
  passphrase: string
  message: Uint8Array
  messageMetadata?: Uint8Array
  scheme: number
  presignSessionId: Uint8Array
  approvalTxSignature: Uint8Array
  approvalSlot: bigint
}): Promise<SignMessageResult> {
  const k = await unwrapWalletKey({ ownerRef: opts.ownerRef, dwalletAddress: opts.dwalletAddress, passphrase: opts.passphrase })
  try {
    const curve = curveNameFromId(k.curve)
    const signature = await requestSign({
      curve,
      senderPubkey: k.signerPubkey,
      message: opts.message,
      messageMetadata: opts.messageMetadata ?? new Uint8Array(0),
      presignSessionId: opts.presignSessionId,
      dwalletAttestationData: k.attestationData,
      dwalletNetworkSignature: k.networkSignature,
      dwalletNetworkPubkey: k.networkPubkey,
      approvalTxSignature: opts.approvalTxSignature,
      approvalSlot: opts.approvalSlot,
    })
    return { signatureBase64: Buffer.from(signature).toString('base64'), scheme: opts.scheme }
  } finally {
    wipe(k.signerSecret)
  }
}

// ── helpers ──────────────────────────────────────────────────────────────

const CURVE_NAME_BY_ID: Record<number, CurveName> = {
  0: 'Secp256k1',
  1: 'Secp256r1',
  2: 'Curve25519',
  3: 'Ristretto',
}
function curveNameFromId(id: number): CurveName {
  const name = CURVE_NAME_BY_ID[id]
  if (!name) throw new Error(`unknown curve id ${id}`)
  return name
}

async function waitForAccount(addr: Address, timeoutMs: number): Promise<boolean> {
  const rpc = getSolanaRpc()
  const deadline = Date.now() + timeoutMs
  for (;;) {
    try {
      const { value } = await rpc.getAccountInfo(addr, { encoding: 'base64' }).send()
      if (value) return true
    } catch (err) {
      logger.debug({ err, addr: String(addr) }, 'getAccountInfo while waiting for commit_dwallet')
    }
    if (Date.now() >= deadline) return false
    await new Promise((r) => setTimeout(r, 2_000))
  }
}

