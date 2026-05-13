// Orchestration for the MCP-facing dWallet operations (option A2):
//   createDwallet            — generate + wrap the signer key, run DKG, derive
//                              the on-chain dWallet PDA, persist; optionally
//                              deploy a rules-policy + transfer_ownership so the
//                              dWallet is born signable + recoverable.
//   transferDwalletOwnership — delegate a dWallet's authority to a new authority
//                              (e.g. a rules-policy CPI PDA), signed by the
//                              passphrase-wrapped keystore key.
//   approveAsOwner           — for a policy-delegated MCP dWallet, the keystore
//                              key (= the policy's primary owner) authorises a
//                              message: drive `recover_as_primary` on-chain and
//                              return the approval tx + slot for the Ika Sign.
//   allocatePresign          — allocate a single-use presign for a dWallet.
//   signMessage              — unwrap the signer key, run the gRPC Sign for an
//                              already on-chain MessageApproval, return the sig.
//
// Wired by POST /v1/dwallet/{create,transfer-ownership,approve,sign,presign} on
// the engine, which the gateway proxies → these surface as the MCP tools.
//
// PRE-ALPHA NOTES
// - The MPC fields and the gRPC user-signature are zero stubs (see request.ts);
//   the keystore key is generated and stored anyway so the same key is used
//   for real at Alpha and for `transfer_ownership` / `recover_as_primary`.
// - No GasDeposit funding step (mock signer, no gas economy in pre-alpha).
// - dWallets created here are wiped at Alpha 1. The API surface says so.

import {
  address as toAddress,
  getAddressEncoder,
  createKeyPairSignerFromBytes,
  type Address,
  type TransactionSigner,
} from '@solana/kit'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { logger } from '../../logger.js'
import { getSolanaRpc } from '../solana-rpc.js'
import { signAndSendInstructions } from '../gas-sponsor.js'
import {
  createWrappedWalletKey,
  finalizeWalletKey,
  setWalletKeyPolicy,
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
  deriveDwalletAddress,
  Curve,
  type CurveName,
} from './request.js'
import { rulesPolicyInitChallenge } from '../../recovery/challenge.js'
import { getPolicyAdapter } from '../../recovery/adapters/SolanaAdapter.js'
import { findCpiAuthorityPda } from '../../clients/rulesPolicy/pda.js'
import { buildTransferOwnershipInstruction } from '../../clients/ika/transferOwnership.js'

const addressEncoder = getAddressEncoder()
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
  /** True once the NOA's `commit_dwallet` has landed and the PDA exists. */
  committed: boolean
  /** The auto-attached rules-policy address, if `attachRecoveryPolicy` succeeded. */
  policyAddress?: string
  /**
   * Base64 of the 32-byte `init_authority_hash` for the auto-attached policy
   * (sha256 of the 34-byte init_authority slot). Needed by every later
   * `/v1/recovery/policy/admin/*` and `/v1/recovery/primary/*` call to address
   * the policy PDA. Present only when `attachRecoveryPolicy` succeeded.
   */
  initAuthorityHashBase64?: string
  /** True once the dWallet's authority is a policy program (signable via `recover_as_primary`). */
  signable: boolean
  /** True once a rules-policy holds the dWallet (recoverable by primary owner / quorum). */
  recoverable: boolean
  /** Non-fatal: set when `attachRecoveryPolicy` was requested but did not fully complete. */
  policyAttachWarning?: string
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
  /**
   * When set, after the dWallet is committed Andromeda deploys a `rules-policy`
   * for it (the keystore key = `init_authority`; the primary owner is
   * `primaryRecoveryOwner` or, if omitted, the keystore key itself) and
   * `transfer_ownership`s the dWallet to that policy program's CPI authority
   * PDA. Pass this only when the recovery policy layer is enabled.
   * `cooldownSeconds` must be ≥ the program's MIN_COOLDOWN_SECONDS.
   */
  recoveryPolicy?: { programId: string; cooldownSeconds: number }
  /** Optional external primary owner for the auto-attached policy. Default: the keystore key. */
  primaryRecoveryOwner?: MemberSlotInput
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
      committed,
      signable: false,
      recoverable: false,
      disclaimer: PREALPHA_DISCLAIMER,
    }

    // 6. (Optional) attach a rules-policy: deploy it, then transfer_ownership.
    if (opts.recoveryPolicy) {
      if (!committed) {
        result.policyAttachWarning =
          'dWallet not yet committed on-chain — recovery policy not attached; once it lands, deploy one via /v1/recovery/policy/deploy then delegate via /v1/dwallet/transfer-ownership'
      } else {
        try {
          await attachRecoveryPolicy({
            created,
            dwalletAddress,
            ikaProgramId,
            policyProgramId: toAddress(opts.recoveryPolicy.programId),
            cooldownSeconds: opts.recoveryPolicy.cooldownSeconds,
            ...(opts.primaryRecoveryOwner ? { primaryRecoveryOwner: opts.primaryRecoveryOwner } : {}),
            result,
          })
        } catch (err) {
          logger.error({ err, dwalletAddress: String(dwalletAddress) }, 'attachRecoveryPolicy failed (the dWallet itself was created)')
          if (!result.policyAttachWarning) {
            result.policyAttachWarning = result.policyAddress
              ? 'recovery policy deployed but transfer_ownership did not complete — call /v1/dwallet/transfer-ownership to finish; the dWallet is recoverable but not yet signable'
              : 'recovery policy could not be deployed — the dWallet is bare; retry the attach'
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
 * Deploy a rules-policy for a freshly committed dWallet (keystore key =
 * `init_authority`; primary = `primaryRecoveryOwner` or the keystore key), then
 * `transfer_ownership` the dWallet to that policy program's CPI authority PDA,
 * then persist the policy ref. Mutates `result`. Throws on failure (the caller
 * records a non-fatal warning — the dWallet itself already exists).
 */
async function attachRecoveryPolicy(args: {
  created: { id: string; signerPubkey: Uint8Array; signerSecret: Uint8Array }
  dwalletAddress: Address
  ikaProgramId: Address
  policyProgramId: Address
  cooldownSeconds: number
  primaryRecoveryOwner?: MemberSlotInput
  result: CreateDwalletResult
}): Promise<void> {
  const { created, dwalletAddress, ikaProgramId, result } = args
  const primary: MemberSlotInput = args.primaryRecoveryOwner ?? { scheme: SCHEME_ED25519, identifier: created.signerPubkey }
  const primarySlot = canonicalSlot(primary)
  const initAuthSlot = canonicalSlot({ scheme: SCHEME_ED25519, identifier: created.signerPubkey })
  const cooldown = BigInt(args.cooldownSeconds)

  // Sign the canonical init challenge with the keystore key (the init_authority).
  const challenge = rulesPolicyInitChallenge({
    dwallet: Uint8Array.from(addressEncoder.encode(dwalletAddress)),
    initAuthoritySlot: initAuthSlot,
    primarySlot,
    quorumThreshold: 1,
    dailyLimitSome: false,
    dailyLimit: 0n,
    cooldownSeconds: cooldown,
    allowedDestinationsSome: false,
  })
  const initAuthSig = ed25519Sign(challenge, created.signerSecret)

  const adapter = getPolicyAdapter()
  const deployed = await adapter.deployRulesPolicy({
    dwalletAddress,
    config: {
      primary: { scheme: primary.scheme, identifier: primary.identifier },
      members: [],
      quorumThreshold: 1,
      dailyLimit: null,
      allowedDestinations: null,
      cooldownSeconds: args.cooldownSeconds,
    },
    initAuthoritySlot: initAuthSlot,
    initAuthoritySignature: initAuthSig,
  })
  await setWalletKeyPolicy({
    id: created.id,
    policyAddress: String(deployed.policyAddress),
    initAuthorityHash: deployed.initAuthorityHash,
    primaryScheme: primary.scheme,
    primaryIdentifier: primary.identifier,
  })
  result.policyAddress = String(deployed.policyAddress)
  result.initAuthorityHashBase64 = Buffer.from(deployed.initAuthorityHash).toString('base64')
  result.recoverable = true

  // transfer_ownership: dwallet.authority = PDA(["__ika_cpi_authority"], policyProgramId)
  const newAuthority = (await findCpiAuthorityPda(args.policyProgramId)).address
  const authoritySigner = await signerFromKeystoreKey(created.signerSecret, created.signerPubkey)
  const transferIx = buildTransferOwnershipInstruction({ ikaProgramId, dwallet: dwalletAddress, authoritySigner, newAuthority })
  await signAndSendInstructions([transferIx], 'ika.transfer-ownership', {
    dwalletAddress: String(dwalletAddress),
    policyAddress: String(deployed.policyAddress),
  })
  result.signable = true
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

/** Raised when the dWallet has no rules-policy attached yet (→ 409). */
export class PolicyNotAttachedError extends Error {
  constructor() {
    super('this dWallet has no rules-policy attached — create it with attachRecoveryPolicy, or call /v1/dwallet/transfer-ownership after deploying one via /v1/recovery/policy/deploy')
    this.name = 'PolicyNotAttachedError'
  }
}
/** Raised when the policy's primary owner is an external wallet, not this keystore key (→ 409). */
export class PolicyPrimaryExternalError extends Error {
  constructor() {
    super("this dWallet's policy primary owner is an external wallet — approve the message via /v1/recovery/primary/{challenge,submit} with that wallet")
    this.name = 'PolicyPrimaryExternalError'
  }
}

export interface ApproveAsOwnerResult {
  /** base58 signature of the Solana tx that created the MessageApproval. */
  approvalTxSignature: string
  /** Slot of that tx — pass both to /v1/dwallet/sign as the approval proof. */
  approvalSlot: bigint
  messageApprovalAddress: string
}

/**
 * For a policy-delegated MCP dWallet whose primary owner is this keystore key:
 * authorise `message` for signing. Drives `recover_as_primary` on-chain (the
 * keystore key signs the canonical challenge; gas-sponsored), which mints the
 * `MessageApproval`. Returns the tx signature + slot so the caller can then
 * call /v1/dwallet/sign. `message` is RAW — the digest is `keccak256(message)`.
 */
export async function approveAsOwner(opts: {
  ownerRef: string
  dwalletAddress: string
  passphrase: string
  message: Uint8Array
  messageMetadata?: Uint8Array
  /** Signature scheme written into the MessageApproval (0..6). */
  signatureScheme: number
}): Promise<ApproveAsOwnerResult> {
  const meta = await getWalletKeyMeta({ ownerRef: opts.ownerRef, dwalletAddress: opts.dwalletAddress })
  if (!meta.policy) throw new PolicyNotAttachedError()
  if (meta.policy.primaryScheme !== SCHEME_ED25519) throw new PolicyPrimaryExternalError()
  if (Buffer.compare(Buffer.from(meta.policy.primaryIdentifier), Buffer.from(meta.signerPubkey)) !== 0) {
    throw new PolicyPrimaryExternalError()
  }

  const dwalletAddr = toAddress(opts.dwalletAddress)
  const messageDigest = keccak_256(opts.message)
  const metadataDigest =
    opts.messageMetadata && opts.messageMetadata.length > 0 ? keccak_256(opts.messageMetadata) : new Uint8Array(32)

  const adapter = getPolicyAdapter()
  const prep = await adapter.prepareRecoverAsPrimary({
    dwalletAddress: dwalletAddr,
    initAuthorityHash: meta.policy.initAuthorityHash,
    messageDigest,
    metadataDigest,
    userPubkey: meta.signerPubkey,
    signatureScheme: opts.signatureScheme,
  })

  const k = await unwrapWalletKey({ ownerRef: opts.ownerRef, dwalletAddress: opts.dwalletAddress, passphrase: opts.passphrase })
  let primarySignature: Uint8Array
  try {
    primarySignature = ed25519Sign(prep.challenge, k.signerSecret)
  } finally {
    wipe(k.signerSecret)
  }

  const sub = await adapter.submitRecoverAsPrimary({
    dwalletAddress: dwalletAddr,
    initAuthorityHash: meta.policy.initAuthorityHash,
    messageDigest,
    metadataDigest,
    userPubkey: meta.signerPubkey,
    signatureScheme: opts.signatureScheme,
    primarySignature,
    expectedNonce: prep.expectedNonce,
  })
  const slot = await getTxSlot(sub.txSignature)
  return { approvalTxSignature: sub.txSignature, approvalSlot: slot, messageApprovalAddress: String(sub.messageApprovalAddress) }
}

export interface AddRecoveryMemberResult {
  /** base58 signature of the Solana tx that ran the `add_member` admin action. */
  txSignature: string
  /** Base64 of the canonical 34-byte member slot that was added. */
  memberSlotBase64: string
}

/**
 * For a policy-delegated MCP dWallet whose primary owner is this keystore key:
 * add `member` (an external wallet — Ed25519 / Secp256k1 eth_address / Secp256r1
 * / WebAuthn) as a quorum recovery member. The keystore key (unwrapped with the
 * passphrase) signs the canonical `add_member` challenge; Andromeda submits and
 * pays gas. Returns the tx signature + the canonical member slot.
 *
 * This is the agent-friendly equivalent of the three-call sequence
 * `/v1/recovery/policy/admin/{challenge,submit}` — usable when the primary owner
 * IS the keystore key (so the policy challenge can be signed server-side from
 * the passphrase). If the primary owner is an external wallet, use the
 * `/v1/recovery/policy/admin/*` flow with that wallet instead.
 */
export async function addAsRecoveryMember(opts: {
  ownerRef: string
  dwalletAddress: string
  passphrase: string
  /** 0=Ed25519, 1=Secp256k1, 2=Secp256r1, 3=WebAuthn. */
  memberScheme: number
  /** Identifier bytes; length must match the scheme (32 / 20 / 33 / 33). */
  memberIdentifier: Uint8Array
}): Promise<AddRecoveryMemberResult> {
  const meta = await getWalletKeyMeta({ ownerRef: opts.ownerRef, dwalletAddress: opts.dwalletAddress })
  if (!meta.policy) throw new PolicyNotAttachedError()
  if (meta.policy.primaryScheme !== SCHEME_ED25519) throw new PolicyPrimaryExternalError()
  if (Buffer.compare(Buffer.from(meta.policy.primaryIdentifier), Buffer.from(meta.signerPubkey)) !== 0) {
    throw new PolicyPrimaryExternalError()
  }

  const member: MemberSlotInput = { scheme: opts.memberScheme, identifier: opts.memberIdentifier }
  // Validate the slot length up-front (canonicalSlot enforces the 33-byte cap;
  // this checks the exact per-scheme length the on-chain program expects).
  const expectedLen = opts.memberScheme === 0 ? 32 : opts.memberScheme === 1 ? 20 : 33
  if (member.identifier.length !== expectedLen) {
    const e = new Error(`member identifier length ${member.identifier.length} does not match scheme ${opts.memberScheme} (expected ${expectedLen})`)
    e.name = 'BadMemberSlotError'
    throw e
  }

  const dwalletAddr = toAddress(opts.dwalletAddress)
  const adapter = getPolicyAdapter()
  const prep = await adapter.prepareAdminAction({
    dwalletAddress: dwalletAddr,
    initAuthorityHash: meta.policy.initAuthorityHash,
    action: { type: 'add_member', member },
  })

  const k = await unwrapWalletKey({ ownerRef: opts.ownerRef, dwalletAddress: opts.dwalletAddress, passphrase: opts.passphrase })
  let primarySignature: Uint8Array
  try {
    primarySignature = ed25519Sign(prep.challenge, k.signerSecret)
  } finally {
    wipe(k.signerSecret)
  }

  const sub = await adapter.submitAdminAction({
    dwalletAddress: dwalletAddr,
    initAuthorityHash: meta.policy.initAuthorityHash,
    action: { type: 'add_member', member },
    primarySignature,
    expectedNonce: prep.expectedNonce,
  })
  return { txSignature: sub.txSignature, memberSlotBase64: Buffer.from(canonicalSlot(member)).toString('base64') }
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
  })
  return { presignSessionId }
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

async function getTxSlot(txSignature: string): Promise<bigint> {
  const rpc = getSolanaRpc()
  for (let i = 0; i < 6; i += 1) {
    const tx = await rpc
      .getTransaction(txSignature as Parameters<typeof rpc.getTransaction>[0], {
        commitment: 'confirmed',
        maxSupportedTransactionVersion: 0,
        encoding: 'base64',
      })
      .send()
    if (tx) return BigInt(tx.slot)
    await new Promise((r) => setTimeout(r, 500))
  }
  throw new Error(`could not read slot for approval tx ${txSignature}`)
}
