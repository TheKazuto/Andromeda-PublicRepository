/**
 * Chain-agnostic adapter interface for the RulesPolicy program v2.
 *
 * All flows are *challenge-based* and *gas-sponsored*: the user signs a
 * canonical challenge off-chain with whatever wallet they have, and the
 * backend signs the Solana transaction itself (fee payer = gas sponsor).
 * The user's wallet never needs to be a Solana signer.
 *
 * Each `prepare*` returns the bytes the user must sign. Each `submit*`
 * accepts the resulting signature, builds a Solana transaction with the
 * proper precompile invocation, signs and sends it, and returns the
 * confirmed transaction signature.
 */

import type { Address } from '@solana/kit'

// ── Member slot ─────────────────────────────────────────────────

export interface MemberSlot {
  /** 0=Ed25519, 1=Secp256k1, 2=Secp256r1, 3=WebAuthn */
  scheme: number
  /**
   * Identifier bytes — length depends on scheme:
   *  - Ed25519: 32 (pubkey)
   *  - Secp256k1: 20 (eth_address)
   *  - Secp256r1: 33 (compressed pubkey)
   *  - WebAuthn: 33 (compressed P-256 pubkey)
   */
  identifier: Uint8Array
  /** Optional human-readable label kept off-chain for UX. */
  label?: string
}

// ── Policy config + state ───────────────────────────────────────

export interface PolicyConfig {
  primary: MemberSlot
  members: MemberSlot[]
  quorumThreshold: number
  dailyLimit: bigint | null
  /** 32-byte addresses or null for no whitelist. */
  allowedDestinations: Uint8Array[] | null
  cooldownSeconds: number
}

export interface PendingChange {
  kind: 'quorum_threshold' | 'daily_limit' | 'cooldown'
  newQuorumThreshold?: number
  newDailyLimit?: bigint | null
  newCooldownSeconds?: number
  activatesAt: Date
}

export interface PolicyState {
  policyAddress: Address
  dwalletAddress: Address
  primary: MemberSlot
  members: MemberSlot[]
  quorumThreshold: number
  dailyLimit: bigint | null
  allowedDestinations: Uint8Array[] | null
  cooldownSeconds: number
  pendingChange: PendingChange | null
  dailyUsed: bigint
  lastResetTs: Date
  nextAdminNonce: bigint
  nextPrimaryRecoverNonce: bigint
  nextSessionNonce: bigint
}

export interface QuorumSessionState {
  sessionAddress: Address
  dwalletAddress: Address
  policyAddress: Address
  sessionNonce: bigint
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  amount: bigint
  destination: Uint8Array
  membersSnapshot: MemberSlot[]
  thresholdRequired: number
  contributionsCount: number
  contributionsBitmap: number
  expiresAt: Date
  finalizedAt: Date | null
}

// ── Deploy ──────────────────────────────────────────────────────

export interface DeployInput {
  dwalletAddress: Address
  config: PolicyConfig
  /**
   * Audit C2 (Opção 4): the credential that signs the canonical init
   * challenge. The on-chain handler verifies a precompile invocation in
   * the same tx and binds `init_authority_hash = sha256(slot)` into the
   * policy PDA seed — squat-resistant.
   */
  initAuthoritySlot: Uint8Array
  /** Off-chain precompile signature over the canonical init challenge. */
  initAuthoritySignature: Uint8Array
  /** Required iff scheme is WebAuthn. */
  initAuthorityWebauthnAuthData?: Uint8Array
  /** Required iff scheme is WebAuthn. */
  initAuthorityWebauthnClientDataJson?: Uint8Array
}

export interface DeployResult {
  policyAddress: Address
  txSignature: string
  /** Audit C2: returned so the caller can store it for future operations. */
  initAuthorityHash: Uint8Array
}

// ── Audit C2 helper for non-init operations ─────────────────────

/**
 * Audit C2 (Opção 4): once a policy is deployed, every other operation
 * needs the `init_authority_hash` to derive the policy PDA. The caller
 * looks it up from its own database (keyed by dwallet or policy address).
 */
export interface InitAuthorityHashCarrier {
  initAuthorityHash: Uint8Array
}

// ── Primary recovery ────────────────────────────────────────────

export interface PrimaryChallengeInput extends InitAuthorityHashCarrier {
  dwalletAddress: Address
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
}

export interface PrimaryChallengeOutput {
  challenge: Uint8Array
  expectedNonce: bigint
  primaryScheme: number
}

export interface PrimarySubmitInput extends InitAuthorityHashCarrier {
  dwalletAddress: Address
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  /** Curve of the dWallet (passed to Ika `approve_message`). */
  signatureScheme: number
  /** Off-chain signature of `challenge` by the primary credential. */
  primarySignature: Uint8Array
  expectedNonce: bigint
}

export interface PrimarySubmitResult {
  txSignature: string
  messageApprovalAddress: Address
}

// ── Quorum staging ──────────────────────────────────────────────

export interface OpenSessionInput extends InitAuthorityHashCarrier {
  dwalletAddress: Address
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
  amount: bigint
  destination: Uint8Array
  expiresAt: Date
}

export interface OpenSessionChallenge {
  challenge: Uint8Array
  expectedSessionNonce: bigint
  primaryScheme: number
  sessionAddress: Address
}

export interface OpenSessionSubmitInput extends OpenSessionInput {
  primarySignature: Uint8Array
  expectedSessionNonce: bigint
}

export interface OpenSessionResult {
  sessionAddress: Address
  txSignature: string
}

export interface ContributeChallengeInput extends InitAuthorityHashCarrier {
  dwalletAddress: Address
  sessionAddress: Address
  memberIndex: number
}

export interface ContributeChallengeOutput {
  challenge: Uint8Array
  memberSlot: MemberSlot
}

export interface ContributeSubmitInput extends InitAuthorityHashCarrier {
  dwalletAddress: Address
  sessionAddress: Address
  memberIndex: number
  memberSignature: Uint8Array
  /** Required iff member scheme is WebAuthn. */
  webauthnAuthData?: Uint8Array
  /** Required iff member scheme is WebAuthn. */
  webauthnClientDataJson?: Uint8Array
}

export interface ContributeResult {
  txSignature: string
  contributionsCount: number
  thresholdRequired: number
}

export interface FinalizeSessionResult {
  txSignature: string
  messageApprovalAddress: Address
}

export interface CloseSessionResult {
  txSignature: string
}

// ── Admin actions (challenge-based) ─────────────────────────────

export type AdminAction =
  | { type: 'add_member'; member: MemberSlot }
  | { type: 'remove_member'; member: MemberSlot }
  | { type: 'add_destination'; destination: Uint8Array }
  | { type: 'remove_destination'; destination: Uint8Array }
  | { type: 'revoke' }
  | { type: 'set_primary'; newPrimary: MemberSlot }
  | { type: 'set_quorum_threshold_immediate'; newThreshold: number }
  | { type: 'set_daily_limit_immediate'; newSome: boolean; newLimit: bigint }
  | { type: 'set_cooldown_immediate'; newCooldownSeconds: bigint }
  | { type: 'propose_quorum_threshold_change'; newThreshold: number }
  | { type: 'propose_daily_limit_change'; newSome: boolean; newLimit: bigint }
  | { type: 'propose_cooldown_change'; newCooldownSeconds: bigint }

export interface AdminChallengeInput extends InitAuthorityHashCarrier {
  dwalletAddress: Address
  action: AdminAction
}

export interface AdminChallengeOutput {
  challenge: Uint8Array
  expectedNonce: bigint
}

export interface AdminSubmitInput extends AdminChallengeInput {
  primarySignature: Uint8Array
  expectedNonce: bigint
}

export interface TxResult {
  txSignature: string
}

// ── Adapter interface ───────────────────────────────────────────

export interface PolicyAdapter {
  // Deploy / read
  deployRulesPolicy(input: DeployInput): Promise<DeployResult>
  readState(dwalletAddress: Address): Promise<PolicyState | null>
  readSession(sessionAddress: Address): Promise<QuorumSessionState | null>

  // Primary recovery
  prepareRecoverAsPrimary(input: PrimaryChallengeInput): Promise<PrimaryChallengeOutput>
  submitRecoverAsPrimary(input: PrimarySubmitInput): Promise<PrimarySubmitResult>

  // Quorum staging
  prepareQuorumSessionOpen(input: OpenSessionInput): Promise<OpenSessionChallenge>
  submitQuorumSessionOpen(input: OpenSessionSubmitInput): Promise<OpenSessionResult>
  prepareQuorumContribute(input: ContributeChallengeInput): Promise<ContributeChallengeOutput>
  submitQuorumContribute(input: ContributeSubmitInput): Promise<ContributeResult>
  submitQuorumFinalize(sessionAddress: Address): Promise<FinalizeSessionResult>
  submitQuorumClose(sessionAddress: Address): Promise<CloseSessionResult>

  // Admin (challenge-based)
  prepareAdminAction(input: AdminChallengeInput): Promise<AdminChallengeOutput>
  submitAdminAction(input: AdminSubmitInput): Promise<TxResult>

  // Pending change apply (no auth — cooldown gate)
  applyPendingChange(input: { dwalletAddress: Address; initAuthorityHash: Uint8Array }): Promise<TxResult>

  // Read variants that need init_authority_hash to derive PDA.
  readStateByHash(input: { dwalletAddress: Address; initAuthorityHash: Uint8Array }): Promise<PolicyState | null>

  // Quorum finalize/close take session by address — they read the policy
  // address from the session account. The init_authority_hash is needed to
  // derive the policy PDA in the on-chain seeds verification.
  submitQuorumFinalizeWithHash(input: { sessionAddress: Address; dwalletAddress: Address; initAuthorityHash: Uint8Array }): Promise<FinalizeSessionResult>
  submitQuorumCloseWithHash(input: { sessionAddress: Address; dwalletAddress: Address; initAuthorityHash: Uint8Array }): Promise<CloseSessionResult>
}
