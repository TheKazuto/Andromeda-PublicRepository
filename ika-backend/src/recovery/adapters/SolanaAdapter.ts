/**
 * Concrete `PolicyAdapter` over the Quasar `rules-policy` program (v2).
 *
 * Every flow is challenge-based + gas-sponsored: the user signs a 32-byte
 * challenge off-chain with whatever wallet/scheme they have, and the adapter
 * builds a Solana transaction containing the matching precompile instruction
 * plus the main `rules-policy` instruction, with the gas sponsor as fee payer.
 * The user's wallet is never required to be a Solana signer.
 *
 * This file is the thin class shell + singleton wiring; the flow logic lives in
 * `solana/{internal,state,deploy,primary,quorum,admin}.ts`.
 */

import type { Address } from '@solana/kit'

import type {
  AdminChallengeInput,
  AdminChallengeOutput,
  AdminSubmitInput,
  CloseSessionResult,
  ContributeChallengeInput,
  ContributeChallengeOutput,
  ContributeResult,
  ContributeSubmitInput,
  DeployInput,
  DeployResult,
  FinalizeSessionResult,
  OpenSessionChallenge,
  OpenSessionInput,
  OpenSessionResult,
  OpenSessionSubmitInput,
  PolicyAdapter,
  PolicyState,
  PrimaryChallengeInput,
  PrimaryChallengeOutput,
  PrimarySubmitInput,
  PrimarySubmitResult,
  QuorumSessionState,
  TxResult,
} from './PolicyAdapter.js'
import { type SolanaAdapterOptions, type SolanaCtx, makeSolanaCtx } from './solana/internal.js'
import { deployRulesPolicy } from './solana/deploy.js'
import { readPolicyState, readQuorumSession } from './solana/state.js'
import { prepareRecoverAsPrimary, submitRecoverAsPrimary } from './solana/primary.js'
import {
  prepareQuorumContribute,
  prepareQuorumSessionOpen,
  submitQuorumCloseWithHash,
  submitQuorumContribute,
  submitQuorumFinalizeWithHash,
  submitQuorumSessionOpen,
} from './solana/quorum.js'
import { applyPendingChange, prepareAdminAction, submitAdminAction } from './solana/admin.js'

export type { SolanaAdapterOptions } from './solana/internal.js'

class SolanaAdapter implements PolicyAdapter {
  private readonly ctx: SolanaCtx

  constructor(opts: SolanaAdapterOptions) {
    this.ctx = makeSolanaCtx(opts)
  }

  // ── Deploy / read ─────────────────────────────────────────
  deployRulesPolicy(input: DeployInput): Promise<DeployResult> {
    return deployRulesPolicy(this.ctx, input)
  }

  /** @deprecated A dwallet can host multiple policies (Audit C2). Use `readStateByHash`. */
  readState(_dwalletAddress: Address): Promise<PolicyState | null> {
    return Promise.reject(
      new Error('readState(dwalletAddress) is no longer sufficient — use readStateByHash({dwalletAddress, initAuthorityHash}) (Audit C2)'),
    )
  }

  readStateByHash(input: { dwalletAddress: Address; initAuthorityHash: Uint8Array }): Promise<PolicyState | null> {
    return readPolicyState(this.ctx, input)
  }

  readSession(sessionAddress: Address): Promise<QuorumSessionState | null> {
    return readQuorumSession(sessionAddress)
  }

  // ── Primary recovery ──────────────────────────────────────
  prepareRecoverAsPrimary(input: PrimaryChallengeInput): Promise<PrimaryChallengeOutput> {
    return prepareRecoverAsPrimary(this.ctx, input)
  }

  submitRecoverAsPrimary(input: PrimarySubmitInput): Promise<PrimarySubmitResult> {
    return submitRecoverAsPrimary(this.ctx, input)
  }

  // ── Quorum staging ────────────────────────────────────────
  prepareQuorumSessionOpen(input: OpenSessionInput): Promise<OpenSessionChallenge> {
    return prepareQuorumSessionOpen(this.ctx, input)
  }

  submitQuorumSessionOpen(input: OpenSessionSubmitInput): Promise<OpenSessionResult> {
    return submitQuorumSessionOpen(this.ctx, input)
  }

  prepareQuorumContribute(input: ContributeChallengeInput): Promise<ContributeChallengeOutput> {
    return prepareQuorumContribute(input)
  }

  submitQuorumContribute(input: ContributeSubmitInput): Promise<ContributeResult> {
    return submitQuorumContribute(this.ctx, input)
  }

  /** @deprecated Requires `init_authority_hash` (Audit C2). Use `submitQuorumFinalizeWithHash`. */
  submitQuorumFinalize(_sessionAddress: Address): Promise<FinalizeSessionResult> {
    return Promise.reject(
      new Error('submitQuorumFinalize(sessionAddress) requires init_authority_hash — use submitQuorumFinalizeWithHash (Audit C2)'),
    )
  }

  submitQuorumFinalizeWithHash(input: {
    sessionAddress: Address
    dwalletAddress: Address
    initAuthorityHash: Uint8Array
  }): Promise<FinalizeSessionResult> {
    return submitQuorumFinalizeWithHash(this.ctx, input)
  }

  /** @deprecated Requires `init_authority_hash` (Audit C2). Use `submitQuorumCloseWithHash`. */
  submitQuorumClose(_sessionAddress: Address): Promise<CloseSessionResult> {
    return Promise.reject(
      new Error('submitQuorumClose(sessionAddress) requires init_authority_hash — use submitQuorumCloseWithHash (Audit C2)'),
    )
  }

  submitQuorumCloseWithHash(input: {
    sessionAddress: Address
    dwalletAddress: Address
    initAuthorityHash: Uint8Array
  }): Promise<CloseSessionResult> {
    return submitQuorumCloseWithHash(this.ctx, input)
  }

  // ── Admin ─────────────────────────────────────────────────
  prepareAdminAction(input: AdminChallengeInput): Promise<AdminChallengeOutput> {
    return prepareAdminAction(this.ctx, input)
  }

  submitAdminAction(input: AdminSubmitInput): Promise<TxResult> {
    return submitAdminAction(this.ctx, input)
  }

  applyPendingChange(input: { dwalletAddress: Address; initAuthorityHash: Uint8Array }): Promise<TxResult> {
    return applyPendingChange(this.ctx, input)
  }
}

// ── Singleton wiring ───────────────────────────────────────────

let adapter: PolicyAdapter | null = null

export function initSolanaAdapter(opts: SolanaAdapterOptions): PolicyAdapter {
  adapter = new SolanaAdapter(opts)
  return adapter
}

export function getPolicyAdapter(): PolicyAdapter {
  if (!adapter) throw new Error('Policy adapter not initialized')
  return adapter
}
