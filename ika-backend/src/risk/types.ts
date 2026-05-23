/**
 * Risk scoring and transaction simulation types.
 *
 * Core principles:
 * - `effectsExtracted: boolean` indicates whether asset changes/approvals were
 *   actually extracted. When false, the consumer should treat the tx as
 *   "not verified" (not "safe").
 * - Decoded instructions/calldata heuristics are always included when possible;
 *   missing decoders are marked explicitly (not fabricated).
 * - Levels and reasons are immutable and sanitized for client exposure.
 */

export type RiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

/**
 * A native or token balance delta. `change` is a signed decimal string
 * ("-1000" = the wallet loses 1000). Shape mirrors the gateway `risk.AssetChange`
 * struct so the gateway risk service consumes it without remapping.
 */
export interface AssetChange {
  /** "native" or the token contract address. */
  asset: string
  /** Signed amount; a leading "-" means an outflow from the wallet. */
  change: string
}

/**
 * An approval granted to a spender. Mirrors the gateway `risk.ApprovalGrant`.
 */
export interface ApprovalGrant {
  /** Token contract address. */
  token: string
  /** Spender/operator address. */
  spender: string
  /** "unlimited" or a numeric amount. */
  amount: string
}

/**
 * An external contract invocation. Mirrors the gateway `risk.ContractCall`.
 */
export interface ContractCall {
  /** Contract address called. */
  address: string
  /** Function selector (e.g. "0x095ea7b3") or method name. */
  method: string
}

/**
 * Decoded instruction or instruction-level error for Solana.
 */
export interface SolanaInstructionDecoded {
  programId: string
  /** Human-readable program name or "Unknown". */
  programName: string
  /** Decoded operation type if known (e.g. "Approve", "Transfer"), or undefined. */
  operationType?: string | undefined
  /** Extracted fields relevant to risk (amount, delegate, authority, etc). */
  fields?: Record<string, unknown> | undefined
  /** Error if decoding failed (program known but structure unrecognizable). */
  error?: string | undefined
}

/**
 * Calldata-level heuristic flags for risk.
 */
export interface CalldataRisk {
  level: RiskLevel
  reasons: string[]
  /** True if the calldata was actually decoded and analyzed. False means fallback (chain unsupported, etc). */
  effectsExtracted: boolean
}

/**
 * Full transaction simulation result from `/v1/dwallet/simulate` (internal endpoint, not exposed as MCP tool).
 */
export interface TransactionSimulation {
  ok: boolean
  /** True if expectedDigestHex matched the recomputed digest. */
  digestMatches: boolean
  /** The recomputed digest in hex format. Included in all responses. */
  actualDigestHex?: string | undefined
  /** Destination address (for EVM/Tron) or undefined if not applicable. */
  destination?: string | undefined
  /** True if the simulation/decode was actually performed and verified. False means fallback/unsupported chain. */
  verified: boolean
  /** Extracted asset changes, approvals, and contract calls. */
  assetChanges: AssetChange[]
  approvals: ApprovalGrant[]
  calls: ContractCall[]
  /** True if decoded instructions/calldata represent actual efffects (false = degraded/RPC unavailable). */
  effectsExtracted: boolean
  /** Calldata-level risk analysis. */
  calldataRisk?: { level: RiskLevel; reasons: string[] } | undefined
  /** For EVM: gas estimate or null if unavailable. For Solana: fee estimate. */
  estimatedGas?: string | undefined
  /** Solana: decoded instructions; EVM: null. */
  solanaInstructions?: SolanaInstructionDecoded[] | undefined
  /** Will the transaction revert? */
  willRevert: boolean
  warnings: string[]
}
