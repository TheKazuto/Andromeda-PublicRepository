/**
 * Transaction decoding and calldata risk heuristics per chain family.
 *
 * Solana: desserializes versioned transactions and decodes SPL Token instructions.
 * EVM/Tron: parses calldata selectors and common patterns (approve, setApprovalForAll, etc).
 * Other families: routed to a pluggable decoder (see `decoders/`) — Cosmos,
 * Bitcoin, VeChain, NEAR, Aptos, MultiversX, Algorand, Filecoin. Families with
 * no registered decoder fall back to `effectsExtracted: false` with an explicit
 * reason (honest "cannot verify").
 */

import { VersionedTransaction } from '@solana/web3.js'
// @ts-ignore - viem has implicit any for parseTransaction
import { parseTransaction } from 'viem'
import type {
  CalldataRisk,
  SolanaInstructionDecoded,
  RiskLevel,
  AssetChange,
  ApprovalGrant,
  ContractCall,
} from './types.js'
import { parseChainId, resolveChainParams } from '../chain/chains.js'
import { getDecoder } from './decoders/index.js'

// SPL Token program address on Solana
const SPL_TOKEN_PROGRAM_ID = 'TokenkegQfeZyiNwAJsyFbPVwwQQfaju6cn5WQqTo9'

// Known program IDs and their human names
const SOLANA_PROGRAM_NAMES: Record<string, string> = {
  '11111111111111111111111111111111': 'System',
  TokenkegQfeZyiNwAJsyFbPVwwQQfaju6cn5WQqTo9: 'SPL Token',
  TokenzQdBNBWnG6PJqVDNsKgEKC9vSmtxj7fF8rD9SPL: 'Token 2022',
  ATokenGPvbdGVqstVQmcLsNZAqeEctipDKXGPU985bcT: 'Associated Token Account',
}

/**
 * Risk level from heuristic signals (EVM).
 */
function riskLevelFromEvmSignals(signals: string[]): RiskLevel {
  if (signals.length === 0) return 'none'
  if (signals.some((s) => s.includes('infinite'))) return 'high'
  if (signals.some((s) => s.includes('setApprovalForAll'))) return 'medium'
  if (signals.some((s) => s.includes('unknown function'))) return 'medium'
  return 'low'
}

/**
 * Parse EVM calldata and extract heuristic risk signals.
 * For MVP: static analysis of function selectors and patterns.
 * For transaction payloads: parse via viem to extract calldata from RLP.
 */
export function decodeEvmCalldata(payloadHex: string): CalldataRisk {
  const signals: string[] = []

  try {
    // Remove 0x prefix if present
    const normalized = payloadHex.startsWith('0x') ? payloadHex.slice(2) : payloadHex

    // Validate hex
    if (!/^[a-fA-F0-9]*$/.test(normalized)) {
      return {
        level: 'high',
        reasons: ['Invalid hex in calldata'],
        effectsExtracted: false,
      }
    }

    if (normalized.length < 8) {
      // Too short for a function selector
      return {
        level: 'none',
        reasons: ['calldata too short for function call'],
        effectsExtracted: true,
      }
    }

    // Check if this looks like a serialized transaction (RLP/EIP-1559 prefix)
    // RLP transactions start with 0xf8/f9 (legacy), 0x01-0x03 (EIP-2930/1559/4844)
    let calldata = normalized

    const firstByte = normalized.substring(0, 2).toLowerCase()
    if (firstByte === '01' || firstByte === '02' || firstByte === '03' || firstByte === 'f8' || firstByte === 'f9') {
      // Attempt to parse as a serialized transaction using viem
      try {
        const tx = parseTransaction(`0x${normalized}`)
        calldata = (tx.data as string | undefined)?.replace(/^0x/, '') || ''
      } catch {
        // If parsing fails, treat the entire hex as calldata
        calldata = normalized
      }
    }

    // Extract function selector from calldata
    const selector = calldata.slice(0, 8).toLowerCase()
    const args = calldata.slice(8)

    // Common heuristics: function selectors and patterns
    switch (selector) {
      // approve(address, uint256) == 0x095ea7b3
      case '095ea7b3': {
        // Check if amount is max uint256 (0xffffffff...f)
        // args start after selector, so:
        //  - address is at position 0-63 (32 bytes)
        //  - amount is at position 64-127 (32 bytes)
        if (args.length >= 128) {
          const amountHex = args.slice(64, 128).toLowerCase()
          if (amountHex === 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff') {
            signals.push('Unlimited token approval (infinite amount)')
          }
        }
        signals.push('Token approval')
        break
      }

      // setApprovalForAll(address, bool) == 0xa22cb465
      case 'a22cb465': {
        signals.push('setApprovalForAll: grants unlimited delegation')
        break
      }

      // permit/Permit2 with high value — heuristic only
      case '8ccf1534': // Permit2.permit
      case 'd505accf': // ERC2612 permit
        signals.push('Permit detected: signature-based approval')
        break

      // transferFrom(address, address, uint256) == 0x23b872dd
      case '23b872dd':
        signals.push('transferFrom: verify recipient is trusted')
        break

      default:
        // Unknown function selector
        if (selector !== '00000000') {
          signals.push(`Unknown function selector: 0x${selector}`)
        }
    }

    const level = riskLevelFromEvmSignals(signals)
    return {
      level,
      reasons: signals.length > 0 ? signals : ['calldata decoded (no high-risk patterns detected)'],
      effectsExtracted: true,
    }
  } catch {
    return {
      level: 'high',
      reasons: ['EVM calldata parse error; unable to verify'],
      effectsExtracted: false,
    }
  }
}

/** Parsed view of an EVM transaction's executable fields. */
export interface EvmTxView {
  /** Destination address (lowercase 0x), or undefined for contract creation / parse failure. */
  to?: string | undefined
  /** Native value in wei. */
  value: bigint
  /** Calldata (0x-prefixed). */
  data: string
  /** True if the input parsed as a serialized tx; false if treated as raw calldata. */
  parsed: boolean
}

const SERIALIZED_TX_PREFIXES = new Set(['01', '02', '03', 'f8', 'f9'])
const MAX_UINT256_HEX = 'f'.repeat(64)

/**
 * Parse a serialized EVM transaction (legacy or typed) into its executable
 * fields. Falls back to treating the input as raw calldata when it isn't a
 * recognizable serialized tx (so callers always get a usable view).
 */
export function decodeEvmTransaction(payloadHex: string): EvmTxView {
  const normalized = payloadHex.startsWith('0x') ? payloadHex.slice(2) : payloadHex
  const firstByte = normalized.substring(0, 2).toLowerCase()

  if (SERIALIZED_TX_PREFIXES.has(firstByte)) {
    try {
      const tx = parseTransaction(`0x${normalized}`)
      return {
        to: (tx.to as string | undefined)?.toLowerCase(),
        value: (tx.value as bigint | undefined) ?? 0n,
        data: (tx.data as string | undefined) ?? '0x',
        parsed: true,
      }
    } catch {
      // Looked like a serialized tx but didn't parse — flag it so callers can
      // degrade honestly instead of treating a malformed tx as plain calldata.
      return { to: undefined, value: 0n, data: `0x${normalized}`, parsed: false }
    }
  }
  return { to: undefined, value: 0n, data: `0x${normalized}`, parsed: false }
}

/** Extract the 20-byte address from a 32-byte ABI word (right-aligned). */
function addressFromSlot(slot: string): string | undefined {
  if (slot.length !== 64) return undefined
  return `0x${slot.slice(24)}`
}

/** Decode a 32-byte ABI word as an unsigned integer decimal string. */
function amountFromSlot(slot: string): string | undefined {
  if (slot.length !== 64) return undefined
  try {
    return BigInt(`0x${slot}`).toString()
  } catch {
    return undefined
  }
}

/**
 * Derive structured, canonical effects from an EVM transaction's executable
 * fields. These are the *intended* effects read directly from the calldata
 * (native value, ERC-20 transfer/approval, NFT operator approval) plus the
 * top-level contract call — NOT a state-diff trace. Shapes mirror the gateway
 * risk structs so the score can consume them as-is.
 */
export function extractEvmEffects(tx: Pick<EvmTxView, 'to' | 'value' | 'data'>): {
  assetChanges: AssetChange[]
  approvals: ApprovalGrant[]
  calls: ContractCall[]
} {
  const assetChanges: AssetChange[] = []
  const approvals: ApprovalGrant[] = []
  const calls: ContractCall[] = []

  if (tx.value > 0n) {
    assetChanges.push({ asset: 'native', change: `-${tx.value.toString()}` })
  }

  const data = tx.data.startsWith('0x') ? tx.data.slice(2) : tx.data

  if (data.length >= 8 && tx.to) {
    const selector = data.slice(0, 8).toLowerCase()
    const args = data.slice(8)
    const slot = (i: number): string => args.slice(i * 64, i * 64 + 64)
    const token = tx.to

    switch (selector) {
      case '095ea7b3': {
        // approve(spender, amount)
        const spender = addressFromSlot(slot(0))
        if (!spender) break
        const raw = slot(1)
        const amount = raw.toLowerCase() === MAX_UINT256_HEX ? 'unlimited' : (amountFromSlot(raw) ?? '0')
        approvals.push({ token, spender, amount })
        break
      }
      case 'a22cb465': {
        // setApprovalForAll(operator, approved)
        const operator = addressFromSlot(slot(0))
        if (!operator) break
        const approved = (amountFromSlot(slot(1)) ?? '0') !== '0'
        if (approved) approvals.push({ token, spender: operator, amount: 'unlimited' })
        break
      }
      case 'a9059cbb': {
        // transfer(to, amount) — token leaves the wallet.
        assetChanges.push({ asset: token, change: `-${amountFromSlot(slot(1)) ?? '0'}` })
        break
      }
      case '23b872dd': {
        // transferFrom(from, to, amount) — treat as an outflow signal.
        assetChanges.push({ asset: token, change: `-${amountFromSlot(slot(2)) ?? '0'}` })
        break
      }
      default:
        break
    }

    calls.push({ address: token, method: `0x${selector}` })
  }

  return { assetChanges, approvals, calls }
}

/**
 * Parse a Solana transaction and decode instructions.
 * Returns an array of decoded instructions, marking unknowns as such.
 */
export function decodeSolanaTransaction(
  payloadHex: string,
): { instructions: SolanaInstructionDecoded[]; error?: string } {
  try {
    // Convert hex to bytes
    const normalized = payloadHex.startsWith('0x') ? payloadHex.slice(2) : payloadHex
    const txBytes = Buffer.from(normalized, 'hex')

    // Deserialize as VersionedTransaction
    const tx = VersionedTransaction.deserialize(txBytes)
    if (!tx) {
      return {
        instructions: [],
        error: 'Failed to deserialize versioned transaction',
      }
    }

    const instructions: SolanaInstructionDecoded[] = []

    // Iterate over instructions in the message
    const message = tx.message
    // MessageV0 uses compiledInstructions; legacy uses instructions
    const msgInstructions = 'compiledInstructions' in message ? message.compiledInstructions : 'instructions' in message ? (message as any).instructions : []
    const accountKeys = message.staticAccountKeys

    for (let i = 0; i < msgInstructions.length; i++) {
      const ix = msgInstructions[i]
      if (!ix) continue

      const programIdIndex = ix.programIdIndex
      if (typeof programIdIndex !== 'number' || programIdIndex >= accountKeys.length) {
        instructions.push({
          programId: `invalid_index_${programIdIndex}`,
          programName: 'Invalid',
          error: 'Program ID index out of bounds',
        })
        continue
      }

      const programId = accountKeys[programIdIndex]
      if (!programId) {
        instructions.push({
          programId: `invalid_index_${programIdIndex}`,
          programName: 'Invalid',
          error: 'Program ID not found',
        })
        continue
      }
      const programIdStr = programId.toBase58()
      const programName = SOLANA_PROGRAM_NAMES[programIdStr] || 'Unknown'

      // Convert data to bytes if necessary (Uint8Array or Buffer)
      const ixData = ix.data instanceof Uint8Array ? ix.data : typeof ix.data === 'string' ? Buffer.from(ix.data, 'base64') : ix.data

      // Heuristic decoding for SPL Token
      if (programIdStr === SPL_TOKEN_PROGRAM_ID && ixData && ixData.length >= 1) {
        const instruction = ixData[0]
        const decoded = decodeSplTokenInstruction(instruction, ixData)
        if (decoded) {
          instructions.push({
            programId: programIdStr,
            programName,
            operationType: decoded.type,
            fields: decoded.fields,
          })
          continue
        }
      }

      // Fallback: unknown instruction
      instructions.push({
        programId: programIdStr,
        programName,
        operationType: undefined as string | undefined,
        fields: {
          data_len: ixData ? ixData.length : 0,
          accounts_len: ix.accounts ? ix.accounts.length : 0,
        },
      })
    }

    return { instructions }
  } catch (err) {
    return {
      instructions: [],
      error: `Solana deserialization error: ${err instanceof Error ? err.message : 'unknown'}`,
    }
  }
}

/**
 * Decode SPL Token instruction at a basic level.
 * Returns { type, fields } or null if not recognized.
 */
function decodeSplTokenInstruction(
  instruction: number,
  data: Uint8Array,
): { type: string; fields: Record<string, unknown> } | null {
  // Canonical SPL Token instruction tags (spl-token program).
  // Off-by-one tags were a confirmed bug caught by the war room.
  switch (instruction) {
    case 0: // InitializeMint
      return { type: 'InitializeMint', fields: {} }
    case 1: // InitializeAccount
      return { type: 'InitializeAccount', fields: {} }
    case 2: // InitializeMultisig
      return { type: 'InitializeMultisig', fields: {} }
    case 3: // Transfer
      return { type: 'Transfer', fields: { dataLen: data.length } }
    case 4: // Approve (creates a delegate)
      return {
        type: 'Approve',
        fields: { dataLen: data.length, riskFlag: 'delegate_created' },
      }
    case 5: // Revoke
      return { type: 'Revoke', fields: {} }
    case 6: // SetAuthority (changes mint/account authority)
      return {
        type: 'SetAuthority',
        fields: { riskFlag: 'authority_changed' },
      }
    case 7: // MintTo
      return { type: 'MintTo', fields: {} }
    case 8: // Burn
      return { type: 'Burn', fields: {} }
    case 9: // CloseAccount (can drain a token account)
      return {
        type: 'CloseAccount',
        fields: { riskFlag: 'account_closed' },
      }
    case 10: // FreezeAccount
      return { type: 'FreezeAccount', fields: { riskFlag: 'account_frozen' } }
    case 11: // ThawAccount
      return { type: 'ThawAccount', fields: {} }
    case 12: // TransferChecked
      return { type: 'TransferChecked', fields: { dataLen: data.length } }
    case 13: // ApproveChecked (creates a delegate)
      return {
        type: 'ApproveChecked',
        fields: { dataLen: data.length, riskFlag: 'delegate_created' },
      }
    default:
      return null
  }
}

/**
 * Decode transaction payload and extract calldata risk for a specific chain.
 */
export function decodeForChain(
  chainId: string,
  payloadHex: string,
  kind: 'transaction' | 'message',
): CalldataRisk {
  try {
    const params = resolveChainParams(chainId)

    switch (params.chainFamily) {
      case 'Solana': {
        // Decode Solana transaction instructions to extract risk signals
        if (payloadHex.length < 2) {
          return {
            level: 'none',
            reasons: ['payload too short'],
            effectsExtracted: false,
          }
        }

        // Actually decode the Solana transaction
        const decoded = decodeSolanaTransaction(payloadHex)
        if (decoded.error) {
          return {
            level: 'medium',
            reasons: ['Solana transaction deserialization failed; unable to verify'],
            effectsExtracted: false,
          }
        }

        // Scan decoded instructions for risk signals
        const signals: string[] = []
        for (const ix of decoded.instructions) {
          if (ix.operationType === 'Approve' || ix.operationType === 'ApproveChecked') {
            signals.push(`SPL Token: ${ix.operationType} instruction creates delegate (verify recipient is trusted)`)
          }
          if (ix.fields?.riskFlag === 'delegate_created') {
            signals.push('SPL Token: delegate created (verify program/recipient)')
          }
          if (ix.fields?.riskFlag === 'authority_changed') {
            signals.push('SPL Token: authority changed (high-risk operation)')
          }
          if (ix.fields?.riskFlag === 'account_closed') {
            signals.push('SPL Token: account closure (verify recipient of lamports)')
          }
        }

        const level = signals.length > 0 ? (signals.some((s) => s.includes('authority')) ? 'high' : 'medium') : 'none'

        return {
          level,
          reasons: signals.length > 0 ? signals : ['Solana transaction decoded successfully'],
          effectsExtracted: decoded.instructions.length > 0,
        }
      }

      case 'EVM':
      case 'Tron': {
        if (kind === 'transaction') {
          // Transaction calldata
          return decodeEvmCalldata(payloadHex)
        } else {
          // Message (personal_sign, etc) — lower risk
          return {
            level: 'none',
            reasons: ['message signature (not a transaction)'],
            effectsExtracted: true,
          }
        }
      }

      default: {
        // Pluggable decoders (Cosmos, Bitcoin, …). Families without one fall
        // back to the honest "cannot verify" path. Note: Avalanche C-Chain is
        // CAIP-2 `eip155` and is handled by the EVM case above; only the
        // Avalanche X/P-chain namespace reaches here.
        const decoder = getDecoder(params.chainFamily)
        if (decoder) {
          return decoder.decode(payloadHex, kind, {
            chainId,
            namespace: params.namespace,
            reference: parseChainId(chainId).reference,
          })
        }
        return {
          level: 'critical',
          reasons: [
            `Decoder not implemented for ${params.chainFamily}; transaction effects cannot be verified`,
          ],
          effectsExtracted: false,
        }
      }
    }
  } catch (err) {
    return {
      level: 'critical',
      reasons: [
        `chain resolution error: ${err instanceof Error ? err.message : 'unknown'}`,
      ],
      effectsExtracted: false,
    }
  }
}
