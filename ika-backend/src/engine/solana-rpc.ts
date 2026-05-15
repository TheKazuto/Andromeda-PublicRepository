import { createSolanaRpc, createSolanaRpcSubscriptions } from '@solana/kit'
import type { Rpc, SolanaRpcApi, RpcSubscriptions, SolanaRpcSubscriptionsApi } from '@solana/kit'

let rpc: Rpc<SolanaRpcApi> | null = null
let rpcSub: RpcSubscriptions<SolanaRpcSubscriptionsApi> | null = null

export function initSolanaRpc(url: string): Rpc<SolanaRpcApi> {
  rpc = createSolanaRpc(url)
  return rpc
}

export function getSolanaRpc(): Rpc<SolanaRpcApi> {
  if (!rpc) throw new Error('Solana RPC not initialized')
  return rpc
}

export function initSolanaRpcSubscriptions(url: string): RpcSubscriptions<SolanaRpcSubscriptionsApi> {
  const wsUrl = url.replace(/^http/, 'ws')
  rpcSub = createSolanaRpcSubscriptions(wsUrl)
  return rpcSub
}

export function getSolanaRpcSubscriptions(): RpcSubscriptions<SolanaRpcSubscriptionsApi> {
  if (!rpcSub) throw new Error('Solana RPC subscriptions not initialized')
  return rpcSub
}

// ── Blockhash cache (TTL + single-flight) ────────────────────────────────
//
// `getLatestBlockhash` é chamado em toda construção de transação não-assinada.
// Blockhashes Solana são válidos por ~150 slots (~60s). Cachear por uma
// fração desse tempo elimina dezenas de RPC calls por minuto sob carga.
//
// Single-flight: se 50 requests chegarem simultaneamente com cache miss,
// apenas 1 dispara a chamada RPC; os outros aguardam a mesma Promise.

interface BlockhashEntry {
  blockhash: string
  lastValidBlockHeight: bigint
  fetchedAt: number
}

const BLOCKHASH_TTL_MS = 10_000
let cachedBlockhash: BlockhashEntry | null = null
let inFlight: Promise<BlockhashEntry> | null = null

export interface CachedBlockhash {
  blockhash: string
  lastValidBlockHeight: bigint
}

export async function getCachedBlockhash(): Promise<CachedBlockhash> {
  const now = Date.now()
  if (cachedBlockhash && now - cachedBlockhash.fetchedAt < BLOCKHASH_TTL_MS) {
    return {
      blockhash: cachedBlockhash.blockhash,
      lastValidBlockHeight: cachedBlockhash.lastValidBlockHeight,
    }
  }
  if (inFlight) {
    const entry = await inFlight
    return { blockhash: entry.blockhash, lastValidBlockHeight: entry.lastValidBlockHeight }
  }
  inFlight = (async () => {
    try {
      const { value: latest } = await getSolanaRpc()
        .getLatestBlockhash({ commitment: 'confirmed' })
        .send()
      const entry: BlockhashEntry = {
        blockhash: latest.blockhash,
        lastValidBlockHeight: latest.lastValidBlockHeight,
        fetchedAt: Date.now(),
      }
      cachedBlockhash = entry
      return entry
    } finally {
      inFlight = null
    }
  })()
  const entry = await inFlight
  return { blockhash: entry.blockhash, lastValidBlockHeight: entry.lastValidBlockHeight }
}
