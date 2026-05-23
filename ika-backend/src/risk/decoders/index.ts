// Decoder registry assembly. Add a family's decoder to the array below and
// `decodeForChain` (../decode.ts) will route to it automatically; families with
// no decoder fall back to the honest "cannot verify" path.
//
// EVM, Tron and Solana are NOT here — they stay inline in ../decode.ts.

import { algorandDecoder } from './algorand.js'
import { aptosDecoder } from './aptos.js'
import { bitcoinDecoder } from './bitcoin.js'
import { cosmosDecoder } from './cosmos.js'
import { filecoinDecoder } from './filecoin.js'
import { multiversxDecoder } from './multiversx.js'
import { nearDecoder } from './near.js'
import { vechainDecoder } from './vechain.js'
import type { ChainDecoder } from './registry.js'

const DECODERS: readonly ChainDecoder[] = [
  cosmosDecoder,
  bitcoinDecoder,
  vechainDecoder,
  nearDecoder,
  aptosDecoder,
  multiversxDecoder,
  algorandDecoder,
  filecoinDecoder,
]

const BY_FAMILY: ReadonlyMap<string, ChainDecoder> = new Map(
  DECODERS.map((d) => [d.family, d]),
)

/** Returns the decoder for a chainFamily, or undefined if none is registered. */
export function getDecoder(family: string): ChainDecoder | undefined {
  return BY_FAMILY.get(family)
}

/** Families that currently have a pluggable decoder (for diagnostics/tests). */
export function decodedFamilies(): string[] {
  return [...BY_FAMILY.keys()]
}

export type { ChainDecoder, DecodeContext } from './registry.js'
