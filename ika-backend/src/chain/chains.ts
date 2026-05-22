// CAIP-2 chain id → Ika signing parameters (curve + on-wire signature scheme).
//
// Ported and adapted from `odws/src/chain/chains.ts`
// (https://github.com/Iamknownasfesal/odws). The original keys off the Sui-side
// `@ika.xyz/sdk` enums (`Curve` / `SignatureAlgorithm` / `Hash`); we key off our
// own single source of truth instead — `CurveName` and the numeric
// `SignatureScheme` (algorithm + hash combined) from
// `engine/ika-client/bcs.ts`. That avoids a translation layer and keeps one
// canonical mapping.
//
// IMPORTANT (see Update 2 plan §1.2): `chain_id` in the Ika protocol is the
// *coordination* chain (always Solana for us), NOT the destination. The
// destination chain is selected purely by `scheme` (curve + hash). This map is
// what turns a CAIP-2 destination chain id into that `(curve, scheme)` pair.
//
// Coverage: the B1 set (EVM, Tron, Bitcoin P2WPKH, Solana, Sui, Cosmos) plus
// the B6/B7 families validated against each chain's official SDK in
// `fixtures/chain/gen.ts` (Filecoin, Stellar, Algorand, Aptos, MultiversX, TON).
// Every entry here is fully signable (curve + scheme the Ika network supports)
// AND address-derivable (see address.ts). Families whose signing hash is not in
// our scheme set (e.g. XRPL's SHA-512Half) or whose account is not derivable
// from the key (Hedera/Flow/Antelope) are intentionally absent. Bitcoin Taproot
// stays out until the Schnorr presign path is resolved (plan §3.6).

import { type CurveName, SignatureScheme } from '../engine/ika-client/bcs.js'
import { ChainIdParseError, UnsupportedChainError } from './errors.js'

/** Resolved signing parameters for a destination chain. */
export interface ChainSigningParams {
  /** The CAIP-2 namespace (e.g. "eip155", "solana"). */
  namespace: string
  /** Ika dWallet curve the destination chain requires. */
  curve: CurveName
  /** On-wire `DWalletSignatureScheme` numeric id (curve + hash). */
  scheme: number
  /** Human-readable chain family. */
  chainFamily: string
}

/**
 * Chain family definitions, keyed by CAIP-2 namespace. One entry covers the
 * whole family: once `eip155` is here, every EVM chain works without further
 * work — only the `reference` (chain number) matters, and that lives in the
 * final tx the client assembles, not here.
 *
 * | Namespace | Family   | Curve      | scheme                |
 * |-----------|----------|------------|-----------------------|
 * | eip155    | EVM      | Secp256k1  | 0 EcdsaKeccak256      |
 * | tron      | Tron     | Secp256k1  | 0 EcdsaKeccak256      |
 * | bip122    | Bitcoin  | Secp256k1  | 2 EcdsaDoubleSha256   |
 * | solana    | Solana     | Curve25519 | 5 EddsaSha512       |
 * | sui       | Sui        | Curve25519 | 5 EddsaSha512       |
 * | cosmos    | Cosmos     | Secp256k1  | 1 EcdsaSha256       |
 * | fil       | Filecoin   | Secp256k1  | 4 EcdsaBlake2b256   |
 * | stellar   | Stellar    | Curve25519 | 5 EddsaSha512       |
 * | algorand  | Algorand   | Curve25519 | 5 EddsaSha512       |
 * | aptos     | Aptos      | Curve25519 | 5 EddsaSha512       |
 * | mvx       | MultiversX | Curve25519 | 5 EddsaSha512       |
 */
const CHAIN_FAMILIES: Record<string, Omit<ChainSigningParams, 'namespace'>> = {
  eip155: { curve: 'Secp256k1', scheme: SignatureScheme.EcdsaKeccak256, chainFamily: 'EVM' },
  tron: { curve: 'Secp256k1', scheme: SignatureScheme.EcdsaKeccak256, chainFamily: 'Tron' },
  bip122: { curve: 'Secp256k1', scheme: SignatureScheme.EcdsaDoubleSha256, chainFamily: 'Bitcoin' },
  solana: { curve: 'Curve25519', scheme: SignatureScheme.EddsaSha512, chainFamily: 'Solana' },
  sui: { curve: 'Curve25519', scheme: SignatureScheme.EddsaSha512, chainFamily: 'Sui' },
  cosmos: { curve: 'Secp256k1', scheme: SignatureScheme.EcdsaSha256, chainFamily: 'Cosmos' },
  // Filecoin secp256k1 signs blake2b-256 of the message → scheme 4. (Resolves
  // the odws §3.6 ambiguity: it is NOT sha256.)
  fil: { curve: 'Secp256k1', scheme: SignatureScheme.EcdsaBlake2b256, chainFamily: 'Filecoin' },
  // VeChain Thor also hashes with blake2b-256 → scheme 4; address is EVM-style.
  vechain: { curve: 'Secp256k1', scheme: SignatureScheme.EcdsaBlake2b256, chainFamily: 'VeChain' },
  // Avalanche X/P-chain signs secp256k1 over sha256 → scheme 1. (C-chain is eip155.)
  avalanche: { curve: 'Secp256k1', scheme: SignatureScheme.EcdsaSha256, chainFamily: 'Avalanche' },
  // ed25519 families (sign the message with ed25519 → scheme 5).
  stellar: { curve: 'Curve25519', scheme: SignatureScheme.EddsaSha512, chainFamily: 'Stellar' },
  algorand: { curve: 'Curve25519', scheme: SignatureScheme.EddsaSha512, chainFamily: 'Algorand' },
  aptos: { curve: 'Curve25519', scheme: SignatureScheme.EddsaSha512, chainFamily: 'Aptos' },
  mvx: { curve: 'Curve25519', scheme: SignatureScheme.EddsaSha512, chainFamily: 'MultiversX' },
  ton: { curve: 'Curve25519', scheme: SignatureScheme.EddsaSha512, chainFamily: 'TON' },
  casper: { curve: 'Curve25519', scheme: SignatureScheme.EddsaSha512, chainFamily: 'Casper' },
  tezos: { curve: 'Curve25519', scheme: SignatureScheme.EddsaSha512, chainFamily: 'Tezos' },
  iota: { curve: 'Curve25519', scheme: SignatureScheme.EddsaSha512, chainFamily: 'IOTA' },
  near: { curve: 'Curve25519', scheme: SignatureScheme.EddsaSha512, chainFamily: 'NEAR' },
  // Substrate via ed25519 accounts (SS58). sr25519 (the Polkadot default) needs
  // Schnorrkel/Ristretto, deferred like Taproot.
  polkadot: { curve: 'Curve25519', scheme: SignatureScheme.EddsaSha512, chainFamily: 'Substrate' },
}

/** All supported CAIP-2 namespaces. */
export const SUPPORTED_NAMESPACES: readonly string[] = Object.keys(CHAIN_FAMILIES)

/**
 * Parse a CAIP-2 chain id into `{ namespace, reference }`.
 * @example parseChainId("eip155:1") → { namespace: "eip155", reference: "1" }
 * @throws {ChainIdParseError} when the id is malformed.
 */
export function parseChainId(chainId: string): { namespace: string; reference: string } {
  const colon = chainId.indexOf(':')
  if (colon <= 0 || colon === chainId.length - 1) {
    throw new ChainIdParseError(chainId)
  }
  return { namespace: chainId.slice(0, colon), reference: chainId.slice(colon + 1) }
}

/**
 * Resolve signing parameters for a CAIP-2 chain id.
 * @throws {ChainIdParseError} when the id is malformed.
 * @throws {UnsupportedChainError} when the namespace is not supported.
 */
export function resolveChainParams(chainId: string): ChainSigningParams {
  const { namespace } = parseChainId(chainId)
  const family = CHAIN_FAMILIES[namespace]
  if (!family) throw new UnsupportedChainError(chainId, SUPPORTED_NAMESPACES)
  return { namespace, ...family }
}

/** Whether a CAIP-2 chain id is supported (does not throw). */
export function isChainSupported(chainId: string): boolean {
  try {
    resolveChainParams(chainId)
    return true
  } catch {
    return false
  }
}

/** All supported chains with their signing parameters. */
export function getSupportedChains(): ChainSigningParams[] {
  return Object.entries(CHAIN_FAMILIES).map(([namespace, params]) => ({ namespace, ...params }))
}

/**
 * Namespaces that use a given curve. A single dWallet on that curve can sign for
 * every chain in the returned list.
 */
export function namespacesForCurve(curve: CurveName): string[] {
  return Object.entries(CHAIN_FAMILIES)
    .filter(([, params]) => params.curve === curve)
    .map(([namespace]) => namespace)
}
