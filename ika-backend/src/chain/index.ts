// Multi-chain layer: CAIP-2 → Ika signing params, chain-specific message
// envelopes, and chain-native address derivation. Ported/adapted from `odws`.
// See the individual modules for details.

export {
  type ChainSigningParams,
  SUPPORTED_NAMESPACES,
  parseChainId,
  resolveChainParams,
  isChainSupported,
  getSupportedChains,
  namespacesForCurve,
} from './chains.js'
export { type MessageKind, preProcessForChain } from './preprocess.js'
export { type DerivedAccount, deriveAddress, deriveAccountsForCurve } from './address.js'
export { schemeDigest } from './digest.js'
export { type PreparedMessage, prepareMessage, prepareZcashMessage } from './prepare.js'
export {
  type ZcashTxFields,
  type ZcashTxInput,
  type ZcashTxOutput,
  type ZcashSignTarget,
  ZCASH_BRANCH_NU5,
  ZCASH_BRANCH_SAPLING,
} from './zcash.js'
export { ChainIdParseError, UnsupportedChainError, InvalidPublicKeyError } from './errors.js'
