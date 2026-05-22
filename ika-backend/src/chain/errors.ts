// Errors for the multi-chain layer. Named so the HTTP layer (routes.ts) maps
// them to 4xx via its `KNOWN_4XX` table instead of leaking a 500. The messages
// are safe to surface to the client (no internal detail, no secrets).

/** A CAIP-2 chain id was malformed (missing/empty namespace or reference). */
export class ChainIdParseError extends Error {
  constructor(chainId: string) {
    super(`invalid CAIP-2 chain id: ${chainId} (expected "namespace:reference", e.g. "eip155:1")`)
    this.name = 'ChainIdParseError'
  }
}

/** A chain whose namespace Andromeda does not (yet) support for signing/derivation. */
export class UnsupportedChainError extends Error {
  constructor(chainId: string, supported: readonly string[]) {
    super(`unsupported chain: ${chainId}. Supported namespaces: ${supported.join(', ')}`)
    this.name = 'UnsupportedChainError'
  }
}

/** The public key's length/shape does not match what the target curve expects. */
export class InvalidPublicKeyError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'InvalidPublicKeyError'
  }
}
