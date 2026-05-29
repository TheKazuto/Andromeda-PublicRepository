package intents

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"

	"github.com/gagliardetto/solana-go"
)

// chainKindOps groups every per-family operation the orchestrator runs at
// prepare/submit time. Each chainKind plugs one entry in the registry; the
// orchestrator never branches on chainKind directly.
type chainKindOps struct {
	// fromAddress derives the dWallet's address on the source chain (the LI.FI
	// `from` field / fee payer) from the prepare request. Solana: base58 of the
	// Ed25519 key. EVM: the explicit chainNativeAddress the caller supplied.
	fromAddress func(req prepareRequest) (string, *userError)

	// tokenAddress32 canonicalizes a token address into the 32-byte slot the
	// on-chain swap_metadata_digest binds. Solana: base58 pubkey (32 bytes).
	// EVM: 0x-prefixed 20-byte hex, left-padded to 32 bytes. An error here
	// makes the caller fall back to NORMAL signing (not a hard failure).
	tokenAddress32 func(token string) ([32]byte, error)
}

// chainKinds is the gateway-side registry: every chainKind the public API
// accepts is registered here. The intents-backend keeps a parallel ChainAdapter
// registry — both surfaces must list the same kinds (verified by tests).
var chainKinds = map[string]chainKindOps{
	"solana": {
		fromAddress:    resolveSolanaFromAddress,
		tokenAddress32: solanaTokenAddress32,
	},
	"evm": {
		fromAddress:    resolveEVMFromAddress,
		tokenAddress32: evmTokenAddress32,
	},
	"sui": {
		fromAddress:    resolveSuiFromAddress,
		tokenAddress32: suiTokenAddress32,
	},
}

// registeredChainKinds is the sorted list of chainKinds the gateway serves.
// Used by /v1/intents/capabilities so the public surface always matches code.
func registeredChainKinds() []string {
	out := make([]string, 0, len(chainKinds))
	for k := range chainKinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isRegisteredChainKind reports whether a chainKind is supported. Returned to
// the handler so a clear 400 fires before any upstream call.
func isRegisteredChainKind(kind string) bool {
	_, ok := chainKinds[kind]
	return ok
}

// resolveFromAddress dispatches to the right per-family resolver. Returns a
// user error if the kind is unknown (defense in depth: the handler validates
// first, but a stale request could still reach here in tests).
func resolveFromAddress(req prepareRequest) (string, *userError) {
	ops, ok := chainKinds[req.ChainKind]
	if !ok {
		return "", &userError{http.StatusBadRequest, "invalid_field", "unsupported chainKind"}
	}
	return ops.fromAddress(req)
}

// parseTokenAddress32 dispatches to the right per-family canonicalizer.
// Caller falls back to NORMAL signing on error.
func parseTokenAddress32(token, chainKind string) ([32]byte, error) {
	var out [32]byte
	ops, ok := chainKinds[chainKind]
	if !ok {
		return out, fmt.Errorf("unsupported chainKind %q", chainKind)
	}
	return ops.tokenAddress32(token)
}

// resolveSolanaFromAddress derives the dWallet's base58 Solana address from its
// 32-byte Ed25519 public key.
func resolveSolanaFromAddress(req prepareRequest) (string, *userError) {
	pkBytes, derr := hex.DecodeString(req.DwalletPublicKeyHex)
	if derr != nil || len(pkBytes) != 32 {
		return "", &userError{http.StatusBadRequest, "invalid_field", "dwalletPublicKeyHex must be 32-byte hex for Solana"}
	}
	return solana.PublicKeyFromBytes(pkBytes).String(), nil
}

// resolveEVMFromAddress returns the explicit chainNativeAddress the client
// supplied. The dWallet cannot sign for an address it does not control, so a
// wrong value simply fails the swap — not a security hole.
func resolveEVMFromAddress(req prepareRequest) (string, *userError) {
	if req.ChainNativeAddress == "" {
		return "", &userError{http.StatusBadRequest, "invalid_field", "chainNativeAddress (the dWallet's 0x address) is required for EVM"}
	}
	return req.ChainNativeAddress, nil
}

// solanaTokenAddress32 decodes a base58 Solana pubkey into its 32-byte form.
func solanaTokenAddress32(token string) ([32]byte, error) {
	var out [32]byte
	pk, err := solana.PublicKeyFromBase58(token)
	if err != nil {
		return out, fmt.Errorf("solana token %q: %w", token, err)
	}
	copy(out[:], pk.Bytes())
	return out, nil
}

// evmTokenAddress32 normalizes a 20-byte EVM token address into a 32-byte slot
// (left-padded with 12 zero bytes). Accepts both 0x-prefixed and bare hex.
func evmTokenAddress32(token string) ([32]byte, error) {
	var out [32]byte
	s := token
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	if len(s) != 40 {
		return out, fmt.Errorf("evm token %q: expected 20-byte hex", token)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("evm token %q: %w", token, err)
	}
	copy(out[12:], b) // left-pad 12 zero bytes, then 20-byte address
	return out, nil
}

// resolveSuiFromAddress returns the explicit Sui address the client supplied
// via chainNativeAddress (derived by the dWallet creation flow as
// blake2b256(0x00 || pubkey)). The dWallet cannot sign for a different sender,
// so a wrong value simply fails at execution — not a security hole.
func resolveSuiFromAddress(req prepareRequest) (string, *userError) {
	if req.ChainNativeAddress == "" {
		return "", &userError{http.StatusBadRequest, "invalid_field", "chainNativeAddress (the dWallet's 0x… Sui address) is required for Sui"}
	}
	return req.ChainNativeAddress, nil
}

// suiTokenAddress32 hashes a Sui Move coin type ("0x...::module::Coin") into a
// 32-byte slot. Sui token "addresses" are full Move type strings, not raw
// 32-byte object IDs, so we sha256 the canonical form to bind it into the
// on-chain swap_metadata_digest. The on-chain handler renders the bytes only
// in the human message — never for value comparison — so any stable hash is
// sufficient (the same function runs on the prepare and submit legs, so the
// value is internally consistent) and avoids guessing which Move-type
// substring to slice.
func suiTokenAddress32(token string) ([32]byte, error) {
	var out [32]byte
	if token == "" {
		return out, fmt.Errorf("sui token is empty")
	}
	h := sha256.Sum256([]byte(token))
	copy(out[:], h[:])
	return out, nil
}
