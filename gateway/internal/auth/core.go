// Package auth mirrors `contracts/auth/` (Rust crate `andromeda_auth`) byte
// for byte. Every challenge / precompile invocation produced by this package
// matches what the on-chain Quasar policies recompute. Keep this file in sync
// with `contracts/auth/src/lib.rs` — the canonical layout reference is there.
package auth

// Member slot schemes (mirror andromeda_auth::SCHEME_*).
const (
	SchemeEd25519   uint8 = 0
	SchemeSecp256k1 uint8 = 1
	SchemeSecp256r1 uint8 = 2
	SchemeWebAuthn  uint8 = 3
)

// MemberSlotLen is the canonical length of the [scheme, ...identifier]
// member slot encoded on-chain.
const MemberSlotLen = 34

// IDLenForScheme returns the identifier length for a scheme. Matches
// `andromeda_auth::id_len_for_scheme`.
func IDLenForScheme(scheme uint8) (int, error) {
	switch scheme {
	case SchemeEd25519:
		return 32, nil
	case SchemeSecp256k1:
		return 20, nil
	case SchemeSecp256r1, SchemeWebAuthn:
		return 33, nil
	default:
		return 0, ErrUnsupportedScheme
	}
}

// BuildMemberSlot canonicalizes (scheme, identifier) into a 34-byte slot
// with zero padding. Errors if the identifier length doesn't match the
// scheme. Matches `andromeda_auth::build_member_slot`.
func BuildMemberSlot(scheme uint8, identifier []byte) ([MemberSlotLen]byte, error) {
	var slot [MemberSlotLen]byte
	expected, err := IDLenForScheme(scheme)
	if err != nil {
		return slot, err
	}
	if len(identifier) != expected {
		return slot, ErrInvalidIdentifierLen
	}
	slot[0] = scheme
	copy(slot[1:], identifier)
	return slot, nil
}

// ValidateSlot confirms a stored slot is well-formed (known scheme + zero
// padding past the identifier). Matches `andromeda_auth::validate_slot`.
func ValidateSlot(slot [MemberSlotLen]byte) error {
	idLen, err := IDLenForScheme(slot[0])
	if err != nil {
		return err
	}
	for i := 1 + idLen; i < MemberSlotLen; i++ {
		if slot[i] != 0 {
			return ErrInvalidSlotLayout
		}
	}
	return nil
}
