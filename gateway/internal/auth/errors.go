package auth

import "errors"

var (
	ErrUnsupportedScheme    = errors.New("unsupported member-slot scheme")
	ErrInvalidIdentifierLen = errors.New("identifier length does not match scheme")
	ErrInvalidSlotLayout    = errors.New("invalid member-slot layout (non-zero padding)")
	ErrInvalidSignatureLen  = errors.New("invalid signature length")
	ErrInvalidPubkeyLen     = errors.New("invalid pubkey length")
	ErrInvalidEthAddrLen    = errors.New("invalid eth_address length")
)
