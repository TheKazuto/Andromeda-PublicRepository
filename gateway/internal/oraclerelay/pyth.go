// Package oraclerelay is the gateway's leader-elected crank that keeps the
// on-chain `pyth-adapter` FeedCache PDAs fresh.
//
// MVP model (sponsored crank): each configured feed points at a Pyth
// `PriceUpdateV2` account that is kept fresh off-band (a Pyth-sponsored price
// feed account, or any pusher). The crank reads that account over RPC and,
// when its `publish_time` advances, sends `refresh_feed` so the adapter
// re-writes the canonical 64-byte view the policy-engine consumes. The
// pull/Hermes `post_update` model (VAA + ALT, same-tx update) is Fase 7.
//
// This file is the parser + normaliser. It is a byte-for-byte mirror of the
// on-chain Rust (`contracts/pyth-adapter/src/lib.rs`) and the offsets frozen
// in `fixtures/pyth/pyth_fixtures.json`; the drift is guarded by the Rust SBF
// test and this package's `pyth_test.go`.
package oraclerelay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// PriceUpdateV2 layout (Anchor account, `Full` verification — confirmed live).
const (
	priceUpdateV2DiscLen      = 8
	puVerificationLevel       = 40
	puFeedID                  = 41
	puPrice                   = 73
	puConf                    = 81
	puExponent                = 89
	puPublishTime             = 93
	PriceUpdateV2Len          = 134
	verificationFull     byte = 1
	// CanonicalExponent is the fixed-point exponent of the canonical view:
	// stored value = real_price * 1e8.
	CanonicalExponent = -8
)

var priceUpdateV2Discriminator = [priceUpdateV2DiscLen]byte{
	0x22, 0xf1, 0x23, 0x63, 0x9d, 0x7e, 0xf4, 0xcd,
}

// ErrPriceOverflow mirrors the on-chain AdapterError::PriceOverflow.
var ErrPriceOverflow = errors.New("oraclerelay: canonical value out of int64 range")

// PriceUpdate is the subset of a Pyth PriceUpdateV2 the adapter consumes.
type PriceUpdate struct {
	FeedID      [32]byte
	Price       int64
	Conf        uint64
	Exponent    int32
	PublishTime int64
}

// ParsePriceUpdateV2 validates and decodes a `Full` PriceUpdateV2 account. It
// applies the same gates as the on-chain program (discriminator, verification
// level, length) so the crank never sends a refresh that would revert.
func ParsePriceUpdateV2(data []byte) (*PriceUpdate, error) {
	if len(data) < PriceUpdateV2Len {
		return nil, fmt.Errorf("price_update too short: %d < %d", len(data), PriceUpdateV2Len)
	}
	if !bytes.Equal(data[0:priceUpdateV2DiscLen], priceUpdateV2Discriminator[:]) {
		return nil, errors.New("price_update discriminator mismatch (not PriceUpdateV2)")
	}
	if data[puVerificationLevel] != verificationFull {
		return nil, errors.New("price_update is not Full-verified")
	}
	var pu PriceUpdate
	copy(pu.FeedID[:], data[puFeedID:puFeedID+32])
	pu.Price = int64(binary.LittleEndian.Uint64(data[puPrice : puPrice+8]))
	pu.Conf = binary.LittleEndian.Uint64(data[puConf : puConf+8])
	pu.Exponent = int32(binary.LittleEndian.Uint32(data[puExponent : puExponent+4]))
	pu.PublishTime = int64(binary.LittleEndian.Uint64(data[puPublishTime : puPublishTime+8]))
	return &pu, nil
}

// ToCanonicalI64 mirrors the on-chain `to_canonical_i64`: decimal-1e8 fixed
// point, `canonical = value * 10^(expo+8)`, truncating toward zero when
// `expo < -8`.
func ToCanonicalI64(value int64, expo int32) (int64, error) {
	shift := int(expo) + 8
	if shift >= 0 {
		scale := pow10(shift)
		prod := new(big.Int).Mul(big.NewInt(value), scale)
		if !prod.IsInt64() {
			return 0, ErrPriceOverflow
		}
		return prod.Int64(), nil
	}
	scale := pow10(-shift)
	return new(big.Int).Quo(big.NewInt(value), scale).Int64(), nil
}

// ToCanonicalU64 is the unsigned variant (confidence).
func ToCanonicalU64(value uint64, expo int32) (uint64, error) {
	shift := int(expo) + 8
	bv := new(big.Int).SetUint64(value)
	if shift >= 0 {
		prod := new(big.Int).Mul(bv, pow10(shift))
		if !prod.IsUint64() {
			return 0, ErrPriceOverflow
		}
		return prod.Uint64(), nil
	}
	return new(big.Int).Quo(bv, pow10(-shift)).Uint64(), nil
}

func pow10(e int) *big.Int {
	return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(e)), nil)
}
