package oraclerelay

import (
	"encoding/binary"

	"github.com/gagliardetto/solana-go"
)

// Instruction discriminators (mirror contracts/pyth-adapter/src/lib.rs).
const (
	discInitAdapter       uint8 = 0
	discInitFeedCache     uint8 = 1
	discRefreshFeed       uint8 = 2
	discTransferAuthority uint8 = 3
	discSetGlobalPause    uint8 = 4
	discSetFeedPause      uint8 = 5
)

// FeedCache canonical offsets (the 64-byte ABI read by policy-engine).
const (
	fcFeedID         = 0
	fcPrice          = 32
	fcConfidence     = 40
	fcPublishTime    = 56
	canonicalViewLen = 64
)

var (
	seedAdapterConfig = []byte("adapter_config")
	seedFeedCache     = []byte("feed_cache")
)

// AdapterConfigPDA derives the singleton config PDA.
func AdapterConfigPDA(programID solana.PublicKey) (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress([][]byte{seedAdapterConfig}, programID)
}

// FeedCachePDA derives a feed's cache PDA from its 32-byte feed id.
func FeedCachePDA(programID solana.PublicKey, feedID [32]byte) (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress([][]byte{seedFeedCache, feedID[:]}, programID)
}

// BuildCanonicalView assembles the 64-byte canonical price view exactly as the
// on-chain `refresh_feed` writes it (used by the drift test).
func BuildCanonicalView(feedID [32]byte, price int64, conf uint64, publishTime int64) [canonicalViewLen]byte {
	var v [canonicalViewLen]byte
	copy(v[fcFeedID:fcFeedID+32], feedID[:])
	binary.LittleEndian.PutUint64(v[fcPrice:fcPrice+8], uint64(price))
	binary.LittleEndian.PutUint64(v[fcConfidence:fcConfidence+8], conf)
	// [48..56] reserved stays zero.
	binary.LittleEndian.PutUint64(v[fcPublishTime:fcPublishTime+8], uint64(publishTime))
	return v
}

// InitFeedCacheIx builds `init_feed_cache(feed_id, bump)`. Permissionless:
// `payer` only funds the rent (and is the tx fee payer). No authority signer.
func InitFeedCacheIx(programID, config, feedCache, payer solana.PublicKey, feedID [32]byte, bump uint8) solana.Instruction {
	data := make([]byte, 0, 1+32+1)
	data = append(data, discInitFeedCache)
	data = append(data, feedID[:]...)
	data = append(data, bump)
	accounts := solana.AccountMetaSlice{
		{PublicKey: config, IsSigner: false, IsWritable: false},
		{PublicKey: feedCache, IsSigner: false, IsWritable: true},
		{PublicKey: payer, IsSigner: true, IsWritable: true},
		{PublicKey: solana.SysVarRentPubkey, IsSigner: false, IsWritable: false},
		{PublicKey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
	}
	return solana.NewInstruction(programID, accounts, data)
}

// RefreshFeedIx builds `refresh_feed`. Permissionless: no signer in the ix; the
// tx fee payer (any funded key) pays. Integrity comes from on-chain Pyth
// verification, not from who calls it.
func RefreshFeedIx(programID, config, feedCache, priceUpdate solana.PublicKey) solana.Instruction {
	accounts := solana.AccountMetaSlice{
		{PublicKey: config, IsSigner: false, IsWritable: false},
		{PublicKey: feedCache, IsSigner: false, IsWritable: true},
		{PublicKey: priceUpdate, IsSigner: false, IsWritable: false},
		{PublicKey: solana.SysVarClockPubkey, IsSigner: false, IsWritable: false},
	}
	return solana.NewInstruction(programID, accounts, []byte{discRefreshFeed})
}

// SetFeedPauseIx builds `set_feed_pause(paused)`. signer is authority OR backup.
func SetFeedPauseIx(programID, config, feedCache, signer solana.PublicKey, paused bool) solana.Instruction {
	p := byte(0)
	if paused {
		p = 1
	}
	accounts := solana.AccountMetaSlice{
		{PublicKey: config, IsSigner: false, IsWritable: false},
		{PublicKey: feedCache, IsSigner: false, IsWritable: true},
		{PublicKey: signer, IsSigner: true, IsWritable: false},
	}
	return solana.NewInstruction(programID, accounts, []byte{discSetFeedPause, p})
}
