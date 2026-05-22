package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/gagliardetto/solana-go"
)

// Challenge domains (mirror of contracts/policy-engine/src/lib.rs §6.1).
var (
	DomainInitV1     = []byte("andromeda::policy-engine::init::v1")
	DomainV3         = []byte("andromeda::policy-engine::v3")
	DomainRequestV1  = []byte("andromeda::policy-engine::request::v1")
	DomainRequestV2  = []byte("andromeda::policy-engine::request::v2")
	DomainRecoveryV3 = []byte("andromeda::policy-engine::recovery::v3")
)

// Op tags (mirror of contracts/policy-engine/src/lib.rs §6.3).
var (
	OpInit                = []byte("init")
	OpInitWithRecovery    = []byte("init-with-recovery")
	OpAddAllowlist        = []byte("add-rule-allowlist")
	OpAllowlistAddDest    = []byte("allowlist-add-destination")
	OpAllowlistRemoveDest = []byte("allowlist-remove-destination")
	OpAddOracle           = []byte("add-rule-oracle")
	OpOracleAddFeed       = []byte("oracle-add-feed")
	OpAddSpendingUsd      = []byte("add-rule-spending-usd")
	OpSpendingUsdAddFeed  = []byte("spending-usd-add-feed")
	OpPause               = []byte("pause")
	OpResume              = []byte("resume")
	OpRevoke              = []byte("revoke")
	OpPrimaryRecover      = []byte("primary-recover")
	// C2 audit fix (2026-05-16): binds the disc 126 admin challenge.
	OpUpdateFheAuth = []byte("update-rule-fhe-authorities")
)

// AdminChallengeInput carries every byte the on-chain handler hashes for a
// clear-signing v2 admin challenge (mirror of `admin_challenge` in
// contracts/policy-engine/src/lib.rs).
type AdminChallengeInput struct {
	OpTag          []byte
	HumanMessage   []byte
	Engine         solana.PublicKey
	DWallet        solana.PublicKey
	RuleKind       uint8
	RuleIndex      uint8
	RuleGeneration uint32
	ExpectedNonce  uint64
	ConfigHash     [32]byte
	OwnerSlot      [MemberSlotLen]byte
	Extras         [][]byte
}

// Preimage returns the canonical byte sequence that gets hashed. The on-chain
// handler recomputes this exact preimage and matches against the precompile
// signature.
func (in *AdminChallengeInput) Preimage() ([]byte, error) {
	if len(in.HumanMessage) > 0xFFFF {
		return nil, fmt.Errorf("policy: human_message > u16 max (%d bytes)", len(in.HumanMessage))
	}
	var buf bytes.Buffer
	buf.Write(DomainV3)
	buf.Write(in.OpTag)
	// human_message_len_u16_le
	var hl [2]byte
	binary.LittleEndian.PutUint16(hl[:], uint16(len(in.HumanMessage)))
	buf.Write(hl[:])
	buf.Write(in.HumanMessage)
	buf.Write(in.Engine.Bytes())
	buf.Write(in.DWallet.Bytes())
	buf.WriteByte(in.RuleKind)
	buf.WriteByte(in.RuleIndex)
	var gen [4]byte
	binary.LittleEndian.PutUint32(gen[:], in.RuleGeneration)
	buf.Write(gen[:])
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], in.ExpectedNonce)
	buf.Write(nonce[:])
	buf.Write(in.ConfigHash[:])
	buf.Write(in.OwnerSlot[:])
	// M2 audit fix (2026-05-16): each extra is prefixed with u16 LE length so
	// two variable-length extras can't be silently concatenated into an
	// ambiguous byte string. Mirror of `admin_challenge` in
	// contracts/policy-engine/src/lib.rs.
	for _, e := range in.Extras {
		if len(e) > 0xFFFF {
			return nil, fmt.Errorf("policy: admin extra > u16 max (%d bytes)", len(e))
		}
		var el [2]byte
		binary.LittleEndian.PutUint16(el[:], uint16(len(e)))
		buf.Write(el[:])
		buf.Write(e)
	}
	return buf.Bytes(), nil
}

// Hash returns the SHA-256 challenge bytes. Off-chain wallets sign these
// 32 bytes; on-chain precompiles validate against the same bytes recomputed
// from the canonical inputs.
func (in *AdminChallengeInput) Hash() ([32]byte, error) {
	pre, err := in.Preimage()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(pre), nil
}

// RequestMetadataDigestInput carries the inputs to the runtime
// request_metadata_digest (ABI §6.4). Not human-signed — gateway computes,
// program recomputes and asserts equality.
type RequestMetadataDigestInput struct {
	Engine          solana.PublicKey
	DWallet         solana.PublicKey
	MessageDigest   [32]byte
	Destination     [32]byte
	UserPubkey      [32]byte
	SignatureScheme uint16
	Path            uint8 // AppliesNormal | AppliesRecovery | AppliesSession
	RulesGeneration uint32
	// Update 3 (ABI V2): the asset amount (base units) and its index in the
	// active KIND_SPENDING_USD allowlist. Bound into the digest so a USD
	// spending limit is enforced end-to-end. Zero for non-spending requests
	// and for the session path (matches the on-chain 0/0 binding).
	Amount     uint64
	AssetIndex uint8
}

func (in *RequestMetadataDigestInput) Preimage() []byte {
	var buf bytes.Buffer
	buf.Write(DomainRequestV2)
	buf.WriteString("request-signature")
	buf.Write(in.Engine.Bytes())
	buf.Write(in.DWallet.Bytes())
	buf.Write(in.MessageDigest[:])
	buf.Write(in.Destination[:])
	buf.Write(in.UserPubkey[:])
	var scheme [2]byte
	binary.LittleEndian.PutUint16(scheme[:], in.SignatureScheme)
	buf.Write(scheme[:])
	buf.WriteByte(in.Path)
	var gen [4]byte
	binary.LittleEndian.PutUint32(gen[:], in.RulesGeneration)
	buf.Write(gen[:])
	var amt [8]byte
	binary.LittleEndian.PutUint64(amt[:], in.Amount)
	buf.Write(amt[:])
	buf.WriteByte(in.AssetIndex)
	return buf.Bytes()
}

func (in *RequestMetadataDigestInput) Hash() [32]byte {
	return sha256.Sum256(in.Preimage())
}

// AllowlistConfigHash computes sha256("allowlist-config-v1" || applies_to ||
// destinations_count || destinations_flat) — the canonical hash stored in
// `RuleHeader.config_hash` and `RuleEntry.config_hash` for the Allowlist
// kind. `destinationsFlat` must be exactly 1024 bytes (32 destinations × 32).
func AllowlistConfigHash(appliesTo uint8, destinationsCount uint8, destinationsFlat []byte) ([32]byte, error) {
	if len(destinationsFlat) != 1024 {
		return [32]byte{}, fmt.Errorf("policy: destinations_flat must be 1024 bytes, got %d", len(destinationsFlat))
	}
	h := sha256.New()
	h.Write([]byte("allowlist-config-v1"))
	h.Write([]byte{appliesTo})
	h.Write([]byte{destinationsCount})
	h.Write(destinationsFlat)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// OracleConfigHash computes sha256("oracle-config-v1" || applies_to ||
// feeds_count || freshness_seconds_div16 || min_confidence_bps_div4 ||
// feeds_flat) — the canonical hash stored in `OracleRule.config_hash` and
// `RuleEntry.config_hash` for the Oracle kind. `feedsFlat` must be exactly
// 320 bytes (4 feeds × 80). Mirror of the on-chain `add_rule_oracle` /
// `update_rule_oracle_add_feed` handlers in contracts/policy-engine/src/lib.rs.
func OracleConfigHash(appliesTo, feedsCount, freshnessSecondsDiv16, minConfidenceBpsDiv4 uint8, feedsFlat []byte) ([32]byte, error) {
	if len(feedsFlat) != MaxOracleFeeds*OracleFeedBytes {
		return [32]byte{}, fmt.Errorf("policy: feeds_flat must be %d bytes, got %d",
			MaxOracleFeeds*OracleFeedBytes, len(feedsFlat))
	}
	h := sha256.New()
	h.Write([]byte("oracle-config-v1"))
	h.Write([]byte{appliesTo, feedsCount, freshnessSecondsDiv16, minConfidenceBpsDiv4})
	h.Write(feedsFlat)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// SpendingUsdConfigHash computes sha256("spending-usd-config-v1" || applies_to
// || feeds_count || freshness_seconds_div16 || max_confidence_bps_div4 ||
// caps(24) || feeds_flat) where caps = LE(max_per_tx ‖ max_per_day ‖
// max_per_week). Mirror of the on-chain `add_rule_spending_usd` /
// `update_rule_spending_usd_add_feed` handlers. `feedsFlat` must be exactly
// MaxSpendingUsdFeeds*SpendingUsdFeedBytes (528) bytes.
func SpendingUsdConfigHash(appliesTo, feedsCount, freshnessSecondsDiv16, maxConfidenceBpsDiv4 uint8, maxPerTx, maxPerDay, maxPerWeek uint64, feedsFlat []byte) ([32]byte, error) {
	if len(feedsFlat) != MaxSpendingUsdFeeds*SpendingUsdFeedBytes {
		return [32]byte{}, fmt.Errorf("policy: spending feeds_flat must be %d bytes, got %d",
			MaxSpendingUsdFeeds*SpendingUsdFeedBytes, len(feedsFlat))
	}
	h := sha256.New()
	h.Write([]byte("spending-usd-config-v1"))
	h.Write([]byte{appliesTo, feedsCount, freshnessSecondsDiv16, maxConfidenceBpsDiv4})
	var caps [24]byte
	binary.LittleEndian.PutUint64(caps[0:8], maxPerTx)
	binary.LittleEndian.PutUint64(caps[8:16], maxPerDay)
	binary.LittleEndian.PutUint64(caps[16:24], maxPerWeek)
	h.Write(caps[:])
	h.Write(feedsFlat)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// HumanMessageSpendingUsdAdd renders the clear-signing v2 line for disc 18.
// Byte-for-byte mirror of `spending_usd_add_message` in
// contracts/auth/src/human_message.rs.
func HumanMessageSpendingUsdAdd(maxPerTx, maxPerDay, maxPerWeek uint64, engine, dwallet solana.PublicKey) []byte {
	var buf bytes.Buffer
	buf.WriteString("Add USD spending limit policy ")
	buf.WriteString(engine.String())
	buf.WriteString(" for dWallet ")
	buf.WriteString(dwallet.String())
	buf.WriteString(" maxPerTx ")
	buf.WriteString(strconv.FormatUint(maxPerTx, 10))
	buf.WriteString(" maxPerDay ")
	buf.WriteString(strconv.FormatUint(maxPerDay, 10))
	buf.WriteString(" maxPerWeek ")
	buf.WriteString(strconv.FormatUint(maxPerWeek, 10))
	return buf.Bytes()
}

// HumanMessageSpendingUsdAddFeed renders the clear-signing v2 line for disc 19.
// Byte-for-byte mirror of `spending_usd_add_feed_message` in
// contracts/auth/src/human_message.rs.
func HumanMessageSpendingUsdAddFeed(feedCache solana.PublicKey, decimals uint8, engine, dwallet solana.PublicKey) []byte {
	var buf bytes.Buffer
	buf.WriteString("Add spending feed ")
	buf.WriteString(feedCache.String())
	buf.WriteString(" decimals ")
	buf.WriteString(strconv.FormatUint(uint64(decimals), 10))
	buf.WriteString(" on USD spending policy ")
	buf.WriteString(engine.String())
	buf.WriteString(" for dWallet ")
	buf.WriteString(dwallet.String())
	return buf.Bytes()
}

// HumanMessageOracleAddFeed renders the clear-signing v2 line for disc 122:
//
//	"Add oracle feed <b58(feed)> owner <b58(owner)> min <min> max <max> on oracle policy <b58(engine)> for dWallet <b58(dwallet)>"
//
// Byte-for-byte mirror of `oracle_add_feed_message` in
// contracts/auth/src/human_message.rs — any drift rejects the signature.
func HumanMessageOracleAddFeed(feedAccount, feedOwner solana.PublicKey, minQ64, maxQ64 int64, engine, dwallet solana.PublicKey) []byte {
	var buf bytes.Buffer
	buf.WriteString("Add oracle feed ")
	buf.WriteString(feedAccount.String())
	buf.WriteString(" owner ")
	buf.WriteString(feedOwner.String())
	buf.WriteString(" min ")
	buf.WriteString(strconv.FormatInt(minQ64, 10))
	buf.WriteString(" max ")
	buf.WriteString(strconv.FormatInt(maxQ64, 10))
	buf.WriteString(" on oracle policy ")
	buf.WriteString(engine.String())
	buf.WriteString(" for dWallet ")
	buf.WriteString(dwallet.String())
	return buf.Bytes()
}

// ─── Human-message renderers (mirror of contracts/auth/src/human_message.rs) ─

// HumanMessageAllowlistAddDestination renders the clear-signing v2 line:
//
//	"Allow destination <hex(dest)> on allowlist policy <b58(engine)> for dWallet <b58(dwallet)>"
//
// The on-chain handler renders the same string and embeds it length-prefixed
// in the challenge — any drift between this Go renderer and the Rust one in
// `contracts/auth/src/human_message.rs::allowlist_add_destination_message`
// will produce a different challenge hash and reject the signature.
func HumanMessageAllowlistAddDestination(dest [32]byte, engine, dwallet solana.PublicKey) []byte {
	var buf bytes.Buffer
	buf.WriteString("Allow destination ")
	buf.WriteString(toHexLower(dest[:]))
	buf.WriteString(" on allowlist policy ")
	buf.WriteString(engine.String())
	buf.WriteString(" for dWallet ")
	buf.WriteString(dwallet.String())
	return buf.Bytes()
}

// HumanMessageAllowlistRemoveDestination — symmetric of the above.
func HumanMessageAllowlistRemoveDestination(dest [32]byte, engine, dwallet solana.PublicKey) []byte {
	var buf bytes.Buffer
	buf.WriteString("Block destination ")
	buf.WriteString(toHexLower(dest[:]))
	buf.WriteString(" on allowlist policy ")
	buf.WriteString(engine.String())
	buf.WriteString(" for dWallet ")
	buf.WriteString(dwallet.String())
	return buf.Bytes()
}

// HumanMessageAllowlistPause — currently reused by `add_rule_allowlist` in
// the on-chain handler (placeholder until a dedicated renderer is added in
// `contracts/auth/src/human_message.rs`). Update both sides together.
func HumanMessageAllowlistPause(engine, dwallet solana.PublicKey) []byte {
	var buf bytes.Buffer
	buf.WriteString("Pause allowlist policy ")
	buf.WriteString(engine.String())
	buf.WriteString(" for dWallet ")
	buf.WriteString(dwallet.String())
	return buf.Bytes()
}

const hexAlphabet = "0123456789abcdef"

func toHexLower(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexAlphabet[v>>4]
		out[i*2+1] = hexAlphabet[v&0x0F]
	}
	return string(out)
}
