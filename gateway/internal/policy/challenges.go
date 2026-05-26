package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/gagliardetto/solana-go"

	"github.com/shinkalabs/andromeda-gateway/internal/humanfmt"
)

// Challenge domains (mirror of contracts/policy-engine/src/lib.rs §6.1).
var (
	DomainInitV1     = []byte("andromeda::policy-engine::init::v1")
	DomainV3         = []byte("andromeda::policy-engine::v3")
	DomainRequestV1  = []byte("andromeda::policy-engine::request::v1")
	DomainRequestV2  = []byte("andromeda::policy-engine::request::v2")
	// Update 7 (2026-05-26): V3 binds swap-specific fields when signing_kind=SWAP.
	DomainRequestV3  = []byte("andromeda::policy-engine::request::v3")
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
	// B1 audit fix (2026-05-25): binds the disc 110 remove_rule admin challenge.
	OpRemoveRule = []byte("remove-rule")
	// Fase 1 (A1, 2026-05-25): binds the NORMAL signing-path owner authorization
	// (disc 1). The owner_slot signs this so the gateway cannot relay a signature
	// without the dWallet owner's consent.
	OpNormalSign = []byte("normal-sign")
	// Update 7 (2026-05-26): swap clear-signing op tag for disc 1 with
	// signing_kind=SIGNING_KIND_SWAP. A wallet showing "Swap X for Y..." produces
	// a distinct challenge hash from a wallet showing "Sign for dWallet..." —
	// the two op tags partition the precompile-verified message space.
	OpSwapSign = []byte("swap-sign")
	// Update 7 (2026-05-26): bundle challenge op tag. When N>=2 message_digests
	// share a single owner signature (EVM approve+swap), each disc 1 uses this
	// op tag and includes its bundle_this_index + other digests so the on-chain
	// handler recomputes the same hash.
	OpBundleSign = []byte("bundle-sign")
	// C2 audit fix (2026-05-16): binds the disc 126 admin challenge.
	OpUpdateFheAuth = []byte("update-rule-fhe-authorities")
)

// Update 7 (2026-05-26) — signing-kind discriminator for disc 1
// (request_signature). Mirror of contracts/policy-engine/src/lib.rs.
const (
	SigningKindNormal uint8 = 0
	SigningKindSwap   uint8 = 1
)

// Update 7 (2026-05-26) — bundle challenge bounds. Mirror of
// contracts/policy-engine/src/lib.rs.
const (
	MinBundleTotal uint8 = 2
	MaxBundleTotal uint8 = 4
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

// ─── Fase 1 (A1) — NORMAL signing-path owner authorization ──────────────────

// HumanMessageNormalSign renders the clear-signing line the dWallet owner reads
// before authorizing a normal-path signature. Byte-for-byte mirror of
// `normal_sign_message` in contracts/auth/src/human_message.rs.
func HumanMessageNormalSign(dwallet solana.PublicKey, destination [32]byte, amount uint64, signatureScheme uint16) []byte {
	var buf bytes.Buffer
	buf.WriteString("Sign for dWallet ")
	buf.WriteString(dwallet.String())
	buf.WriteString(" to ")
	buf.WriteString(toHexLower(destination[:]))
	buf.WriteString(" amount ")
	buf.WriteString(strconv.FormatUint(amount, 10))
	buf.WriteString(" scheme ")
	buf.WriteString(strconv.FormatUint(uint64(signatureScheme), 10))
	return buf.Bytes()
}

// NormalUseChallengeInput carries the inputs the on-chain `normal_use_challenge`
// (disc 1) hashes. The owner signs the resulting 32-byte hash off-chain; the
// gateway relays the precompile invocation. Mirror of `normal_use_challenge` in
// contracts/policy-engine/src/lib.rs.
type NormalUseChallengeInput struct {
	HumanMessage   []byte
	Engine         solana.PublicKey
	DWallet        solana.PublicKey
	MetadataDigest [32]byte
	OwnerSlot      [MemberSlotLen]byte
}

func (in *NormalUseChallengeInput) Preimage() []byte {
	var buf bytes.Buffer
	buf.Write(DomainV3)
	buf.Write(OpNormalSign)
	var hl [2]byte
	binary.LittleEndian.PutUint16(hl[:], uint16(len(in.HumanMessage)))
	buf.Write(hl[:])
	buf.Write(in.HumanMessage)
	buf.Write(in.Engine.Bytes())
	buf.Write(in.DWallet.Bytes())
	buf.Write(in.MetadataDigest[:])
	buf.Write(in.OwnerSlot[:])
	return buf.Bytes()
}

func (in *NormalUseChallengeInput) Hash() [32]byte {
	return sha256.Sum256(in.Preimage())
}

// ─── Update 7 (2026-05-26) — SWAP signing-kind ─────────────────────────────

// HumanMessageSwap renders the clear-signing line the dWallet owner reads
// before authorizing a swap signature (disc 1 with signing_kind=SIGNING_KIND_SWAP).
// Byte-for-byte mirror of `swap_sign_message` in contracts/auth/src/human_message.rs.
//
// Tokens are 32-byte address-padded (mint for Solana, EVM contract zero-padded);
// `chainTag` is ASCII null-padded (e.g. "solana\x00\x00", "evm:1\x00\x00\x00").
func HumanMessageSwap(dwallet solana.PublicKey, fromToken [32]byte, fromAmount uint64, toToken [32]byte, minAmountOut uint64, chainTag [8]byte, signatureScheme uint16) []byte {
	var buf bytes.Buffer
	buf.WriteString("Swap ")
	buf.WriteString(strconv.FormatUint(fromAmount, 10))
	buf.WriteString(" of ")
	buf.WriteString(toHexLower(fromToken[:]))
	buf.WriteString(" for at least ")
	buf.WriteString(strconv.FormatUint(minAmountOut, 10))
	buf.WriteString(" of ")
	buf.WriteString(toHexLower(toToken[:]))
	buf.WriteString(" on ")
	// chain_tag is ASCII null-padded — strip trailing NULs to match the Rust
	// renderer, which stops at the first 0x00 byte.
	tagLen := 0
	for tagLen < len(chainTag) && chainTag[tagLen] != 0 {
		tagLen++
	}
	buf.Write(chainTag[:tagLen])
	buf.WriteString(" for dWallet ")
	buf.WriteString(dwallet.String())
	buf.WriteString(" scheme ")
	buf.WriteString(strconv.FormatUint(uint64(signatureScheme), 10))
	return buf.Bytes()
}

// SwapMetadataDigestInput is the V3 metadata digest binding for the SWAP
// signing path. Extends V2 with the swap-specific fields the on-chain handler
// recomputes when `signing_kind = SIGNING_KIND_SWAP`. Mirror of
// `swap_metadata_digest` in contracts/policy-engine/src/lib.rs.
type SwapMetadataDigestInput struct {
	Engine          solana.PublicKey
	DWallet         solana.PublicKey
	MessageDigest   [32]byte
	Destination     [32]byte
	UserPubkey      [32]byte
	SignatureScheme uint16
	RulesGeneration uint32
	FromAmount      uint64
	AssetIndex      uint8
	FromToken       [32]byte
	ToToken         [32]byte
	MinAmountOut    uint64
	ChainTag        [8]byte
}

func (in *SwapMetadataDigestInput) Preimage() []byte {
	var buf bytes.Buffer
	buf.Write(DomainRequestV3)
	buf.WriteString("request-signature-swap")
	buf.Write(in.Engine.Bytes())
	buf.Write(in.DWallet.Bytes())
	buf.Write(in.MessageDigest[:])
	buf.Write(in.Destination[:])
	buf.Write(in.UserPubkey[:])
	var scheme [2]byte
	binary.LittleEndian.PutUint16(scheme[:], in.SignatureScheme)
	buf.Write(scheme[:])
	// path = PATH_NORMAL (1) — dispatch loop still runs as NORMAL even on the swap path.
	buf.WriteByte(1)
	var gen [4]byte
	binary.LittleEndian.PutUint32(gen[:], in.RulesGeneration)
	buf.Write(gen[:])
	var amt [8]byte
	binary.LittleEndian.PutUint64(amt[:], in.FromAmount)
	buf.Write(amt[:])
	buf.WriteByte(in.AssetIndex)
	buf.Write(in.FromToken[:])
	buf.Write(in.ToToken[:])
	var minOut [8]byte
	binary.LittleEndian.PutUint64(minOut[:], in.MinAmountOut)
	buf.Write(minOut[:])
	buf.Write(in.ChainTag[:])
	return buf.Bytes()
}

func (in *SwapMetadataDigestInput) Hash() [32]byte {
	return sha256.Sum256(in.Preimage())
}

// SwapUseChallengeInput carries the inputs the on-chain `swap_use_challenge`
// (disc 1 with signing_kind=SWAP, no bundle) hashes. Same shape as
// NormalUseChallengeInput but the op tag changes so a swap-clear-signed
// message can't be replayed as a generic signature. Mirror of
// `swap_use_challenge` in contracts/policy-engine/src/lib.rs.
type SwapUseChallengeInput struct {
	HumanMessage   []byte
	Engine         solana.PublicKey
	DWallet        solana.PublicKey
	MetadataDigest [32]byte
	OwnerSlot      [MemberSlotLen]byte
}

func (in *SwapUseChallengeInput) Preimage() []byte {
	var buf bytes.Buffer
	buf.Write(DomainV3)
	buf.Write(OpSwapSign)
	var hl [2]byte
	binary.LittleEndian.PutUint16(hl[:], uint16(len(in.HumanMessage)))
	buf.Write(hl[:])
	buf.Write(in.HumanMessage)
	buf.Write(in.Engine.Bytes())
	buf.Write(in.DWallet.Bytes())
	buf.Write(in.MetadataDigest[:])
	buf.Write(in.OwnerSlot[:])
	return buf.Bytes()
}

func (in *SwapUseChallengeInput) Hash() [32]byte {
	return sha256.Sum256(in.Preimage())
}

// ─── Update 7 (2026-05-26) — BUNDLE challenge ──────────────────────────────

// BundleUseChallengeInput is the bundle owner-authorization challenge: one
// owner signature covers `Total` distinct request_signature legs. Each leg's
// disc 1 recomputes the same hash by passing its own `ThisIndex` + the other
// legs' metadata digests in supplied order. Mirror of `bundle_use_challenge`
// in contracts/policy-engine/src/lib.rs.
//
// The bundle hash is op_tag- and human-agnostic on purpose: legs can mix
// signing kinds (e.g. EVM 2-step = NORMAL approve + SWAP swap) and still share
// the same owner signature. Each leg's metadata digest already binds its own
// preimage variant (V2 for NORMAL, V3 for SWAP), so a tampered tx changes the
// digest, which changes the bundle hash.
type BundleUseChallengeInput struct {
	Engine             solana.PublicKey
	DWallet            solana.PublicKey
	ThisMetadataDigest [32]byte
	OwnerSlot          [MemberSlotLen]byte
	Total              uint8 // 2..=MaxBundleTotal
	ThisIndex          uint8 // 0..=Total-1
	OtherDigests       [][32]byte
}

func (in *BundleUseChallengeInput) Preimage() ([]byte, error) {
	if in.Total < MinBundleTotal || in.Total > MaxBundleTotal {
		return nil, fmt.Errorf("policy: bundle total %d outside [%d,%d]", in.Total, MinBundleTotal, MaxBundleTotal)
	}
	if in.ThisIndex >= in.Total {
		return nil, fmt.Errorf("policy: bundle this_index %d >= total %d", in.ThisIndex, in.Total)
	}
	if uint8(len(in.OtherDigests)) != in.Total-1 {
		return nil, fmt.Errorf("policy: bundle expected %d other digests, got %d", in.Total-1, len(in.OtherDigests))
	}
	// Reorder: place `ThisMetadataDigest` at `ThisIndex`, fill remaining slots
	// with `OtherDigests` in supplied order. Mirror of the on-chain reordering.
	ordered := make([][32]byte, in.Total)
	otherIter := 0
	for i := uint8(0); i < in.Total; i++ {
		if i == in.ThisIndex {
			ordered[i] = in.ThisMetadataDigest
		} else {
			ordered[i] = in.OtherDigests[otherIter]
			otherIter++
		}
	}
	var buf bytes.Buffer
	buf.Write(DomainV3)
	buf.Write(OpBundleSign)
	buf.Write(in.Engine.Bytes())
	buf.Write(in.DWallet.Bytes())
	buf.WriteByte(in.Total)
	for _, d := range ordered {
		buf.Write(d[:])
	}
	buf.Write(in.OwnerSlot[:])
	return buf.Bytes(), nil
}

func (in *BundleUseChallengeInput) Hash() ([32]byte, error) {
	pre, err := in.Preimage()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(pre), nil
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
	buf.WriteString(humanfmt.FormatU64Shifted(maxPerTx, humanfmt.ValueDecimals1e8))
	buf.WriteString(" maxPerDay ")
	buf.WriteString(humanfmt.FormatU64Shifted(maxPerDay, humanfmt.ValueDecimals1e8))
	buf.WriteString(" maxPerWeek ")
	buf.WriteString(humanfmt.FormatU64Shifted(maxPerWeek, humanfmt.ValueDecimals1e8))
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
	buf.WriteString(humanfmt.FormatI64Shifted(minQ64, humanfmt.ValueDecimals1e8))
	buf.WriteString(" max ")
	buf.WriteString(humanfmt.FormatI64Shifted(maxQ64, humanfmt.ValueDecimals1e8))
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
