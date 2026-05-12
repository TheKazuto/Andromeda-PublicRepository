package webhooks

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// CanonicalEvent is the structured form of an `emit!()` payload from one of
// the Andromeda policy templates. The schema mirrors `contracts/shared/src/
// events.rs` — keep them in lockstep.
type CanonicalEvent struct {
	Type          string         `json:"type"` // dotted name (signature.requested, policy.paused, ...)
	Discriminator uint8          `json:"discriminator"`
	Policy        string         `json:"policy"` // base58 PublicKey
	Dwallet       string         `json:"dwallet,omitempty"`
	Owner         string         `json:"owner,omitempty"`
	RequestHash   string         `json:"requestHash,omitempty"`
	TS            int64          `json:"ts"`
	ReasonCode    *uint64        `json:"reasonCode,omitempty"`
	Slot          int64          `json:"slot,omitempty"`
	Signature     string         `json:"signature,omitempty"`
	Raw           map[string]any `json:"raw,omitempty"` // catch-all for forward-compat
}

// Event discriminators must match `contracts/shared/src/events.rs`.
const (
	eventPolicyDeployed     = 0
	eventSignatureRequested = 1
	eventSignatureApproved  = 2
	eventSignatureRejected  = 3
	eventPolicyPaused       = 4
	eventPolicyResumed      = 5
)

// IkaEventTagLE is the Anchor-compatible 8-byte tag the Ika dWallet program
// prepends to every emitted event (Anchor self-CPI format). Documented in
// `ika-pre-alpha/docs/src/reference/events.md` as `EVENT_IX_TAG_LE`.
//
// Stored byte-by-byte in little-endian: 0xe4a545ea51cb9a1d → bytes
// [0x1d, 0x9a, 0xcb, 0x51, 0xea, 0x45, 0xa5, 0xe4]
var ikaEventTagLE = [8]byte{0x1d, 0x9a, 0xcb, 0x51, 0xea, 0x45, 0xa5, 0xe4}

// Ika event discriminators. The 1-byte discriminator follows the 8-byte
// IkaEventTagLE prefix. Documented in
// `ika-pre-alpha/docs/src/reference/events.md`. The exact disc-to-event
// mapping isn't documented in the public reference; we conservatively map by
// payload size and surface unknown discriminators as ika.event.unknown so
// later schema drift surfaces as a parse warning, not a silent miss.
const (
	ikaEventDWalletCreated         = 0 // dwallet(32) + authority(32) + curve(1) = 65
	ikaEventMessageApprovalCreated = 1 // dwallet(32) + message_hash(32) + caller_program(32) = 96
	ikaEventSignatureCommitted     = 2 // message_approval(32) + signature_len(u16 LE) = 34
	ikaEventAuthorityTransferred   = 3 // dwallet(32) + old(32) + new(32) = 96
)

// programDataPrefix is the line prefix Solana uses for `emit!()` payloads —
// base64-encoded after the prefix.
const programDataPrefix = "Program data: "

// extractEventLines walks a logsNotification log array and returns the base64
// payloads from `Program data:` lines. The dWallet program also writes
// "Program data:" entries for its own self-CPI events; in Phase 2 we accept
// those too and tag them with the program ID that produced them when the
// caller knows it.
func extractEventLines(logs []string) []string {
	out := make([]string, 0, len(logs))
	for _, l := range logs {
		if strings.HasPrefix(l, programDataPrefix) {
			out = append(out, strings.TrimPrefix(l, programDataPrefix))
		}
	}
	return out
}

// ParseEvent decodes a `Program data:` payload into a CanonicalEvent. Unknown
// discriminators yield (nil, nil) — the listener should skip them quietly.
//
// Two payload layouts are supported:
//
//  1. **Andromeda templates (Quasar)**: a single discriminator byte followed
//     by the struct's fields in declaration order. Field order matches
//     `contracts/shared/src/events.rs`.
//  2. **Ika dWallet program (Anchor self-CPI)**: 8-byte `IkaEventTagLE`
//     prefix + 1-byte disc + event-specific payload. Documented in
//     `ika-pre-alpha/docs/src/reference/events.md`.
//
// The dispatcher inspects the first 8 bytes; a match against `ikaEventTagLE`
// routes to the Ika decoder, otherwise the legacy Quasar decoder runs.
func ParseEvent(b64 string, programID string, slot int64, signature string) (*CanonicalEvent, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) >= 8 && bytesEqual(raw[:8], ikaEventTagLE[:]) {
		return parseIkaEvent(raw[8:], slot, signature)
	}
	disc := raw[0]
	payload := raw[1:]
	ev := &CanonicalEvent{
		Discriminator: disc,
		Slot:          slot,
		Signature:     signature,
	}
	switch disc {
	case eventPolicyDeployed:
		// fields: policy(32) + dwallet(32) + owner(32) + ts(i64) = 104 bytes
		if len(payload) < 104 {
			return nil, nil
		}
		ev.Type = "policy.deployed"
		ev.Policy = encodePub(payload[0:32])
		ev.Dwallet = encodePub(payload[32:64])
		ev.Owner = encodePub(payload[64:96])
		ev.TS = int64(binary.LittleEndian.Uint64(payload[96:104]))
	case eventSignatureRequested:
		// fields: policy(32) + request_hash(32) + ts(i64) = 72 bytes
		if len(payload) < 72 {
			return nil, nil
		}
		ev.Type = "signature.requested"
		ev.Policy = encodePub(payload[0:32])
		ev.RequestHash = encodePub(payload[32:64])
		ev.TS = int64(binary.LittleEndian.Uint64(payload[64:72]))
	case eventSignatureApproved:
		if len(payload) < 72 {
			return nil, nil
		}
		ev.Type = "signature.approved"
		ev.Policy = encodePub(payload[0:32])
		ev.RequestHash = encodePub(payload[32:64])
		ev.TS = int64(binary.LittleEndian.Uint64(payload[64:72]))
	case eventSignatureRejected:
		// fields: policy(32) + request_hash(32) + ts(i64) + reason_code(u64) = 80 bytes
		if len(payload) < 80 {
			return nil, nil
		}
		ev.Type = "signature.rejected"
		ev.Policy = encodePub(payload[0:32])
		ev.RequestHash = encodePub(payload[32:64])
		ev.TS = int64(binary.LittleEndian.Uint64(payload[64:72]))
		reason := binary.LittleEndian.Uint64(payload[72:80])
		ev.ReasonCode = &reason
	case eventPolicyPaused:
		// fields: policy(32) + ts(i64) = 40 bytes
		if len(payload) < 40 {
			return nil, nil
		}
		ev.Type = "policy.paused"
		ev.Policy = encodePub(payload[0:32])
		ev.TS = int64(binary.LittleEndian.Uint64(payload[32:40]))
	case eventPolicyResumed:
		if len(payload) < 40 {
			return nil, nil
		}
		ev.Type = "policy.resumed"
		ev.Policy = encodePub(payload[0:32])
		ev.TS = int64(binary.LittleEndian.Uint64(payload[32:40]))
	default:
		// Unknown discriminator — Phase 3 candidate (Ika program emits its own
		// events with different schemas; we skip them silently for now).
		return nil, nil
	}
	return ev, nil
}

// encodePub returns the base58 form of a 32-byte pubkey slice. Imported
// inline to avoid pulling in `solana-go` here.
func encodePub(b []byte) string {
	return base58Encode(b)
}

// base58Encode is a minimal base58 encoder for 32-byte Solana pubkeys. We
// implement it locally to avoid an extra dep — solana-go's PublicKey.String()
// would also work but pulling that in just for encoding here is overkill.
func base58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	// Count leading zeros.
	zeros := 0
	for _, b := range input {
		if b != 0 {
			break
		}
		zeros++
	}
	// Allocate enough room (1.4x is conservative for 32-byte input).
	size := len(input)*138/100 + 1
	out := make([]byte, size)
	length := 0
	for _, b := range input {
		carry := int(b)
		i := 0
		for j := size - 1; j >= 0 && (carry != 0 || i < length); j-- {
			carry += 256 * int(out[j])
			out[j] = byte(carry % 58)
			carry /= 58
			i++
		}
		length = i
	}
	// Skip leading zeros in the converted buffer and translate bytes to chars.
	it := size - length
	for it < size && out[it] == 0 {
		it++
	}
	result := make([]byte, zeros+(size-it))
	for i := 0; i < zeros; i++ {
		result[i] = alphabet[0]
	}
	for j := zeros; it < size; j++ {
		result[j] = alphabet[out[it]]
		it++
	}
	return string(result)
}

// bytesEqual is a tiny helper to avoid importing "bytes" just for one cmp.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// parseIkaEvent decodes the body that follows the IkaEventTagLE prefix. The
// first byte is the 1-byte event discriminator. We map by both discriminator
// and payload size — the public Ika reference doesn't pin down disc IDs,
// so the size check is the safety belt against schema drift.
func parseIkaEvent(body []byte, slot int64, signature string) (*CanonicalEvent, error) {
	if len(body) < 1 {
		return nil, nil
	}
	disc := body[0]
	payload := body[1:]
	ev := &CanonicalEvent{
		Discriminator: disc,
		Slot:          slot,
		Signature:     signature,
		Raw:           map[string]any{"source": "ika", "raw_bytes": fmt.Sprintf("%x", body)},
	}
	switch {
	case disc == ikaEventDWalletCreated && len(payload) >= 65:
		ev.Type = "dwallet.created"
		ev.Dwallet = encodePub(payload[0:32])
		ev.Owner = encodePub(payload[32:64])
		// payload[64] = curve byte; expose via Raw for now
		ev.Raw["curve"] = payload[64]
	case disc == ikaEventMessageApprovalCreated && len(payload) >= 96:
		ev.Type = "ika.message_approval.created"
		ev.Dwallet = encodePub(payload[0:32])
		ev.RequestHash = encodePub(payload[32:64])
		ev.Raw["caller_program"] = encodePub(payload[64:96])
	case disc == ikaEventSignatureCommitted && len(payload) >= 34:
		ev.Type = "signature.completed"
		ev.Raw["message_approval"] = encodePub(payload[0:32])
		// payload[32:34] = signature_len u16 LE
		sigLen := uint16(payload[32]) | (uint16(payload[33]) << 8)
		ev.Raw["signature_len"] = sigLen
	case disc == ikaEventAuthorityTransferred && len(payload) >= 96:
		ev.Type = "dwallet.authority.transferred"
		ev.Dwallet = encodePub(payload[0:32])
		ev.Raw["old_authority"] = encodePub(payload[32:64])
		ev.Raw["new_authority"] = encodePub(payload[64:96])
	default:
		// Unknown disc — surface as ika.event.unknown so the listener can log
		// it (helps schema-drift debugging) without silently dropping.
		ev.Type = fmt.Sprintf("ika.event.unknown.%d", disc)
		ev.Raw["payload_len"] = len(payload)
	}
	return ev, nil
}
