package auth

// Clear-signing renderers — mirror `contracts/auth/src/human_message.rs`
// byte-for-byte for the 23 admin templates across the 7 policy crates
// (Phase 2). The rules-policy templates (17 ops) live in the ika-backend
// TS mirror (`ika-backend/src/recovery/clear_signing.ts`) because the
// rules-policy gateway flow goes through the engine. Golden vectors:
// `fixtures/clear_signing_vectors.json`.
//
// Output is plain ASCII (0x20..=0x7E), valid UTF-8, fits in
// MaxHumanMessageBytes (768). Any wire-format change here MUST regenerate
// the fixture and update the Rust + TS mirrors in the same commit.

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/gagliardetto/solana-go"

	"github.com/shinkalabs/andromeda-gateway/internal/humanfmt"
)

// MaxHumanMessageBytes mirrors `contracts/auth/src/human_message.rs::
// MAX_HUMAN_MESSAGE_BYTES`. Bumped 512 → 768 on 2026-05-14 (Phase D) to
// fit `quorum-contribute` worst case.
const MaxHumanMessageBytes = 768

// ClearSigningVersionPolicy is the `clearSigning.version` value used by
// every Phase 2 policy admin response.
const ClearSigningVersionPolicy = "policy-clear-v1"

var (
	errNonAscii       = errors.New("clear-signing message contains non-ASCII byte")
	errBufferTooSmall = errors.New("clear-signing message exceeds MaxHumanMessageBytes")
)

// ClearSigning is the structured envelope returned alongside every
// human-signed challenge response. The on-chain handler does not consume
// this — it recomputes `humanMessage` from typed params and validates the
// hash — but the gateway returns it so the caller can render the message
// to the approver and audit the operation later.
type ClearSigning struct {
	Version   string         `json:"version"`
	Operation string         `json:"operation"`
	Fields    map[string]any `json:"fields"`
}

// msgWriter is an ASCII writer with a fixed 768-byte capacity. Mirrors
// the Rust `MsgWriter` byte-for-byte.
type msgWriter struct {
	buf [MaxHumanMessageBytes]byte
	n   int
}

func newMsgWriter() *msgWriter { return &msgWriter{} }

func (w *msgWriter) bytes() []byte { return w.buf[:w.n] }

func (w *msgWriter) writeBytes(p []byte) error {
	if w.n+len(p) > MaxHumanMessageBytes {
		return errBufferTooSmall
	}
	copy(w.buf[w.n:], p)
	w.n += len(p)
	return nil
}

func (w *msgWriter) writeStr(s string) error {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			return errNonAscii
		}
	}
	return w.writeBytes([]byte(s))
}

func (w *msgWriter) writeU16Dec(v uint16) error { return w.writeStr(strconv.FormatUint(uint64(v), 10)) }
func (w *msgWriter) writeU32Dec(v uint32) error { return w.writeStr(strconv.FormatUint(uint64(v), 10)) }
func (w *msgWriter) writeU64Dec(v uint64) error { return w.writeStr(strconv.FormatUint(v, 10)) }
func (w *msgWriter) writeI64Dec(v int64) error  { return w.writeStr(strconv.FormatInt(v, 10)) }

func (w *msgWriter) writeHexLower(b []byte) error {
	if w.n+len(b)*2 > MaxHumanMessageBytes {
		return errBufferTooSmall
	}
	const hex = "0123456789abcdef"
	for _, x := range b {
		w.buf[w.n] = hex[x>>4]
		w.buf[w.n+1] = hex[x&0x0f]
		w.n += 2
	}
	return nil
}

func (w *msgWriter) writeBase58_32(addr [32]byte) error {
	pk := solana.PublicKeyFromBytes(addr[:])
	return w.writeStr(pk.String())
}

// timeLockModeLabel mirrors `andromeda_auth::human_message::time_lock_mode_label`.
func timeLockModeLabel(mode uint8) string {
	switch mode {
	case 0:
		return "before"
	case 1:
		return "after"
	case 2:
		return "between"
	case 3:
		return "recurring"
	default:
		return "unknown"
	}
}

// HumanLenLE returns the u16 LE length prefix of a rendered humanMessage.
// Used by the admin-hash helper to bind `humanMessage` into the challenge.
//
// The panic is intentional and is an unreachable invariant assertion, not a
// recoverable error: every `human` passed here comes from a msgWriter capped at
// MaxHumanMessageBytes (768), which fits in a u16 many times over. If that
// invariant were ever violated, a silent u16 wrap would emit a length prefix
// that diverges from the Rust/TS mirrors and corrupt the challenge hash
// (producing a bad signature) — failing loud is strictly safer than that, so we
// do NOT clamp or swallow it.
func HumanLenLE(human []byte) []byte {
	if len(human) > 0xffff {
		panic(fmt.Sprintf("human message too long: %d", len(human)))
	}
	return U16LE(uint16(len(human)))
}

// ── Renderers (23) ───────────────────────────────────────────────

// AllowlistAddDestinationMessage renders the human-readable text for
// `allowlist-destinations::add-destination`.
func AllowlistAddDestinationMessage(destination [32]byte, policy, dwallet solana.PublicKey) (string, error) {
	w := newMsgWriter()
	if err := w.writeStr("Allow destination "); err != nil {
		return "", err
	}
	if err := w.writeHexLower(destination[:]); err != nil {
		return "", err
	}
	if err := w.writeStr(" on allowlist policy "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(policy)); err != nil {
		return "", err
	}
	if err := w.writeStr(" for dWallet "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(dwallet)); err != nil {
		return "", err
	}
	return string(w.bytes()), nil
}

func AllowlistRemoveDestinationMessage(destination [32]byte, policy, dwallet solana.PublicKey) (string, error) {
	w := newMsgWriter()
	if err := w.writeStr("Block destination "); err != nil {
		return "", err
	}
	if err := w.writeHexLower(destination[:]); err != nil {
		return "", err
	}
	if err := w.writeStr(" on allowlist policy "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(policy)); err != nil {
		return "", err
	}
	if err := w.writeStr(" for dWallet "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(dwallet)); err != nil {
		return "", err
	}
	return string(w.bytes()), nil
}

func AllowlistPauseMessage(policy, dwallet solana.PublicKey) (string, error) {
	return pauseResumeMessage("Pause allowlist policy ", policy, dwallet)
}

func AllowlistResumeMessage(policy, dwallet solana.PublicKey) (string, error) {
	return pauseResumeMessage("Resume allowlist policy ", policy, dwallet)
}

func VelocityUpdateWindowMessage(maxSigsPerWindow uint32, windowSlots uint64, policy, dwallet solana.PublicKey) (string, error) {
	w := newMsgWriter()
	if err := w.writeStr("Update velocity window on policy "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(policy)); err != nil {
		return "", err
	}
	if err := w.writeStr(" for dWallet "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(dwallet)); err != nil {
		return "", err
	}
	if err := w.writeStr(" to "); err != nil {
		return "", err
	}
	if err := w.writeU32Dec(maxSigsPerWindow); err != nil {
		return "", err
	}
	if err := w.writeStr(" signatures per "); err != nil {
		return "", err
	}
	if err := w.writeU64Dec(windowSlots); err != nil {
		return "", err
	}
	if err := w.writeStr(" slots"); err != nil {
		return "", err
	}
	return string(w.bytes()), nil
}

func VelocityPauseMessage(policy, dwallet solana.PublicKey) (string, error) {
	return pauseResumeMessage("Pause velocity-guard policy ", policy, dwallet)
}

func VelocityResumeMessage(policy, dwallet solana.PublicKey) (string, error) {
	return pauseResumeMessage("Resume velocity-guard policy ", policy, dwallet)
}

func TimeLockUpdateWindowMessage(mode uint8, startSlot, endSlot, recurringPeriodSlots uint64, policy, dwallet solana.PublicKey) (string, error) {
	w := newMsgWriter()
	if err := w.writeStr("Update time-lock window on policy "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(policy)); err != nil {
		return "", err
	}
	if err := w.writeStr(" for dWallet "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(dwallet)); err != nil {
		return "", err
	}
	if err := w.writeStr(" mode "); err != nil {
		return "", err
	}
	if err := w.writeStr(timeLockModeLabel(mode)); err != nil {
		return "", err
	}
	if err := w.writeStr(" start "); err != nil {
		return "", err
	}
	if err := w.writeU64Dec(startSlot); err != nil {
		return "", err
	}
	if err := w.writeStr(" end "); err != nil {
		return "", err
	}
	if err := w.writeU64Dec(endSlot); err != nil {
		return "", err
	}
	if err := w.writeStr(" period "); err != nil {
		return "", err
	}
	if err := w.writeU64Dec(recurringPeriodSlots); err != nil {
		return "", err
	}
	return string(w.bytes()), nil
}

func TimeLockPauseMessage(policy, dwallet solana.PublicKey) (string, error) {
	return pauseResumeMessage("Pause time-lock policy ", policy, dwallet)
}

func TimeLockResumeMessage(policy, dwallet solana.PublicKey) (string, error) {
	return pauseResumeMessage("Resume time-lock policy ", policy, dwallet)
}

func OracleUpdateBoundsMessage(minPrice, maxPrice int64, maxAgeSlots uint64, maxConfidenceBps uint16, policy, dwallet solana.PublicKey) (string, error) {
	w := newMsgWriter()
	if err := w.writeStr("Update oracle bounds on policy "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(policy)); err != nil {
		return "", err
	}
	if err := w.writeStr(" for dWallet "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(dwallet)); err != nil {
		return "", err
	}
	if err := w.writeStr(" min "); err != nil {
		return "", err
	}
	if err := w.writeStr(humanfmt.FormatI64Shifted(minPrice, humanfmt.ValueDecimals1e8)); err != nil {
		return "", err
	}
	if err := w.writeStr(" max "); err != nil {
		return "", err
	}
	if err := w.writeStr(humanfmt.FormatI64Shifted(maxPrice, humanfmt.ValueDecimals1e8)); err != nil {
		return "", err
	}
	if err := w.writeStr(" maxAge "); err != nil {
		return "", err
	}
	if err := w.writeU64Dec(maxAgeSlots); err != nil {
		return "", err
	}
	if err := w.writeStr(" maxConfidence "); err != nil {
		return "", err
	}
	if err := w.writeU16Dec(maxConfidenceBps); err != nil {
		return "", err
	}
	if err := w.writeStr(" bps"); err != nil {
		return "", err
	}
	return string(w.bytes()), nil
}

func OraclePauseMessage(policy, dwallet solana.PublicKey) (string, error) {
	return pauseResumeMessage("Pause oracle-conditional policy ", policy, dwallet)
}

func OracleResumeMessage(policy, dwallet solana.PublicKey) (string, error) {
	return pauseResumeMessage("Resume oracle-conditional policy ", policy, dwallet)
}

func PasskeyUpdatePolicyMessage(thresholdAmount uint64, passkeyPubkey [33]byte, policy, dwallet solana.PublicKey) (string, error) {
	w := newMsgWriter()
	if err := w.writeStr("Update passkey step-up on policy "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(policy)); err != nil {
		return "", err
	}
	if err := w.writeStr(" for dWallet "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(dwallet)); err != nil {
		return "", err
	}
	if err := w.writeStr(" threshold "); err != nil {
		return "", err
	}
	if err := w.writeU64Dec(thresholdAmount); err != nil {
		return "", err
	}
	if err := w.writeStr(" passkey "); err != nil {
		return "", err
	}
	if err := w.writeHexLower(passkeyPubkey[:]); err != nil {
		return "", err
	}
	return string(w.bytes()), nil
}

func PasskeyPauseMessage(policy, dwallet solana.PublicKey) (string, error) {
	return pauseResumeMessage("Pause passkey step-up policy ", policy, dwallet)
}

func PasskeyResumeMessage(policy, dwallet solana.PublicKey) (string, error) {
	return pauseResumeMessage("Resume passkey step-up policy ", policy, dwallet)
}

func SessionKeysRevokeSessionMessage(policy, dwallet solana.PublicKey) (string, error) {
	w := newMsgWriter()
	if err := w.writeStr("Revoke session keys on policy "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(policy)); err != nil {
		return "", err
	}
	if err := w.writeStr(" for dWallet "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(dwallet)); err != nil {
		return "", err
	}
	return string(w.bytes()), nil
}

func SessionKeysAddAllowedProgramMessage(programID, policy, dwallet solana.PublicKey) (string, error) {
	return programSessionKeysMessage("Allow program ", programID, policy, dwallet)
}

func SessionKeysRemoveAllowedProgramMessage(programID, policy, dwallet solana.PublicKey) (string, error) {
	return programSessionKeysMessage("Block program ", programID, policy, dwallet)
}

func SessionKeysCloseSessionMessage(recipient, policy, dwallet solana.PublicKey) (string, error) {
	w := newMsgWriter()
	if err := w.writeStr("Close session-keys policy "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(policy)); err != nil {
		return "", err
	}
	if err := w.writeStr(" for dWallet "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(dwallet)); err != nil {
		return "", err
	}
	if err := w.writeStr(" refund recipient "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(recipient)); err != nil {
		return "", err
	}
	return string(w.bytes()), nil
}

func FHERotateAuthorityMessage(newFHEAuthority, policy, dwallet solana.PublicKey) (string, error) {
	w := newMsgWriter()
	if err := w.writeStr("Rotate FHE authority on policy "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(policy)); err != nil {
		return "", err
	}
	if err := w.writeStr(" for dWallet "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(dwallet)); err != nil {
		return "", err
	}
	if err := w.writeStr(" to "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(newFHEAuthority)); err != nil {
		return "", err
	}
	return string(w.bytes()), nil
}

func FHEPauseMessage(policy, dwallet solana.PublicKey) (string, error) {
	return pauseResumeMessage("Pause fhe-gated policy ", policy, dwallet)
}

func FHEResumeMessage(policy, dwallet solana.PublicKey) (string, error) {
	return pauseResumeMessage("Resume fhe-gated policy ", policy, dwallet)
}

// ── Shared shapes ────────────────────────────────────────────────

func pauseResumeMessage(prefix string, policy, dwallet solana.PublicKey) (string, error) {
	w := newMsgWriter()
	if err := w.writeStr(prefix); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(policy)); err != nil {
		return "", err
	}
	if err := w.writeStr(" for dWallet "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(dwallet)); err != nil {
		return "", err
	}
	return string(w.bytes()), nil
}

func programSessionKeysMessage(prefix string, programID, policy, dwallet solana.PublicKey) (string, error) {
	w := newMsgWriter()
	if err := w.writeStr(prefix); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(programID)); err != nil {
		return "", err
	}
	if err := w.writeStr(" on session-keys policy "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(policy)); err != nil {
		return "", err
	}
	if err := w.writeStr(" for dWallet "); err != nil {
		return "", err
	}
	if err := w.writeBase58_32(toAddr(dwallet)); err != nil {
		return "", err
	}
	return string(w.bytes()), nil
}

func toAddr(pk solana.PublicKey) [32]byte {
	var out [32]byte
	copy(out[:], pk.Bytes())
	return out
}
