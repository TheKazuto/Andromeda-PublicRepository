package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/gagliardetto/solana-go"
)

// Recovery-flow challenge primitives. These mirror the Rust functions in
// `contracts/auth/src/challenge.rs` and `contracts/auth/src/human_message.rs`.
//
// The PolicyEngine v3 program imports `andromeda_auth::challenge::primary_recover_challenge`
// directly (lib.rs §6.5), so the wire format is the **same** as the legacy
// rules-policy: `DOMAIN = "andromeda::rules-policy::v2"`, OP tags below.
// Frozen golden vectors live at `fixtures/clear_signing_vectors.json` and are
// asserted by `challenges_recovery_test.go`.
//
// Drift between Rust and Go here = silent on-chain rejection. Treat this file
// as a byte-for-byte mirror; any change to the Rust functions MUST update
// this file in the same commit and regenerate fixtures.

// DomainRulesPolicyV2 is the clear-signing v2 domain tag — shared with the
// legacy `rules-policy` program because the on-chain `andromeda_auth` crate
// produces the same hash for both.
var DomainRulesPolicyV2 = []byte("andromeda::rules-policy::v2")

// OP tags for recovery operations (mirror of `contracts/auth/src/challenge.rs`).
var (
	OpTagPrimaryRecover       = []byte("primary-recover")
	OpTagQuorumSessionOpen    = []byte("quorum-session-open")
	OpTagQuorumContribute     = []byte("quorum-contribute")
	OpTagPasskeySessionOpen   = []byte("passkey-session-open")
	OpTagPasskeyPrimaryUse    = []byte("passkey-primary-use")
)

// MaxHumanMessageBytes mirrors `andromeda_auth::human_message::MAX_HUMAN_MESSAGE_BYTES`.
// Raised from 512 to 768 on 2026-05-14 because `quorum-contribute` carries the
// full session snapshot (session + member_slot + dwallet + 3 digests +
// user_pubkey + amount + destination + expires_at). Reduce only after CU
// profiling shows headroom.
const MaxHumanMessageBytes = 768

// idLenForScheme mirrors `andromeda_auth::id_len_for_scheme`. Used by the
// member-slot renderer to know how many bytes of the slot payload to print
// after the scheme byte.
func idLenForScheme(scheme uint8) (int, error) {
	switch scheme {
	case 0: // Ed25519
		return 32, nil
	case 1: // Secp256k1
		return 20, nil
	case 2, 3: // Secp256r1 / WebAuthn (compressed P-256)
		return 33, nil
	case 4: // OIDC JWT addr_seed
		return 32, nil
	default:
		return 0, fmt.Errorf("policy: unsupported scheme %d", scheme)
	}
}

// renderMemberSlot mirrors `MsgWriter::write_member_slot`:
//
//	"scheme:<u8_dec>;id:<hex_lower of slot[1..1+id_len]>"
func renderMemberSlot(slot [MemberSlotLen]byte) (string, error) {
	idLen, err := idLenForScheme(slot[0])
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	buf.WriteString("scheme:")
	buf.WriteString(strconv.FormatUint(uint64(slot[0]), 10))
	buf.WriteString(";id:")
	buf.WriteString(toHexLower(slot[1 : 1+idLen]))
	return buf.String(), nil
}

// ─── primary_recover_message (mirror of contracts/auth/src/human_message.rs) ─

// HumanMessagePrimaryRecover renders the clear-signing v2 text:
//
//	"Recover dWallet <b58> for message <hex> metadata <hex> scheme <u16> user <hex>"
//
// Byte-for-byte identical to `primary_recover_message` in the Rust crate.
func HumanMessagePrimaryRecover(
	dwallet solana.PublicKey,
	messageDigest, metadataDigest, userPubkey [32]byte,
	signatureScheme uint16,
) []byte {
	var buf bytes.Buffer
	buf.WriteString("Recover dWallet ")
	buf.WriteString(dwallet.String())
	buf.WriteString(" for message ")
	buf.WriteString(toHexLower(messageDigest[:]))
	buf.WriteString(" metadata ")
	buf.WriteString(toHexLower(metadataDigest[:]))
	buf.WriteString(" scheme ")
	buf.WriteString(strconv.FormatUint(uint64(signatureScheme), 10))
	buf.WriteString(" user ")
	buf.WriteString(toHexLower(userPubkey[:]))
	return buf.Bytes()
}

// ─── primary_recover_challenge (mirror of challenge.rs) ─────────────────────

// PrimaryRecoverChallengeInput packs every byte that goes into the hash.
//
// The primary credential signs the resulting `Hash` off-chain; the on-chain
// `recover_as_primary` handler recomputes the same preimage and validates the
// signature via the appropriate precompile (Ed25519 / Secp256k1 / Secp256r1).
type PrimaryRecoverChallengeInput struct {
	DWallet             solana.PublicKey
	MessageApproval     solana.PublicKey
	MessageDigest       [32]byte
	MetadataDigest      [32]byte
	UserPubkey          [32]byte
	SignatureScheme     uint16
	MessageApprovalBump uint8
	Nonce               uint64
	PrimarySlot         [MemberSlotLen]byte
}

// Preimage returns the canonical byte sequence hashed by SHA-256.
func (in *PrimaryRecoverChallengeInput) Preimage() ([]byte, error) {
	human := HumanMessagePrimaryRecover(
		in.DWallet, in.MessageDigest, in.MetadataDigest, in.UserPubkey, in.SignatureScheme,
	)
	if len(human) > MaxHumanMessageBytes {
		return nil, fmt.Errorf("policy: human message %d > %d", len(human), MaxHumanMessageBytes)
	}
	var buf bytes.Buffer
	buf.Write(DomainRulesPolicyV2)
	buf.Write(OpTagPrimaryRecover)
	var hl [2]byte
	binary.LittleEndian.PutUint16(hl[:], uint16(len(human)))
	buf.Write(hl[:])
	buf.Write(human)
	buf.Write(in.DWallet.Bytes())
	buf.Write(in.MessageApproval.Bytes())
	buf.Write(in.MessageDigest[:])
	buf.Write(in.MetadataDigest[:])
	buf.Write(in.UserPubkey[:])
	var scheme [2]byte
	binary.LittleEndian.PutUint16(scheme[:], in.SignatureScheme)
	buf.Write(scheme[:])
	buf.WriteByte(in.MessageApprovalBump)
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], in.Nonce)
	buf.Write(nonce[:])
	buf.Write(in.PrimarySlot[:])
	return buf.Bytes(), nil
}

// Hash returns the 32-byte SHA-256 over Preimage().
func (in *PrimaryRecoverChallengeInput) Hash() ([32]byte, error) {
	pre, err := in.Preimage()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(pre), nil
}

// HashAndHuman is a convenience wrapper that returns both the rendered text
// and the hash — useful for HTTP responses that need to show the user what
// they're signing.
func (in *PrimaryRecoverChallengeInput) HashAndHuman() (human []byte, hash [32]byte, err error) {
	human = HumanMessagePrimaryRecover(
		in.DWallet, in.MessageDigest, in.MetadataDigest, in.UserPubkey, in.SignatureScheme,
	)
	hash, err = in.Hash()
	return human, hash, err
}

// ─── quorum_session_open_message + challenge ───────────────────────────────

// HumanMessageQuorumSessionOpen mirrors `quorum_session_open_message`:
//
//	"Open quorum session for dWallet <b58> amount <u64> destination <hex>
//	 message <hex> metadata <hex> scheme <u16> expires <i64>"
func HumanMessageQuorumSessionOpen(
	dwallet solana.PublicKey,
	amount uint64,
	destination, messageDigest, metadataDigest [32]byte,
	signatureScheme uint16,
	expiresAt int64,
) []byte {
	var buf bytes.Buffer
	buf.WriteString("Open quorum session for dWallet ")
	buf.WriteString(dwallet.String())
	buf.WriteString(" amount ")
	buf.WriteString(strconv.FormatUint(amount, 10))
	buf.WriteString(" destination ")
	buf.WriteString(toHexLower(destination[:]))
	buf.WriteString(" message ")
	buf.WriteString(toHexLower(messageDigest[:]))
	buf.WriteString(" metadata ")
	buf.WriteString(toHexLower(metadataDigest[:]))
	buf.WriteString(" scheme ")
	buf.WriteString(strconv.FormatUint(uint64(signatureScheme), 10))
	buf.WriteString(" expires ")
	buf.WriteString(strconv.FormatInt(expiresAt, 10))
	return buf.Bytes()
}

// QuorumSessionOpenChallengeInput is the canonical hash input for OP
// `quorum-session-open` (mirror of `andromeda_auth::challenge`).
type QuorumSessionOpenChallengeInput struct {
	DWallet             solana.PublicKey
	MessageDigest       [32]byte
	MetadataDigest      [32]byte
	UserPubkey          [32]byte
	SignatureScheme     uint16
	MessageApprovalBump uint8
	Amount              uint64
	Destination         [32]byte
	ExpiresAt           int64
	SessionNonce        uint64
	PrimarySlot         [MemberSlotLen]byte
}

func (in *QuorumSessionOpenChallengeInput) Preimage() ([]byte, error) {
	human := HumanMessageQuorumSessionOpen(
		in.DWallet, in.Amount, in.Destination, in.MessageDigest, in.MetadataDigest,
		in.SignatureScheme, in.ExpiresAt,
	)
	if len(human) > MaxHumanMessageBytes {
		return nil, fmt.Errorf("policy: human message %d > %d", len(human), MaxHumanMessageBytes)
	}
	var buf bytes.Buffer
	buf.Write(DomainRulesPolicyV2)
	buf.Write(OpTagQuorumSessionOpen)
	var hl [2]byte
	binary.LittleEndian.PutUint16(hl[:], uint16(len(human)))
	buf.Write(hl[:])
	buf.Write(human)
	buf.Write(in.DWallet.Bytes())
	buf.Write(in.MessageDigest[:])
	buf.Write(in.MetadataDigest[:])
	buf.Write(in.UserPubkey[:])
	var scheme [2]byte
	binary.LittleEndian.PutUint16(scheme[:], in.SignatureScheme)
	buf.Write(scheme[:])
	buf.WriteByte(in.MessageApprovalBump)
	var amount [8]byte
	binary.LittleEndian.PutUint64(amount[:], in.Amount)
	buf.Write(amount[:])
	buf.Write(in.Destination[:])
	var expires [8]byte
	binary.LittleEndian.PutUint64(expires[:], uint64(in.ExpiresAt))
	buf.Write(expires[:])
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], in.SessionNonce)
	buf.Write(nonce[:])
	buf.Write(in.PrimarySlot[:])
	return buf.Bytes(), nil
}

func (in *QuorumSessionOpenChallengeInput) Hash() ([32]byte, error) {
	pre, err := in.Preimage()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(pre), nil
}

// ─── quorum_contribute_message + challenge ─────────────────────────────────

// HumanMessageQuorumContribute mirrors `quorum_contribute_message`. The
// session and member_slot are embedded so any tamper with the snapshot
// invalidates every contributor's signature.
func HumanMessageQuorumContribute(
	session solana.PublicKey,
	memberSlot [MemberSlotLen]byte,
	dwallet solana.PublicKey,
	amount uint64,
	destination, messageDigest, metadataDigest, userPubkey [32]byte,
	signatureScheme uint16,
	expiresAt int64,
) ([]byte, error) {
	slotText, err := renderMemberSlot(memberSlot)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("Contribute to quorum session ")
	buf.WriteString(session.String())
	buf.WriteString(" as member ")
	buf.WriteString(slotText)
	buf.WriteString(" for dWallet ")
	buf.WriteString(dwallet.String())
	buf.WriteString(" amount ")
	buf.WriteString(strconv.FormatUint(amount, 10))
	buf.WriteString(" destination ")
	buf.WriteString(toHexLower(destination[:]))
	buf.WriteString(" message ")
	buf.WriteString(toHexLower(messageDigest[:]))
	buf.WriteString(" metadata ")
	buf.WriteString(toHexLower(metadataDigest[:]))
	buf.WriteString(" scheme ")
	buf.WriteString(strconv.FormatUint(uint64(signatureScheme), 10))
	buf.WriteString(" user ")
	buf.WriteString(toHexLower(userPubkey[:]))
	buf.WriteString(" expires ")
	buf.WriteString(strconv.FormatInt(expiresAt, 10))
	return buf.Bytes(), nil
}

// QuorumContributeChallengeInput — hashes the full session snapshot used in
// `approve_message`. Tampering with any field invalidates every member's
// signature.
type QuorumContributeChallengeInput struct {
	Session             solana.PublicKey
	MemberSlot          [MemberSlotLen]byte
	DWallet             solana.PublicKey
	Amount              uint64
	Destination         [32]byte
	MessageDigest       [32]byte
	MetadataDigest      [32]byte
	UserPubkey          [32]byte
	SignatureScheme     uint16
	MessageApprovalBump uint8
	ExpiresAt           int64
}

func (in *QuorumContributeChallengeInput) Preimage() ([]byte, error) {
	human, err := HumanMessageQuorumContribute(
		in.Session, in.MemberSlot, in.DWallet, in.Amount,
		in.Destination, in.MessageDigest, in.MetadataDigest, in.UserPubkey,
		in.SignatureScheme, in.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	if len(human) > MaxHumanMessageBytes {
		return nil, fmt.Errorf("policy: human message %d > %d", len(human), MaxHumanMessageBytes)
	}
	var buf bytes.Buffer
	buf.Write(DomainRulesPolicyV2)
	buf.Write(OpTagQuorumContribute)
	var hl [2]byte
	binary.LittleEndian.PutUint16(hl[:], uint16(len(human)))
	buf.Write(hl[:])
	buf.Write(human)
	buf.Write(in.Session.Bytes())
	buf.Write(in.MemberSlot[:])
	buf.Write(in.DWallet.Bytes())
	var amount [8]byte
	binary.LittleEndian.PutUint64(amount[:], in.Amount)
	buf.Write(amount[:])
	buf.Write(in.Destination[:])
	buf.Write(in.MessageDigest[:])
	buf.Write(in.MetadataDigest[:])
	buf.Write(in.UserPubkey[:])
	var scheme [2]byte
	binary.LittleEndian.PutUint16(scheme[:], in.SignatureScheme)
	buf.Write(scheme[:])
	buf.WriteByte(in.MessageApprovalBump)
	var expires [8]byte
	binary.LittleEndian.PutUint64(expires[:], uint64(in.ExpiresAt))
	buf.Write(expires[:])
	return buf.Bytes(), nil
}

func (in *QuorumContributeChallengeInput) Hash() ([32]byte, error) {
	pre, err := in.Preimage()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(pre), nil
}

// ─── passkey_session_open_message + challenge ──────────────────────────────

// HumanMessagePasskeySessionOpen mirrors `passkey_session_open_message`:
//
//	"Open passkey session for dWallet <b58> until <u64> using ephemeral key <hex>"
func HumanMessagePasskeySessionOpen(
	dwallet solana.PublicKey,
	notAfterUnixTs uint64,
	ephPk [32]byte,
) []byte {
	var buf bytes.Buffer
	buf.WriteString("Open passkey session for dWallet ")
	buf.WriteString(dwallet.String())
	buf.WriteString(" until ")
	buf.WriteString(strconv.FormatUint(notAfterUnixTs, 10))
	buf.WriteString(" using ephemeral key ")
	buf.WriteString(toHexLower(ephPk[:]))
	return buf.Bytes()
}

// PasskeySessionOpenChallengeInput — signed by the passkey credential
// (Secp256r1 + WebAuthn) when opening a short-lived session bound to an
// ephemeral Ed25519 key.
type PasskeySessionOpenChallengeInput struct {
	DWallet            solana.PublicKey
	PrimarySlot        [MemberSlotLen]byte // SCHEME_WEBAUTHN(3) || credential_pubkey(33)
	EphPk              [32]byte
	NotAfterUnixTs     uint64
	CredentialIDHash   [32]byte
	SessionNonce       uint64
}

func (in *PasskeySessionOpenChallengeInput) Preimage() ([]byte, error) {
	human := HumanMessagePasskeySessionOpen(in.DWallet, in.NotAfterUnixTs, in.EphPk)
	if len(human) > MaxHumanMessageBytes {
		return nil, fmt.Errorf("policy: human message %d > %d", len(human), MaxHumanMessageBytes)
	}
	var buf bytes.Buffer
	buf.Write(DomainRulesPolicyV2)
	buf.Write(OpTagPasskeySessionOpen)
	var hl [2]byte
	binary.LittleEndian.PutUint16(hl[:], uint16(len(human)))
	buf.Write(hl[:])
	buf.Write(human)
	buf.Write(in.DWallet.Bytes())
	buf.Write(in.PrimarySlot[:])
	buf.Write(in.EphPk[:])
	var notAfter [8]byte
	binary.LittleEndian.PutUint64(notAfter[:], in.NotAfterUnixTs)
	buf.Write(notAfter[:])
	buf.Write(in.CredentialIDHash[:])
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], in.SessionNonce)
	buf.Write(nonce[:])
	return buf.Bytes(), nil
}

func (in *PasskeySessionOpenChallengeInput) Hash() ([32]byte, error) {
	pre, err := in.Preimage()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(pre), nil
}

// ─── passkey_primary_use_message + challenge ───────────────────────────────

// HumanMessagePasskeyPrimaryUse mirrors `passkey_primary_use_message`.
func HumanMessagePasskeyPrimaryUse(
	session, dwallet solana.PublicKey,
	messageDigest, metadataDigest, userPubkey [32]byte,
	signatureScheme uint16,
) []byte {
	var buf bytes.Buffer
	buf.WriteString("Authorize passkey session ")
	buf.WriteString(session.String())
	buf.WriteString(" for dWallet ")
	buf.WriteString(dwallet.String())
	buf.WriteString(" message ")
	buf.WriteString(toHexLower(messageDigest[:]))
	buf.WriteString(" metadata ")
	buf.WriteString(toHexLower(metadataDigest[:]))
	buf.WriteString(" scheme ")
	buf.WriteString(strconv.FormatUint(uint64(signatureScheme), 10))
	buf.WriteString(" user ")
	buf.WriteString(toHexLower(userPubkey[:]))
	return buf.Bytes()
}

// PasskeyPrimaryUseChallengeInput — signed by the ephemeral Ed25519 key for
// each `recover_as_primary_passkey_session` call. Single-use via `use_nonce`.
type PasskeyPrimaryUseChallengeInput struct {
	Session             solana.PublicKey
	DWallet             solana.PublicKey
	MessageApproval     solana.PublicKey
	MessageDigest       [32]byte
	MetadataDigest      [32]byte
	UserPubkey          [32]byte
	SignatureScheme     uint16
	MessageApprovalBump uint8
	UseNonce            uint64
	PrimarySlot         [MemberSlotLen]byte
}

func (in *PasskeyPrimaryUseChallengeInput) Preimage() ([]byte, error) {
	human := HumanMessagePasskeyPrimaryUse(
		in.Session, in.DWallet, in.MessageDigest, in.MetadataDigest, in.UserPubkey, in.SignatureScheme,
	)
	if len(human) > MaxHumanMessageBytes {
		return nil, fmt.Errorf("policy: human message %d > %d", len(human), MaxHumanMessageBytes)
	}
	var buf bytes.Buffer
	buf.Write(DomainRulesPolicyV2)
	buf.Write(OpTagPasskeyPrimaryUse)
	var hl [2]byte
	binary.LittleEndian.PutUint16(hl[:], uint16(len(human)))
	buf.Write(hl[:])
	buf.Write(human)
	buf.Write(in.Session.Bytes())
	buf.Write(in.DWallet.Bytes())
	buf.Write(in.MessageApproval.Bytes())
	buf.Write(in.MessageDigest[:])
	buf.Write(in.MetadataDigest[:])
	buf.Write(in.UserPubkey[:])
	var scheme [2]byte
	binary.LittleEndian.PutUint16(scheme[:], in.SignatureScheme)
	buf.Write(scheme[:])
	buf.WriteByte(in.MessageApprovalBump)
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], in.UseNonce)
	buf.Write(nonce[:])
	buf.Write(in.PrimarySlot[:])
	return buf.Bytes(), nil
}

func (in *PasskeyPrimaryUseChallengeInput) Hash() ([32]byte, error) {
	pre, err := in.Preimage()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(pre), nil
}
