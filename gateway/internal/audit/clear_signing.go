package audit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/shinkalabs/andromeda-gateway/internal/auth"
)

// Clear-signing metadata helpers — turn an `auth.ClearSigning` envelope
// plus the 32-byte challenge hash into a small allowlisted payload that
// each governance audit event can carry. The whole point of clear signing
// is that the message the approver read is preserved end-to-end; this
// helper writes that exact text into the immutable audit log so a future
// review can replay the decision a human authorized.
//
// The payload contains:
//   * clear_signing_version: e.g. "policy-clear-v1" / "rules-policy-clear-v1"
//   * operation:             canonical op tag (e.g. "allowlist.add_destination")
//   * challenge_hash_base64: base64 of the 32-byte hash signed by the owner
//   * human_message:         exact ASCII text shown to the approver
//   * fields_hash_base64:    base64 of sha256(JCS(clearSigning.fields))
//                            — RFC 8785 canonical JSON of the structured
//                            fields, so two records with the same fields
//                            map produce the same hash regardless of key
//                            order.
//
// We never write JWT / sub / email / API keys / signatures / private
// material; clearSigning.fields itself is curated by the renderer (only
// hashes, addresses and decimal numbers).

// ClearSigningPayload is the subset of the audit record dedicated to a
// clear-signed governance approval. Build it once per event with
// `BuildClearSigningPayload` and merge it into the event's payload map.
type ClearSigningPayload struct {
	ClearSigningVersion string `json:"clear_signing_version"`
	Operation           string `json:"operation"`
	ChallengeHashBase64 string `json:"challenge_hash_base64"`
	HumanMessage        string `json:"human_message"`
	FieldsHashBase64    string `json:"fields_hash_base64"`
}

// BuildClearSigningPayload returns the audit-ready map. `humanMessage` is
// clamped to MaxHumanMessageBytes (768) — anything longer is rejected as
// an indication of a renderer bug.
func BuildClearSigningPayload(challengeHash [32]byte, humanMessage string, cs auth.ClearSigning) (ClearSigningPayload, error) {
	if len(humanMessage) > auth.MaxHumanMessageBytes {
		return ClearSigningPayload{}, fmt.Errorf("audit: humanMessage exceeds %d bytes", auth.MaxHumanMessageBytes)
	}
	fieldsHash, err := hashFieldsJCS(cs.Fields)
	if err != nil {
		return ClearSigningPayload{}, fmt.Errorf("audit: hash clearSigning.fields: %w", err)
	}
	return ClearSigningPayload{
		ClearSigningVersion: cs.Version,
		Operation:           cs.Operation,
		ChallengeHashBase64: base64.StdEncoding.EncodeToString(challengeHash[:]),
		HumanMessage:        humanMessage,
		FieldsHashBase64:    base64.StdEncoding.EncodeToString(fieldsHash[:]),
	}, nil
}

// AsMap returns the payload as a map[string]any suitable for merging into
// `audit.Log(..., payload)` calls.
func (p ClearSigningPayload) AsMap() map[string]any {
	return map[string]any{
		"clear_signing_version": p.ClearSigningVersion,
		"operation":             p.Operation,
		"challenge_hash_base64": p.ChallengeHashBase64,
		"human_message":         p.HumanMessage,
		"fields_hash_base64":    p.FieldsHashBase64,
	}
}

// hashFieldsJCS computes sha256(JCS(fields)) — canonical JSON of the
// fields map. We use a hand-rolled minimal canonicalizer (sorted map
// keys, no whitespace) sufficient for the typed shapes the gateway emits
// in `clearSigning.fields` (strings, bools, ints, addresses). The
// package-level `canonicalJSON` is intentionally not reused: it relies
// on `encoding/json`'s native map ordering which is non-deterministic
// for nested maps, and we need a deterministic byte string here.
func hashFieldsJCS(fields map[string]any) ([32]byte, error) {
	buf, err := canonicalizeForJCS(fields)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(buf), nil
}

// canonicalizeForJCS recursively serializes `v` with sorted map keys and
// no extra whitespace.
func canonicalizeForJCS(v any) ([]byte, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			out = append(out, kb...)
			out = append(out, ':')
			vb, err := canonicalizeForJCS(t[k])
			if err != nil {
				return nil, err
			}
			out = append(out, vb...)
		}
		out = append(out, '}')
		return out, nil
	case []any:
		out := []byte{'['}
		for i, item := range t {
			if i > 0 {
				out = append(out, ',')
			}
			vb, err := canonicalizeForJCS(item)
			if err != nil {
				return nil, err
			}
			out = append(out, vb...)
		}
		out = append(out, ']')
		return out, nil
	default:
		return json.Marshal(v)
	}
}
