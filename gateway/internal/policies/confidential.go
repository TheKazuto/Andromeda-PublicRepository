package policies

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

// Confidential Workflows (Andromeda Features Roadmap §3) orchestrates
// `encrypt-backend` (FHE evaluation) + Ika (signing) under a single REST
// endpoint. The dev provides the policy + dwallet + message; the gateway:
//
//   1. Asks encrypt-backend to evaluate the FHE graph and produce a signed
//      `EncryptedDecision` (ed25519 over [policy || message_digest ||
//      created_slot || authorize], signed inside the KMS).
//   2. Builds the fhe-gated::request_signature ix with the decision bytes
//      embedded.
//   3. Returns the unsigned tx for the dev to sign locally, just like every
//      other request_signature endpoint — preserving custody-free.
//
// The actual KMS sign call lives in the encrypt-backend (decision/sign route).
// This file glues the orchestration together.

// ConfidentialSignClient is the subset of encrypt-backend we need. Decoupled
// for testability; the production wiring uses HTTPConfidentialClient below.
type ConfidentialSignClient interface {
	SignDecision(ctx context.Context, req DecisionRequest) (*DecisionResponse, error)
}

// DecisionRequest mirrors the body the encrypt-backend `decision/sign` route
// accepts.
type DecisionRequest struct {
	PolicyAddress   string   `json:"policy_address"`
	RequestHashHex  string   `json:"request_hash_hex"`
	OperationName   string   `json:"operation_name"`
	EncryptedInputs []string `json:"encrypted_inputs"` // ciphertext refs
	// MockAuthorize is forwarded to encrypt-backend; honoured only when
	// FHE_MOCK_MODE=true on that side. Devnet/test paths only — production
	// must leave it unset and rely on real FHE evaluation once the Encrypt
	// SDK exposes a DecryptionRequest decoder.
	MockAuthorize *bool `json:"mock_authorize,omitempty"`
}

// DecisionResponse is what the encrypt-backend returns: the canonical
// `EncryptedDecision` bytes split into the parts the on-chain program needs.
type DecisionResponse struct {
	RequestHashHex   string `json:"request_hash_hex"`
	CreatedSlot      uint64 `json:"created_slot"`
	Authorize        bool   `json:"authorize"`
	SignatureB64     string `json:"signature_base64"`     // ed25519 over canonical decision bytes
	FHEAuthorityB64  string `json:"fhe_authority_base64"`  // pubkey for client-side verification
}

// HTTPConfidentialClient is the production implementation that POSTs to the
// encrypt-backend over the private network using X-Internal-Key auth.
type HTTPConfidentialClient struct {
	BaseURL string
	APIKey  string
	Client  *http.Client
}

func NewHTTPConfidentialClient(baseURL, apiKey string) *HTTPConfidentialClient {
	return &HTTPConfidentialClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		Client:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *HTTPConfidentialClient) SignDecision(ctx context.Context, req DecisionRequest) (*DecisionResponse, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("encrypt-backend base URL not configured")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/v1/encrypt/decision/sign", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		httpReq.Header.Set("X-Internal-Key", c.APIKey)
	}
	resp, err := c.Client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("decision/sign request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("decision/sign non-2xx: %d body=%s", resp.StatusCode, string(respBody))
	}
	var parsed DecisionResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("decode decision response: %w", err)
	}
	return &parsed, nil
}

// confidentialSignReq is the body of POST /v1/confidential/sign.
type confidentialSignReq struct {
	PolicyAddress       string   `json:"policy_address"`
	DwalletAddress      string   `json:"dwallet_address"`
	DwalletCurve        uint16   `json:"dwallet_curve"`
	DwalletPublicKeyB64 string   `json:"dwallet_public_key_base64"`
	PayerAddress        string   `json:"payer_address"`
	MessageDigestBase64 string   `json:"message_digest_base64"`
	UserPubkeyBase64    string   `json:"user_pubkey_base64"`
	SignatureScheme     uint16   `json:"signature_scheme"`
	CpiAuthorityBump    uint8    `json:"cpi_authority_bump"`
	OperationName       string   `json:"operation_name"`
	EncryptedInputs     []string `json:"encrypted_inputs"`
	MockAuthorize       *bool    `json:"mock_authorize,omitempty"`

	// Audit C2 (Opção 4): client supplies init_authority_hash for the
	// fhe-gated PDA derivation. The gateway recomputes the policy address
	// and verifies it matches `policy_address` (defense in depth).
	InitAuthorityHashBase64 string `json:"init_authority_hash_base64"`

	// Audit M4: required FHE authority pubkey — the on-chain program now
	// validates this against the hardcoded `ALLOWED_FHE_AUTHORITIES`.
	FHEAuthorityAddress string `json:"fhe_authority_address"`
}

// canonicalRequestHash binds the policy + message in a stable hash that both
// the gateway and the encrypt-backend agree on. The on-chain fhe-gated
// program accepts only decisions that were minted for THIS specific message,
// preventing decision-replay across messages.
func canonicalRequestHash(policy solana.PublicKey, messageDigest []byte) []byte {
	h := sha256.New()
	h.Write(policy.Bytes())
	h.Write(messageDigest)
	out := h.Sum(nil)
	return out
}

// confidentialSign is the handler for POST /v1/confidential/sign — the §3
// orchestrator. Returns an unsigned tx the dev's client signs and submits.
func (s *Service) confidentialSign(w http.ResponseWriter, r *http.Request) {
	if s.ConfidentialClient == nil {
		writeErr(w, http.StatusServiceUnavailable, "confidential_disabled",
			"set ENCRYPT_UPSTREAM_URL + INTERNAL_API_KEY to enable")
		return
	}
	var req confidentialSignReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_body", "invalid JSON body")
		return
	}
	policyPub, err := solana.PublicKeyFromBase58(req.PolicyAddress)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_policy", "policy_address must be base58")
		return
	}
	dwallet, err := solana.PublicKeyFromBase58(req.DwalletAddress)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_dwallet", "dwallet_address must be base58")
		return
	}
	initAuthorityHash, err := decodeInitAuthorityHash(req.InitAuthorityHashBase64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_init_authority_hash", err.Error())
		return
	}
	payer, err := solana.PublicKeyFromBase58(req.PayerAddress)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_payer", "payer_address must be base58")
		return
	}
	msg, err := decodeFixed32(req.MessageDigestBase64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_message_digest", err.Error())
		return
	}
	user, err := decodeFixed32(req.UserPubkeyBase64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_user_pubkey", err.Error())
		return
	}
	if req.DwalletPublicKeyB64 == "" {
		writeErr(w, http.StatusBadRequest, "missing_dwallet_public_key",
			"dwallet_public_key_base64 is required")
		return
	}
	dwalletPK, err := base64.StdEncoding.DecodeString(req.DwalletPublicKeyB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_dwallet_public_key", err.Error())
		return
	}
	switch len(dwalletPK) {
	case 32, 33, 65:
	default:
		writeErr(w, http.StatusBadRequest, "invalid_dwallet_public_key",
			"dwallet_public_key must be 32/33/65 bytes")
		return
	}

	// Compute the canonical request hash and ask the encrypt-backend to sign
	// an EncryptedDecision over it.
	requestHash := canonicalRequestHash(policyPub, msg[:])

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	decision, err := s.ConfidentialClient.SignDecision(ctx, DecisionRequest{
		PolicyAddress:   policyPub.String(),
		RequestHashHex:  hex.EncodeToString(requestHash),
		OperationName:   req.OperationName,
		EncryptedInputs: req.EncryptedInputs,
		MockAuthorize:   req.MockAuthorize,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, "fhe_decision_failed", err.Error())
		return
	}
	if decision == nil || decision.SignatureB64 == "" {
		writeErr(w, http.StatusBadGateway, "fhe_decision_invalid",
			"encrypt-backend returned an empty decision — confirm KMS configuration")
		return
	}
	if !decision.Authorize {
		writeJSON(w, http.StatusOK, map[string]any{
			"authorized": false,
			"reason":     "FHE evaluation rejected the request — no signing transaction generated",
			"decision":   decision,
		})
		return
	}
	sigBytes, err := base64.StdEncoding.DecodeString(decision.SignatureB64)
	if err != nil || len(sigBytes) != 64 {
		writeErr(w, http.StatusBadGateway, "fhe_decision_invalid",
			"signature_base64 must decode to 64 bytes")
		return
	}
	var sigArr [64]byte
	copy(sigArr[:], sigBytes)

	// Audit C2 (Opção 4): no longer build the ix manually here — delegate
	// to BuildFHEGatedRequestSignature so the precompile + new wire format
	// stay in sync with the on-chain ABI.
	prog, err := s.Registry.ProgramID(TemplateFHEGated)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "template_not_deployed", err.Error())
		return
	}
	policyPDA, _, err := PolicyPDA(TemplateFHEGated, prog, dwallet, initAuthorityHash)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "policy_pda_failed", err.Error())
		return
	}
	// Defense in depth: verify the client-supplied policy_address matches
	// what we derived from (dwallet, init_authority_hash).
	if policyPDA != policyPub {
		writeErr(w, http.StatusBadRequest, "policy_address_mismatch",
			"policy_address does not match the derived PDA for (dwallet, init_authority_hash)")
		return
	}
	maPDA, maBump, err := MessageApprovalPDA(
		s.Registry.IkaProgramID,
		req.DwalletCurve, dwalletPK,
		req.SignatureScheme,
		msg[:], make([]byte, 32),
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "ma_pda_failed", err.Error())
		return
	}

	// Audit C2 (Opção 4) + M4 + C1: delegate the wire format to the
	// canonical builder. It produces `[ed25519PrecompileIx, mainIx]` —
	// the precompile validates the decision signature by `fhe_authority`
	// over `decision_canonical_bytes(policy, message_digest, slot, auth)`,
	// and the main ix carries init_authority_hash + the same fields.
	if req.FHEAuthorityAddress == "" {
		writeErr(w, http.StatusBadRequest, "missing_fhe_authority",
			"fhe_authority_address is required (Audit M4)")
		return
	}
	fheAuth, err := solana.PublicKeyFromBase58(req.FHEAuthorityAddress)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_fhe_authority", err.Error())
		return
	}
	common := RequestSigCommon{
		Dwallet:           dwallet,
		DwalletCurve:      req.DwalletCurve,
		DwalletPublicKey:  dwalletPK,
		Sponsor:           payer,
		InitAuthorityHash: initAuthorityHash,
		MessageDigest:     msg,
		MetaDigest:        [32]byte{},
		UserPubkey:        user,
		SignatureScheme:   req.SignatureScheme,
		CurrentTS:         time.Now().Unix(),
	}
	ixs, err := BuildFHEGatedRequestSignature(s.Registry, FHEGatedRequestSignatureInput{
		RequestSigCommon:    common,
		MessageApprovalBump: maBump,
		CpiAuthorityBump:    req.CpiAuthorityBump,
		DecisionCreatedSlot: decision.CreatedSlot,
		DecisionAuthorize:   boolToU8(decision.Authorize),
		DecisionSignature:   sigArr[:],
		FHEAuthority:        fheAuth,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "build_failed", err.Error())
		return
	}

	unsigned, err := BuildUnsignedTx(r.Context(), s.RPCClient, payer, ixs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "tx_build_failed", err.Error())
		return
	}

	currentSlot, err := s.RPCClient.GetSlot(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		// Non-fatal — used only for response telemetry.
		currentSlot = 0
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authorized":         true,
		"unsigned_tx_base64": unsigned,
		"policy_address":     policyPDA.String(),
		"message_approval":   maPDA.String(),
		"current_slot":       currentSlot,
		"decision":           decision,
		"signers_required":   []string{payer.String()},
	})
}

func boolToU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// silence binary unused import warnings if encoding/binary becomes optional.
var _ = binary.LittleEndian
