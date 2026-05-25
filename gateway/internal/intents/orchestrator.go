package intents

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/google/uuid"

	"github.com/shinkalabs/andromeda-gateway/internal/policy"
	"github.com/shinkalabs/andromeda-gateway/internal/upstream"
)

// Publisher emits per-tenant webhooks (satisfied by *webhooks.Publisher).
// Defined here so the orchestrator stays decoupled and testable.
type Publisher interface {
	Publish(ctx context.Context, apiKeyID uuid.UUID, eventType string, payload any) (int, error)
}

// defaultIntentTTL bounds how long a prepared intent stays signable. LI.FI
// quotes are short-lived; a tight window limits slippage between prepare and
// submit.
const defaultIntentTTL = 90 * time.Second

// Authorizer is the seam onto policy.Service: on-chain authorization (no owner
// signature), the presign prefetch (single-use, gas-aware), and the advisory
// risk + simulation. All satisfied by *policy.Service; defined here so the
// orchestrator stays testable with a fake.
type Authorizer interface {
	AuthorizeSwap(ctx context.Context, in policy.SwapAuthorizeInput) (policy.AuthorizeResult, error)
	// SwapChallengeDigest returns the request-signature challenge digest — the
	// presign cache key + the persisted policy_metadata_digest.
	SwapChallengeDigest(in policy.SwapAuthorizeInput) (string, error)
	// FirePresignPrefetchDirect starts a single-use presign at prepare time
	// (no-op unless IKA_PRESIGN_PREFETCH_ENABLED).
	FirePresignPrefetchDirect(tenant, dwalletAddress, challengeHex string)
	// HarvestPresignDirect collects the prefetched presign at submit time ("" =
	// miss/disabled/stale → /sign allocates inline).
	HarvestPresignDirect(ctx context.Context, tenant, challengeHex string) string
	// EvaluateSwapRisk returns an advisory risk + simulation snapshot. Never blocks.
	EvaluateSwapRisk(ctx context.Context, in policy.SwapRiskInput) json.RawMessage
}

// Orchestrator coordinates prepare/submit/status across the intents-backend,
// ika-backend and PolicyEngine, persisting state in Postgres.
type Orchestrator struct {
	store      intentStore
	up         *upstream.Registry
	authorizer Authorizer
	audit      AuditAppender
	webhooks   Publisher
	metrics    *Metrics
	logger     *slog.Logger
	ttl        time.Duration
}

// Options wires the orchestrator. Audit, Webhooks and Metrics are optional.
type Options struct {
	Store      intentStore
	Upstreams  *upstream.Registry
	Authorizer Authorizer
	Audit      AuditAppender
	Webhooks   Publisher
	Metrics    *Metrics
	Logger     *slog.Logger
	TTL        time.Duration
}

func NewOrchestrator(o Options) *Orchestrator {
	ttl := o.TTL
	if ttl <= 0 {
		ttl = defaultIntentTTL
	}
	return &Orchestrator{
		store:      o.Store,
		up:         o.Upstreams,
		authorizer: o.Authorizer,
		audit:      o.Audit,
		webhooks:   o.Webhooks,
		metrics:    o.Metrics,
		logger:     o.Logger,
		ttl:        ttl,
	}
}

// ---- intents-backend / ika response shapes -------------------------------

type ibPrepareResult struct {
	ChainKind          string          `json:"chainKind"`
	ChainID            int             `json:"chainId"`
	SignChainID        string          `json:"signChainId"`
	SignScheme         int             `json:"signScheme"`
	ChainNativeAddress string          `json:"chainNativeAddress"`
	UnsignedTxB64      string          `json:"unsignedTxB64"`
	MessageToSignHex   string          `json:"messageToSignHex"`
	UnsignedTxHash     string          `json:"unsignedTxHash"`
	AmountOut          string          `json:"amountOut"`
	AmountOutMin       string          `json:"amountOutMin"`
	TransactionFeeUSD  string          `json:"transactionFeeUsd"`
	NativeFeeEstimate  string          `json:"nativeFeeEstimate"`
	RouteSnapshot      json.RawMessage `json:"routeSnapshot"`
	Notice             string          `json:"notice"`
	EVMNonce           uint64          `json:"evmNonce"`
	Approval           *ibApproval     `json:"approval"`
}

// ibApproval is the optional ERC20 approve tx the intents-backend builds.
type ibApproval struct {
	UnsignedTxB64    string `json:"unsignedTxB64"`
	MessageToSignHex string `json:"messageToSignHex"`
	Token            string `json:"token"`
	Spender          string `json:"spender"`
	Nonce            uint64 `json:"nonce"`
}

type ikaPrepareMsg struct {
	PreprocessedHex         string `json:"preprocessedHex"`
	DigestHex               string `json:"digestHex"`
	MessageMetadataHex      string `json:"messageMetadataHex"`
	IkaMsgMetadataDigestHex string `json:"ikaMsgMetadataDigestHex"`
	Scheme                  int    `json:"scheme"`
}

type ikaSignResult struct {
	SignatureBase64     string `json:"signatureBase64"`
	PresignSessionIDHex string `json:"presignSessionIdHex"`
}

type ibFinalizeResult struct {
	TxHash           string `json:"txHash"`
	BroadcastUnknown bool   `json:"broadcastUnknown"`
}

// buildSwap fetches the LI.FI route and derives the canonical signing material
// (preprocessed bytes + digest, validated against drift). Shared by Prepare
// (which persists) and Simulate (preview only). Read-only against the dWallet.
func (o *Orchestrator) buildSwap(ctx context.Context, userID string, req prepareRequest) (*ibPrepareResult, *ikaPrepareMsg, *userError) {
	// Cross-chain (bridge) needs an explicit destination: the user's own dWallet
	// address on toChain. Same-chain defaults to the source dWallet. Whenever a
	// destination IS supplied (cross-chain, or same-chain with an explicit
	// toAddress) it MUST be one of this dWallet's own derived addresses (§6.5:
	// toAddress must be the dWallet, never an external wallet) — this also cleanly
	// rejects cross-curve-family routes (a Curve25519 dWallet has no EVM address,
	// so an EVM destination cannot be its own). Same-chain with no toAddress falls
	// through: LI.FI defaults the recipient to the source dWallet (fromAddress).
	if req.FromChain != req.ToChain && req.ToAddress == "" {
		return nil, nil, &userError{http.StatusBadRequest, "to_address_required", "toAddress (your dWallet address on the destination chain) is required for cross-chain swaps"}
	}
	if req.ToAddress != "" {
		if uerr := o.verifyOwnDestination(ctx, userID, req.DwalletAddress, req.ToAddress); uerr != nil {
			return nil, nil, uerr
		}
	}
	// Resolve the dWallet's address on the source chain (the fee payer / `from`
	// LI.FI must use). Solana: base58 of the Ed25519 key. EVM: the 0x address the
	// caller supplies (it cannot sign for an address it does not control, so a
	// wrong value simply fails the swap — not a security hole).
	var fromAddress string
	switch req.ChainKind {
	case "solana":
		pkBytes, derr := hex.DecodeString(req.DwalletPublicKeyHex)
		if derr != nil || len(pkBytes) != 32 {
			return nil, nil, &userError{http.StatusBadRequest, "invalid_field", "dwalletPublicKeyHex must be 32-byte hex for Solana"}
		}
		fromAddress = solana.PublicKeyFromBytes(pkBytes).String()
	case "evm":
		if req.ChainNativeAddress == "" {
			return nil, nil, &userError{http.StatusBadRequest, "invalid_field", "chainNativeAddress (the dWallet's 0x address) is required for EVM"}
		}
		fromAddress = req.ChainNativeAddress
	default:
		return nil, nil, &userError{http.StatusBadRequest, "invalid_field", "unsupported chainKind"}
	}

	ibBody := map[string]any{
		"fromChain": req.FromChain, "toChain": req.ToChain,
		"fromToken": req.FromToken, "toToken": req.ToToken,
		"fromAmount": req.FromAmount, "fromAddress": fromAddress, "toAddress": req.ToAddress,
		"slippageBps": req.SlippageBps, "chainKind": req.ChainKind,
	}
	body, st, err := o.call(ctx, o.up.Intents, http.MethodPost, "/prepare", ibBody, userID)
	if err != nil {
		return nil, nil, &userError{http.StatusBadGateway, "intents_unavailable", "swap router unavailable"}
	}
	if st != http.StatusOK {
		return nil, nil, upstreamUserError(st, body, "swap could not be prepared")
	}
	var pr ibPrepareResult
	if err := json.Unmarshal(body, &pr); err != nil {
		return nil, nil, &userError{http.StatusBadGateway, "intents_bad_response", "swap router returned an unreadable response"}
	}

	// Derive the canonical signing material via ika prepare-message — single
	// source of truth shared with the on-chain approval + the sign step.
	ikaBody := map[string]any{"chainId": pr.SignChainID, "payloadHex": pr.MessageToSignHex, "kind": "transaction"}
	body, st, err = o.call(ctx, o.up.Ika, http.MethodPost, "/v1/dwallet/prepare-message", ikaBody, userID)
	if err != nil || st != http.StatusOK {
		return nil, nil, &userError{http.StatusBadGateway, "prepare_message_failed", "failed to derive signing material"}
	}
	var ikaEnv struct {
		Data ikaPrepareMsg `json:"data"`
	}
	if err := json.Unmarshal(body, &ikaEnv); err != nil {
		return nil, nil, &userError{http.StatusBadGateway, "prepare_message_bad_response", "unreadable prepare-message response"}
	}
	pm := ikaEnv.Data
	if pm.PreprocessedHex != pr.MessageToSignHex {
		return nil, nil, &userError{http.StatusBadGateway, "sign_material_drift", "prepare-message preprocessed bytes do not match the swap message"}
	}
	if pm.Scheme != pr.SignScheme {
		return nil, nil, &userError{http.StatusBadGateway, "scheme_mismatch", "signature scheme mismatch between router and engine"}
	}
	return &pr, &pm, nil
}

// simulateResponse is the read-only preview from /v1/intents/simulate.
type simulateResponse struct {
	ChainKind         string          `json:"chainKind"`
	AmountOut         string          `json:"amountOut"`
	AmountOutMin      string          `json:"amountOutMin"`
	TransactionFeeUSD string          `json:"transactionFeeUsd"`
	NativeFeeEstimate string          `json:"nativeFeeEstimate"`
	RequiresApproval  bool            `json:"requiresApproval"`
	MessageDigestHex  string          `json:"messageDigestHex"`
	Route             json.RawMessage `json:"route"`
	Risk              json.RawMessage `json:"risk"`
	Notice            string          `json:"notice"`
}

// Simulate builds the swap and runs the advisory risk + simulation WITHOUT
// creating an intent, allocating a presign, or signing. Pure preview for an
// agent to decide before committing.
func (o *Orchestrator) Simulate(ctx context.Context, userID string, req prepareRequest) (*simulateResponse, error) {
	pr, pm, uerr := o.buildSwap(ctx, userID, req)
	if uerr != nil {
		return nil, uerr
	}
	risk := o.authorizer.EvaluateSwapRisk(ctx, policy.SwapRiskInput{
		PayloadHex:          pm.PreprocessedHex,
		ChainID:             pr.SignChainID,
		MessageDigestHex:    pm.DigestHex,
		DWalletAddress:      req.DwalletAddress,
		DWalletPublicKeyHex: req.DwalletPublicKeyHex,
		TenantID:            userID,
	})
	o.metrics.recordRisk(pr.ChainKind, riskLevel(risk))
	return &simulateResponse{
		ChainKind:         pr.ChainKind,
		AmountOut:         pr.AmountOut,
		AmountOutMin:      pr.AmountOutMin,
		TransactionFeeUSD: pr.TransactionFeeUSD,
		NativeFeeEstimate: pr.NativeFeeEstimate,
		RequiresApproval:  pr.Approval != nil,
		MessageDigestHex:  pm.DigestHex,
		Route:             pr.RouteSnapshot,
		Risk:              risk,
		Notice:            "preview only — no intent created, nothing signed; pre-alpha / devnet, not for real value",
	}, nil
}

// ---- Prepare -------------------------------------------------------------

// Prepare builds the swap, derives the signing material and persists a PREPARED
// intent. No keys, no signing — read-only against the dWallet.
func (o *Orchestrator) Prepare(ctx context.Context, userID, apiKeyID string, req prepareRequest) (resp *prepareResponse, err error) {
	start := time.Now()
	defer func() {
		result := "ok"
		if err != nil {
			result = "error"
		}
		o.metrics.recordPrepare(req.ChainKind, result, time.Since(start).Seconds())
	}()
	pr, pm, uerr := o.buildSwap(ctx, userID, req)
	if uerr != nil {
		return nil, uerr
	}

	// Pre-check the dWallet can pay the swap gas (§13) — fail clear before
	// creating the intent rather than at broadcast.
	if uerr := o.checkNativeBalance(ctx, userID, req.ChainKind, pr.ChainID, pr.ChainNativeAddress, pr.NativeFeeEstimate); uerr != nil {
		return nil, uerr
	}

	it := &Intent{
		UserID: userID, APIKeyID: apiKeyID,
		ChainKind: req.ChainKind, FromChain: req.FromChain, ToChain: req.ToChain,
		FromToken: req.FromToken, ToToken: req.ToToken, FromAmount: req.FromAmount,
		QuotedAmountOut: pr.AmountOut, QuotedAmountOutMin: pr.AmountOutMin,
		IkaDwalletAddress: req.DwalletAddress, DwalletPublicKeyHex: req.DwalletPublicKeyHex,
		OwnerPubkeyHex: req.OwnerPubkeyHex, InitAuthorityHashHex: req.InitAuthorityHashHex,
		IkaCurve: req.IkaCurve, ChainNativeAddress: pr.ChainNativeAddress,
		ChainID: strconv.Itoa(pr.ChainID), SignChainID: pr.SignChainID,
		Status: StatusPrepared, SignScheme: uint16(pm.Scheme),
		SignMessageHex: pm.PreprocessedHex, MessageDigestHex: pm.DigestHex,
		MessageMetadataHex: pm.MessageMetadataHex, IkaMsgMetadataDigestHex: pm.IkaMsgMetadataDigestHex,
		UnsignedTxB64: pr.UnsignedTxB64, UnsignedTxHash: pr.UnsignedTxHash,
		RouteSnapshot: pr.RouteSnapshot,
		ExpiresAt:     time.Now().Add(o.ttl),
	}

	it.EVMNonce = pr.EVMNonce

	// ERC20 two-step approve (EVM): derive the approve tx's signing material via
	// prepare-message and persist it. submit runs approve → confirm → swap.
	if pr.Approval != nil {
		apBody := map[string]any{"chainId": pr.SignChainID, "payloadHex": pr.Approval.MessageToSignHex, "kind": "transaction"}
		apResp, st, err := o.call(ctx, o.up.Ika, http.MethodPost, "/v1/dwallet/prepare-message", apBody, userID)
		if err != nil || st != http.StatusOK {
			return nil, &userError{http.StatusBadGateway, "approve_prepare_failed", "failed to derive approval signing material"}
		}
		var apEnv struct {
			Data ikaPrepareMsg `json:"data"`
		}
		if err := json.Unmarshal(apResp, &apEnv); err != nil || apEnv.Data.PreprocessedHex != pr.Approval.MessageToSignHex {
			return nil, &userError{http.StatusBadGateway, "approve_drift", "approval signing material mismatch"}
		}
		it.ApproveUnsignedTxB64 = pr.Approval.UnsignedTxB64
		it.ApproveMessageHex = apEnv.Data.PreprocessedHex
		it.ApproveMessageDigestHex = apEnv.Data.DigestHex
	}

	// Presign prefetch: compute the request-signature challenge digest now, start
	// a single-use presign in the background (no-op unless enabled), and persist
	// the digest as the harvest key for submit. Best-effort — submit's /sign
	// allocates inline if the prefetch missed.
	authInput := o.swapAuthInput(it)
	if digest, derr := o.authorizer.SwapChallengeDigest(authInput); derr == nil {
		it.PolicyMetadataDigestHex = digest
		o.authorizer.FirePresignPrefetchDirect(userID, req.DwalletAddress, digest)
	} else {
		o.logger.Warn("intent challenge digest failed (presign skipped)", "err", derr)
	}

	if err := o.store.InsertPrepared(ctx, it); err != nil {
		if err == ErrEVMInFlight {
			return nil, &userError{http.StatusConflict, "evm_in_flight", "another EVM swap for this wallet and chain is still in flight; wait for it to settle"}
		}
		o.logger.Error("intent insert failed", "err", err)
		return nil, &userError{http.StatusInternalServerError, "persist_failed", "could not persist intent"}
	}

	return &prepareResponse{
		IntentID: it.ID, Status: it.Status, ChainKind: it.ChainKind,
		AmountOut: pr.AmountOut, AmountOutMin: pr.AmountOutMin,
		TransactionFeeUSD: pr.TransactionFeeUSD, NativeFeeEstimate: pr.NativeFeeEstimate,
		MessageDigestHex: pm.DigestHex, ExpiresAt: it.ExpiresAt,
		Route:  pr.RouteSnapshot,
		Notice: "pre-alpha on Solana devnet — not for real value; the dWallet pays the swap gas",
	}, nil
}

// ---- Submit --------------------------------------------------------------

// approveReceiptInlineWait bounds the synchronous wait for an ERC20 approve to
// confirm before the swap. If it doesn't confirm in time, submit returns
// APPROVING and the client re-calls submit (resumable + idempotent).
const approveReceiptInlineWait = 15 * time.Second

// Submit authorizes, signs and broadcasts a prepared intent. Resumable and
// concurrency-safe: the PREPARED→AUTHORIZING transition is a compare-and-swap;
// an ERC20 swap runs approve → confirm → swap and can be resumed from APPROVING.
func (o *Orchestrator) Submit(ctx context.Context, userID string, req submitRequest) (resp *submitResponse, err error) {
	start := time.Now()
	chainKind := "unknown"
	defer func() {
		result := "error"
		if err == nil && resp != nil {
			result = strings.ToLower(resp.Status)
		}
		o.metrics.recordSubmit(chainKind, result, time.Since(start).Seconds())
	}()

	it, err := o.store.GetForUser(ctx, req.IntentID, userID)
	if err == ErrNotFound {
		return nil, &userError{http.StatusNotFound, "not_found", "intent not found"}
	}
	if err != nil {
		return nil, &userError{http.StatusInternalServerError, "load_failed", "could not load intent"}
	}
	chainKind = it.ChainKind

	switch it.Status {
	case StatusPrepared:
		if time.Now().After(it.ExpiresAt) {
			_ = o.store.SetStatus(ctx, it.ID, StatusExpired)
			o.metrics.recordTransition(StatusPrepared, StatusExpired)
			return nil, &userError{http.StatusConflict, "expired", "intent expired; request a fresh quote"}
		}
		// Lock: PREPARED → AUTHORIZING. Loser of a race returns current state.
		if cerr := o.store.CASStatus(ctx, it.ID, StatusPrepared, StatusAuthorizing, "submit"); cerr != nil {
			return o.currentState(ctx, userID, it)
		}
		o.metrics.recordTransition(StatusPrepared, StatusAuthorizing)
		// Risk advisory + simulation (advisory-only — never blocks; the on-chain
		// rules are the real gate). Persist for the caller/audit.
		riskSnap := o.authorizer.EvaluateSwapRisk(ctx, policy.SwapRiskInput{
			PayloadHex:          it.SignMessageHex,
			ChainID:             it.SignChainID,
			MessageDigestHex:    it.MessageDigestHex,
			DWalletAddress:      it.IkaDwalletAddress,
			DWalletPublicKeyHex: it.DwalletPublicKeyHex,
			TenantID:            userID,
		})
		_ = o.store.SaveRisk(ctx, it.ID, riskSnap)
		o.metrics.recordRisk(it.ChainKind, riskLevel(riskSnap))
		// ERC20 two-step: approve first, then (once confirmed) the swap.
		if it.ApproveMessageDigestHex != "" {
			return o.runApprove(ctx, userID, it, req.Passphrase)
		}
		return o.runSwap(ctx, userID, it, StatusAuthorizing, req.Passphrase)

	case StatusApproving:
		return o.resumeApprove(ctx, userID, it, req.Passphrase)

	default:
		// In-progress (AUTHORIZING/SIGNING/BROADCASTING) or terminal → return
		// current state (the reconciler resolves anything stuck).
		return &submitResponse{IntentID: it.ID, Status: it.Status, TxHash: it.SwapTxHash}, nil
	}
}

func (o *Orchestrator) currentState(ctx context.Context, userID string, it *Intent) (*submitResponse, error) {
	if cur, err := o.store.GetForUser(ctx, it.ID, userID); err == nil && cur != nil {
		return &submitResponse{IntentID: cur.ID, Status: cur.Status, TxHash: cur.SwapTxHash}, nil
	}
	return &submitResponse{IntentID: it.ID, Status: it.Status, TxHash: it.SwapTxHash}, nil
}

// runApprove authorizes, signs and broadcasts the ERC20 approve, then waits
// (bounded) for it to confirm before proceeding to the swap.
func (o *Orchestrator) runApprove(ctx context.Context, userID string, it *Intent, passphrase string) (*submitResponse, error) {
	// §11 re-validation of the approve payload before signing it.
	if uerr := o.revalidate(ctx, userID, "evm", it.ApproveUnsignedTxB64, it.ApproveMessageHex, it.ApproveMessageDigestHex, ""); uerr != nil {
		_ = o.store.SetError(ctx, it.ID, StatusFailed, "approve payload re-validation failed")
		o.metrics.recordTransition(StatusAuthorizing, StatusFailed)
		return nil, uerr
	}
	sig, err := o.authorizeAndSign(ctx, userID, it, it.ApproveMessageHex, it.ApproveMessageDigestHex, "", passphrase)
	if err != nil {
		o.logger.Error("intent approve authorize/sign failed", "intent", it.ID, "err", err)
		_ = o.store.SetError(ctx, it.ID, StatusFailed, "approval authorization/signing failed")
		o.metrics.recordTransition(StatusAuthorizing, StatusFailed)
		return nil, &userError{http.StatusBadGateway, "approve_failed", "ERC20 approval failed"}
	}
	txHash, _, _ := o.broadcastTx(ctx, userID, it, it.ApproveUnsignedTxB64, sig, atoiOrZero(it.ChainID))
	_ = o.store.SaveERC20Approve(ctx, it.ID, txHash) // status APPROVING
	o.metrics.recordTransition(StatusAuthorizing, StatusApproving)
	o.appendAudit(ctx, it, "intent.swap.approve", txHash)
	return o.continueAfterApprove(ctx, userID, it, txHash, passphrase, approveReceiptInlineWait)
}

// resumeApprove is the APPROVING re-entry: check the approve receipt and, once
// confirmed, run the swap. A quick check only — the client drives the retries.
func (o *Orchestrator) resumeApprove(ctx context.Context, userID string, it *Intent, passphrase string) (*submitResponse, error) {
	return o.continueAfterApprove(ctx, userID, it, it.ApproveTxHash, passphrase, 3*time.Second)
}

func (o *Orchestrator) continueAfterApprove(ctx context.Context, userID string, it *Intent, approveTxHash, passphrase string, maxWait time.Duration) (*submitResponse, error) {
	if approveTxHash == "" {
		return &submitResponse{IntentID: it.ID, Status: StatusApproving}, nil
	}
	found, success := o.pollApproveReceipt(ctx, it, approveTxHash, maxWait)
	if !found {
		return &submitResponse{IntentID: it.ID, Status: StatusApproving, TxHash: it.SwapTxHash}, nil
	}
	if !success {
		_ = o.store.SetError(ctx, it.ID, StatusFailed, "ERC20 approval reverted on-chain")
		o.metrics.recordTransition(StatusApproving, StatusFailed)
		return nil, &userError{http.StatusBadGateway, "approve_reverted", "ERC20 approval reverted on-chain"}
	}
	// Confirmed → claim the swap leg (APPROVING → SIGNING) and run it.
	if err := o.store.CASStatus(ctx, it.ID, StatusApproving, StatusSigning, "submit"); err != nil {
		return o.currentState(ctx, userID, it)
	}
	o.metrics.recordTransition(StatusApproving, StatusSigning)
	return o.runSwap(ctx, userID, it, StatusSigning, passphrase)
}

// runSwap authorizes, signs and broadcasts the swap tx. `from` is the status the
// intent is transitioning out of (AUTHORIZING for a direct swap, SIGNING after
// an ERC20 approve) — used for the state-transition metric.
func (o *Orchestrator) runSwap(ctx context.Context, userID string, it *Intent, from, passphrase string) (*submitResponse, error) {
	// §11 re-validation: recompute the signing material from the persisted
	// unsignedTx and confirm it matches the snapshot before signing.
	if uerr := o.revalidate(ctx, userID, it.ChainKind, it.UnsignedTxB64, it.SignMessageHex, it.MessageDigestHex, it.UnsignedTxHash); uerr != nil {
		_ = o.store.SetError(ctx, it.ID, StatusFailed, "swap payload re-validation failed")
		o.metrics.recordTransition(from, StatusFailed)
		return nil, uerr
	}
	sig, err := o.authorizeAndSignSwap(ctx, userID, it, passphrase)
	if err != nil {
		o.logger.Error("intent swap authorize/sign failed", "intent", it.ID, "err", err)
		_ = o.store.SetError(ctx, it.ID, StatusFailed, "authorization/signing failed")
		o.metrics.recordTransition(from, StatusFailed)
		return nil, &userError{http.StatusBadGateway, "sign_failed", "authorization or signing failed"}
	}
	_ = o.store.SetStatus(ctx, it.ID, StatusBroadcasting)
	o.metrics.recordTransition(from, StatusBroadcasting)
	txHash, unknown, berr := o.broadcastTx(ctx, userID, it, it.UnsignedTxB64, sig, atoiOrZero(it.ChainID))
	status := StatusSubmitted
	if unknown || berr != nil {
		status = StatusBroadcastUnknown
	}
	_ = o.store.SaveBroadcast(ctx, it.ID, status, txHash)
	o.metrics.recordTransition(StatusBroadcasting, status)
	it.Status, it.SwapTxHash = status, txHash
	o.appendAudit(ctx, it, "intent.swap.submit", txHash)
	o.publish(ctx, it, "intent.swap."+strings.ToLower(status), txHash)
	return &submitResponse{IntentID: it.ID, Status: status, TxHash: txHash}, nil
}

// authorizeAndSignSwap runs the swap-specific authorize (with presign harvest +
// approval persistence) then signs.
func (o *Orchestrator) authorizeAndSignSwap(ctx context.Context, userID string, it *Intent, passphrase string) (string, error) {
	auth, err := o.authorizer.AuthorizeSwap(ctx, o.swapAuthInput(it))
	if err != nil {
		return "", err
	}
	presign := o.authorizer.HarvestPresignDirect(ctx, userID, auth.MetadataDigestHex)
	_ = o.store.SaveApproval(ctx, it.ID, auth.TxSignature, auth.ApprovalSlot, presign, auth.MetadataDigestHex)
	return o.signWithApproval(ctx, userID, it, it.SignMessageHex, it.MessageMetadataHex, auth, presign, passphrase)
}

// authorizeAndSign is the generic authorize (for an arbitrary message digest,
// e.g. the ERC20 approve) + sign. No swap-specific persistence.
func (o *Orchestrator) authorizeAndSign(ctx context.Context, userID string, it *Intent, msgHex, msgDigest, metadataHex, passphrase string) (string, error) {
	auth, err := o.authorizer.AuthorizeSwap(ctx, o.authInputWithDigest(it, msgDigest))
	if err != nil {
		return "", err
	}
	presign := o.authorizer.HarvestPresignDirect(ctx, userID, auth.MetadataDigestHex)
	return o.signWithApproval(ctx, userID, it, msgHex, metadataHex, auth, presign, passphrase)
}

// signWithApproval calls ika /v1/dwallet/sign with the approval proof + presign.
func (o *Orchestrator) signWithApproval(ctx context.Context, userID string, it *Intent, msgHex, metadataHex string, auth policy.AuthorizeResult, presign, passphrase string) (string, error) {
	signBody := map[string]any{
		"dwalletAddress":            it.IkaDwalletAddress,
		"passphrase":                passphrase,
		"messageHex":                msgHex,
		"scheme":                    it.SignScheme,
		"approvalTxSignatureBase58": auth.TxSignature,
		"approvalSlot":              auth.ApprovalSlot,
	}
	if metadataHex != "" {
		signBody["messageMetadataHex"] = metadataHex
	}
	if presign != "" {
		signBody["presignSessionIdHex"] = presign
	}
	body, st, err := o.call(ctx, o.up.Ika, http.MethodPost, "/v1/dwallet/sign", signBody, userID)
	if err != nil || st != http.StatusOK {
		return "", fmt.Errorf("sign failed (status %d)", st)
	}
	var signEnv struct {
		Data ikaSignResult `json:"data"`
	}
	if err := json.Unmarshal(body, &signEnv); err != nil || signEnv.Data.SignatureBase64 == "" {
		return "", fmt.Errorf("sign returned no signature")
	}
	return signEnv.Data.SignatureBase64, nil
}

// broadcastTx calls the intents-backend /finalize (insert sig + broadcast).
// Returns (txHash, broadcastUnknown, err). A transport failure is treated as
// unknown so the reconciler resolves it rather than a blind retry.
func (o *Orchestrator) broadcastTx(ctx context.Context, userID string, it *Intent, unsignedTxB64, sigB64 string, chainID int) (string, bool, error) {
	finBody := map[string]any{
		"chainKind":       it.ChainKind,
		"unsignedTxB64":   unsignedTxB64,
		"signatureB64":    sigB64,
		"signerPubkeyHex": it.DwalletPublicKeyHex,
		"chainId":         chainID,
	}
	body, st, err := o.call(ctx, o.up.Intents, http.MethodPost, "/finalize", finBody, userID)
	if err != nil || st != http.StatusOK {
		return "", true, fmt.Errorf("finalize status %d", st)
	}
	var fin ibFinalizeResult
	if err := json.Unmarshal(body, &fin); err != nil {
		return "", true, fmt.Errorf("bad finalize response")
	}
	return fin.TxHash, fin.BroadcastUnknown, nil
}

// pollApproveReceipt polls the intents-backend for the EVM approve receipt until
// found or the deadline. Returns (found, success).
func (o *Orchestrator) pollApproveReceipt(ctx context.Context, it *Intent, txHash string, maxWait time.Duration) (bool, bool) {
	deadline := time.Now().Add(maxWait)
	for {
		if found, success := o.checkReceiptOnce(ctx, it, txHash); found {
			return found, success
		}
		if time.Now().After(deadline) {
			return false, false
		}
		select {
		case <-ctx.Done():
			return false, false
		case <-time.After(2 * time.Second):
		}
	}
}

func (o *Orchestrator) checkReceiptOnce(ctx context.Context, it *Intent, txHash string) (bool, bool) {
	q := url.Values{}
	q.Set("chainId", it.ChainID)
	q.Set("txHash", txHash)
	res, err := o.up.Intents.Call(ctx, http.MethodGet, "/evm/receipt", q, nil, map[string]string{"X-Andromeda-User-Id": it.UserID})
	if err != nil || res.StatusCode != http.StatusOK {
		return false, false
	}
	var rc struct {
		Found   bool `json:"found"`
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(res.Body, &rc); err != nil {
		return false, false
	}
	return rc.Found, rc.Success
}

// ---- Status --------------------------------------------------------------

func (o *Orchestrator) Status(ctx context.Context, userID, id string) (*statusResponse, error) {
	it, err := o.store.GetForUser(ctx, id, userID)
	if err == ErrNotFound {
		return nil, &userError{http.StatusNotFound, "not_found", "intent not found"}
	}
	if err != nil {
		return nil, &userError{http.StatusInternalServerError, "load_failed", "could not load intent"}
	}
	return &statusResponse{
		IntentID: it.ID, Status: it.Status, ChainKind: it.ChainKind,
		FromToken: it.FromToken, ToToken: it.ToToken, FromAmount: it.FromAmount,
		AmountOut: it.QuotedAmountOut, TxHash: it.SwapTxHash, UpdatedAt: it.UpdatedAt,
	}, nil
}

// ---- helpers -------------------------------------------------------------

// swapAuthInput builds the PolicyEngine authorize input from a persisted intent.
// Shared by prepare (challenge digest / presign) and submit (authorize).
func (o *Orchestrator) swapAuthInput(it *Intent) policy.SwapAuthorizeInput {
	return policy.SwapAuthorizeInput{
		DwalletAddress:          it.IkaDwalletAddress,
		InitAuthorityHashHex:    it.InitAuthorityHashHex,
		MessageDigestHex:        it.MessageDigestHex,
		UserPubkeyHex:           it.OwnerPubkeyHex,
		SignatureScheme:         it.SignScheme,
		IkaCurve:                it.IkaCurve,
		IkaDWalletPubkeyHex:     it.DwalletPublicKeyHex,
		IkaMsgMetadataDigestHex: nonZeroDigest(it.IkaMsgMetadataDigestHex),
	}
}

// verifyOwnDestination confirms toAddress is one of the dWallet's own derived
// addresses (across the curve's chains), via ika GET /v1/dwallet/addresses. It
// enforces "send to your own wallet" for cross-chain and rejects cross-family
// destinations (which would belong to a different dWallet).
func (o *Orchestrator) verifyOwnDestination(ctx context.Context, userID, dwalletAddress, toAddress string) *userError {
	path := "/v1/dwallet/addresses/" + url.PathEscape(dwalletAddress)
	res, err := o.up.Ika.Call(ctx, http.MethodGet, path, nil, nil, map[string]string{"X-Andromeda-User-Id": userID})
	if err != nil || res.StatusCode != http.StatusOK {
		return &userError{http.StatusBadGateway, "address_check_failed", "could not verify the destination address"}
	}
	var env struct {
		Data struct {
			Addresses []struct {
				ChainID string `json:"chainId"`
				Address string `json:"address"`
			} `json:"addresses"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body, &env); err != nil {
		return &userError{http.StatusBadGateway, "address_check_failed", "could not read derived addresses"}
	}
	want := normAddr(toAddress)
	for _, a := range env.Data.Addresses {
		if normAddr(a.Address) == want {
			return nil
		}
	}
	return &userError{http.StatusBadRequest, "external_destination",
		"toAddress must be your dWallet's own address on the destination chain; sending to a different/external wallet is not supported"}
}

// normAddr normalizes an address for comparison: EVM (0x) is hex case-insensitive
// (lowercased); base58 chains stay exact.
func normAddr(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strings.ToLower(s)
	}
	return s
}

// revalidate re-derives the signing material from the persisted unsignedTx (via
// the intents-backend, no re-quote) and verifies it matches the persisted
// snapshot byte-for-byte BEFORE authorizing/signing — defense against snapshot
// tampering (§11). wantTxHash "" skips the snapshot-hash check (the ERC20 approve
// has no separate stored hash).
func (o *Orchestrator) revalidate(ctx context.Context, userID, chainKind, unsignedTxB64, wantMsg, wantDigest, wantTxHash string) *userError {
	body := map[string]any{"chainKind": chainKind, "unsignedTxB64": unsignedTxB64}
	resp, st, err := o.call(ctx, o.up.Intents, http.MethodPost, "/derive-message", body, userID)
	if err != nil || st != http.StatusOK {
		return &userError{http.StatusBadGateway, "revalidate_failed", "could not re-validate the swap payload"}
	}
	var d struct {
		MessageToSignHex string `json:"messageToSignHex"`
		DigestHex        string `json:"digestHex"`
		UnsignedTxHash   string `json:"unsignedTxHash"`
	}
	if err := json.Unmarshal(resp, &d); err != nil {
		return &userError{http.StatusBadGateway, "revalidate_failed", "unreadable re-validation response"}
	}
	if d.MessageToSignHex != wantMsg || d.DigestHex != wantDigest || (wantTxHash != "" && d.UnsignedTxHash != wantTxHash) {
		return &userError{http.StatusConflict, "payload_drift", "the persisted swap payload failed re-validation"}
	}
	return nil
}

// checkNativeBalance pre-checks the dWallet has enough native token for the swap
// gas (§13). Best-effort: an empty/zero estimate or an RPC failure is not a
// blocker (the broadcast would surface a real shortfall) — only a confirmed
// shortfall fails the call, with a clear message.
func (o *Orchestrator) checkNativeBalance(ctx context.Context, userID, chainKind string, chainID int, address, needStr string) *userError {
	need, ok := new(big.Int).SetString(strings.TrimSpace(needStr), 10)
	if !ok || need.Sign() <= 0 {
		return nil
	}
	q := url.Values{}
	q.Set("chainKind", chainKind)
	q.Set("chainId", strconv.Itoa(chainID))
	q.Set("address", address)
	res, err := o.up.Intents.Call(ctx, http.MethodGet, "/native-balance", q, nil, map[string]string{"X-Andromeda-User-Id": userID})
	if err != nil || res.StatusCode != http.StatusOK {
		return nil
	}
	var b struct {
		Balance string `json:"balance"`
	}
	if err := json.Unmarshal(res.Body, &b); err != nil {
		return nil
	}
	bal, ok := new(big.Int).SetString(b.Balance, 10)
	if !ok {
		return nil
	}
	if bal.Cmp(need) < 0 {
		return &userError{http.StatusBadRequest, "insufficient_native_balance",
			fmt.Sprintf("dWallet needs at least %s native base units for swap gas but holds %s", need.String(), bal.String())}
	}
	return nil
}

// publish emits a per-tenant webhook (best-effort, nil-safe).
func (o *Orchestrator) publish(ctx context.Context, it *Intent, event, txHash string) {
	if o.webhooks == nil || it.APIKeyID == "" {
		return
	}
	apiKeyUUID, err := uuid.Parse(it.APIKeyID)
	if err != nil {
		return
	}
	_, _ = o.webhooks.Publish(ctx, apiKeyUUID, event, map[string]any{
		"intentId":  it.ID,
		"status":    it.Status,
		"chainKind": it.ChainKind,
		"fromToken": it.FromToken,
		"toToken":   it.ToToken,
		"txHash":    txHash,
	})
}

// authInputWithDigest is swapAuthInput with a different message digest — used to
// authorize the ERC20 approve tx (whose digest differs from the swap's).
func (o *Orchestrator) authInputWithDigest(it *Intent, msgDigest string) policy.SwapAuthorizeInput {
	in := o.swapAuthInput(it)
	in.MessageDigestHex = msgDigest
	return in
}

func (o *Orchestrator) call(ctx context.Context, target *upstream.Target, method, path string, body any, userID string) ([]byte, int, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	res, err := target.Call(ctx, method, path, nil, raw, map[string]string{"X-Andromeda-User-Id": userID})
	if err != nil {
		return nil, 0, err
	}
	return res.Body, res.StatusCode, nil
}

func (o *Orchestrator) appendAudit(ctx context.Context, it *Intent, action, txHash string) {
	if o.audit == nil || it.APIKeyID == "" {
		return
	}
	_ = o.audit.Append(ctx, AuditEvent{
		APIKeyID: it.APIKeyID, EventType: action, ResourceType: "intent",
		ResourceID: it.ID, Actor: it.UserID,
		Payload: map[string]any{
			"chain_kind": it.ChainKind, "from_token": it.FromToken, "to_token": it.ToToken,
			"tx_hash": txHash, "status": it.Status,
		},
	})
}

// riskLevel extracts the advisory level from a risk snapshot (none when absent).
func riskLevel(snap json.RawMessage) string {
	if len(snap) == 0 {
		return "none"
	}
	var parsed struct {
		Risk struct {
			Level string `json:"level"`
		} `json:"risk"`
	}
	if err := json.Unmarshal(snap, &parsed); err != nil || parsed.Risk.Level == "" {
		return "none"
	}
	return parsed.Risk.Level
}

func nonZeroDigest(hexStr string) string {
	if hexStr == "" {
		return ""
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return ""
	}
	for _, x := range b {
		if x != 0 {
			return hexStr
		}
	}
	return "" // all-zero → omit (no metadata seed, e.g. Solana)
}

func atoiOrZero(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// userError carries an HTTP-shaped failure to the handler.
type userError struct {
	status int
	code   string
	msg    string
}

func (e *userError) Error() string { return e.msg }

func upstreamUserError(status int, _ []byte, fallback string) *userError {
	if status == http.StatusUnprocessableEntity {
		return &userError{http.StatusUnprocessableEntity, "no_route", "no swap route available for these parameters"}
	}
	if status == http.StatusTooManyRequests {
		return &userError{http.StatusTooManyRequests, "backpressure", "aggregator rate limit reached, retry shortly"}
	}
	return &userError{http.StatusBadGateway, "upstream_error", fallback}
}
