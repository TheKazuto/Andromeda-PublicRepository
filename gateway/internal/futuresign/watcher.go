package futuresign

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/shinkalabs/andromeda-gateway/internal/netsafety"
)

// IkaCompleter is the subset of the ika-backend we need: posting a
// completed future-sign and getting the raw signatureHex back.
//
// Default implementation in this package issues an HTTP request to the
// ika-backend's `/v1/dwallet/future-sign/complete/submit` over the private
// network. Tests inject a fake.
type IkaCompleter interface {
	CompleteFutureSign(ctx context.Context, payload json.RawMessage) (signatureHex string, err error)
}

// EventPublisher is the subset of webhooks.Publisher we need.
type EventPublisher interface {
	Publish(ctx context.Context, apiKeyID uuid.UUID, eventType string, payload any) (int, error)
}

// WatcherOptions configures the watcher loops.
type WatcherOptions struct {
	Store     *Store
	Ika       IkaCompleter
	Publisher EventPublisher
	Logger    *slog.Logger
	URLGuard  *netsafety.Validator // optional; defaults to production validator

	// SlotTimeTickInterval — how often the slot_time loop scans the DB for
	// triggers due to fire. Defaults to 5s.
	SlotTimeTickInterval time.Duration

	// ExternalWebhookTickInterval — how often the external_webhook loop polls
	// each registered callback. Defaults to 30s.
	ExternalWebhookTickInterval time.Duration

	// ExpiryTickInterval — how often the watcher reaps expired triggers.
	// Defaults to 60s.
	ExpiryTickInterval time.Duration

	// SolanaSlotProvider returns the latest finalized Solana slot. If nil,
	// the slot_time loop falls back to wall-clock time using
	// `triggerAtSlot * 400ms` from epoch. That is an approximation good enough
	// for off-chain mock signing in pre-alpha; production replaces this with a
	// real Solana RPC call.
	SolanaSlotProvider func(context.Context) (int64, error)
}

// Watcher orchestrates the per-trigger-type loops.
type Watcher struct {
	opts WatcherOptions
}

// NewWatcher returns a watcher. It is safe to call Start multiple times in
// independent goroutines for horizontal scaling — the SELECT FOR UPDATE
// SKIP LOCKED claim guarantees no double-fire.
func NewWatcher(opts WatcherOptions) *Watcher {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.SlotTimeTickInterval == 0 {
		opts.SlotTimeTickInterval = 5 * time.Second
	}
	if opts.ExternalWebhookTickInterval == 0 {
		opts.ExternalWebhookTickInterval = 30 * time.Second
	}
	if opts.ExpiryTickInterval == 0 {
		opts.ExpiryTickInterval = 60 * time.Second
	}
	if opts.URLGuard == nil {
		opts.URLGuard = netsafety.New(netsafety.ModeProduction)
	}
	return &Watcher{opts: opts}
}

// Start runs all enabled loops until ctx is cancelled.
func (w *Watcher) Start(ctx context.Context) {
	go w.runSlotTimeLoop(ctx)
	go w.runExternalWebhookLoop(ctx)
	go w.runExpiryLoop(ctx)
}

// ----- slot_time loop -----

func (w *Watcher) runSlotTimeLoop(ctx context.Context) {
	ticker := time.NewTicker(w.opts.SlotTimeTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.tickSlotTime(ctx)
		}
	}
}

func (w *Watcher) tickSlotTime(ctx context.Context) {
	now := time.Now().UTC()
	currentSlot, err := w.currentSlot(ctx, now)
	if err != nil {
		w.opts.Logger.Warn("slot provider failed", "err", err)
		return
	}
	for {
		t, err := w.opts.Store.ClaimDueArmed(ctx, []TriggerType{TriggerTypeSlotTime}, now)
		if err != nil {
			w.opts.Logger.Warn("claim due slot_time failed", "err", err)
			return
		}
		if t == nil {
			return
		}
		var cond ConditionSlotTime
		if err := json.Unmarshal(t.Condition, &cond); err != nil {
			w.fail(ctx, t, fmt.Sprintf("invalid condition: %v", err))
			continue
		}
		if currentSlot < cond.TriggerAtSlot {
			// Not due yet — bounce back to armed.
			if err := w.opts.Store.MarkFailed(ctx, t.ID, "slot not yet reached"); err != nil {
				w.opts.Logger.Warn("revert to armed failed", "err", err)
			}
			continue
		}
		w.fire(ctx, t)
	}
}

func (w *Watcher) currentSlot(ctx context.Context, now time.Time) (int64, error) {
	if w.opts.SolanaSlotProvider != nil {
		return w.opts.SolanaSlotProvider(ctx)
	}
	// Fallback approximation: 400 ms per slot since unix epoch.
	const slotMs = 400
	return now.UnixMilli() / slotMs, nil
}

// ----- external_webhook loop -----

func (w *Watcher) runExternalWebhookLoop(ctx context.Context) {
	ticker := time.NewTicker(w.opts.ExternalWebhookTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.tickExternalWebhook(ctx)
		}
	}
}

func (w *Watcher) tickExternalWebhook(ctx context.Context) {
	now := time.Now().UTC()
	for {
		t, err := w.opts.Store.ClaimDueArmed(ctx, []TriggerType{TriggerTypeExternalWebhook}, now)
		if err != nil {
			w.opts.Logger.Warn("claim due external_webhook failed", "err", err)
			return
		}
		if t == nil {
			return
		}
		var cond ConditionExternalWebhook
		if err := json.Unmarshal(t.Condition, &cond); err != nil {
			w.fail(ctx, t, fmt.Sprintf("invalid condition: %v", err))
			continue
		}
		// Re-validate the callback URL at dispatch time so DNS rebinding
		// (registration → fire) cannot redirect the gateway at a private IP.
		if err := w.opts.URLGuard.ValidateDispatch(ctx, cond.CallbackURL); err != nil {
			if revertErr := w.opts.Store.MarkFailed(ctx, t.ID, "callbackUrl rejected by url guard"); revertErr != nil {
				w.opts.Logger.Warn("revert external_webhook (url guard) failed", "err", revertErr)
			}
			continue
		}
		shouldFire, err := pollExternalWebhook(ctx, cond)
		if err != nil {
			if revertErr := w.opts.Store.MarkFailed(ctx, t.ID, err.Error()); revertErr != nil {
				w.opts.Logger.Warn("revert external_webhook failed", "err", revertErr)
			}
			continue
		}
		if !shouldFire {
			if err := w.opts.Store.MarkFailed(ctx, t.ID, "external_webhook not yet ready"); err != nil {
				w.opts.Logger.Warn("revert external_webhook failed", "err", err)
			}
			continue
		}
		w.fire(ctx, t)
	}
}

// pollExternalWebhook posts an empty body to the dev's callback URL. The dev
// returns 200 with `{"shouldFire": true}` when the trigger is ready.
//
// SSRF defense lives in the watcher loop (ValidateDispatch) and at
// registration time (ValidateRegister); this function trusts that the URL has
// already been vetted. We still strip the bearer token if the URL ever
// resolves to a non-HTTPS scheme — bearers must never travel in clear.
func pollExternalWebhook(ctx context.Context, cond ConditionExternalWebhook) (bool, error) {
	if cond.CallbackURL == "" {
		return false, fmt.Errorf("callbackUrl missing")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cond.CallbackURL, nil)
	if err != nil {
		return false, err
	}
	if cond.BearerToken != "" && strings.HasPrefix(strings.ToLower(cond.CallbackURL), "https://") {
		req.Header.Set("Authorization", "Bearer "+cond.BearerToken)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("callback request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("callback non-2xx: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return false, fmt.Errorf("read callback: %w", err)
	}
	var parsed struct {
		ShouldFire bool `json:"shouldFire"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false, fmt.Errorf("decode callback: %w", err)
	}
	return parsed.ShouldFire, nil
}

// ----- expiry loop -----

func (w *Watcher) runExpiryLoop(ctx context.Context) {
	ticker := time.NewTicker(w.opts.ExpiryTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ids, err := w.opts.Store.ExpireOverdue(ctx, time.Now().UTC())
			if err != nil {
				w.opts.Logger.Warn("expire overdue failed", "err", err)
				continue
			}
			for _, id := range ids {
				if w.opts.Publisher != nil {
					_, _ = w.opts.Publisher.Publish(ctx, uuid.Nil, "future_sign.expired", map[string]any{
						"trigger_id": id.String(),
					})
				}
			}
		}
	}
}

// ----- fire path -----

func (w *Watcher) fire(ctx context.Context, t *Trigger) {
	w.opts.Logger.Info("future-sign trigger firing", "trigger_id", t.ID, "type", t.TriggerType)
	if w.opts.Ika == nil {
		w.fail(ctx, t, "ika completer not configured")
		return
	}
	signatureHex, err := w.opts.Ika.CompleteFutureSign(ctx, t.CompletePayload)
	if err != nil {
		if revertErr := w.opts.Store.MarkFailed(ctx, t.ID, err.Error()); revertErr != nil {
			w.opts.Logger.Warn("mark failed during fire failed", "err", revertErr)
		}
		w.opts.Logger.Warn("future-sign fire failed", "trigger_id", t.ID, "err", err)
		return
	}
	if err := w.opts.Store.MarkFired(ctx, t.ID, signatureHex); err != nil {
		w.opts.Logger.Warn("mark fired failed", "trigger_id", t.ID, "err", err)
		return
	}
	if w.opts.Publisher != nil {
		_, perr := w.opts.Publisher.Publish(ctx, t.APIKeyID, "future_sign.fired", map[string]any{
			"trigger_id":      t.ID.String(),
			"dwallet_address": t.DWalletAddress,
			"signature_hex":   signatureHex,
		})
		if perr != nil {
			w.opts.Logger.Warn("publish future_sign.fired failed", "err", perr)
		}
	}
}

func (w *Watcher) fail(ctx context.Context, t *Trigger, reason string) {
	if err := w.opts.Store.MarkFailed(ctx, t.ID, reason); err != nil {
		w.opts.Logger.Warn("mark failed (terminal) failed", "trigger_id", t.ID, "err", err)
	}
}

// ----- IkaCompleter default impl -----

// HTTPCompleter is the production implementation of IkaCompleter — POSTs the
// completePayload to /v1/dwallet/future-sign/complete/submit on the ika-backend
// in the private network.
type HTTPCompleter struct {
	BaseURL string
	APIKey  string
	Client  *http.Client
}

// NewHTTPCompleter returns an HTTPCompleter with sane defaults.
func NewHTTPCompleter(baseURL, apiKey string) *HTTPCompleter {
	return &HTTPCompleter{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		Client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// CompleteFutureSign POSTs the payload and returns the signatureHex.
func (h *HTTPCompleter) CompleteFutureSign(ctx context.Context, payload json.RawMessage) (string, error) {
	if h.BaseURL == "" {
		return "", fmt.Errorf("ika base URL not configured")
	}
	url := h.BaseURL + "/v1/dwallet/future-sign/complete/submit"
	body := payload
	if len(body) == 0 {
		body = json.RawMessage("{}")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.APIKey != "" {
		req.Header.Set("X-Api-Key", h.APIKey)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ika complete: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read ika response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("ika complete non-2xx: %d body=%s", resp.StatusCode, string(respBody))
	}
	var parsed struct {
		Data struct {
			SignatureHex string `json:"signatureHex"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("decode ika response: %w", err)
	}
	if parsed.Data.SignatureHex == "" {
		return "", fmt.Errorf("ika response missing signatureHex")
	}
	return parsed.Data.SignatureHex, nil
}
