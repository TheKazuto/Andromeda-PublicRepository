package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/webhook"

	"github.com/shinkalabs/andromeda-backend/internal/auth"
	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// GiftPurchaseObserver is invoked AFTER a paid gift card is persisted.
// Used to send the confirmation email + redeem URL. Optional — when nil
// the webhook handler skips notifications.
type GiftPurchaseObserver interface {
	OnGiftPurchased(ctx context.Context, ev GiftPurchaseEvent)
}

// GiftPurchaseEvent is the payload passed to the observer.
type GiftPurchaseEvent struct {
	GiftCard *store.GiftCard
	BuyerEmail string
}

// WebhookHandler applies Stripe events to our subscription state. The
// handler is invoked once per event id; the dedupe table prevents
// double-application on Stripe redeliveries.
//
// Events handled:
//
//   * checkout.session.completed       — assigns plan + persists Stripe ids
//   * customer.subscription.updated    — syncs status, cancellation
//   * customer.subscription.deleted    — marks cancelled
//   * invoice.payment_failed           — marks past_due
//   * invoice.paid / invoice.payment_succeeded — restores active
//
// Anything else is logged at debug and acknowledged with HTTP 200.
type WebhookHandler struct {
	svc          *Service
	store        store.BillingStore
	logger       *slog.Logger
	giftObserver GiftPurchaseObserver
}

func NewWebhookHandler(svc *Service, db store.BillingStore, logger *slog.Logger) *WebhookHandler {
	return &WebhookHandler{svc: svc, store: db, logger: logger}
}

// WithGiftObserver wires a side-effect for paid gift card creation —
// typically the SMTP mailer that emails the buyer with the redeem URL.
func (h *WebhookHandler) WithGiftObserver(obs GiftPurchaseObserver) *WebhookHandler {
	h.giftObserver = obs
	return h
}

// Verify parses the raw body + Stripe-Signature header, validating the
// signature with the configured webhook secret. Returns a stripe.Event
// ready for dispatch.
func (h *WebhookHandler) Verify(payload []byte, sigHeader string) (stripe.Event, error) {
	if h.svc.WebhookSecret() == "" {
		return stripe.Event{}, errors.New("webhook secret not configured")
	}
	return webhook.ConstructEvent(payload, sigHeader, h.svc.WebhookSecret())
}

// Handle dispatches a verified event. Idempotent — the caller is
// expected to persist the event id via store.MarkStripeEventProcessed
// before invoking this; on duplicate, Handle is not called.
func (h *WebhookHandler) Handle(ctx context.Context, ev stripe.Event) error {
	switch ev.Type {
	case "checkout.session.completed":
		return h.onCheckoutCompleted(ctx, ev)
	case "customer.subscription.created",
		"customer.subscription.updated":
		return h.onSubscriptionUpdated(ctx, ev)
	case "customer.subscription.deleted":
		return h.onSubscriptionDeleted(ctx, ev)
	case "invoice.payment_failed":
		return h.onInvoiceFailed(ctx, ev)
	case "invoice.paid", "invoice.payment_succeeded":
		return h.onInvoicePaid(ctx, ev)
	default:
		h.logger.Debug("stripe event ignored", "type", string(ev.Type), "id", ev.ID)
		return nil
	}
}

// ----- handlers -----

func (h *WebhookHandler) onCheckoutCompleted(ctx context.Context, ev stripe.Event) error {
	var sess stripe.CheckoutSession
	if err := json.Unmarshal(ev.Data.Raw, &sess); err != nil {
		return fmt.Errorf("unmarshal checkout session: %w", err)
	}

	// Two flows share this event: subscription (paid plan) and payment
	// (paid gift card). Dispatch on metadata.andromeda_flow.
	if sess.Metadata["andromeda_flow"] == MetadataFlowGift {
		return h.onGiftCheckoutCompleted(ctx, sess)
	}

	userID := sess.Metadata["andromeda_user_id"]
	planCode := sess.Metadata["plan_code"]
	if userID == "" || planCode == "" {
		return fmt.Errorf("checkout session missing required metadata (user_id=%q plan=%q)", userID, planCode)
	}

	customerID := ""
	if sess.Customer != nil {
		customerID = sess.Customer.ID
	}
	subID := ""
	if sess.Subscription != nil {
		subID = sess.Subscription.ID
	}

	// Persist customer linkage on user (idempotent — overwrites only when blank).
	if customerID != "" {
		if err := h.store.SetUserStripeCustomerID(ctx, userID, customerID); err != nil &&
			!errors.Is(err, store.ErrAlreadyExists) {
			h.logger.Warn("set user stripe customer failed", "err", err, "user", userID)
		}
	}

	// Assign the plan; the store creates a fresh subscription period.
	sub, err := h.store.AssignPlan(ctx, userID, planCode)
	if err != nil {
		return fmt.Errorf("assign plan: %w", err)
	}

	// Stamp Stripe linkage on the new subscription.
	if err := h.store.SetSubscriptionStripeIDs(ctx, sub.ID, customerID, subID); err != nil {
		h.logger.Warn("set sub stripe ids failed", "err", err, "sub", sub.ID)
	}

	h.logger.Info("checkout completed",
		"user", userID, "plan", planCode, "stripe_sub", subID)
	return nil
}

// onGiftCheckoutCompleted mints a paid gift card after Stripe confirms
// payment. Idempotent: the unique index on stripe_payment_id makes a
// second attempt return ErrAlreadyExists and we treat that as success.
func (h *WebhookHandler) onGiftCheckoutCompleted(ctx context.Context, sess stripe.CheckoutSession) error {
	planCode := strings.ToLower(strings.TrimSpace(sess.Metadata["plan_code"]))
	if planCode == "" {
		return fmt.Errorf("gift checkout missing plan_code metadata")
	}
	durationStr := sess.Metadata["duration_months"]
	durationMonths, err := strconv.Atoi(durationStr)
	if err != nil || (durationMonths != 1 && durationMonths != 12) {
		return fmt.Errorf("gift checkout invalid duration_months: %q", durationStr)
	}
	message := sess.Metadata["gift_message"]

	buyerEmail := ""
	if sess.CustomerDetails != nil {
		buyerEmail = sess.CustomerDetails.Email
	}

	paidAmountCents := 0
	if sess.AmountTotal > 0 {
		paidAmountCents = int(sess.AmountTotal)
	}

	// Use the session id as the stripe_payment_id key — the actual
	// payment_intent id is also available but the session id is what
	// uniquely identifies THIS purchase from THIS link.
	stripePaymentID := sess.ID

	token, err := auth.GenerateGiftToken()
	if err != nil {
		return fmt.Errorf("generate gift token: %w", err)
	}

	in := store.GiftCardCreate{
		RedeemToken:     token,
		PlanCode:        planCode,
		DurationMonths:  durationMonths,
		Source:          "paid",
		BuyerEmail:      buyerEmail,
		PaidAmountCents: &paidAmountCents,
		StripePaymentID: stripePaymentID,
		Message:         message,
		ExpiresAt:       time.Now().UTC().Add(store.GiftCardTTL),
	}

	gift, err := h.store.CreateGiftCard(ctx, in)
	if err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			// Webhook redelivery — idempotent skip.
			h.logger.Info("gift checkout already minted (redelivery)", "session", sess.ID)
			return nil
		}
		return fmt.Errorf("create paid gift card: %w", err)
	}
	h.logger.Info("paid gift card minted",
		"session", sess.ID, "gift", gift.ID, "plan", planCode,
		"duration_months", durationMonths, "amount_cents", paidAmountCents)

	if h.giftObserver != nil {
		h.giftObserver.OnGiftPurchased(ctx, GiftPurchaseEvent{
			GiftCard:   gift,
			BuyerEmail: buyerEmail,
		})
	}
	return nil
}

func (h *WebhookHandler) onSubscriptionUpdated(ctx context.Context, ev stripe.Event) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(ev.Data.Raw, &sub); err != nil {
		return fmt.Errorf("unmarshal subscription: %w", err)
	}
	internal, err := h.store.GetSubscriptionByStripeID(ctx, sub.ID)
	if err != nil {
		// Race: webhook arrived before checkout.session.completed wrote
		// the linkage. Stripe will retry — return nil so we ack the event
		// and rely on the redelivery to find the row.
		if errors.Is(err, store.ErrNotFound) {
			h.logger.Info("subscription event without local match — will rely on retry",
				"stripe_sub", sub.ID)
			return nil
		}
		return err
	}
	mapped := mapStripeStatus(sub.Status)
	if mapped == "" {
		h.logger.Debug("ignoring subscription status", "status", sub.Status, "stripe_sub", sub.ID)
		return nil
	}
	if err := h.store.SetSubscriptionStatus(ctx, internal.ID, mapped); err != nil {
		return err
	}
	h.logger.Info("subscription status synced",
		"sub", internal.ID, "stripe_sub", sub.ID, "status", mapped)
	return nil
}

func (h *WebhookHandler) onSubscriptionDeleted(ctx context.Context, ev stripe.Event) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(ev.Data.Raw, &sub); err != nil {
		return fmt.Errorf("unmarshal subscription: %w", err)
	}
	internal, err := h.store.GetSubscriptionByStripeID(ctx, sub.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if err := h.store.SetSubscriptionStatus(ctx, internal.ID, "cancelled"); err != nil {
		return err
	}
	h.logger.Info("subscription cancelled via Stripe", "sub", internal.ID, "stripe_sub", sub.ID)
	return nil
}

func (h *WebhookHandler) onInvoiceFailed(ctx context.Context, ev stripe.Event) error {
	subID := extractInvoiceSubscriptionID(ev.Data.Raw)
	if subID == "" {
		return nil
	}
	internal, err := h.store.GetSubscriptionByStripeID(ctx, subID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if err := h.store.SetSubscriptionStatus(ctx, internal.ID, "past_due"); err != nil {
		return err
	}
	h.logger.Warn("invoice payment failed — sub marked past_due",
		"sub", internal.ID, "stripe_sub", subID)
	return nil
}

func (h *WebhookHandler) onInvoicePaid(ctx context.Context, ev stripe.Event) error {
	subID := extractInvoiceSubscriptionID(ev.Data.Raw)
	if subID == "" {
		return nil
	}
	internal, err := h.store.GetSubscriptionByStripeID(ctx, subID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if internal.Status == "past_due" {
		if err := h.store.SetSubscriptionStatus(ctx, internal.ID, "active"); err != nil {
			return err
		}
		h.logger.Info("subscription restored to active after successful invoice",
			"sub", internal.ID, "stripe_sub", subID)
	}
	return nil
}

// extractInvoiceSubscriptionID pulls the .subscription field out of a raw
// invoice payload without forcing the whole stripe.Invoice deserialisation
// (the field is sometimes a string id, sometimes an expanded object).
func extractInvoiceSubscriptionID(raw json.RawMessage) string {
	var probe struct {
		Subscription json.RawMessage `json:"subscription"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil || len(probe.Subscription) == 0 {
		return ""
	}
	// Try string form first.
	var s string
	if err := json.Unmarshal(probe.Subscription, &s); err == nil && s != "" {
		return s
	}
	// Fall through: object with an id field.
	var obj struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(probe.Subscription, &obj); err == nil {
		return obj.ID
	}
	return ""
}

// mapStripeStatus converts Stripe's subscription.status taxonomy to our
// 4-value internal state. Returns empty string for transient states we
// ignore (incomplete_expired, etc) — callers leave the row untouched.
func mapStripeStatus(s stripe.SubscriptionStatus) string {
	switch s {
	case stripe.SubscriptionStatusActive:
		return "active"
	case stripe.SubscriptionStatusTrialing:
		return "trialing"
	case stripe.SubscriptionStatusPastDue, stripe.SubscriptionStatusUnpaid:
		return "past_due"
	case stripe.SubscriptionStatusCanceled, stripe.SubscriptionStatusIncompleteExpired:
		return "cancelled"
	default:
		return ""
	}
}
