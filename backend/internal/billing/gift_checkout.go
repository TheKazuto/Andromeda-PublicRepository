package billing

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
)

// MetadataFlowGift identifies a Checkout Session created via the gift
// purchase flow. The webhook handler dispatches on this metadata key
// to distinguish from regular subscription checkouts.
const MetadataFlowGift = "gift"

// CreateGiftCheckoutInput is the payload for buying a gift card. The
// buyer's email is collected by Stripe Checkout — we only declare the
// price for the (plan, duration) and pass through enough metadata for
// the webhook handler to mint the gift_cards row on payment success.
type CreateGiftCheckoutInput struct {
	PlanCode           string
	DurationMonths     int    // 1 or 12
	Message            string // optional buyer-supplied note for the recipient
	SuccessURLOverride string
	CancelURLOverride  string
}

// CreateGiftCheckoutSession builds a Stripe Checkout Session in
// `payment` mode for a one-time gift card purchase. Returns the URL
// the browser should be redirected to. The buyer enters their email +
// payment details on Stripe; on completion, our webhook handler creates
// the gift_cards row and emails the redeem URL.
func (s *Service) CreateGiftCheckoutSession(ctx context.Context, in CreateGiftCheckoutInput) (*CheckoutSessionResult, error) {
	if !s.Enabled() {
		return nil, ErrServiceDisabled
	}
	if in.DurationMonths != 1 && in.DurationMonths != 12 {
		return nil, errors.New("durationMonths must be 1 or 12")
	}

	cycle := "monthly"
	if in.DurationMonths == 12 {
		cycle = "annual"
	}
	priceKey := "gift:" + in.PlanCode + ":" + cycle
	priceID, ok := s.priceIDs[priceKey]
	if !ok || priceID == "" {
		return nil, fmt.Errorf("%w: %s", ErrPriceNotConfigured, priceKey)
	}

	successURL := firstNonEmpty(in.SuccessURLOverride, s.successURL)
	cancelURL := firstNonEmpty(in.CancelURLOverride, s.cancelURL)
	if successURL == "" || cancelURL == "" {
		return nil, errors.New("checkout success_url and cancel_url must be configured")
	}

	params := &stripe.CheckoutSessionParams{
		Mode: stripe.String(string(stripe.CheckoutSessionModePayment)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(priceID),
				Quantity: stripe.Int64(1),
			},
		},
		SuccessURL: stripe.String(successURL),
		CancelURL:  stripe.String(cancelURL),
		// Stripe collects the buyer's email automatically in payment mode.
	}
	params.AddMetadata("andromeda_flow", MetadataFlowGift)
	params.AddMetadata("plan_code", in.PlanCode)
	params.AddMetadata("duration_months", strconv.Itoa(in.DurationMonths))
	if in.Message != "" {
		params.AddMetadata("gift_message", in.Message)
	}

	sess, err := session.New(params)
	if err != nil {
		return nil, fmt.Errorf("create gift checkout session: %w", err)
	}
	return &CheckoutSessionResult{
		URL:       sess.URL,
		SessionID: sess.ID,
	}, nil
}
