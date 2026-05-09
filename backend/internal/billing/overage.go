package billing

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/billing/meterevent"
	"github.com/stripe/stripe-go/v82/subscriptionitem"
)

// MeterEventName is the Stripe Billing Meter event_name our overage
// pipeline reports against. Configure a meter in the Stripe dashboard
// with this exact name and sum-aggregation, then attach metered prices
// to subscriptions for "overage:standard" and "overage:enterprise".
const MeterEventName = "andromeda_overage_tokens"

// AddOverageItem appends the metered overage subscription item to an
// existing Stripe subscription. Returns the new subscription_item id —
// caller persists it on subscriptions.stripe_overage_item_id so the
// matching DisableOverage call can locate the row.
//
// `overageTier` is "standard" or "enterprise"; the corresponding price
// id is resolved from the same STRIPE_PRICES_JSON map ("overage:standard"
// → price_xxx).
func (s *Service) AddOverageItem(ctx context.Context, stripeSubscriptionID, overageTier string) (string, error) {
	if !s.Enabled() {
		return "", ErrServiceDisabled
	}
	if stripeSubscriptionID == "" {
		return "", errors.New("stripe subscription id required")
	}
	priceID, err := s.PriceID("overage", overageTier)
	if err != nil {
		return "", err
	}
	params := &stripe.SubscriptionItemParams{
		Subscription: stripe.String(stripeSubscriptionID),
		Price:        stripe.String(priceID),
		// We never count overage as the recurring quantity — meter events
		// drive the billable amount. Quantity must be omitted for metered
		// items, which Stripe enforces server-side.
	}
	item, err := subscriptionitem.New(params)
	if err != nil {
		return "", fmt.Errorf("add overage item: %w", err)
	}
	return item.ID, nil
}

// RemoveOverageItem deletes the metered subscription item created by
// AddOverageItem. Idempotent — a missing item returns nil.
func (s *Service) RemoveOverageItem(ctx context.Context, stripeItemID string) error {
	if !s.Enabled() {
		return ErrServiceDisabled
	}
	if stripeItemID == "" {
		return nil
	}
	_, err := subscriptionitem.Del(stripeItemID, nil)
	if err != nil {
		// Stripe returns 404 wrapped in stripe.Error when the item is
		// already gone. Treat that as success.
		var stripeErr *stripe.Error
		if errors.As(err, &stripeErr) && stripeErr.HTTPStatusCode == 404 {
			return nil
		}
		return fmt.Errorf("remove overage item: %w", err)
	}
	return nil
}

// ReportOverage sends a meter event to Stripe with the cumulative tokens
// consumed since the last report. Stripe aggregates these events against
// the configured meter and bills at the end of the period.
//
// Returns the value reported (for telemetry). The caller is responsible
// for advancing overage_reported_tokens by the same amount AFTER this
// returns nil.
func (s *Service) ReportOverage(ctx context.Context, stripeCustomerID string, tokens int64) (int64, error) {
	if !s.Enabled() {
		return 0, ErrServiceDisabled
	}
	if stripeCustomerID == "" {
		return 0, errors.New("stripe customer id required")
	}
	if tokens <= 0 {
		return 0, nil
	}
	params := &stripe.BillingMeterEventParams{
		EventName: stripe.String(MeterEventName),
		Payload: map[string]string{
			"stripe_customer_id": stripeCustomerID,
			"value":              strconv.FormatInt(tokens, 10),
		},
	}
	if _, err := meterevent.New(params); err != nil {
		return 0, fmt.Errorf("report meter event: %w", err)
	}
	return tokens, nil
}
