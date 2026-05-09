package store

import (
	"context"
	"time"
)

// Billing-related types. Tables themselves are owned by the gateway —
// see `gateway/internal/store/migrations/*.sql`. Backend reads/writes
// via SQL through the same Postgres pool. MemoryStore does NOT support
// billing operations; the BillingStore interface is satisfied only by
// PostgresStore.
//
// Field shapes mirror gateway's so values flow through unchanged when
// both services share the same DB.

// Subscription is a per-user copy of a plan, snapshotted at activation.
type Subscription struct {
	ID                    string     `json:"id"`
	UserID                string     `json:"userId"`
	PlanID                string     `json:"planId"`
	PlanCode              string     `json:"planCode"`
	Status                string     `json:"status"`
	BillingCycle          string     `json:"billingCycle"`
	CurrentPeriodStart    time.Time  `json:"currentPeriodStart"`
	CurrentPeriodEnd      time.Time  `json:"currentPeriodEnd"`
	TokensUsed            int64      `json:"tokensUsed"`
	TokensLimit           int64      `json:"tokensLimit"`
	OverageEnabled        bool       `json:"overageEnabled"`
	OverageCardPresent    bool       `json:"overageCardPresent"`
	OverageUsedTokens     int64      `json:"overageUsedTokens"`
	OverageCapTokens      int64      `json:"overageCapTokens"`
	OverageReportedTokens int64      `json:"overageReportedTokens"`
	OverageLastReportedAt *time.Time `json:"overageLastReportedAt,omitempty"`
	StripeCustomerID      string     `json:"stripeCustomerId,omitempty"`
	StripeSubscriptionID  string     `json:"stripeSubscriptionId,omitempty"`
	StripeOverageItemID   string     `json:"stripeOverageItemId,omitempty"`
	CreatedAt             time.Time  `json:"createdAt"`
	UpdatedAt             time.Time  `json:"updatedAt"`
}

// GiftCard is a redeemable plan voucher, paid or promo.
type GiftCard struct {
	ID              string     `json:"id"`
	RedeemToken     string     `json:"redeemToken"`
	PlanCode        string     `json:"planCode"`
	DurationMonths  int        `json:"durationMonths"`
	Source          string     `json:"source"`
	BuyerUserID     *string    `json:"buyerUserId,omitempty"`
	BuyerEmail      string     `json:"buyerEmail,omitempty"`
	PaidAmountCents *int       `json:"paidAmountCents,omitempty"`
	StripePaymentID string     `json:"stripePaymentId,omitempty"`
	GrantedBy       string     `json:"grantedBy,omitempty"`
	Message         string     `json:"message"`
	ExpiresAt       time.Time  `json:"expiresAt"`
	RedeemedAt      *time.Time `json:"redeemedAt,omitempty"`
	RedeemedBy      *string    `json:"redeemedBy,omitempty"`
	RefundedAt      *time.Time `json:"refundedAt,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
}

// GiftCardCreate is the input for inserting a gift card row.
type GiftCardCreate struct {
	RedeemToken     string
	PlanCode        string
	DurationMonths  int
	Source          string
	BuyerUserID     *string
	BuyerEmail      string
	PaidAmountCents *int
	StripePaymentID string
	GrantedBy       string
	Message         string
	ExpiresAt       time.Time
}

// SubscriptionMutation is a partial update for subscriptions.
type SubscriptionMutation struct {
	OverageEnabled       *bool
	OverageCardPresent   *bool
	OverageCapTokens     *int64
	BillingCycle         *string
	StripeCustomerID     *string
	StripeSubscriptionID *string
}

// OverageReportTarget is the projection the reporting worker iterates.
type OverageReportTarget struct {
	SubscriptionID        string
	StripeCustomerID      string
	StripeSubscriptionID  string
	StripeOverageItemID   string
	OverageUsedTokens     int64
	OverageReportedTokens int64
}

// PendingDelta returns the (used - reported) value the worker should
// send to Stripe. Always non-negative.
func (o OverageReportTarget) PendingDelta() int64 {
	d := o.OverageUsedTokens - o.OverageReportedTokens
	if d < 0 {
		return 0
	}
	return d
}

// GiftCardTTL is how long a gift card stays redeemable from purchase.
const GiftCardTTL = 365 * 24 * time.Hour

// BillingStore is the subset of operations the billing pipeline needs.
// PostgresStore satisfies it; MemoryStore explicitly does not (returns
// ErrNotFound or panics in dev — billing without Postgres is unsupported).
type BillingStore interface {
	// User → Stripe customer linkage.
	SetUserStripeCustomerID(ctx context.Context, userID, stripeCustomerID string) error
	GetUserByStripeCustomerID(ctx context.Context, stripeCustomerID string) (*User, error)

	// Subscription lifecycle.
	AssignPlan(ctx context.Context, userID, planCode string) (*Subscription, error)
	GetActiveSubscription(ctx context.Context, userID string) (*Subscription, error)
	GetSubscriptionByStripeID(ctx context.Context, stripeSubscriptionID string) (*Subscription, error)
	SetSubscriptionStripeIDs(ctx context.Context, subscriptionID, stripeCustomerID, stripeSubscriptionID string) error
	SetSubscriptionStatus(ctx context.Context, subscriptionID, status string) error
	UpdateSubscription(ctx context.Context, subscriptionID string, mut SubscriptionMutation) (*Subscription, error)

	// Overage reporting state.
	SetSubscriptionOverageItem(ctx context.Context, subscriptionID, stripeItemID string) error
	AdvanceOverageReported(ctx context.Context, subscriptionID string, delta int64) error
	ListSubscriptionsForOverageReport(ctx context.Context) ([]OverageReportTarget, error)

	// Gift cards.
	CreateGiftCard(ctx context.Context, in GiftCardCreate) (*GiftCard, error)

	// Stripe webhook idempotency.
	MarkStripeEventProcessed(ctx context.Context, eventID, eventType, apiVersion string) (bool, error)
	UnmarkStripeEventProcessed(ctx context.Context, eventID string) error
}
