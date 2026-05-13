package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound          = errors.New("not found")
	ErrAlreadyExists     = errors.New("already exists")
	ErrQuotaExceeded     = errors.New("quota exceeded")
	ErrKeyRevoked        = errors.New("api key revoked")
	ErrGiftAlreadyUsed   = errors.New("gift card already redeemed")
	ErrGiftExpired       = errors.New("gift card expired")
	ErrGiftRefunded      = errors.New("gift card refunded")
	ErrGiftNotEligible   = errors.New("gift card not eligible for refund")
	ErrCreditExpired     = errors.New("credit expired")
	ErrAdminInactive     = errors.New("admin user is not active")
	ErrPricingChangeBusy = errors.New("pricing change already applied or cancelled")
)

// =============================================================================
// Domain types
// =============================================================================

type User struct {
	ID               string    `json:"id"`
	Email            string    `json:"email"`
	Name             string    `json:"name"`
	StripeCustomerID string    `json:"stripeCustomerId,omitempty"`
	CreatedAt        time.Time `json:"createdAt"`
}

type APIKey struct {
	ID             string     `json:"id"`
	UserID         string     `json:"userId"`
	Name           string     `json:"name"`
	Prefix         string     `json:"prefix"`
	HashedKey      string     `json:"-"`
	Scopes         []string   `json:"scopes"`
	IPAllowlist    []string   `json:"ipAllowlist"`
	AllowedOrigins []string   `json:"allowedOrigins"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastUsedAt     *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt      *time.Time `json:"revokedAt,omitempty"`
}

// Plan describes a subscription tier. The legacy single-bucket fields
// (RateLimitRPS / RateLimitBurst) are kept alongside the new per-class
// buckets (Read* / Tx*) so the existing middleware keeps working until
// it's migrated.
type Plan struct {
	ID                string         `json:"id"`
	Code              string         `json:"code"`
	Name              string         `json:"name"`
	MonthlyTokens     int64          `json:"monthlyTokens"`
	PriceCents        int            `json:"priceCents"`
	AnnualPriceCents  int            `json:"annualPriceCents"`
	OveragePer1kCents int            `json:"overagePer1kCents"`
	RateLimitRPS      int            `json:"rateLimitRps"`   // legacy single bucket
	RateLimitBurst    int            `json:"rateLimitBurst"` // legacy single bucket
	ReadRPS           int            `json:"readRps"`
	ReadBurst         int            `json:"readBurst"`
	TxRPS             int            `json:"txRps"`
	TxBurst           int            `json:"txBurst"`
	Features          map[string]any `json:"features"`
	IsActive          bool           `json:"isActive"`
	IsGiftable        bool           `json:"isGiftable"`
	SortOrder         int            `json:"sortOrder"`
	CreatedAt         time.Time      `json:"createdAt"`
	UpdatedAt         time.Time      `json:"updatedAt"`
}

// Subscription is the per-user copy of a plan, snapshotted at activation
// time. Plan changes don't affect active subscriptions until rollover —
// this is what enforces the "grandfather" contract on pricing changes.
type Subscription struct {
	ID                    string     `json:"id"`
	UserID                string     `json:"userId"`
	PlanID                string     `json:"planId"`
	PlanCode              string     `json:"planCode"`
	Status                string     `json:"status"`
	BillingCycle          string     `json:"billingCycle"` // 'monthly' | 'annual'
	CurrentPeriodStart    time.Time  `json:"currentPeriodStart"`
	CurrentPeriodEnd      time.Time  `json:"currentPeriodEnd"`
	TokensUsed            int64      `json:"tokensUsed"`
	TokensLimit           int64      `json:"tokensLimit"`
	OverageEnabled        bool       `json:"overageEnabled"`
	OverageCardPresent    bool       `json:"overageCardPresent"`
	OverageUsedTokens     int64      `json:"overageUsedTokens"`
	OverageCapTokens      int64      `json:"overageCapTokens"` // hard cap (2× tokens_limit)
	OverageReportedTokens int64      `json:"overageReportedTokens"`
	OverageLastReportedAt *time.Time `json:"overageLastReportedAt,omitempty"`
	StripeOverageItemID   string     `json:"stripeOverageItemId,omitempty"`
	RateLimitRPS          int        `json:"rateLimitRps"`   // legacy single bucket
	RateLimitBurst        int        `json:"rateLimitBurst"` // legacy single bucket
	ReadRPS               int        `json:"readRps"`
	ReadBurst             int        `json:"readBurst"`
	TxRPS                 int        `json:"txRps"`
	TxBurst               int        `json:"txBurst"`
	StripeCustomerID      string     `json:"stripeCustomerId,omitempty"`
	StripeSubscriptionID  string     `json:"stripeSubscriptionId,omitempty"`
	CreatedAt             time.Time  `json:"createdAt"`
	UpdatedAt             time.Time  `json:"updatedAt"`
}

type RequestCost struct {
	RouteKey    string    `json:"routeKey"`
	CostTokens  int       `json:"costTokens"`
	Description string    `json:"description"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type UsageEvent struct {
	UserID         string
	APIKeyID       *string
	SubscriptionID *string
	RouteKey       string
	CostTokens     int
	StatusCode     int
	LatencyMs      int
	RequestID      string
	OccurredAt     time.Time
}

// Credit is a granted token allowance (free, by Andromeda) that expires
// after 30 days and is consumed BEFORE monthly tokens.
type Credit struct {
	ID          string     `json:"id"`
	UserID      string     `json:"userId"`
	Amount      int64      `json:"amount"`
	Consumed    int64      `json:"consumed"`
	Reason      string     `json:"reason"` // 'trial' | 'support' | 'promo' | 'hackathon' | 'partner'
	GrantedBy   string     `json:"grantedBy"`
	ExpiresAt   time.Time  `json:"expiresAt"`
	ExhaustedAt *time.Time `json:"exhaustedAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
}

// Remaining returns how many tokens this credit can still cover.
// Returns 0 when expired or exhausted.
func (c Credit) Remaining(now time.Time) int64 {
	if c.ExhaustedAt != nil {
		return 0
	}
	if !now.Before(c.ExpiresAt) {
		return 0
	}
	r := c.Amount - c.Consumed
	if r < 0 {
		return 0
	}
	return r
}

// GiftCard is a redeemable plan voucher. Two flavours, distinguished by
// Source: 'paid' (bought via Stripe) or 'promo' (issued by an admin for
// hackathons / partners — same redeem flow, free of charge).
type GiftCard struct {
	ID              string     `json:"id"`
	RedeemToken     string     `json:"redeemToken"`
	PlanCode        string     `json:"planCode"`
	DurationMonths  int        `json:"durationMonths"` // 1 or 12
	Source          string     `json:"source"`         // 'paid' | 'promo'
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

// IsRedeemable returns true when the card can still be redeemed right now.
func (g GiftCard) IsRedeemable(now time.Time) bool {
	if g.RedeemedAt != nil || g.RefundedAt != nil {
		return false
	}
	return now.Before(g.ExpiresAt)
}

// PricingChange is a scheduled mutation to plans / request_costs. The
// gateway exposes this for /admin/pricing-changes and a background worker
// applies pending changes once Effective_at is reached.
type PricingChange struct {
	ID                 int64      `json:"id"`
	ChangeType         string     `json:"changeType"`
	TargetKey          string     `json:"targetKey"`
	OldValue           *int64     `json:"oldValue,omitempty"`
	NewValue           int64      `json:"newValue"`
	EffectiveAt        time.Time  `json:"effectiveAt"`
	AppliedAt          *time.Time `json:"appliedAt,omitempty"`
	CancelledAt        *time.Time `json:"cancelledAt,omitempty"`
	NotificationSentAt *time.Time `json:"notificationSentAt,omitempty"`
	CreatedBy          string     `json:"createdBy"`
	Reason             string     `json:"reason"`
	CreatedAt          time.Time  `json:"createdAt"`
}

// AdminUser is an operator with access to /admin endpoints. Lives in a
// completely separate auth namespace from regular `users`.
type AdminUser struct {
	ID             string     `json:"id"`
	Email          string     `json:"email"`
	HashedPassword string     `json:"-"`
	Role           string     `json:"role"` // 'super_admin' | 'support' | 'billing'
	MFASecret      string     `json:"-"`
	MFARequired    bool       `json:"mfaRequired"`
	IsActive       bool       `json:"isActive"`
	LastLoginAt    *time.Time `json:"lastLoginAt,omitempty"`
	LastLoginIP    string     `json:"lastLoginIp,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
}

// AdminAuditEntry is a single line in admin_audit_log.
type AdminAuditEntry struct {
	ID         int64          `json:"id"`
	AdminID    string         `json:"adminId"`
	AdminEmail string         `json:"adminEmail"`
	Action     string         `json:"action"`
	Target     string         `json:"target,omitempty"`
	Payload    map[string]any `json:"payload"`
	IPAddress  string         `json:"ipAddress,omitempty"`
	UserAgent  string         `json:"userAgent,omitempty"`
	CreatedAt  time.Time      `json:"createdAt"`
}

// AuthenticatedKey is the bundle returned by API-key lookup.
type AuthenticatedKey struct {
	User         *User
	APIKey       *APIKey
	Subscription *Subscription
}

// =============================================================================
// Mutations
// =============================================================================

// PlanMutation is a partial update for plans. Nil fields are left untouched.
type PlanMutation struct {
	Name              *string
	MonthlyTokens     *int64
	PriceCents        *int
	AnnualPriceCents  *int
	OveragePer1kCents *int
	RateLimitRPS      *int
	RateLimitBurst    *int
	ReadRPS           *int
	ReadBurst         *int
	TxRPS             *int
	TxBurst           *int
	Features          map[string]any
	IsActive          *bool
	IsGiftable        *bool
	SortOrder         *int
}

// APIKeyMutation is a partial update for api_keys. Pass nil for any
// field to leave it unchanged. The handler validates scopes and CIDRs
// before calling — store-level checks are basic ("non-empty").
type APIKeyMutation struct {
	Name           *string
	Scopes         []string // nil = unchanged; empty slice = clear
	IPAllowlist    []string // nil = unchanged; empty slice = clear
	AllowedOrigins []string // nil = unchanged; empty slice = clear
}

// SubscriptionMutation is a partial update for subscriptions. Used by
// the admin endpoints to flip overage / billing cycle / Stripe ids.
type SubscriptionMutation struct {
	OverageEnabled       *bool
	OverageCardPresent   *bool
	OverageCapTokens     *int64
	BillingCycle         *string
	StripeCustomerID     *string
	StripeSubscriptionID *string
}

// CreditGrant is the input for granting a credit.
type CreditGrant struct {
	UserID    string
	Amount    int64
	Reason    string
	GrantedBy string
	// Optional override of the 30-day default.
	ExpiresAt time.Time
}

// GiftCardCreate is the input for creating a gift card.
type GiftCardCreate struct {
	RedeemToken     string
	PlanCode        string
	DurationMonths  int
	Source          string  // 'paid' | 'promo'
	BuyerUserID     *string // paid only
	BuyerEmail      string  // paid only
	PaidAmountCents *int    // paid only
	StripePaymentID string  // paid only
	GrantedBy       string  // promo only
	Message         string
	ExpiresAt       time.Time
}

// PricingChangeCreate is the input for scheduling a pricing change.
type PricingChangeCreate struct {
	ChangeType  string
	TargetKey   string
	NewValue    int64
	EffectiveAt time.Time
	CreatedBy   string
	Reason      string
}

// AdminUserCreate is the input for creating an admin user.
type AdminUserCreate struct {
	Email          string
	HashedPassword string
	Role           string
	MFARequired    bool
}

// AdminAuditAppend is the input for recording an admin action.
type AdminAuditAppend struct {
	AdminID    string
	AdminEmail string
	Action     string
	Target     string
	Payload    map[string]any
	IPAddress  string
	UserAgent  string
}

// CreditDebit records that `Amount` tokens were consumed from a specific
// credit row during a single ConsumeTokensV2 call. The slice on
// ConsumptionResult is non-nil iff `FromCredits > 0` and is what
// RefundTokensV2 uses to roll back per-row.
type CreditDebit struct {
	CreditID string `json:"creditId"`
	Amount   int64  `json:"amount"`
}

// ConsumptionResult is what ConsumeTokensV2 returns: a per-bucket breakdown
// of how `cost` was charged, the resulting tokens_used / overage_used
// counters, and threshold-crossing flags. Threshold flags are true the
// FIRST time this period crosses the percentage; subsequent calls return
// false even if the value stays above the threshold.
type ConsumptionResult struct {
	Cost         int           `json:"cost"`
	FromCredits  int           `json:"fromCredits"`
	FromMonthly  int           `json:"fromMonthly"`
	FromOverage  int           `json:"fromOverage"`
	TokensUsed   int64         `json:"tokensUsed"`
	OverageUsed  int64         `json:"overageUsed"`
	Subscription *Subscription `json:"-"`
	// CreditDebits records WHICH credit rows were debited and by how
	// much. Empty when FromCredits == 0. RefundTokensV2 reverses each
	// entry exactly to undo a charge cleanly.
	CreditDebits  []CreditDebit `json:"creditDebits,omitempty"`
	Crossed80Pct  bool          `json:"crossed80Pct,omitempty"`
	Crossed95Pct  bool          `json:"crossed95Pct,omitempty"`
	Crossed100Pct bool          `json:"crossed100Pct,omitempty"`
	Crossed200Pct bool          `json:"crossed200Pct,omitempty"`
}

// Balance is the user-facing snapshot of remaining tokens across all
// buckets. Used by GET /v1/me/balance and the dashboard.
type Balance struct {
	Subscription     *Subscription `json:"subscription,omitempty"`
	Credits          int64         `json:"credits"`
	MonthlyRemaining int64         `json:"monthlyRemaining"`
	OverageAvailable int64         `json:"overageAvailable"`
	TotalRemaining   int64         `json:"totalRemaining"`
	PeriodEnd        time.Time     `json:"periodEnd,omitempty"`
}

// GiftCardRedemption is what ApplyGiftCard returns: the gift card after
// being marked redeemed, plus the subscription that received the benefit
// and a label describing what happened.
//
//   - Action == "created"  — user had no active subscription; a new one was
//     assigned with the gift's plan + duration.
//   - Action == "extended" — current subscription's tokens_limit and
//     current_period_end were bumped.
//   - Action == "upgraded" — same as "extended" PLUS the active plan was
//     swapped for the gift's plan (gift tier > current).
type GiftCardRedemption struct {
	GiftCard     *GiftCard     `json:"giftCard"`
	Subscription *Subscription `json:"subscription"`
	Action       string        `json:"action"`
	AddedTokens  int64         `json:"addedTokens"`
	AddedDays    int           `json:"addedDays"`
}

// AppliedPricingChange describes the result of running the pricing
// applier worker once. Useful for telemetry / admin dashboards.
type AppliedPricingChange struct {
	ChangeID   int64
	ChangeType string
	TargetKey  string
	NewValue   int64
	Error      error
}

// UsageDailyBucket is one day's worth of consumption for a user.
type UsageDailyBucket struct {
	Date   time.Time `json:"date"`
	Tokens int64     `json:"tokens"`
	Calls  int64     `json:"calls"`
}

// UsageRouteBucket aggregates consumption per route over a window.
type UsageRouteBucket struct {
	RouteKey string `json:"routeKey"`
	Tokens   int64  `json:"tokens"`
	Calls    int64  `json:"calls"`
}

// UsageReport bundles the daily series + per-route top list + totals
// for a user over a window. Used by GET /v1/me/usage.
type UsageReport struct {
	Since     time.Time          `json:"since"`
	Until     time.Time          `json:"until"`
	Tokens    int64              `json:"tokens"`
	Calls     int64              `json:"calls"`
	Daily     []UsageDailyBucket `json:"daily"`
	TopRoutes []UsageRouteBucket `json:"topRoutes"`
}

// =============================================================================
// Store interface
// =============================================================================

// Store is the persistence interface used by the gateway. Implementations
// are expected to be safe for concurrent use.
type Store interface {
	// --- Lookup hot path ---
	AuthenticateAPIKey(ctx context.Context, hashedKey string) (*AuthenticatedKey, error)
	TouchAPIKeyUsed(ctx context.Context, apiKeyID string) error

	// --- Quota V2 (credits → monthly → overage) ---
	// ConsumeTokensV2 charges `cost` against credits first, then monthly
	// tokens, then overage (only when subscription has overage_enabled
	// AND overage_card_present). Returns ErrQuotaExceeded if all buckets
	// combined cannot cover the cost.
	ConsumeTokensV2(ctx context.Context, subscriptionID string, cost int) (*ConsumptionResult, error)
	// RefundTokensV2 reverses a prior ConsumeTokensV2. Refunds monthly
	// and overage usage; credit refunds are NOT yet implemented (the
	// schema doesn't track which credit row was debited).
	RefundTokensV2(ctx context.Context, subscriptionID string, r ConsumptionResult) error
	// ComputeBalance returns the per-bucket remaining-token snapshot.
	ComputeBalance(ctx context.Context, userID string) (*Balance, error)
	// ApplyPendingPricingChanges runs the scheduler worker step: copies
	// any pricing_history rows whose effective_at has passed into the
	// live tables (request_costs / plans) and marks applied_at. Returns
	// per-change outcomes for telemetry.
	ApplyPendingPricingChanges(ctx context.Context) ([]AppliedPricingChange, error)

	// --- Pricing ---
	ListRequestCosts(ctx context.Context) ([]RequestCost, error)
	UpsertRequestCost(ctx context.Context, c RequestCost) error

	// --- Usage events ---
	InsertUsageEvent(ctx context.Context, e UsageEvent) error
	// GetUsageReport aggregates events for `userID` over [since, until).
	// Daily buckets are at UTC day granularity; topRoutes are limited to
	// `routeLimit` entries (most tokens first). Empty windows return
	// zeroes (not an error).
	GetUsageReport(ctx context.Context, userID string, since, until time.Time, routeLimit int) (*UsageReport, error)

	// --- Plans (read-only — admin updates moved to backend in M4) ---
	ListPlans(ctx context.Context) ([]Plan, error)
	GetPlanByCode(ctx context.Context, code string) (*Plan, error)

	// --- Users / keys / subscriptions ---
	CreateUser(ctx context.Context, u *User) error
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	CreateAPIKey(ctx context.Context, k *APIKey) error
	ListAPIKeysByUser(ctx context.Context, userID string) ([]APIKey, error)
	RevokeAPIKey(ctx context.Context, userID, keyID string) error
	AssignPlan(ctx context.Context, userID, planCode string) (*Subscription, error)
	GetActiveSubscription(ctx context.Context, userID string) (*Subscription, error)
	UpdateSubscription(ctx context.Context, subscriptionID string, mut SubscriptionMutation) (*Subscription, error)

	// --- Credits (read-only — grants moved to backend in M4) ---
	ListActiveCredits(ctx context.Context, userID string) ([]Credit, error)
	SumActiveCredits(ctx context.Context, userID string) (int64, error)

	// --- Gift cards ---
	CreateGiftCard(ctx context.Context, in GiftCardCreate) (*GiftCard, error)
	GetGiftCardByToken(ctx context.Context, token string) (*GiftCard, error)
	ListGiftCardsByBuyer(ctx context.Context, userID string) ([]GiftCard, error)
	ListGiftCardsByRecipient(ctx context.Context, userID string) ([]GiftCard, error)
	RedeemGiftCard(ctx context.Context, token, recipientUserID string) (*GiftCard, error)
	// ApplyGiftCard atomically redeems a gift card AND applies the
	// benefit to the recipient's subscription. Used by the gateway's
	// proxy hot path (gift_observer) to keep cached state fresh.
	ApplyGiftCard(ctx context.Context, token, recipientUserID string) (*GiftCardRedemption, error)

	// /admin/* surface (admin users, audit log, pricing-change CRUD,
	// credit grants, plan/cost mutations, gift refunds, threshold
	// notifications, applier worker) all moved to the backend service
	// in M4. The gateway no longer needs those methods on this interface.

	// --- Stripe ---
	// SetUserStripeCustomerID associates a stripe_customer_id with the
	// Andromeda user. Idempotent — calling with the same id is a no-op.
	SetUserStripeCustomerID(ctx context.Context, userID, stripeCustomerID string) error
	// GetUserByStripeCustomerID is the reverse lookup used by the Stripe
	// webhook handler to resolve incoming events back to Andromeda users.
	GetUserByStripeCustomerID(ctx context.Context, stripeCustomerID string) (*User, error)
	// SetSubscriptionStripeIDs writes Stripe linkage onto a subscription.
	// Used by the checkout completion + subscription.updated handlers.
	SetSubscriptionStripeIDs(ctx context.Context, subscriptionID, stripeCustomerID, stripeSubscriptionID string) error
	// SetSubscriptionStatus flips the subscription state machine: 'active'
	// | 'past_due' | 'cancelled' | 'trialing'. Pass empty string for
	// stripeStatus to keep the current Stripe label.
	SetSubscriptionStatus(ctx context.Context, subscriptionID, status string) error
	// GetSubscriptionByStripeID looks up a subscription by Stripe id,
	// used by webhook handlers for invoice.* and subscription.* events.
	GetSubscriptionByStripeID(ctx context.Context, stripeSubscriptionID string) (*Subscription, error)
	// MarkStripeEventProcessed inserts the event id into stripe_events;
	// returns true if it was the first time (caller should process).
	// Returns false on conflict (already processed — skip).
	MarkStripeEventProcessed(ctx context.Context, eventID, eventType, apiVersion string) (bool, error)
	// SetSubscriptionOverageItem persists the Stripe subscription_item
	// id created when the user opts in to overage. Empty string clears
	// the value (used by DisableOverage).
	SetSubscriptionOverageItem(ctx context.Context, subscriptionID, stripeItemID string) error
	// AdvanceOverageReported atomically increments overage_reported_tokens
	// and stamps overage_last_reported_at. Used by the reporting worker
	// AFTER the meter event is acknowledged by Stripe — safe-restart
	// invariant: never advance unless Stripe confirmed the event.
	AdvanceOverageReported(ctx context.Context, subscriptionID string, delta int64) error

	// --- Login Social OAuth broker ---
	// IsTenantOAuthRedirectAllowed returns true when (user_id, redirect_uri)
	// exists in tenant_oauth_redirects. Used by the broker's /authorize to
	// gate the URI before minting the state cookie.
	IsTenantOAuthRedirectAllowed(ctx context.Context, userID, redirectURI string) (bool, error)

	// --- Raw access ---
	Pool() *pgxpool.Pool
	Close()
}
