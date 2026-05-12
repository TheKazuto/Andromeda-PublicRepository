//go:build integration

// Integration tests for the Postgres-backed quota engine. They spin up a real
// Postgres in a container (testcontainers), run the embedded migrations, and
// exercise ConsumeTokensV2 / RefundTokensV2 / ComputeBalance end to end.
//
// Excluded from the default build — run with:
//
//	go test -tags integration ./internal/store/...
//
// Requires a working Docker daemon. The pure bucket arithmetic is covered
// without Docker in quotamath_test.go.
package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/shinkalabs/andromeda-gateway/internal/store"
)

// newDB starts a throwaway Postgres, runs migrations, and returns the Store.
func newDB(t *testing.T) store.Store {
	t.Helper()
	ctx := context.Background()
	pg, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("andromeda"),
		tcpostgres.WithUsername("andromeda"),
		tcpostgres.WithPassword("andromeda"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(90*time.Second)),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(context.Background()) })

	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	db, err := store.NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgres (runs migrations): %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// seedSubscription gives plan `pro` a real monthly limit, creates a fresh user
// and assigns the plan. Returns (userID, subscription).
func seedSubscription(t *testing.T, db store.Store, monthlyTokens int64) (string, *store.Subscription) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.Pool().Exec(ctx,
		`UPDATE plans SET monthly_tokens = $1 WHERE code = 'pro'`, monthlyTokens); err != nil {
		t.Fatalf("seed plan: %v", err)
	}
	u := &store.User{ID: uuid.NewString(), Email: uuid.NewString() + "@example.com", Name: "T"}
	if err := db.CreateUser(ctx, u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	sub, err := db.AssignPlan(ctx, u.ID, "pro")
	if err != nil {
		t.Fatalf("assign plan: %v", err)
	}
	if sub.TokensLimit != monthlyTokens {
		t.Fatalf("subscription limit = %d, want %d", sub.TokensLimit, monthlyTokens)
	}
	return u.ID, sub
}

func TestIntegration_ConsumeMonthly(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	_, sub := seedSubscription(t, db, 1000)

	r, err := db.ConsumeTokensV2(ctx, sub.ID, 300)
	if err != nil {
		t.Fatalf("consume 300: %v", err)
	}
	if r.FromMonthly != 300 || r.FromCredits != 0 || r.FromOverage != 0 || r.TokensUsed != 300 {
		t.Fatalf("first consume = %+v, want monthly=300 used=300", r)
	}

	r, err = db.ConsumeTokensV2(ctx, sub.ID, 600)
	if err != nil {
		t.Fatalf("consume 600: %v", err)
	}
	if r.FromMonthly != 600 || r.TokensUsed != 900 {
		t.Fatalf("second consume = %+v, want monthly=600 used=900", r)
	}
	if !r.Crossed80Pct {
		t.Fatalf("crossing 900/1000 should flag 80%%: %+v", r)
	}

	if _, err := db.ConsumeTokensV2(ctx, sub.ID, 200); err != store.ErrQuotaExceeded {
		t.Fatalf("over-limit consume err = %v, want ErrQuotaExceeded", err)
	}
}

func TestIntegration_Refund(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	_, sub := seedSubscription(t, db, 1000)

	r, err := db.ConsumeTokensV2(ctx, sub.ID, 400)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := db.RefundTokensV2(ctx, sub.ID, *r); err != nil {
		t.Fatalf("refund: %v", err)
	}
	bal, err := db.ComputeBalance(ctx, sub.UserID)
	if err != nil {
		t.Fatalf("balance: %v", err)
	}
	if bal.Subscription.TokensUsed != 0 {
		t.Fatalf("after refund tokens_used = %d, want 0", bal.Subscription.TokensUsed)
	}
	// Double refund must clamp at 0, not go negative.
	if err := db.RefundTokensV2(ctx, sub.ID, *r); err != nil {
		t.Fatalf("double refund: %v", err)
	}
	bal, _ = db.ComputeBalance(ctx, sub.UserID)
	if bal.Subscription.TokensUsed != 0 {
		t.Fatalf("after double refund tokens_used = %d, want 0", bal.Subscription.TokensUsed)
	}
}

func TestIntegration_Overage(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	_, sub := seedSubscription(t, db, 1000) // overage_cap = 2000

	yes := true
	if _, err := db.UpdateSubscription(ctx, sub.ID, store.SubscriptionMutation{
		OverageEnabled: &yes, OverageCardPresent: &yes,
	}); err != nil {
		t.Fatalf("enable overage: %v", err)
	}

	if _, err := db.ConsumeTokensV2(ctx, sub.ID, 1000); err != nil { // fill monthly
		t.Fatalf("fill monthly: %v", err)
	}
	r, err := db.ConsumeTokensV2(ctx, sub.ID, 500) // → overage
	if err != nil {
		t.Fatalf("overage consume: %v", err)
	}
	if r.FromMonthly != 0 || r.FromOverage != 500 || r.OverageUsed != 500 {
		t.Fatalf("overage consume = %+v, want overage=500", r)
	}
	// Cap is 2000; 500 used; 1600 more would exceed it.
	if _, err := db.ConsumeTokensV2(ctx, sub.ID, 1600); err != store.ErrQuotaExceeded {
		t.Fatalf("over-cap consume err = %v, want ErrQuotaExceeded", err)
	}
	// But 1500 exactly fits.
	if _, err := db.ConsumeTokensV2(ctx, sub.ID, 1500); err != nil {
		t.Fatalf("exact-cap consume: %v", err)
	}
}

func TestIntegration_Credits(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	userID, sub := seedSubscription(t, db, 1000)

	// Grant a 400-token trial credit directly (grants moved to backend).
	creditID := uuid.NewString()
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO credits (id, user_id, amount, consumed, reason, granted_by, expires_at)
         VALUES ($1, $2, 400, 0, 'trial', 'test', now() + interval '30 days')`,
		creditID, userID); err != nil {
		t.Fatalf("insert credit: %v", err)
	}

	// First 300 come fully from credits.
	r, err := db.ConsumeTokensV2(ctx, sub.ID, 300)
	if err != nil {
		t.Fatalf("consume 300: %v", err)
	}
	if r.FromCredits != 300 || r.FromMonthly != 0 || len(r.CreditDebits) != 1 || r.CreditDebits[0].CreditID != creditID {
		t.Fatalf("first consume = %+v, want all from credit %s", r, creditID)
	}

	// Next 300: 100 left on the credit, 200 from monthly. Credit exhausts.
	r2, err := db.ConsumeTokensV2(ctx, sub.ID, 300)
	if err != nil {
		t.Fatalf("consume 300 again: %v", err)
	}
	if r2.FromCredits != 100 || r2.FromMonthly != 200 || r2.TokensUsed != 200 {
		t.Fatalf("second consume = %+v, want credits=100 monthly=200", r2)
	}
	var exhaustedAt *time.Time
	if err := db.Pool().QueryRow(ctx, `SELECT exhausted_at FROM credits WHERE id = $1`, creditID).Scan(&exhaustedAt); err != nil {
		t.Fatalf("read credit: %v", err)
	}
	if exhaustedAt == nil {
		t.Fatal("credit should be marked exhausted after the second consume")
	}

	// Refund the second charge → credit un-exhausts, consumed drops back.
	if err := db.RefundTokensV2(ctx, sub.ID, *r2); err != nil {
		t.Fatalf("refund: %v", err)
	}
	var consumed int64
	if err := db.Pool().QueryRow(ctx, `SELECT consumed, exhausted_at FROM credits WHERE id = $1`, creditID).
		Scan(&consumed, &exhaustedAt); err != nil {
		t.Fatalf("read credit after refund: %v", err)
	}
	if consumed != 300 || exhaustedAt != nil {
		t.Fatalf("after refund: consumed=%d exhausted_at=%v, want 300 / nil", consumed, exhaustedAt)
	}
}

func TestIntegration_ComputeBalance(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	userID, sub := seedSubscription(t, db, 1000)

	creditID := uuid.NewString()
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO credits (id, user_id, amount, consumed, reason, granted_by, expires_at)
         VALUES ($1, $2, 250, 0, 'support', 'test', now() + interval '30 days')`,
		creditID, userID); err != nil {
		t.Fatalf("insert credit: %v", err)
	}
	// Consume 100: drains 100 from the credit (oldest-first), 0 monthly.
	if _, err := db.ConsumeTokensV2(ctx, sub.ID, 100); err != nil {
		t.Fatalf("consume: %v", err)
	}

	bal, err := db.ComputeBalance(ctx, userID)
	if err != nil {
		t.Fatalf("balance: %v", err)
	}
	if bal.Subscription == nil {
		t.Fatal("balance.Subscription nil for a subscribed user")
	}
	if bal.Credits != 150 { // 250 - 100
		t.Fatalf("credits remaining = %d, want 150", bal.Credits)
	}
	if bal.MonthlyRemaining != 1000 { // nothing taken from monthly yet
		t.Fatalf("monthly remaining = %d, want 1000", bal.MonthlyRemaining)
	}
	if bal.TotalRemaining != 1150 {
		t.Fatalf("total remaining = %d, want 1150", bal.TotalRemaining)
	}

	// A user with no subscription → credits-only balance, no error.
	other := &store.User{ID: uuid.NewString(), Email: uuid.NewString() + "@example.com", Name: "X"}
	if err := db.CreateUser(ctx, other); err != nil {
		t.Fatalf("create other user: %v", err)
	}
	bal2, err := db.ComputeBalance(ctx, other.ID)
	if err != nil {
		t.Fatalf("balance (no sub): %v", err)
	}
	if bal2.Subscription != nil || bal2.MonthlyRemaining != 0 || bal2.Credits != 0 || bal2.TotalRemaining != 0 {
		t.Fatalf("no-subscription balance = %+v, want all zero", bal2)
	}
}

func TestIntegration_PeriodRollover(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	_, sub := seedSubscription(t, db, 1000)

	if _, err := db.ConsumeTokensV2(ctx, sub.ID, 700); err != nil {
		t.Fatalf("pre-rollover consume: %v", err)
	}
	// Force the window into the past so the next consume triggers a rollover.
	if _, err := db.Pool().Exec(ctx,
		`UPDATE subscriptions
		   SET current_period_start = now() - interval '40 days',
		       current_period_end   = now() - interval '10 days'
		 WHERE id = $1`, sub.ID); err != nil {
		t.Fatalf("rewind period: %v", err)
	}

	r, err := db.ConsumeTokensV2(ctx, sub.ID, 200)
	if err != nil {
		t.Fatalf("post-rollover consume: %v", err)
	}
	// Usage must reflect ONLY the new period's charge, not 700 + 200.
	if r.TokensUsed != 200 {
		t.Fatalf("after rollover tokens_used = %d, want 200 (reset)", r.TokensUsed)
	}
	if !r.Subscription.CurrentPeriodEnd.After(time.Now()) {
		t.Fatalf("rolled period end %v should be in the future", r.Subscription.CurrentPeriodEnd)
	}
}
