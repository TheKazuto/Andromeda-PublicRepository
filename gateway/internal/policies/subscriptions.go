package policies

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SubscriptionsStore tracks which api_key owns each deployed policy PDA so the
// Solana log listener can fan events out to the right tenant. A row is upserted
// when a policy is created via /v1/policies/{template}/init/prepare; subsequent
// calls with the same `(api_key_id, policy_address)` are no-ops.
type SubscriptionsStore struct {
	pool *pgxpool.Pool
}

func NewSubscriptionsStore(pool *pgxpool.Pool) *SubscriptionsStore {
	return &SubscriptionsStore{pool: pool}
}

// Subscribe upserts the (policy_address → api_key_id) mapping. Idempotent.
func (s *SubscriptionsStore) Subscribe(
	ctx context.Context,
	apiKeyID uuid.UUID,
	policyAddress, template, programID, dwalletAddress string,
) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO policy_subscriptions
			(policy_address, api_key_id, template, program_id, dwallet_address)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (policy_address) DO UPDATE SET
			api_key_id = EXCLUDED.api_key_id,
			template = EXCLUDED.template,
			program_id = EXCLUDED.program_id,
			dwallet_address = EXCLUDED.dwallet_address
	`, policyAddress, apiKeyID, template, programID, dwalletAddress)
	if err != nil {
		return fmt.Errorf("policy_subscriptions upsert: %w", err)
	}
	return nil
}

// Resolve returns the api_key_id that owns `policyAddress`, or `(uuid.Nil,
// false)` when the policy is unknown. Designed to be passed as the
// PolicyTenantResolver to webhooks.NewListener.
func (s *SubscriptionsStore) Resolve(ctx context.Context, policyAddress string) (uuid.UUID, bool) {
	var apiKeyID uuid.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT api_key_id FROM policy_subscriptions WHERE policy_address = $1
	`, policyAddress).Scan(&apiKeyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false
	}
	if err != nil {
		return uuid.Nil, false
	}
	return apiKeyID, true
}

// ResolveAny tries to resolve the api_key_id by `addr` against either
// `policy_address` (Andromeda template events) or `dwallet_address` (Ika
// dWallet program events). Used by the listener Phase 3 dispatcher where
// a single resolver call needs to handle both event families.
func (s *SubscriptionsStore) ResolveAny(ctx context.Context, addr string) (uuid.UUID, bool) {
	var apiKeyID uuid.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT api_key_id FROM policy_subscriptions
		WHERE policy_address = $1 OR dwallet_address = $1
		LIMIT 1
	`, addr).Scan(&apiKeyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false
	}
	if err != nil {
		return uuid.Nil, false
	}
	return apiKeyID, true
}

// Touch updates last_event_at for diagnostics. Failures are swallowed — this
// is observability, not load-bearing.
func (s *SubscriptionsStore) Touch(ctx context.Context, policyAddress string) {
	_, _ = s.pool.Exec(ctx, `
		UPDATE policy_subscriptions SET last_event_at = $1 WHERE policy_address = $2
	`, time.Now().UTC(), policyAddress)
}
