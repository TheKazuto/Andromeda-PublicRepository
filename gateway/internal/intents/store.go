package intents

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrNotFound is returned when an intent does not exist (or is not owned by
	// the caller — same error, no enumeration leak).
	ErrNotFound = errors.New("intent not found")
	// ErrConflict is returned when a compare-and-swap status transition matched
	// zero rows (another submit already advanced the intent, or it expired).
	ErrConflict = errors.New("intent state conflict")
	// ErrEVMInFlight is returned when another EVM swap for the same
	// (dwallet, chain) is still open — serialized so nonces never collide.
	ErrEVMInFlight = errors.New("another EVM swap for this wallet and chain is still in flight")
)

// intentStore is the persistence surface the orchestrator + reconciler use.
// *Store (Postgres) is the production impl; tests use an in-memory fake.
type intentStore interface {
	InsertPrepared(ctx context.Context, it *Intent) error
	GetForUser(ctx context.Context, id, userID string) (*Intent, error)
	CASStatus(ctx context.Context, id, from, to, lockOwner string) error
	SetStatus(ctx context.Context, id, status string) error
	SetError(ctx context.Context, id, status, sanitized string) error
	SaveApproval(ctx context.Context, id, txSig string, slot uint64, presign, policyMetaDigest string) error
	SaveERC20Approve(ctx context.Context, id, txHash string) error
	SaveRisk(ctx context.Context, id string, snapshot json.RawMessage) error
	SaveBroadcast(ctx context.Context, id, status, txHash string) error
	ListOpenOlderThan(ctx context.Context, olderThan time.Duration, limit int) ([]*Intent, error)
	OldestOpenAgeByStatus(ctx context.Context) (map[string]float64, error)
}

// Store is the Postgres-backed intent store (pgx). The gateway owns the schema;
// the intents-backend is stateless.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// intentColumns is the canonical SELECT list (kept in sync with scanIntent).
const intentColumns = `
  id, user_id, COALESCE(api_key_id::text,''), chain_kind, from_chain, to_chain,
  from_token, to_token, from_amount::text, COALESCE(quoted_amount_out::text,''),
  COALESCE(quoted_amount_out_min::text,''),
  ika_dwallet_address, dwallet_public_key_hex, owner_pubkey_hex, init_authority_hash_hex,
  ika_curve, chain_native_address, chain_id, sign_chain_id, status, sign_scheme,
  sign_message, message_digest, message_metadata, ika_msg_metadata_digest,
  policy_metadata_digest, unsigned_tx, unsigned_tx_hash, route_snapshot, risk_snapshot,
  COALESCE(approval_tx_sig,''), COALESCE(approval_slot,0), COALESCE(presign_session_id,''),
  COALESCE(swap_tx_hash,''), COALESCE(evm_nonce,0)::bigint,
  COALESCE(approve_unsigned_tx,'\x'::bytea), COALESCE(approve_message,'\x'::bytea),
  COALESCE(approve_message_digest,''), COALESCE(approve_tx_hash,''),
  COALESCE(expires_at, now()), updated_at`

// InsertPrepared writes a freshly prepared intent (status PREPARED). For EVM it
// runs under an advisory lock + single-in-flight guard so two concurrent swaps
// for the same (dwallet, chain) can never claim overlapping nonces.
func (s *Store) InsertPrepared(ctx context.Context, it *Intent) error {
	signMsg, err := hex.DecodeString(it.SignMessageHex)
	if err != nil {
		return err
	}
	meta, err := hex.DecodeString(it.MessageMetadataHex)
	if err != nil {
		return err
	}
	tx, err := base64.StdEncoding.DecodeString(it.UnsignedTxB64)
	if err != nil {
		return err
	}
	var approveTx, approveMsg []byte
	if it.ApproveUnsignedTxB64 != "" {
		if approveTx, err = base64.StdEncoding.DecodeString(it.ApproveUnsignedTxB64); err != nil {
			return err
		}
	}
	if it.ApproveMessageHex != "" {
		if approveMsg, err = hex.DecodeString(it.ApproveMessageHex); err != nil {
			return err
		}
	}
	route := nonEmptyJSON(it.RouteSnapshot)
	risk := nonEmptyJSON(it.RiskSnapshot)

	conn, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer conn.Rollback(ctx)

	if it.ChainKind == "evm" {
		key := it.UserID + ":" + it.ChainNativeAddress + ":" + it.ChainID
		if _, err := conn.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, key); err != nil {
			return err
		}
		var open int
		err = conn.QueryRow(ctx, `
SELECT count(*) FROM intents
WHERE user_id=$1 AND chain_native_address=$2 AND chain_id=$3 AND chain_kind='evm'
  AND status NOT IN ('SETTLED','FAILED','EXPIRED','CANCELLED')`,
			it.UserID, it.ChainNativeAddress, it.ChainID).Scan(&open)
		if err != nil {
			return err
		}
		if open > 0 {
			return ErrEVMInFlight
		}
	}

	const q = `
INSERT INTO intents (
  user_id, api_key_id, chain_kind, from_chain, to_chain, from_token, to_token,
  from_amount, quoted_amount_out, quoted_amount_out_min,
  ika_dwallet_address, dwallet_public_key_hex, owner_pubkey_hex, init_authority_hash_hex,
  ika_curve, chain_native_address, chain_id, sign_chain_id, status, sign_scheme,
  sign_message, message_digest, message_metadata, ika_msg_metadata_digest,
  policy_metadata_digest, unsigned_tx, unsigned_tx_hash, route_snapshot, risk_snapshot,
  evm_nonce, approve_unsigned_tx, approve_message, approve_message_digest, expires_at
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,
  $8::numeric, NULLIF($9,'')::numeric, NULLIF($10,'')::numeric,
  $11,$12,$13,$14,
  $15,$16,$17,$18,$19,$20,
  $21,$22,$23,$24,
  $25,$26,$27,$28::jsonb,$29::jsonb,
  $30,$31,$32,NULLIF($33,''),$34
) RETURNING id, updated_at`
	if err := conn.QueryRow(ctx, q,
		it.UserID, nullable(it.APIKeyID), it.ChainKind, it.FromChain, it.ToChain, it.FromToken, it.ToToken,
		it.FromAmount, it.QuotedAmountOut, it.QuotedAmountOutMin,
		it.IkaDwalletAddress, it.DwalletPublicKeyHex, it.OwnerPubkeyHex, it.InitAuthorityHashHex,
		it.IkaCurve, it.ChainNativeAddress, it.ChainID, it.SignChainID, it.Status, it.SignScheme,
		signMsg, it.MessageDigestHex, meta, it.IkaMsgMetadataDigestHex,
		it.PolicyMetadataDigestHex, tx, it.UnsignedTxHash, string(route), string(risk),
		int64(it.EVMNonce), approveTx, approveMsg, it.ApproveMessageDigestHex, it.ExpiresAt,
	).Scan(&it.ID, &it.UpdatedAt); err != nil {
		return err
	}
	return conn.Commit(ctx)
}

// GetForUser loads an intent scoped to the owner (tenant isolation / IDOR guard).
func (s *Store) GetForUser(ctx context.Context, id, userID string) (*Intent, error) {
	return scanIntent(s.pool.QueryRow(ctx,
		`SELECT `+intentColumns+` FROM intents WHERE id=$1 AND user_id=$2`, id, userID))
}

// CASStatus transitions status from→to only if the current status matches `from`.
func (s *Store) CASStatus(ctx context.Context, id, from, to, lockOwner string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE intents SET status=$3, locked_at=now(), lock_owner=$4, updated_at=now() WHERE id=$1 AND status=$2`,
		id, from, to, lockOwner)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

// SetStatus unconditionally sets the status.
func (s *Store) SetStatus(ctx context.Context, id, status string) error {
	_, err := s.pool.Exec(ctx, `UPDATE intents SET status=$2, updated_at=now() WHERE id=$1`, id, status)
	return err
}

// SetError records a sanitized error and a status.
func (s *Store) SetError(ctx context.Context, id, status, sanitized string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE intents SET status=$2, error=$3, updated_at=now() WHERE id=$1`, id, status, sanitized)
	return err
}

// SaveApproval persists the PolicyEngine approval tx + slot + presign + digest.
func (s *Store) SaveApproval(ctx context.Context, id, txSig string, slot uint64, presign, policyMetaDigest string) error {
	_, err := s.pool.Exec(ctx, `
UPDATE intents SET approval_tx_sig=$2, approval_slot=$3, presign_session_id=NULLIF($4,''),
  policy_metadata_digest=$5, updated_at=now() WHERE id=$1`,
		id, txSig, int64(slot), presign, policyMetaDigest)
	return err
}

// SaveERC20Approve records the ERC20 approve tx hash and moves to APPROVING.
func (s *Store) SaveERC20Approve(ctx context.Context, id, txHash string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE intents SET approve_tx_hash=NULLIF($2,''), status='APPROVING', updated_at=now() WHERE id=$1`,
		id, txHash)
	return err
}

// SaveRisk persists the advisory risk snapshot (never blocks the swap).
func (s *Store) SaveRisk(ctx context.Context, id string, snapshot json.RawMessage) error {
	if len(snapshot) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE intents SET risk_snapshot=$2::jsonb, updated_at=now() WHERE id=$1`, id, string(snapshot))
	return err
}

// SaveBroadcast records the swap tx hash and final status.
func (s *Store) SaveBroadcast(ctx context.Context, id, status, txHash string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE intents SET status=$2, swap_tx_hash=NULLIF($3,''), updated_at=now() WHERE id=$1`,
		id, status, txHash)
	return err
}

// ListOpenOlderThan returns non-final intents older than the cutoff (reconciler).
func (s *Store) ListOpenOlderThan(ctx context.Context, olderThan time.Duration, limit int) ([]*Intent, error) {
	cutoff := time.Now().Add(-olderThan)
	rows, err := s.pool.Query(ctx, `SELECT `+intentColumns+` FROM intents
WHERE status NOT IN ('SETTLED','FAILED','EXPIRED','CANCELLED') AND updated_at < $1
ORDER BY updated_at ASC LIMIT $2`, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Intent
	for rows.Next() {
		it, err := scanIntent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// OldestOpenAgeByStatus returns, per non-final status, the age in seconds of the
// oldest open intent in that status. Powers the open_age_seconds gauge.
func (s *Store) OldestOpenAgeByStatus(ctx context.Context) (map[string]float64, error) {
	const q = `
SELECT status, EXTRACT(EPOCH FROM (now() - min(created_at)))::float8
FROM intents
WHERE status NOT IN ('SETTLED','FAILED','EXPIRED','CANCELLED')
GROUP BY status`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]float64{}
	for rows.Next() {
		var status string
		var age float64
		if err := rows.Scan(&status, &age); err != nil {
			return nil, err
		}
		out[status] = age
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanIntent(row rowScanner) (*Intent, error) {
	var it Intent
	var signMsg, meta, tx, approveTx, approveMsg []byte
	var route, risk []byte
	var slot, evmNonce int64
	err := row.Scan(
		&it.ID, &it.UserID, &it.APIKeyID, &it.ChainKind, &it.FromChain, &it.ToChain,
		&it.FromToken, &it.ToToken, &it.FromAmount, &it.QuotedAmountOut, &it.QuotedAmountOutMin,
		&it.IkaDwalletAddress, &it.DwalletPublicKeyHex, &it.OwnerPubkeyHex, &it.InitAuthorityHashHex,
		&it.IkaCurve, &it.ChainNativeAddress, &it.ChainID, &it.SignChainID, &it.Status, &it.SignScheme,
		&signMsg, &it.MessageDigestHex, &meta, &it.IkaMsgMetadataDigestHex,
		&it.PolicyMetadataDigestHex, &tx, &it.UnsignedTxHash, &route, &risk,
		&it.ApprovalTxSig, &slot, &it.PresignSessionID,
		&it.SwapTxHash, &evmNonce, &approveTx, &approveMsg, &it.ApproveMessageDigestHex, &it.ApproveTxHash,
		&it.ExpiresAt, &it.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	it.SignMessageHex = hex.EncodeToString(signMsg)
	it.MessageMetadataHex = hex.EncodeToString(meta)
	it.UnsignedTxB64 = base64.StdEncoding.EncodeToString(tx)
	it.RouteSnapshot = json.RawMessage(route)
	it.RiskSnapshot = json.RawMessage(risk)
	it.ApprovalSlot = uint64(slot)
	it.EVMNonce = uint64(evmNonce)
	it.ApproveUnsignedTxB64 = base64.StdEncoding.EncodeToString(approveTx)
	it.ApproveMessageHex = hex.EncodeToString(approveMsg)
	return &it, nil
}

func nonEmptyJSON(j json.RawMessage) json.RawMessage {
	if len(j) == 0 {
		return json.RawMessage(`{}`)
	}
	return j
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
