package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationLockID is a fixed pg_advisory_lock id shared by every
// backend instance that runs migrations. A 64-bit constant — the value
// is arbitrary as long as nobody else in this Postgres uses the same
// number for unrelated locks.
const migrationLockID int64 = 0x416E64726F6D6564 // "Andromed"

// Migrate applies all SQL files under migrations/ in lexical order. Tracking
// is done via a `backend_schema_migrations` table; idempotent by file name.
//
// A session-level advisory lock guarantees that two concurrent processes
// (e.g. blue/green deploys, or two replicas booting at the same moment)
// serialise migration work without corrupting the schema.
//
// PgBouncer note: session-level locks do NOT work under transaction
// pooling. When DATABASE_URL points at PgBouncer in tx-pool mode, set
// MIGRATION_DATABASE_URL to a direct Postgres DSN so this connection
// bypasses the pooler.
func Migrate(ctx context.Context, databaseURL string) error {
	dsn := databaseURL
	if override := strings.TrimSpace(os.Getenv("MIGRATION_DATABASE_URL")); override != "" {
		dsn = override
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(ctx)

	// Acquire the advisory lock for the duration of the connection. Other
	// instances will block on pg_advisory_lock until we release.
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		// Best-effort release; the lock is automatically dropped when the
		// connection closes, so a failure here is non-fatal.
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockID)
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS backend_schema_migrations (
			name       TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("create backend_schema_migrations: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	names := []string{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var exists string
		err := conn.QueryRow(ctx, `SELECT name FROM backend_schema_migrations WHERE name = $1`, name).Scan(&exists)
		if err == nil {
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		body, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO backend_schema_migrations (name) VALUES ($1) ON CONFLICT DO NOTHING`, name); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
	}
	return nil
}
