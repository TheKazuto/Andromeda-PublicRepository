# Down migrations

This directory holds rollback scripts for emergency use. **They are NOT
applied automatically** — the boot sequence only forward-applies pending
migrations. To roll back manually:

```bash
psql "$DATABASE_URL" < internal/store/migrations/down/015_api_keys_ip_allowlist.down.sql
psql "$DATABASE_URL" -c "DELETE FROM schema_migrations WHERE version = 15"
```

Order matters: roll back the highest version first, then descend.

## Coverage

Down scripts are provided for migrations **010 onward** (the token economy
overhaul + everything since). Migrations 001–009 are foundational schema
that we don't expect to roll back — if you need to drop those tables, do
it explicitly via SQL and treat it as a destructive reset.

## Caveats

- **Data loss**: dropping a column drops every value in it. Snapshot the
  table first if the data matters.
- **Constraint dependencies**: some down scripts drop CHECK constraints
  added in the up; if a later migration depends on the constraint, roll
  back the dependent first.
- **Seed data**: 011 (seed_pricing_v2) is non-reversible — the down
  script restores the seed values from 002/003 instead of "deleting"
  them, since deleting plans cascades into subscriptions.
