-- Down migration for 020_mcp_dwallet_extra_route_costs.sql.
--   psql "$DATABASE_URL" < internal/store/migrations/down/020_mcp_dwallet_extra_route_costs.down.sql
--   psql "$DATABASE_URL" -c "DELETE FROM schema_migrations WHERE version = 20"

DELETE FROM request_costs WHERE route_key IN (
    'ika.dwallet.transferOwnership',
    'ika.dwallet.approve'
);
