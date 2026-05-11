-- Down migration for 019_mcp_dwallet_route_costs.sql.
--   psql "$DATABASE_URL" < internal/store/migrations/down/019_mcp_dwallet_route_costs.down.sql
--   psql "$DATABASE_URL" -c "DELETE FROM schema_migrations WHERE version = 19"

DELETE FROM request_costs WHERE route_key IN (
    'ika.dwallet.create',
    'ika.dwallet.presign',
    'ika.dwallet.sign'
);
