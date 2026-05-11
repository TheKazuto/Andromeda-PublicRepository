-- Down migration for 021_mcp_dwallet_admin_add_member_cost.sql.
--   psql "$DATABASE_URL" < internal/store/migrations/down/021_mcp_dwallet_admin_add_member_cost.down.sql
--   psql "$DATABASE_URL" -c "DELETE FROM schema_migrations WHERE version = 21"

DELETE FROM request_costs WHERE route_key = 'ika.dwallet.adminAddMember';
