-- Migration 024 — remove pricing rows for the retired Identity Layer routes.
--
-- The legacy `/v1/identity/email/{request,verify}` routes were retired together
-- with the rest of the Identity Layer (replaced by Login Social / OIDC). The
-- corresponding entries in `route_costs` are no longer reachable from the API
-- surface; this migration purges them so the pricing catalogue stays consistent
-- with the live route table.

DELETE FROM route_costs WHERE route_key LIKE 'ika.identity.%';
