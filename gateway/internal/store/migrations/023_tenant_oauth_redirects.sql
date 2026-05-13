-- Login Social — OAuth broker (loginsocial.md §5.4 item 1).
--
-- Per-tenant allowlist of redirect URIs the broker is willing to send the
-- short-lived `code` back to after a successful OAuth handshake. The broker
-- rejects any /v1/oauth/authorize request whose `redirect_uri` does not match
-- an exact row here for the calling tenant.
--
-- MVP: rows are inserted manually via SQL when registering a new client app.
-- A dashboard CRUD is a later-fase item (loginsocial.md §22, "auth broker").

CREATE TABLE IF NOT EXISTS tenant_oauth_redirects (
    user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri text        NOT NULL,
    description  text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, redirect_uri)
);

CREATE INDEX IF NOT EXISTS idx_tenant_oauth_redirects_user
    ON tenant_oauth_redirects(user_id);
