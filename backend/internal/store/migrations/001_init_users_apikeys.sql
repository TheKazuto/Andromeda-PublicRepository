-- Andromeda backend (product API) — schema extensions.
--
-- Backend e gateway compartilham as tabelas `users` e `api_keys` no mesmo
-- Postgres (decisão Kazuto). O gateway é o owner do schema dessas duas
-- tabelas (ver gateway/internal/store/migrations/001_init.sql).
--
-- Esta migration apenas estende o que o backend precisa:
--   1. Colunas extras em `users` (password_hash, plan) — o gateway não usa.
--   2. Índice case-insensitive em email (auth no backend é case-insensitive).
--   3. Tabela nova `user_oauth_links` (apenas o backend conhece OAuth).
--
-- As tabelas `users` e `api_keys` em si NÃO são criadas aqui — confiar no
-- gateway. As colunas dele (id uuid, etc.) ditam os tipos.

-- (1) Estende `users` com colunas usadas só pelo backend. ADD COLUMN IF NOT
-- EXISTS é idempotente; rodar múltiplas vezes é seguro.
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS plan          TEXT NOT NULL DEFAULT 'free';

-- (2) UNIQUE INDEX case-insensitive em email — auth do backend lowercase-iza
-- antes de buscar. Gateway já tem UNIQUE em email (case-sensitive); ambos
-- coexistem porque cobrem espaços de busca diferentes (LOWER vs raw).
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower_unique
    ON users (LOWER(email));

-- (3) OAuth links — só o backend usa. user_id é uuid para casar com a PK
-- de users criada pelo gateway.
CREATE TABLE IF NOT EXISTS user_oauth_links (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider   TEXT NOT NULL,
    subject    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, subject)
);

CREATE INDEX IF NOT EXISTS idx_user_oauth_links_user ON user_oauth_links(user_id);
