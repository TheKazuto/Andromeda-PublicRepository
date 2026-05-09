-- Andromeda backend — soft delete para users.
--
-- Por que soft delete e não hard?
--   A tabela `users` é compartilhada com o gateway (decisão Kazuto). O
--   gateway possui subscriptions, billing, usage records etc. com FK em
--   users(id). Hard delete bombaria essas constraints e perderia o audit
--   trail financeiro (necessário para compliance e disputas Stripe).
--
-- Estratégia:
--   1. Adicionar `deleted_at TIMESTAMPTZ NULL`. NULL = ativo.
--   2. No soft delete, a application layer também:
--        - anonimiza email (`__deleted__:<id>`) para liberar o LOWER(email)
--          unique para um futuro re-signup com o mesmo email,
--        - zera name e password_hash (PII removida),
--        - remove oauth_links (libera o provider/subject para reuso),
--        - revoga todas as API keys do user.
--   3. GetUserByID/GetUserByEmail filtram deleted_at IS NULL.

ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

-- Índice parcial: acelera as queries do hot path (login, me) que só
-- olham usuários ativos. Cobre o filtro implícito deleted_at IS NULL.
CREATE INDEX IF NOT EXISTS idx_users_active
    ON users (id)
    WHERE deleted_at IS NULL;
