DROP TABLE IF EXISTS stripe_events;
DROP INDEX IF EXISTS idx_users_stripe_customer;
ALTER TABLE users DROP COLUMN IF EXISTS stripe_customer_id;
