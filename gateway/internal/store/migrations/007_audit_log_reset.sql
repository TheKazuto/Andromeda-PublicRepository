-- Reset audit_log entries that were written before the timestamp-truncation
-- fix (gateway < this commit). Those entries hash a nanosecond-precision TS
-- but the DB stores only microseconds, so the chain is unverifiable.
--
-- Safe to run because no production tenant has audit data yet.

TRUNCATE TABLE audit_log RESTART IDENTITY;
