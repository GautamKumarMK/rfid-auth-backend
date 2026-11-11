-- 000001_init.down.sql
-- Drops everything 000001_init.up.sql created, in reverse dependency order.
-- Destroys all data: never run against production except to roll back a failed first deploy.

BEGIN;

SET LOCAL lock_timeout = '5s';

DROP TABLE IF EXISTS dead_letters;
DROP TABLE IF EXISTS access_logs;
DROP TABLE IF EXISTS session_events;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS users;

DROP FUNCTION IF EXISTS forbid_mutation();
DROP FUNCTION IF EXISTS set_updated_at();

COMMIT;