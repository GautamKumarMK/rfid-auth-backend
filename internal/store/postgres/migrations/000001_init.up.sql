-- 000001_init.up.sql
-- EVSE platform: initial schema (MVP, Phase 1).
-- Requires PostgreSQL 15+ (UNIQUE NULLS NOT DISTINCT). Tested on 16; deploy target 17.
--
-- Conventions
--   * IDs are UUIDv7 generated in Go; the database never generates business ids.
--   * Every timestamp is TIMESTAMPTZ. Times that matter come from Go (server clock) so tests can
--     inject a clock; DEFAULT now() is only a fallback for rows created outside the app.
--   * Every constraint is named, so a later migration can DROP / re-ADD it (for example to extend
--     an allowed-values list) without guessing generated names.
--   * Nothing is ever hard-deleted from users, credentials, devices or sessions: foreign keys
--     use the default NO ACTION, so a stray DELETE fails instead of cascading.
--   * access_logs and session_events are append-only, enforced by trigger.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

-- ---------------------------------------------------------------------------------------------
-- Shared trigger functions
-- ---------------------------------------------------------------------------------------------

-- Sets updated_at to now() only when the UPDATE did not set it itself. Go normally passes its own
-- clock value; this catches manual or forgotten updates without overriding the app's time.
CREATE FUNCTION set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.updated_at IS NOT DISTINCT FROM OLD.updated_at THEN
    NEW.updated_at := now();
  END IF;
  RETURN NEW;
END;
$$;

-- Rejects UPDATE and DELETE on audit tables. Retention is done later by dropping partitions or by a
-- dedicated migration, never by the application role.
CREATE FUNCTION forbid_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % not allowed', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'restrict_violation';
END;
$$;

-- ---------------------------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------------------------
CREATE TABLE users (
  user_id       UUID        NOT NULL,
  display_name  TEXT        NOT NULL,
  role          TEXT        NOT NULL DEFAULT 'driver',
  email         TEXT,
  password_hash TEXT,
  is_active     BOOLEAN     NOT NULL DEFAULT true,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT users_pkey PRIMARY KEY (user_id),
  CONSTRAINT users_display_name_check CHECK (length(btrim(display_name)) BETWEEN 1 AND 128),
  CONSTRAINT users_role_check         CHECK (role IN ('admin', 'driver')),
  CONSTRAINT users_email_check        CHECK (email IS NULL OR (length(email) <= 254 AND email ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$')),
  CONSTRAINT users_password_hash_check CHECK (password_hash IS NULL OR length(password_hash) BETWEEN 20 AND 255),
  CONSTRAINT users_admin_can_login    CHECK (role <> 'admin' OR (email IS NOT NULL AND password_hash IS NOT NULL))
);
CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));

CREATE TRIGGER users_set_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  users IS 'People: admins (log in to the UI) and drivers (own RFID cards).';
COMMENT ON COLUMN users.password_hash IS 'argon2id or bcrypt hash; never a plain password. Required for admins.';

-- ---------------------------------------------------------------------------------------------
-- credentials (RFID cards)
-- ---------------------------------------------------------------------------------------------
CREATE TABLE credentials (
  credential_id UUID        NOT NULL,
  user_id       UUID        NOT NULL,
  uid           TEXT        NOT NULL,
  is_revoked    BOOLEAN     NOT NULL DEFAULT false,
  revoked_at    TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT credentials_pkey PRIMARY KEY (credential_id),
  CONSTRAINT credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES users (user_id),
  -- 4-, 7- or 10-byte UID as uppercase hex. Go normalises to upper case before insert and lookup.
  CONSTRAINT credentials_uid_check CHECK (uid ~ '^([0-9A-F]{8}|[0-9A-F]{14}|[0-9A-F]{20})$'),
  CONSTRAINT credentials_revoked_at_check CHECK (is_revoked = (revoked_at IS NOT NULL))
);
-- A UID can be re-issued after revocation, but only one active card per UID.
CREATE UNIQUE INDEX credentials_uid_active_key ON credentials (uid) WHERE NOT is_revoked;
-- Tap lookup including revoked cards (distinguishes CARD_REVOKED from CARD_UNKNOWN).
CREATE INDEX credentials_uid_idx  ON credentials (uid, is_revoked, created_at DESC);
CREATE INDEX credentials_user_idx ON credentials (user_id);

CREATE TRIGGER credentials_set_updated_at BEFORE UPDATE ON credentials
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  credentials IS 'RFID cards. Sessions reference credential_id, never the UID, so history survives re-issue.';
COMMENT ON COLUMN credentials.uid IS 'Card UID, uppercase hex. Not secret: UIDs can be cloned.';

-- ---------------------------------------------------------------------------------------------
-- devices (chargers)
-- ---------------------------------------------------------------------------------------------
CREATE TABLE devices (
  device_id    TEXT        NOT NULL,
  name         TEXT        NOT NULL,
  is_active    BOOLEAN     NOT NULL DEFAULT true,
  is_online    BOOLEAN     NOT NULL DEFAULT false,
  last_boot_id UUID,
  last_seen_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT devices_pkey PRIMARY KEY (device_id),
  -- Equals the TLS cert CN, the MQTT username and the topic segment: no MQTT wildcards or '/'.
  CONSTRAINT devices_device_id_check CHECK (device_id ~ '^[A-Za-z0-9_-]{1,64}$'),
  CONSTRAINT devices_name_check      CHECK (length(btrim(name)) BETWEEN 1 AND 128)
);

CREATE TRIGGER devices_set_updated_at BEFORE UPDATE ON devices
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  devices IS 'Chargers. device_id = certificate CN = MQTT username = topic segment.';
COMMENT ON COLUMN devices.last_boot_id IS 'boot_id of the latest birth; a will carrying an older boot_id is ignored.';

-- ---------------------------------------------------------------------------------------------
-- sessions
-- ---------------------------------------------------------------------------------------------
CREATE TABLE sessions (
  session_id         UUID        NOT NULL,
  device_id          TEXT        NOT NULL,
  evse_id            INTEGER     NOT NULL DEFAULT 1,
  credential_id      UUID        NOT NULL,
  start_key          TEXT        NOT NULL,
  status             TEXT        NOT NULL,
  termination_reason TEXT,
  auth_expires_at    TIMESTAMPTZ NOT NULL,
  degraded_since     TIMESTAMPTZ,
  energy_wh          BIGINT      NOT NULL DEFAULT 0,
  last_seq           BIGINT,
  started_at         TIMESTAMPTZ NOT NULL,
  ended_at           TIMESTAMPTZ,
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT sessions_pkey PRIMARY KEY (session_id),
  CONSTRAINT sessions_device_id_fkey     FOREIGN KEY (device_id)     REFERENCES devices (device_id),
  CONSTRAINT sessions_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES credentials (credential_id),
  -- Parent key for the ownership foreign keys of access_logs and session_events.
  CONSTRAINT sessions_device_session_key UNIQUE (device_id, session_id),
  -- Idempotent start: a retried tap returns the same session.
  CONSTRAINT sessions_device_start_key_key UNIQUE (device_id, start_key),
  CONSTRAINT sessions_evse_id_check   CHECK (evse_id >= 1),
  CONSTRAINT sessions_start_key_check CHECK (length(start_key) BETWEEN 1 AND 128),
  CONSTRAINT sessions_status_check    CHECK (status IN ('AUTHORIZED', 'CHARGING', 'COMPLETED', 'FAILED', 'INTERRUPTED')),
  CONSTRAINT sessions_termination_reason_check CHECK (termination_reason IN (
    -- reported by the charger
    'USER_TAP', 'REMOTE_STOP', 'UNPLUG', 'SAFETY_TRIP', 'OFFLINE_LIMIT',
    'POWER_LOSS', 'METER_FAULT', 'STOP_FAILURE',
    -- set by the backend; the first three are soft-terminal (a late SESSION_STARTED may revive)
    'AUTH_EXPIRED_NO_PLUG', 'LWT_BEFORE_CHARGE', 'OFFLINE_TIMEOUT',
    'AUTH_CANCELLED', 'AUTH_ORPHANED')),
  CONSTRAINT sessions_energy_wh_check CHECK (energy_wh >= 0),
  CONSTRAINT sessions_last_seq_check  CHECK (last_seq >= 0),
  -- Active <=> not ended <=> no termination reason. A revive clears both together.
  CONSTRAINT sessions_ended_at_status_check
    CHECK ((status IN ('AUTHORIZED', 'CHARGING')) = (ended_at IS NULL)),
  CONSTRAINT sessions_termination_reason_status_check
    CHECK ((status IN ('AUTHORIZED', 'CHARGING')) = (termination_reason IS NULL)),
  CONSTRAINT sessions_ended_at_order_check  CHECK (ended_at IS NULL OR ended_at >= started_at),
  CONSTRAINT sessions_auth_expires_order_check CHECK (auth_expires_at >= started_at)
);

-- At most one live session per charging point: the database-level guard against double starts.
CREATE UNIQUE INDEX sessions_one_active_per_evse_key
  ON sessions (device_id, evse_id) WHERE status IN ('AUTHORIZED', 'CHARGING');
-- Plug-in reaper (every 5 s).
CREATE INDEX sessions_reaper_idx
  ON sessions (auth_expires_at) WHERE status = 'AUTHORIZED';
-- Offline reaper (every 60 s).
CREATE INDEX sessions_degraded_idx
  ON sessions (degraded_since) WHERE status = 'CHARGING' AND degraded_since IS NOT NULL;
-- Per-card history; also covers the credential_id foreign key.
CREATE INDEX sessions_credential_idx ON sessions (credential_id, started_at DESC);
-- Per-charger history and dashboard.
CREATE INDEX sessions_device_started_idx ON sessions (device_id, started_at DESC);

CREATE TRIGGER sessions_set_updated_at BEFORE UPDATE ON sessions
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  sessions IS 'One charging session from tap to confirmed stop.';
COMMENT ON COLUMN sessions.start_key IS 'request_id of the tap that created the session (idempotency key).';
COMMENT ON COLUMN sessions.energy_wh IS 'Session energy in Wh; only ever increases (GREATEST in Ingest).';
COMMENT ON COLUMN sessions.last_seq IS 'Highest event seq seen; NULL until the first event.';
COMMENT ON COLUMN sessions.degraded_since IS 'When the charger went offline mid-charge; cleared by telemetry or a same-boot birth.';

-- ---------------------------------------------------------------------------------------------
-- session_events (append-only)
-- ---------------------------------------------------------------------------------------------
CREATE TABLE session_events (
  device_id    TEXT        NOT NULL,
  event_id     UUID        NOT NULL,
  session_id   UUID        NOT NULL,
  seq          BIGINT      NOT NULL,
  event_type   TEXT        NOT NULL,
  energy_wh    BIGINT      NOT NULL,
  register_wh  BIGINT      NOT NULL,
  reason       TEXT,
  payload_hash TEXT        NOT NULL,
  device_ts    TIMESTAMPTZ,
  received_at  TIMESTAMPTZ NOT NULL,
  CONSTRAINT session_events_pkey PRIMARY KEY (device_id, event_id),
  -- Ownership: charger A can never write into charger B's session.
  CONSTRAINT session_events_session_fkey FOREIGN KEY (device_id, session_id)
    REFERENCES sessions (device_id, session_id),
  CONSTRAINT session_events_session_seq_key UNIQUE (session_id, seq),
  CONSTRAINT session_events_seq_check        CHECK (seq >= 0),
  CONSTRAINT session_events_event_type_check CHECK (event_type IN
    ('SESSION_STARTED', 'METER_UPDATE', 'SESSION_STOPPED', 'SESSION_FAULT')),
  CONSTRAINT session_events_energy_wh_check   CHECK (energy_wh >= 0),
  CONSTRAINT session_events_register_wh_check CHECK (register_wh >= 0),
  CONSTRAINT session_events_reason_check CHECK (reason IN (
    'USER_TAP', 'REMOTE_STOP', 'UNPLUG', 'SAFETY_TRIP', 'OFFLINE_LIMIT',
    'POWER_LOSS', 'METER_FAULT', 'STOP_FAILURE')),
  CONSTRAINT session_events_reason_required_check
    CHECK (event_type NOT IN ('SESSION_STOPPED', 'SESSION_FAULT') OR reason IS NOT NULL),
  -- SHA-256 of the canonical event content, lowercase hex.
  CONSTRAINT session_events_payload_hash_check CHECK (payload_hash ~ '^[0-9a-f]{64}$')
);
-- (session_id, seq) unique index already serves per-session reads in order.
CREATE INDEX session_events_received_idx ON session_events (received_at);

CREATE TRIGGER session_events_append_only BEFORE UPDATE OR DELETE ON session_events
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

COMMENT ON TABLE  session_events IS 'Raw telemetry per session. Deduplicated by (device_id, event_id); append-only.';
COMMENT ON COLUMN session_events.payload_hash IS 'Same event_id with a different hash is an idempotency conflict (dead-lettered).';
COMMENT ON COLUMN session_events.device_ts IS 'Charger clock; diagnostic only, never trusted.';

-- ---------------------------------------------------------------------------------------------
-- access_logs (append-only)
-- ---------------------------------------------------------------------------------------------
CREATE TABLE access_logs (
  device_id             TEXT        NOT NULL,
  request_id            TEXT        NOT NULL,
  evse_id               INTEGER     NOT NULL DEFAULT 1,
  credential_id         UUID,
  uid                   TEXT        NOT NULL,
  device_active_session UUID,
  granted               BOOLEAN     NOT NULL,
  session_id            UUID,
  reason                TEXT        NOT NULL,
  received_at           TIMESTAMPTZ NOT NULL,
  -- (device_id, request_id) is also the replay key for retried auth/req.
  CONSTRAINT access_logs_pkey PRIMARY KEY (device_id, request_id),
  -- No FK on device_id alone, on purpose: denials from unprovisioned chargers are still logged.
  CONSTRAINT access_logs_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES credentials (credential_id),
  CONSTRAINT access_logs_session_fkey FOREIGN KEY (device_id, session_id)
    REFERENCES sessions (device_id, session_id),
  CONSTRAINT access_logs_request_id_check CHECK (length(request_id) BETWEEN 1 AND 128),
  CONSTRAINT access_logs_evse_id_check    CHECK (evse_id >= 1),
  -- As presented: no format check so garbage is still logged, but bounded.
  CONSTRAINT access_logs_uid_check        CHECK (length(uid) <= 64),
  CONSTRAINT access_logs_reason_check CHECK (reason IN (
    'AUTHORIZED', 'AUTHORIZED_RESUMED', 'STOP_REQUESTED',
    'CARD_UNKNOWN', 'CARD_REVOKED', 'USER_INACTIVE',
    'DEVICE_UNKNOWN_OR_INACTIVE', 'DEVICE_BUSY', 'STATE_MISMATCH')),
  CONSTRAINT access_logs_granted_reason_check
    CHECK (granted = (reason IN ('AUTHORIZED', 'AUTHORIZED_RESUMED', 'STOP_REQUESTED'))),
  CONSTRAINT access_logs_granted_session_check
    CHECK (granted = (session_id IS NOT NULL))
);
CREATE INDEX access_logs_credential_idx ON access_logs (credential_id, received_at DESC)
  WHERE credential_id IS NOT NULL;
CREATE INDEX access_logs_device_time_idx ON access_logs (device_id, received_at DESC);
CREATE INDEX access_logs_received_idx    ON access_logs (received_at);
-- CancelAuthorization and audit lookups by session; also covers the session foreign key.
CREATE INDEX access_logs_session_idx ON access_logs (device_id, session_id) WHERE session_id IS NOT NULL;

CREATE TRIGGER access_logs_append_only BEFORE UPDATE OR DELETE ON access_logs
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

COMMENT ON TABLE  access_logs IS 'Every authorization decision, granted or denied. Replay cache for retried taps; append-only.';
COMMENT ON COLUMN access_logs.device_active_session IS 'Session the charger believed was active; used for tap reconciliation and checked on replay.';

-- ---------------------------------------------------------------------------------------------
-- dead_letters
-- ---------------------------------------------------------------------------------------------
CREATE TABLE dead_letters (
  id          BIGINT      GENERATED ALWAYS AS IDENTITY,
  device_id   TEXT,
  source      TEXT        NOT NULL,
  idem_key    TEXT        NOT NULL,
  payload     BYTEA       NOT NULL,
  error       TEXT        NOT NULL,
  status      TEXT        NOT NULL DEFAULT 'NEW',
  received_at TIMESTAMPTZ NOT NULL,
  resolved_at TIMESTAMPTZ,
  CONSTRAINT dead_letters_pkey PRIMARY KEY (id),
  -- No FK on device_id: poison can come from anyone. NULL when the topic is unparseable.
  -- PG15+: NULLs compare equal, so redelivery after a lost ACK never makes a second row.
  CONSTRAINT dead_letters_dedupe_key UNIQUE NULLS NOT DISTINCT (device_id, source, idem_key),
  CONSTRAINT dead_letters_source_check   CHECK (length(source) BETWEEN 1 AND 512),
  CONSTRAINT dead_letters_idem_key_check CHECK (length(idem_key) BETWEEN 1 AND 160),
  CONSTRAINT dead_letters_status_check   CHECK (status IN ('NEW', 'REPLAYED', 'DISCARDED')),
  CONSTRAINT dead_letters_resolved_check CHECK ((status = 'NEW') = (resolved_at IS NULL))
);
CREATE INDEX dead_letters_new_idx ON dead_letters (received_at) WHERE status = 'NEW';

COMMENT ON TABLE  dead_letters IS 'Messages that can never succeed. Stored before the MQTT ACK so nothing is lost.';
COMMENT ON COLUMN dead_letters.idem_key IS 'request_id / event_id / cmd_id, else ''raw:'' || sha256(topic || payload).';
COMMENT ON COLUMN dead_letters.payload IS 'Exact bytes received, for replay. Size is capped at the broker (message_size_limit).';

COMMIT;