-- 000001_init.up.sql

CREATE TABLE users (
  user_id       UUID PRIMARY KEY,                       -- UUIDv7 from Go
  display_name  TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'driver' CHECK (role IN ('admin','driver')),
  email         TEXT,
  password_hash TEXT,
  is_active     BOOLEAN NOT NULL DEFAULT true,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT users_admin_can_login
    CHECK (role <> 'admin' OR (email IS NOT NULL AND password_hash IS NOT NULL))
);
CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));

CREATE TABLE credentials (
  credential_id UUID PRIMARY KEY,
  user_id       UUID NOT NULL REFERENCES users(user_id),
  uid           TEXT NOT NULL
                CHECK (uid ~ '^([0-9A-F]{8}|[0-9A-F]{14}|[0-9A-F]{20})$'),  -- 4/7/10-byte UID
  is_revoked    BOOLEAN NOT NULL DEFAULT false,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX credentials_uid_active_key ON credentials (uid) WHERE NOT is_revoked;
CREATE INDEX idx_credentials_user ON credentials (user_id);

CREATE TABLE devices (
  device_id    TEXT PRIMARY KEY CHECK (device_id ~ '^[A-Za-z0-9_-]{1,64}$'),  -- = cert CN
  name         TEXT NOT NULL,
  is_active    BOOLEAN NOT NULL DEFAULT true,
  is_online    BOOLEAN NOT NULL DEFAULT false,
  last_boot_id UUID,
  last_seen_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
  session_id         UUID PRIMARY KEY,
  device_id          TEXT NOT NULL REFERENCES devices(device_id),
  evse_id            INTEGER NOT NULL DEFAULT 1 CHECK (evse_id >= 1),
  credential_id      UUID NOT NULL REFERENCES credentials(credential_id),
  start_key          TEXT NOT NULL,
  status             TEXT NOT NULL CHECK (status IN
                       ('AUTHORIZED','CHARGING','COMPLETED','FAILED','INTERRUPTED')),
  termination_reason TEXT,
  auth_expires_at    TIMESTAMPTZ NOT NULL,
  degraded_since     TIMESTAMPTZ,
  energy_wh          BIGINT NOT NULL DEFAULT 0 CHECK (energy_wh >= 0),
  last_seq           BIGINT CHECK (last_seq >= 0),          -- NULL until the first event
  started_at         TIMESTAMPTZ NOT NULL,
  ended_at           TIMESTAMPTZ,
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),    -- set from Go on every UPDATE
  UNIQUE (device_id, session_id),
  UNIQUE (device_id, start_key),
  CHECK ((status IN ('AUTHORIZED','CHARGING')) = (ended_at IS NULL)),
  CHECK (ended_at IS NULL OR ended_at >= started_at)
);

CREATE UNIQUE INDEX idx_one_active_per_evse
  ON sessions (device_id, evse_id) WHERE status IN ('AUTHORIZED','CHARGING');
CREATE INDEX idx_sessions_reaper
  ON sessions (auth_expires_at) WHERE status = 'AUTHORIZED';
CREATE INDEX idx_sessions_degraded
  ON sessions (degraded_since) WHERE status = 'CHARGING' AND degraded_since IS NOT NULL;
CREATE INDEX idx_sessions_cred ON sessions (credential_id, started_at DESC);

CREATE TABLE session_events (
  device_id    TEXT NOT NULL,
  event_id     UUID NOT NULL,
  session_id   UUID NOT NULL,
  seq          BIGINT NOT NULL CHECK (seq >= 0),
  event_type   TEXT NOT NULL CHECK (event_type IN
                 ('SESSION_STARTED','METER_UPDATE','SESSION_STOPPED','SESSION_FAULT')),
  energy_wh    BIGINT NOT NULL CHECK (energy_wh >= 0),
  register_wh  BIGINT NOT NULL CHECK (register_wh >= 0),
  reason       TEXT
  payload_hash TEXT NOT NULL,
  device_ts    TIMESTAMPTZ,                                  -- charger clock; diagnostic, never trusted
  received_at  TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (device_id, event_id),
  UNIQUE (session_id, seq),
  FOREIGN KEY (device_id, session_id) REFERENCES sessions (device_id, session_id)
);

CREATE TABLE access_logs (
  device_id             TEXT NOT NULL,   -- no FK on purpose: unprovisioned chargers' denials are still logged
  request_id            TEXT NOT NULL,
  evse_id               INTEGER NOT NULL DEFAULT 1 CHECK (evse_id >= 1),
  credential_id         UUID REFERENCES credentials(credential_id),
  uid                   TEXT NOT NULL,   -- as presented; no format CHECK, so garbage is still logged
  device_active_session UUID,            -- charger's view of its active session (tap reconciliation)
  granted               BOOLEAN NOT NULL,
  session_id            UUID,
  reason                TEXT NOT NULL,
  received_at           TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (device_id, request_id),
  FOREIGN KEY (device_id, session_id) REFERENCES sessions (device_id, session_id)
);
CREATE INDEX idx_access_logs_cred ON access_logs (credential_id, received_at DESC);
CREATE INDEX idx_access_logs_time ON access_logs (received_at);

CREATE TABLE dead_letters (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  device_id   TEXT,                 -- from the topic; NULL if unparseable. No FK: poison can come from anyone
  source      TEXT NOT NULL,        -- MQTT topic
  idem_key    TEXT NOT NULL,        -- request_id / event_id / cmd_id, else 'raw:' || sha256(topic + payload)
  payload     BYTEA NOT NULL,       -- exact bytes received, for replay
  error       TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW','REPLAYED','DISCARDED')),
  received_at TIMESTAMPTZ NOT NULL,
  resolved_at TIMESTAMPTZ,
  CHECK ((status = 'NEW') = (resolved_at IS NULL)),
  UNIQUE NULLS NOT DISTINCT (device_id, idem_key)   -- PG15+: redelivery after a lost ACK makes no 2nd row
);
CREATE INDEX idx_dead_letters_new ON dead_letters (received_at) WHERE status = 'NEW';