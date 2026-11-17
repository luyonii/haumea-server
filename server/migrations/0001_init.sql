-- Initial schema. Drop `session_salt` from SERVER_PLAN: the client's HKDF salt
-- for /auth/login is `hwid_bytes || "SecBlind_HKDF_v1"` with info empty, so
-- there is no per-license salt to store.

CREATE TABLE licenses (
    id          BIGSERIAL PRIMARY KEY,
    license_key TEXT UNIQUE NOT NULL,
    banned      BOOLEAN     NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE hwid_binds (
    license_id BIGINT      PRIMARY KEY REFERENCES licenses(id) ON DELETE CASCADE,
    hwid       CHAR(64)    NOT NULL,
    bound_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE hwid_cooldown (
    license_id  BIGINT      PRIMARY KEY REFERENCES licenses(id) ON DELETE CASCADE,
    last_change TIMESTAMPTZ NOT NULL
);

CREATE TABLE payload_builds (
    id         BIGSERIAL PRIMARY KEY,
    license_id BIGINT      REFERENCES licenses(id),
    pe_bytes   BYTEA       NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX payload_builds_license_updated_idx
    ON payload_builds (license_id, updated_at DESC);

CREATE TABLE license_kill (
    license_id BIGINT      PRIMARY KEY REFERENCES licenses(id) ON DELETE CASCADE,
    killed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason     TEXT
);

CREATE TABLE abuse_log (
    id          BIGSERIAL PRIMARY KEY,
    license_id  BIGINT,
    ip          INET,
    reason      TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
