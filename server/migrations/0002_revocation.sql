-- License revocation: distinct from license_kill. Revocation is admin-driven
-- and permanent (session TTL + 7d Redis cache for fast checks); kill is
-- operator panic-button, can be lifted.

ALTER TABLE licenses
    ADD COLUMN revoked_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS licenses_revoked_at_idx
    ON licenses (revoked_at) WHERE revoked_at IS NOT NULL;
