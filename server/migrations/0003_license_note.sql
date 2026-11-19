-- Admin-authored note (e.g. discord_user:123). Optional free-form text.
ALTER TABLE licenses
    ADD COLUMN IF NOT EXISTS note TEXT NULL;
