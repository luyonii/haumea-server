-- Per-license override for the host executable the client should launch and
-- inject into. NULL / empty means the client falls back to its argv[1].
ALTER TABLE licenses
    ADD COLUMN IF NOT EXISTS target_exe_path TEXT NULL;
