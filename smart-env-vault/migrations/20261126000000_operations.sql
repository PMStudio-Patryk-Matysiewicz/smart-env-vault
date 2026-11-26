-- Schema 1 -> 2: what wrote each value version (import / set / undo).
-- New vaults get these columns from the initial schema; this only upgrades
-- vaults created with schema 1. Existing versions become 'unknown'.
ALTER TABLE secrets ADD COLUMN operation TEXT NOT NULL DEFAULT 'unknown'
    CHECK (operation IN ('import', 'set', 'undo', 'unknown'));
ALTER TABLE secrets ADD COLUMN restored_version INTEGER CHECK (restored_version >= 1)
    CHECK ((operation = 'undo') = (restored_version IS NOT NULL));
ALTER TABLE secret_versions ADD COLUMN operation TEXT NOT NULL DEFAULT 'unknown'
    CHECK (operation IN ('import', 'set', 'undo', 'unknown'));
ALTER TABLE secret_versions ADD COLUMN restored_version INTEGER CHECK (restored_version >= 1)
    CHECK ((operation = 'undo') = (restored_version IS NOT NULL));
