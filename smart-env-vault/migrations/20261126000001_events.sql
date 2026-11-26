-- Schema 2 -> 3: changes of a secret that are not new values (rename,
-- remove, restore), shown next to the value versions by `history`.
-- New vaults get this table from the initial schema.
CREATE TABLE secret_events (
    id            INTEGER NOT NULL PRIMARY KEY,
    key_id        BLOB    NOT NULL REFERENCES secrets(key_id) ON DELETE CASCADE,
    after_version INTEGER NOT NULL CHECK (after_version >= 1),
    kind          TEXT    NOT NULL CHECK (kind IN ('rename', 'remove', 'restore')),
    from_name     TEXT,
    to_name       TEXT,
    at            TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK ((kind = 'rename') = (from_name IS NOT NULL)),
    CHECK ((kind = 'rename') = (to_name IS NOT NULL))
) STRICT;

CREATE INDEX secret_events_by_secret ON secret_events (key_id, id);
