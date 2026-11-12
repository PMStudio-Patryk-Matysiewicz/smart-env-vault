-- Connections must run `PRAGMA foreign_keys = ON`.

CREATE TABLE vaults (
    id         BLOB NOT NULL PRIMARY KEY CHECK (length(id) = 16),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE projects (
    id         BLOB NOT NULL PRIMARY KEY CHECK (length(id) = 16),
    vault_id   BLOB NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (vault_id, name)
) STRICT;

CREATE TABLE environments (
    id         BLOB NOT NULL PRIMARY KEY CHECK (length(id) = 16),
    project_id BLOB NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    kind       TEXT NOT NULL CHECK (kind IN ('dev', 'staging', 'prod', 'custom')),
    protected  INTEGER NOT NULL DEFAULT 0 CHECK (protected IN (0, 1)),
    access     TEXT NOT NULL DEFAULT 'direct' CHECK (access IN ('direct', 'proxied')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (project_id, name)
) STRICT;

CREATE TABLE environment_deks (
    environment_id BLOB    NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    version        INTEGER NOT NULL CHECK (version >= 1),
    wrapped        BLOB    NOT NULL CHECK (length(wrapped) > 0),
    created_at     TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at     TEXT,
    PRIMARY KEY (environment_id, version)
) STRICT;

CREATE UNIQUE INDEX environment_deks_one_active
    ON environment_deks (environment_id)
    WHERE retired_at IS NULL;

CREATE TABLE secrets (
    key_id         BLOB    NOT NULL PRIMARY KEY CHECK (length(key_id) = 16),
    environment_id BLOB    NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name           TEXT    NOT NULL CHECK (
                       length(name) BETWEEN 1 AND 255
                       AND name NOT GLOB '[0-9]*'
                       AND name NOT GLOB '*[^A-Za-z0-9_]*'
                   ),
    format_version INTEGER NOT NULL CHECK (format_version >= 1),
    dek_version    INTEGER NOT NULL,
    nonce          BLOB    NOT NULL CHECK (length(nonce) = 12),
    ciphertext     BLOB    NOT NULL CHECK (length(ciphertext) BETWEEN 16 AND 65552),
    updated_at     TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (environment_id, name),
    FOREIGN KEY (environment_id, dek_version)
        REFERENCES environment_deks (environment_id, version)
) STRICT;