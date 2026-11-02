CREATE TABLE vault_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    key_salt BLOB NOT NULL
);
