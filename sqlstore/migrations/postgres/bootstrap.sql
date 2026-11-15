CREATE TABLE IF NOT EXISTS {prefix}schema (
    id              SMALLINT    NOT NULL PRIMARY KEY,
    version         INTEGER     NOT NULL,
    applied_at      TIMESTAMPTZ NOT NULL,
    lock_holder     TEXT,
    lock_expires_at TIMESTAMPTZ
)
