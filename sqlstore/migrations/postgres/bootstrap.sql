CREATE TABLE IF NOT EXISTS {prefix}schema (
    id              SMALLINT    NOT NULL PRIMARY KEY,
    version         INTEGER     NOT NULL,
    applied_at      TIMESTAMPTZ NOT NULL,
    lock_holder     VARCHAR(64),
    lock_expires_at TIMESTAMPTZ
)
