CREATE TABLE IF NOT EXISTS {prefix}sessions (
    tenant_id    TEXT        NOT NULL DEFAULT 'default',
    id           TEXT        NOT NULL,
    kind         TEXT        NOT NULL,
    secret_hash  BYTEA,
    user_id      TEXT        NOT NULL,
    ip           TEXT,
    user_agent   TEXT,
    created_at   TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT {prefix}sessions_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT {prefix}sessions_kind_check CHECK (kind IN ('cookie', 'token')),
    CONSTRAINT {prefix}sessions_secret_check CHECK ((kind = 'cookie') = (secret_hash IS NOT NULL)),
    CONSTRAINT {prefix}sessions_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES {prefix}users (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS {prefix}sessions_user_idx ON {prefix}sessions (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS {prefix}refresh_tokens (
    token_hash BYTEA       NOT NULL PRIMARY KEY,
    tenant_id  TEXT        NOT NULL DEFAULT 'default',
    session_id TEXT        NOT NULL,
    used_at    TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT {prefix}refresh_tokens_session_fk FOREIGN KEY (tenant_id, session_id)
        REFERENCES {prefix}sessions (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS {prefix}refresh_tokens_session_idx ON {prefix}refresh_tokens (tenant_id, session_id);

CREATE TABLE IF NOT EXISTS {prefix}attempts (
    attempt_key     TEXT        NOT NULL PRIMARY KEY,
    window_start    TIMESTAMPTZ NOT NULL,
    hit_count       INTEGER     NOT NULL,
    blocked_until   TIMESTAMPTZ,
    next_allowed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS {prefix}signing_keys (
    kid          TEXT        NOT NULL PRIMARY KEY,
    algorithm    TEXT        NOT NULL,
    generation   BIGINT      NOT NULL,
    private_key  BYTEA       NOT NULL,
    public_key   BYTEA       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    retire_after TIMESTAMPTZ,
    CONSTRAINT {prefix}signing_keys_generation_key UNIQUE (generation)
);
