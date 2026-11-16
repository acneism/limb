CREATE TABLE IF NOT EXISTS {prefix}sessions (
    tenant_id    VARCHAR(64) NOT NULL DEFAULT 'default',
    id           VARCHAR(64) NOT NULL,
    kind         VARCHAR(16) NOT NULL,
    secret_hash  BYTEA,
    user_id      VARCHAR(64) NOT NULL,
    ip           VARCHAR(45),
    user_agent   VARCHAR(512),
    created_at   TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT {prefix}sessions_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT {prefix}sessions_kind_check CHECK (kind IN ('cookie', 'token')),
    CONSTRAINT {prefix}sessions_secret_check CHECK (
        (kind = 'cookie' AND secret_hash IS NOT NULL) OR (kind <> 'cookie' AND secret_hash IS NULL)
    ),
    CONSTRAINT {prefix}sessions_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES {prefix}users (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS {prefix}sessions_user_idx ON {prefix}sessions (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS {prefix}refresh_tokens (
    token_hash BYTEA       NOT NULL PRIMARY KEY,
    tenant_id  VARCHAR(64) NOT NULL DEFAULT 'default',
    session_id VARCHAR(64) NOT NULL,
    used_at    TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT {prefix}refresh_tokens_session_fk FOREIGN KEY (tenant_id, session_id)
        REFERENCES {prefix}sessions (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS {prefix}refresh_tokens_session_idx ON {prefix}refresh_tokens (tenant_id, session_id);

CREATE TABLE IF NOT EXISTS {prefix}attempts (
    attempt_key     VARCHAR(64) NOT NULL PRIMARY KEY,
    window_start    TIMESTAMPTZ NOT NULL,
    hit_count       INTEGER     NOT NULL,
    blocked_until   TIMESTAMPTZ,
    next_allowed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS {prefix}signing_keys (
    kid          VARCHAR(64) NOT NULL PRIMARY KEY,
    algorithm    VARCHAR(16) NOT NULL,
    generation   BIGINT      NOT NULL,
    private_key  BYTEA       NOT NULL,
    public_key   BYTEA       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    retire_after TIMESTAMPTZ,
    CONSTRAINT {prefix}signing_keys_generation_key UNIQUE (generation)
);
