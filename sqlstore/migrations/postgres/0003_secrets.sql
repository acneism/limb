CREATE TABLE IF NOT EXISTS {prefix}secrets (
    tenant_id     VARCHAR(64)  NOT NULL DEFAULT 'default',
    id            VARCHAR(64)  NOT NULL,
    kind          VARCHAR(16)  NOT NULL,
    secret_hash   BYTEA        NOT NULL,
    user_id       VARCHAR(64)  NOT NULL,
    purpose       VARCHAR(16)  NOT NULL,
    channel_type  VARCHAR(32)  NOT NULL,
    channel_value VARCHAR(512) NOT NULL,
    attempts      INTEGER      NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ  NOT NULL,
    expires_at    TIMESTAMPTZ  NOT NULL,
    used_at       TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT {prefix}secrets_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT {prefix}secrets_kind_check CHECK (kind IN ('link', 'code')),
    CONSTRAINT {prefix}secrets_attempts_check CHECK (attempts >= 0),
    CONSTRAINT {prefix}secrets_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES {prefix}users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT {prefix}secrets_channel_fk FOREIGN KEY (tenant_id, channel_type, channel_value)
        REFERENCES {prefix}identifiers (tenant_id, type, value) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS {prefix}secrets_user_idx ON {prefix}secrets (tenant_id, user_id, purpose);

CREATE INDEX IF NOT EXISTS {prefix}secrets_channel_idx ON {prefix}secrets (tenant_id, channel_type, channel_value);
