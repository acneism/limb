CREATE TABLE IF NOT EXISTS {prefix}sessions (
    tenant_id    VARCHAR(64)  NOT NULL DEFAULT 'default',
    id           VARCHAR(64)  NOT NULL,
    kind         VARCHAR(16)  NOT NULL,
    secret_hash  BINARY(32)   NULL,
    user_id      VARCHAR(64)  NOT NULL,
    ip           VARCHAR(45)  NULL,
    user_agent   VARCHAR(512) NULL,
    created_at   DATETIME(6)  NOT NULL,
    last_seen_at DATETIME(6)  NOT NULL,
    expires_at   DATETIME(6)  NOT NULL,
    revoked_at   DATETIME(6)  NULL,
    PRIMARY KEY (tenant_id, id),
    INDEX {prefix}sessions_user_idx (tenant_id, user_id),
    CONSTRAINT {prefix}sessions_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT {prefix}sessions_kind_check CHECK (kind IN ('cookie', 'token')),
    CONSTRAINT {prefix}sessions_secret_check CHECK (
        (kind = 'cookie' AND secret_hash IS NOT NULL) OR (kind <> 'cookie' AND secret_hash IS NULL)
    ),
    CONSTRAINT {prefix}sessions_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES {prefix}users (tenant_id, id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS {prefix}refresh_tokens (
    token_hash BINARY(32)  NOT NULL,
    tenant_id  VARCHAR(64) NOT NULL DEFAULT 'default',
    session_id VARCHAR(64) NOT NULL,
    used_at    DATETIME(6) NULL,
    expires_at DATETIME(6) NOT NULL,
    PRIMARY KEY (token_hash),
    INDEX {prefix}refresh_tokens_session_idx (tenant_id, session_id),
    CONSTRAINT {prefix}refresh_tokens_session_fk FOREIGN KEY (tenant_id, session_id)
        REFERENCES {prefix}sessions (tenant_id, id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS {prefix}attempts (
    attempt_key     VARCHAR(64) NOT NULL,
    window_start    DATETIME(6) NOT NULL,
    hit_count       INT         NOT NULL,
    blocked_until   DATETIME(6) NULL,
    next_allowed_at DATETIME(6) NULL,
    PRIMARY KEY (attempt_key)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS {prefix}signing_keys (
    kid          VARCHAR(64) NOT NULL,
    algorithm    VARCHAR(16) NOT NULL,
    generation   BIGINT      NOT NULL,
    private_key  BLOB        NOT NULL,
    public_key   BLOB        NOT NULL,
    created_at   DATETIME(6) NOT NULL,
    retire_after DATETIME(6) NULL,
    PRIMARY KEY (kid),
    CONSTRAINT {prefix}signing_keys_generation_key UNIQUE (generation)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_nopad_bin
