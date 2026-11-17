CREATE TABLE IF NOT EXISTS {prefix}secrets (
    tenant_id     VARCHAR(64)  NOT NULL DEFAULT 'default',
    id            VARCHAR(64)  NOT NULL,
    kind          VARCHAR(16)  NOT NULL,
    secret_hash   BINARY(32)   NOT NULL,
    user_id       VARCHAR(64)  NOT NULL,
    purpose       VARCHAR(16)  NOT NULL,
    channel_type  VARCHAR(32)  NOT NULL,
    channel_value VARCHAR(512) NOT NULL,
    attempts      INT          NOT NULL DEFAULT 0,
    created_at    DATETIME(6)  NOT NULL,
    expires_at    DATETIME(6)  NOT NULL,
    used_at       DATETIME(6)  NULL,
    PRIMARY KEY (tenant_id, id),
    INDEX {prefix}secrets_user_idx (tenant_id, user_id, purpose),
    INDEX {prefix}secrets_channel_idx (tenant_id, channel_type, channel_value),
    CONSTRAINT {prefix}secrets_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT {prefix}secrets_kind_check CHECK (kind IN ('link', 'code')),
    CONSTRAINT {prefix}secrets_attempts_check CHECK (attempts >= 0),
    CONSTRAINT {prefix}secrets_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES {prefix}users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT {prefix}secrets_channel_fk FOREIGN KEY (tenant_id, channel_type, channel_value)
        REFERENCES {prefix}identifiers (tenant_id, type, value) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_nopad_bin
