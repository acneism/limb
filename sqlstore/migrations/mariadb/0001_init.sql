CREATE TABLE IF NOT EXISTS {prefix}users (
    tenant_id            VARCHAR(64)  NOT NULL DEFAULT 'default',
    id                   VARCHAR(64)  NOT NULL,
    status               VARCHAR(16)  NOT NULL,
    password_hash        VARCHAR(512) NULL,
    must_change_password TINYINT(1)   NOT NULL DEFAULT 0,
    blocked_reason       VARCHAR(512) NULL,
    blocked_until        DATETIME(6)  NULL,
    deleted_at           DATETIME(6)  NULL,
    purge_after          DATETIME(6)  NULL,
    created_at           DATETIME(6)  NOT NULL,
    last_login_at        DATETIME(6)  NULL,
    version              BIGINT       NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT {prefix}users_status_check CHECK (status IN ('active', 'blocked', 'deleted'))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS {prefix}identifiers (
    tenant_id     VARCHAR(64)   NOT NULL DEFAULT 'default',
    type          VARCHAR(32)   NOT NULL,
    value         VARCHAR(512)  NOT NULL,
    display_value VARCHAR(1024) NOT NULL,
    user_id       VARCHAR(64)   NOT NULL,
    verified_at   DATETIME(6)   NULL,
    PRIMARY KEY (tenant_id, type, value),
    INDEX {prefix}identifiers_user_idx (tenant_id, user_id),
    CONSTRAINT {prefix}identifiers_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES {prefix}users (tenant_id, id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_nopad_bin
