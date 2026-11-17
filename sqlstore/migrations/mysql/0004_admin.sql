CREATE TABLE IF NOT EXISTS {prefix}admins (
    tenant_id         VARCHAR(64)    NOT NULL DEFAULT 'default',
    id                VARCHAR(64)    NOT NULL,
    login             VARCHAR(64)    NOT NULL,
    password_hash     VARCHAR(512)   NOT NULL,
    totp_secret       VARBINARY(256) NULL,
    totp_confirmed_at DATETIME(6)    NULL,
    totp_last_step    BIGINT         NOT NULL DEFAULT 0,
    status            VARCHAR(16)    NOT NULL,
    created_at        DATETIME(6)    NOT NULL,
    last_login_at     DATETIME(6)    NULL,
    version           BIGINT         NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT {prefix}admins_login_key UNIQUE (tenant_id, login),
    CONSTRAINT {prefix}admins_status_check CHECK (status IN ('active', 'disabled')),
    CONSTRAINT {prefix}admins_totp_check CHECK (totp_confirmed_at IS NULL OR totp_secret IS NOT NULL)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_bin;

CREATE TABLE IF NOT EXISTS {prefix}admin_sessions (
    tenant_id     VARCHAR(64)  NOT NULL DEFAULT 'default',
    id            VARCHAR(64)  NOT NULL,
    admin_id      VARCHAR(64)  NOT NULL,
    stage         VARCHAR(16)  NOT NULL,
    secret_hash   BINARY(32)   NOT NULL,
    admin_version BIGINT       NOT NULL,
    attempts      INT          NOT NULL DEFAULT 0,
    ip            VARCHAR(45)  NULL,
    user_agent    VARCHAR(512) NULL,
    created_at    DATETIME(6)  NOT NULL,
    last_seen_at  DATETIME(6)  NOT NULL,
    expires_at    DATETIME(6)  NOT NULL,
    PRIMARY KEY (tenant_id, id),
    INDEX {prefix}admin_sessions_admin_idx (tenant_id, admin_id),
    CONSTRAINT {prefix}admin_sessions_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT {prefix}admin_sessions_stage_check CHECK (stage IN ('password', 'full')),
    CONSTRAINT {prefix}admin_sessions_attempts_check CHECK (attempts >= 0),
    CONSTRAINT {prefix}admin_sessions_admin_fk FOREIGN KEY (tenant_id, admin_id)
        REFERENCES {prefix}admins (tenant_id, id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_bin;

CREATE TABLE IF NOT EXISTS {prefix}admin_recovery_codes (
    tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
    admin_id  VARCHAR(64) NOT NULL,
    code_hash BINARY(32)  NOT NULL,
    used_at   DATETIME(6) NULL,
    PRIMARY KEY (tenant_id, admin_id, code_hash),
    CONSTRAINT {prefix}admin_recovery_codes_admin_fk FOREIGN KEY (tenant_id, admin_id)
        REFERENCES {prefix}admins (tenant_id, id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_bin;

CREATE TABLE IF NOT EXISTS {prefix}audit_log (
    tenant_id      VARCHAR(64)   NOT NULL DEFAULT 'default',
    id             VARCHAR(64)   NOT NULL,
    occurred_at    DATETIME(6)   NOT NULL,
    actor_kind     VARCHAR(16)   NOT NULL,
    actor_id       VARCHAR(64)   NULL,
    action         VARCHAR(64)   NOT NULL,
    target_user_id VARCHAR(64)   NULL,
    ip             VARCHAR(45)   NULL,
    details        VARCHAR(4000) NULL,
    PRIMARY KEY (tenant_id, id),
    INDEX {prefix}audit_log_time_idx (tenant_id, occurred_at, id),
    INDEX {prefix}audit_log_target_idx (tenant_id, target_user_id, occurred_at),
    INDEX {prefix}audit_log_actor_idx (tenant_id, actor_id, occurred_at),
    CONSTRAINT {prefix}audit_log_actor_check CHECK (actor_kind IN ('admin', 'user', 'system'))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_bin;

CREATE TABLE IF NOT EXISTS {prefix}settings (
    tenant_id  VARCHAR(64)  NOT NULL DEFAULT 'default',
    name       VARCHAR(64)  NOT NULL,
    value      VARCHAR(512) NOT NULL,
    updated_at DATETIME(6)  NOT NULL,
    updated_by VARCHAR(64)  NULL,
    PRIMARY KEY (tenant_id, name)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_bin;

CREATE INDEX {prefix}users_created_idx ON {prefix}users (tenant_id, created_at, id);

CREATE INDEX {prefix}users_login_idx ON {prefix}users (tenant_id, last_login_at, id);

CREATE INDEX {prefix}users_status_idx ON {prefix}users (tenant_id, status, created_at);

CREATE INDEX {prefix}identifiers_value_idx ON {prefix}identifiers (tenant_id, value);

ALTER TABLE {prefix}users
    ADD COLUMN created_via VARCHAR(16) NOT NULL DEFAULT 'api',
    ADD CONSTRAINT {prefix}users_created_via_check CHECK (created_via IN ('api', 'signup', 'admin', 'invite'))
