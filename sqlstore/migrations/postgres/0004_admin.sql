CREATE TABLE IF NOT EXISTS {prefix}admins (
    tenant_id         VARCHAR(64)  NOT NULL DEFAULT 'default',
    id                VARCHAR(64)  NOT NULL,
    login             VARCHAR(64)  NOT NULL,
    password_hash     VARCHAR(512) NOT NULL,
    totp_secret       BYTEA,
    totp_confirmed_at TIMESTAMPTZ,
    totp_last_step    BIGINT       NOT NULL DEFAULT 0,
    status            VARCHAR(16)  NOT NULL,
    created_at        TIMESTAMPTZ  NOT NULL,
    last_login_at     TIMESTAMPTZ,
    version           BIGINT       NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT {prefix}admins_login_key UNIQUE (tenant_id, login),
    CONSTRAINT {prefix}admins_status_check CHECK (status IN ('active', 'disabled')),
    CONSTRAINT {prefix}admins_totp_check CHECK (totp_confirmed_at IS NULL OR totp_secret IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS {prefix}admin_sessions (
    tenant_id     VARCHAR(64) NOT NULL DEFAULT 'default',
    id            VARCHAR(64) NOT NULL,
    admin_id      VARCHAR(64) NOT NULL,
    stage         VARCHAR(16) NOT NULL,
    secret_hash   BYTEA       NOT NULL,
    admin_version BIGINT      NOT NULL,
    attempts      INTEGER     NOT NULL DEFAULT 0,
    ip            VARCHAR(45),
    user_agent    VARCHAR(512),
    created_at    TIMESTAMPTZ NOT NULL,
    last_seen_at  TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT {prefix}admin_sessions_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT {prefix}admin_sessions_stage_check CHECK (stage IN ('password', 'full')),
    CONSTRAINT {prefix}admin_sessions_attempts_check CHECK (attempts >= 0),
    CONSTRAINT {prefix}admin_sessions_admin_fk FOREIGN KEY (tenant_id, admin_id)
        REFERENCES {prefix}admins (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS {prefix}admin_sessions_admin_idx ON {prefix}admin_sessions (tenant_id, admin_id);

CREATE TABLE IF NOT EXISTS {prefix}admin_recovery_codes (
    tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
    admin_id  VARCHAR(64) NOT NULL,
    code_hash BYTEA       NOT NULL,
    used_at   TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, admin_id, code_hash),
    CONSTRAINT {prefix}admin_recovery_codes_admin_fk FOREIGN KEY (tenant_id, admin_id)
        REFERENCES {prefix}admins (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS {prefix}audit_log (
    tenant_id      VARCHAR(64) NOT NULL DEFAULT 'default',
    id             VARCHAR(64) NOT NULL,
    occurred_at    TIMESTAMPTZ NOT NULL,
    actor_kind     VARCHAR(16) NOT NULL,
    actor_id       VARCHAR(64),
    action         VARCHAR(64) NOT NULL,
    target_user_id VARCHAR(64),
    ip             VARCHAR(45),
    details        VARCHAR(4000),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT {prefix}audit_log_actor_check CHECK (actor_kind IN ('admin', 'user', 'system'))
);

CREATE INDEX IF NOT EXISTS {prefix}audit_log_time_idx ON {prefix}audit_log (tenant_id, occurred_at, id);

CREATE INDEX IF NOT EXISTS {prefix}audit_log_target_idx ON {prefix}audit_log (tenant_id, target_user_id, occurred_at);

CREATE INDEX IF NOT EXISTS {prefix}audit_log_actor_idx ON {prefix}audit_log (tenant_id, actor_id, occurred_at);

CREATE TABLE IF NOT EXISTS {prefix}settings (
    tenant_id  VARCHAR(64)  NOT NULL DEFAULT 'default',
    name       VARCHAR(64)  NOT NULL,
    value      VARCHAR(512) NOT NULL,
    updated_at TIMESTAMPTZ  NOT NULL,
    updated_by VARCHAR(64),
    PRIMARY KEY (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS {prefix}users_created_idx ON {prefix}users (tenant_id, created_at, id);

CREATE INDEX IF NOT EXISTS {prefix}users_login_idx ON {prefix}users (tenant_id, last_login_at, id);

CREATE INDEX IF NOT EXISTS {prefix}users_status_idx ON {prefix}users (tenant_id, status, created_at);

CREATE INDEX IF NOT EXISTS {prefix}identifiers_value_idx ON {prefix}identifiers (tenant_id, value varchar_pattern_ops);

ALTER TABLE {prefix}users ADD COLUMN IF NOT EXISTS created_via VARCHAR(16) NOT NULL DEFAULT 'api'
    CONSTRAINT {prefix}users_created_via_check CHECK (created_via IN ('api', 'signup', 'admin', 'invite'))
