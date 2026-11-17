CREATE TABLE {prefix}admins (
    tenant_id         VARCHAR2(64 BYTE)  DEFAULT 'default' NOT NULL,
    id                VARCHAR2(64 BYTE)  NOT NULL,
    login             VARCHAR2(64 BYTE)  NOT NULL,
    password_hash     VARCHAR2(512 BYTE) NOT NULL,
    totp_secret       RAW(256),
    totp_confirmed_at TIMESTAMP(6) WITH TIME ZONE,
    totp_last_step    NUMBER(19)         DEFAULT 0 NOT NULL,
    status            VARCHAR2(16 BYTE)  NOT NULL,
    created_at        TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    last_login_at     TIMESTAMP(6) WITH TIME ZONE,
    version           NUMBER(19)         DEFAULT 1 NOT NULL,
    CONSTRAINT {prefix}admins_pk PRIMARY KEY (tenant_id, id),
    CONSTRAINT {prefix}admins_login_key UNIQUE (tenant_id, login),
    CONSTRAINT {prefix}admins_status_check CHECK (status IN ('active', 'disabled')),
    CONSTRAINT {prefix}admins_totp_check CHECK (totp_confirmed_at IS NULL OR totp_secret IS NOT NULL)
);

CREATE TABLE {prefix}admin_sessions (
    tenant_id     VARCHAR2(64 BYTE)  DEFAULT 'default' NOT NULL,
    id            VARCHAR2(64 BYTE)  NOT NULL,
    admin_id      VARCHAR2(64 BYTE)  NOT NULL,
    stage         VARCHAR2(16 BYTE)  NOT NULL,
    secret_hash   RAW(32)            NOT NULL,
    admin_version NUMBER(19)         NOT NULL,
    attempts      NUMBER(10)         DEFAULT 0 NOT NULL,
    ip            VARCHAR2(45 BYTE),
    user_agent    VARCHAR2(512 BYTE),
    created_at    TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    last_seen_at  TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    expires_at    TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT {prefix}admin_sessions_pk PRIMARY KEY (tenant_id, id),
    CONSTRAINT {prefix}admin_sessions_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT {prefix}admin_sessions_stage_check CHECK (stage IN ('password', 'full')),
    CONSTRAINT {prefix}admin_sessions_attempts_check CHECK (attempts >= 0),
    CONSTRAINT {prefix}admin_sessions_admin_fk FOREIGN KEY (tenant_id, admin_id)
        REFERENCES {prefix}admins (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX {prefix}admin_sessions_admin_idx ON {prefix}admin_sessions (tenant_id, admin_id);

CREATE TABLE {prefix}admin_recovery_codes (
    tenant_id VARCHAR2(64 BYTE) DEFAULT 'default' NOT NULL,
    admin_id  VARCHAR2(64 BYTE) NOT NULL,
    code_hash RAW(32)           NOT NULL,
    used_at   TIMESTAMP(6) WITH TIME ZONE,
    CONSTRAINT {prefix}admin_recovery_codes_pk PRIMARY KEY (tenant_id, admin_id, code_hash),
    CONSTRAINT {prefix}admin_recovery_codes_admin_fk FOREIGN KEY (tenant_id, admin_id)
        REFERENCES {prefix}admins (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE {prefix}audit_log (
    tenant_id      VARCHAR2(64 BYTE)   DEFAULT 'default' NOT NULL,
    id             VARCHAR2(64 BYTE)   NOT NULL,
    occurred_at    TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    actor_kind     VARCHAR2(16 BYTE)   NOT NULL,
    actor_id       VARCHAR2(64 BYTE),
    action         VARCHAR2(64 BYTE)   NOT NULL,
    target_user_id VARCHAR2(64 BYTE),
    ip             VARCHAR2(45 BYTE),
    details        VARCHAR2(4000 BYTE),
    CONSTRAINT {prefix}audit_log_pk PRIMARY KEY (tenant_id, id),
    CONSTRAINT {prefix}audit_log_actor_check CHECK (actor_kind IN ('admin', 'user', 'system'))
);

CREATE INDEX {prefix}audit_log_time_idx ON {prefix}audit_log (tenant_id, occurred_at, id);

CREATE INDEX {prefix}audit_log_target_idx ON {prefix}audit_log (tenant_id, target_user_id, occurred_at);

CREATE INDEX {prefix}audit_log_actor_idx ON {prefix}audit_log (tenant_id, actor_id, occurred_at);

CREATE TABLE {prefix}settings (
    tenant_id  VARCHAR2(64 BYTE)  DEFAULT 'default' NOT NULL,
    name       VARCHAR2(64 BYTE)  NOT NULL,
    value      VARCHAR2(512 BYTE) NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_by VARCHAR2(64 BYTE),
    CONSTRAINT {prefix}settings_pk PRIMARY KEY (tenant_id, name)
);

CREATE INDEX {prefix}users_created_idx ON {prefix}users (tenant_id, created_at, id);

CREATE INDEX {prefix}users_login_idx ON {prefix}users (tenant_id, last_login_at, id);

CREATE INDEX {prefix}users_status_idx ON {prefix}users (tenant_id, status, created_at);

CREATE INDEX {prefix}identifiers_value_idx ON {prefix}identifiers (tenant_id, value);

ALTER TABLE {prefix}users ADD (
    created_via VARCHAR2(16 BYTE) DEFAULT 'api' NOT NULL
        CONSTRAINT {prefix}users_created_via_check CHECK (created_via IN ('api', 'signup', 'admin', 'invite'))
)
