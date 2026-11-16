CREATE TABLE IF NOT EXISTS {prefix}users (
    tenant_id            VARCHAR(64)  NOT NULL DEFAULT 'default',
    id                   VARCHAR(64)  NOT NULL,
    status               VARCHAR(16)  NOT NULL,
    password_hash        VARCHAR(512),
    must_change_password BOOLEAN      NOT NULL DEFAULT FALSE,
    blocked_reason       VARCHAR(512),
    blocked_until        TIMESTAMPTZ,
    deleted_at           TIMESTAMPTZ,
    purge_after          TIMESTAMPTZ,
    created_at           TIMESTAMPTZ  NOT NULL,
    last_login_at        TIMESTAMPTZ,
    version              BIGINT       NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT {prefix}users_status_check CHECK (status IN ('active', 'blocked', 'deleted'))
);

CREATE TABLE IF NOT EXISTS {prefix}identifiers (
    tenant_id     VARCHAR(64)   NOT NULL DEFAULT 'default',
    type          VARCHAR(32)   NOT NULL,
    value         VARCHAR(512)  NOT NULL,
    display_value VARCHAR(1024) NOT NULL,
    user_id       VARCHAR(64)   NOT NULL,
    verified_at   TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, type, value),
    CONSTRAINT {prefix}identifiers_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES {prefix}users (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS {prefix}identifiers_user_idx ON {prefix}identifiers (tenant_id, user_id);
