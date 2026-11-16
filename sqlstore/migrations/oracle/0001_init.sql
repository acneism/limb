CREATE TABLE {prefix}users (
    tenant_id            VARCHAR2(64 BYTE)  DEFAULT 'default' NOT NULL,
    id                   VARCHAR2(64 BYTE)  NOT NULL,
    status               VARCHAR2(16 BYTE)  NOT NULL,
    password_hash        VARCHAR2(512 BYTE),
    must_change_password NUMBER(1)          DEFAULT 0 NOT NULL,
    blocked_reason       VARCHAR2(512 BYTE),
    blocked_until        TIMESTAMP(6) WITH TIME ZONE,
    deleted_at           TIMESTAMP(6) WITH TIME ZONE,
    purge_after          TIMESTAMP(6) WITH TIME ZONE,
    created_at           TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    last_login_at        TIMESTAMP(6) WITH TIME ZONE,
    version              NUMBER(19)         DEFAULT 1 NOT NULL,
    CONSTRAINT {prefix}users_pk PRIMARY KEY (tenant_id, id),
    CONSTRAINT {prefix}users_status_check CHECK (status IN ('active', 'blocked', 'deleted'))
);

CREATE TABLE {prefix}identifiers (
    tenant_id     VARCHAR2(64 BYTE)   DEFAULT 'default' NOT NULL,
    type          VARCHAR2(32 BYTE)   NOT NULL,
    value         VARCHAR2(512 BYTE)  NOT NULL,
    display_value VARCHAR2(1024 BYTE) NOT NULL,
    user_id       VARCHAR2(64 BYTE)   NOT NULL,
    verified_at   TIMESTAMP(6) WITH TIME ZONE,
    CONSTRAINT {prefix}identifiers_pk PRIMARY KEY (tenant_id, type, value),
    CONSTRAINT {prefix}identifiers_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES {prefix}users (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX {prefix}identifiers_user_idx ON {prefix}identifiers (tenant_id, user_id)
