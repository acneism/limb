CREATE TABLE {prefix}secrets (
    tenant_id     VARCHAR2(64 BYTE)  DEFAULT 'default' NOT NULL,
    id            VARCHAR2(64 BYTE)  NOT NULL,
    kind          VARCHAR2(16 BYTE)  NOT NULL,
    secret_hash   RAW(32)            NOT NULL,
    user_id       VARCHAR2(64 BYTE)  NOT NULL,
    purpose       VARCHAR2(16 BYTE)  NOT NULL,
    channel_type  VARCHAR2(32 BYTE)  NOT NULL,
    channel_value VARCHAR2(512 BYTE) NOT NULL,
    attempts      NUMBER(10)         DEFAULT 0 NOT NULL,
    created_at    TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    expires_at    TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    used_at       TIMESTAMP(6) WITH TIME ZONE,
    CONSTRAINT {prefix}secrets_pk PRIMARY KEY (tenant_id, id),
    CONSTRAINT {prefix}secrets_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT {prefix}secrets_kind_check CHECK (kind IN ('link', 'code')),
    CONSTRAINT {prefix}secrets_attempts_check CHECK (attempts >= 0),
    CONSTRAINT {prefix}secrets_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES {prefix}users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT {prefix}secrets_channel_fk FOREIGN KEY (tenant_id, channel_type, channel_value)
        REFERENCES {prefix}identifiers (tenant_id, type, value) ON DELETE CASCADE
);

CREATE INDEX {prefix}secrets_user_idx ON {prefix}secrets (tenant_id, user_id, purpose);

CREATE INDEX {prefix}secrets_channel_idx ON {prefix}secrets (tenant_id, channel_type, channel_value)
