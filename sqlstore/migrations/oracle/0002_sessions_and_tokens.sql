CREATE TABLE {prefix}sessions (
    tenant_id    VARCHAR2(64 BYTE)  DEFAULT 'default' NOT NULL,
    id           VARCHAR2(64 BYTE)  NOT NULL,
    kind         VARCHAR2(16 BYTE)  NOT NULL,
    secret_hash  RAW(32),
    user_id      VARCHAR2(64 BYTE)  NOT NULL,
    ip           VARCHAR2(45 BYTE),
    user_agent   VARCHAR2(512 BYTE),
    created_at   TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    last_seen_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    expires_at   TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    revoked_at   TIMESTAMP(6) WITH TIME ZONE,
    CONSTRAINT {prefix}sessions_pk PRIMARY KEY (tenant_id, id),
    CONSTRAINT {prefix}sessions_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT {prefix}sessions_kind_check CHECK (kind IN ('cookie', 'token')),
    CONSTRAINT {prefix}sessions_secret_check CHECK (
        (kind = 'cookie' AND secret_hash IS NOT NULL) OR (kind <> 'cookie' AND secret_hash IS NULL)
    ),
    CONSTRAINT {prefix}sessions_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES {prefix}users (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX {prefix}sessions_user_idx ON {prefix}sessions (tenant_id, user_id);

CREATE TABLE {prefix}refresh_tokens (
    token_hash RAW(32)           NOT NULL,
    tenant_id  VARCHAR2(64 BYTE) DEFAULT 'default' NOT NULL,
    session_id VARCHAR2(64 BYTE) NOT NULL,
    used_at    TIMESTAMP(6) WITH TIME ZONE,
    expires_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT {prefix}refresh_tokens_pk PRIMARY KEY (token_hash),
    CONSTRAINT {prefix}refresh_tokens_session_fk FOREIGN KEY (tenant_id, session_id)
        REFERENCES {prefix}sessions (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX {prefix}refresh_tokens_session_idx ON {prefix}refresh_tokens (tenant_id, session_id);

CREATE TABLE {prefix}attempts (
    attempt_key     VARCHAR2(64 BYTE) NOT NULL,
    window_start    TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    hit_count       NUMBER(10)        NOT NULL,
    blocked_until   TIMESTAMP(6) WITH TIME ZONE,
    next_allowed_at TIMESTAMP(6) WITH TIME ZONE,
    CONSTRAINT {prefix}attempts_pk PRIMARY KEY (attempt_key)
);

CREATE TABLE {prefix}signing_keys (
    kid          VARCHAR2(64 BYTE) NOT NULL,
    algorithm    VARCHAR2(16 BYTE) NOT NULL,
    generation   NUMBER(19)        NOT NULL,
    private_key  BLOB              NOT NULL,
    public_key   BLOB              NOT NULL,
    created_at   TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    retire_after TIMESTAMP(6) WITH TIME ZONE,
    CONSTRAINT {prefix}signing_keys_pk PRIMARY KEY (kid),
    CONSTRAINT {prefix}signing_keys_generation_key UNIQUE (generation)
)
