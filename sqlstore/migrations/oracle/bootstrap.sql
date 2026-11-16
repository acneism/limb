CREATE TABLE {prefix}schema (
    id              NUMBER(5)           NOT NULL,
    version         NUMBER(10)          NOT NULL,
    applied_at      TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    lock_holder     VARCHAR2(64 BYTE),
    lock_expires_at TIMESTAMP(6) WITH TIME ZONE,
    CONSTRAINT {prefix}schema_pk PRIMARY KEY (id)
)
