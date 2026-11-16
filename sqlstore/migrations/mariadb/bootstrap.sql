CREATE TABLE IF NOT EXISTS {prefix}schema (
    id              SMALLINT    NOT NULL,
    version         INT         NOT NULL,
    applied_at      DATETIME(6) NOT NULL,
    lock_holder     VARCHAR(64) NULL,
    lock_expires_at DATETIME(6) NULL,
    PRIMARY KEY (id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_nopad_bin
