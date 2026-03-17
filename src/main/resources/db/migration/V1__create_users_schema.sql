-- Roles reference table — seeded by V2, never created at runtime
CREATE TABLE roles (
    id    BIGINT       NOT NULL AUTO_INCREMENT,
    name  VARCHAR(50)  NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_roles_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- Main users table
CREATE TABLE users (
    id                    VARCHAR(36)  NOT NULL DEFAULT (UUID()),
    email                 VARCHAR(100) NOT NULL,
    phone_number          VARCHAR(20)  NOT NULL,
    password_hash         VARCHAR(255) NOT NULL,
    first_name            VARCHAR(60)  NOT NULL,
    last_name             VARCHAR(60)  NOT NULL,
    status                VARCHAR(20)  NOT NULL DEFAULT 'PENDING',
    kyc_status            VARCHAR(20)  NOT NULL DEFAULT 'UNVERIFIED',
    mfa_enabled           TINYINT(1)   NOT NULL DEFAULT 0,
    mfa_secret            TEXT,
    failed_login_attempts INT          NOT NULL DEFAULT 0,
    locked_until          DATETIME(6),
    last_login_at         DATETIME(6),
    last_login_ip         VARCHAR(45),
    created_at            DATETIME(6)  NOT NULL DEFAULT NOW(6),
    updated_at            DATETIME(6)  NOT NULL DEFAULT NOW(6) ON UPDATE NOW(6),

    PRIMARY KEY (id),
    UNIQUE KEY uk_users_email        (email),
    UNIQUE KEY uk_users_phone_number (phone_number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Explicit indexes beyond unique constraints
CREATE INDEX idx_users_email  ON users (email);
CREATE INDEX idx_users_phone  ON users (phone_number);
CREATE INDEX idx_users_status ON users (status);


-- User ↔ Role many-to-many join table
CREATE TABLE user_roles (
    user_id VARCHAR(36) NOT NULL,
    role_id BIGINT      NOT NULL,

    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id)
        REFERENCES roles (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- Refresh tokens — one row per device session
-- SHA-256 hash stored (64 hex chars), never the raw token
CREATE TABLE refresh_tokens (
    id          VARCHAR(36)  NOT NULL,
    user_id     VARCHAR(36)  NOT NULL,
    token_hash  VARCHAR(64)  NOT NULL,
    ip_address  VARCHAR(45),
    user_agent  TEXT,
    expires_at  DATETIME(6)  NOT NULL,
    revoked     TINYINT(1)   NOT NULL DEFAULT 0,
    created_at  DATETIME(6)  NOT NULL DEFAULT NOW(6),

    PRIMARY KEY (id),
    UNIQUE KEY uk_refresh_token_hash (token_hash),
    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_refresh_user_id    ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_token_hash ON refresh_tokens (token_hash);


-- Immutable audit log — append-only by application convention
-- Revoke UPDATE/DELETE on this table in production:
--   REVOKE UPDATE, DELETE ON user_audit_log FROM 'wallet_app_user'@'%';
CREATE TABLE user_audit_log (
    id          BIGINT      NOT NULL AUTO_INCREMENT,
    user_id     VARCHAR(36) NOT NULL,
    action      VARCHAR(50) NOT NULL,
    metadata    TEXT,
    ip_address  VARCHAR(45),
    created_at  DATETIME(6) NOT NULL DEFAULT NOW(6),

    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Composite index for per-user audit history queries (most recent first)
CREATE INDEX idx_audit_user_time ON user_audit_log (user_id, created_at DESC);
