-- Schema for the CLI login system.
-- Applied automatically on startup (see internal/db/db.go). All statements
-- use IF NOT EXISTS so re-running this file on an existing database is safe.

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,

    -- TOTP / 2FA
    totp_secret     TEXT,               -- base32 secret; NULL until 2FA is set up
    totp_enabled    INTEGER NOT NULL DEFAULT 0,  -- 0 = false, 1 = true

    -- Account lockout tracking
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,               -- ISO8601 timestamp; NULL if not locked

    -- Audit timestamps
    created_at      TEXT NOT NULL,      -- ISO8601, set at registration
    last_login_at   TEXT                -- ISO8601, updated on each successful login
);

CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,       -- random UUID session token
    user_id     INTEGER NOT NULL,
    created_at  TEXT NOT NULL,          -- ISO8601
    expires_at  TEXT NOT NULL,          -- ISO8601; session is invalid after this
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
