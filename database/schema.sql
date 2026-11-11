
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
        CHECK(role IN ('admin', 'user')),
    is_active INTEGER NOT NULL DEFAULT 1,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS files (
    file_id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    display_filename TEXT NOT NULL,
    storage_id TEXT NOT NULL UNIQUE,
    encrypted_size INTEGER NOT NULL,
    original_size INTEGER NOT NULL,
    encryption_algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM',
    encryption_version INTEGER NOT NULL DEFAULT 1,
    original_sha256 TEXT NOT NULL,
    nonce BLOB,
    key_nonce BLOB,
    wrapped_key BLOB,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(owner_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    file_id INTEGER,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(actor_id)
        REFERENCES users(user_id)
        ON DELETE SET NULL,

    FOREIGN KEY(file_id)
        REFERENCES files(file_id)
        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_files_owner
ON files(owner_id);

CREATE INDEX IF NOT EXISTS idx_audit_actor
ON audit_events(actor_id);

CREATE INDEX IF NOT EXISTS idx_audit_created
ON audit_events(created_at);
