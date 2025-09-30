-- Add multi-provider support to users table

-- Add new columns for provider support
ALTER TABLE users ADD COLUMN provider TEXT NOT NULL DEFAULT 'google';
ALTER TABLE users ADD COLUMN caldav_url TEXT;
ALTER TABLE users ADD COLUMN caldav_username TEXT;

-- Rename google_calendar_id to calendar_id (provider-agnostic)
-- SQLite doesn't support ALTER COLUMN RENAME, so we need to recreate the table
CREATE TABLE users_new (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT,
  provider TEXT NOT NULL DEFAULT 'google',
  calendar_id TEXT NOT NULL,
  caldav_url TEXT,
  caldav_username TEXT,
  refresh_token_encrypted TEXT NOT NULL,
  last_auth_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Copy data from old table
INSERT INTO users_new (id, email, display_name, provider, calendar_id, refresh_token_encrypted, last_auth_at, created_at, updated_at)
SELECT id, email, display_name, 'google', google_calendar_id, refresh_token_encrypted, last_auth_at, created_at, updated_at
FROM users;

-- Drop old table and rename new one
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

-- Recreate foreign key references (they're preserved through the rename)
CREATE INDEX IF NOT EXISTS idx_users_provider ON users(provider);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);