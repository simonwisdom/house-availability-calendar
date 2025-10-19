-- Track when a user needs to reconnect their calendar provider

ALTER TABLE users
  ADD COLUMN reauth_required INTEGER NOT NULL DEFAULT 0;

ALTER TABLE users
  ADD COLUMN reauth_required_reason TEXT;

ALTER TABLE users
  ADD COLUMN reauth_required_at TEXT;

CREATE INDEX IF NOT EXISTS idx_users_reauth_required ON users(reauth_required);
