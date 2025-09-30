-- Add support for multiple calendars per user

CREATE TABLE user_calendars (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  calendar_id TEXT NOT NULL,
  calendar_name TEXT,
  is_primary INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(user_id, calendar_id)
);

CREATE INDEX idx_user_calendars_user_id ON user_calendars(user_id);

-- Migrate existing calendar_id data to user_calendars table
INSERT INTO user_calendars (id, user_id, calendar_id, calendar_name, is_primary, created_at)
SELECT
  hex(randomblob(16)),
  id,
  calendar_id,
  NULL,
  1,
  datetime('now')
FROM users
WHERE calendar_id IS NOT NULL AND calendar_id != '';

-- Add pending_auth table for temporary storage during calendar selection
CREATE TABLE pending_auth (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  display_name TEXT,
  provider TEXT NOT NULL,
  refresh_token_encrypted TEXT NOT NULL,
  caldav_url TEXT,
  caldav_username TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX idx_pending_auth_created_at ON pending_auth(created_at);