-- D1 initial schema for house availability app

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT,
  google_calendar_id TEXT NOT NULL,
  refresh_token_encrypted TEXT NOT NULL,
  last_auth_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  status TEXT NOT NULL,
  message TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS freebusy_windows (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  start_at TEXT NOT NULL,
  end_at TEXT NOT NULL,
  source TEXT NOT NULL,
  sync_run_id INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (sync_run_id) REFERENCES sync_runs(id)
);

CREATE INDEX IF NOT EXISTS idx_freebusy_user_dates
  ON freebusy_windows (user_id, start_at, end_at);

CREATE TABLE IF NOT EXISTS daily_availability (
  date TEXT NOT NULL,
  user_id TEXT NOT NULL,
  is_free_evening INTEGER NOT NULL,
  computed_at TEXT NOT NULL,
  PRIMARY KEY (date, user_id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS daily_summary (
  date TEXT PRIMARY KEY,
  free_count INTEGER NOT NULL,
  free_user_ids TEXT,
  computed_at TEXT NOT NULL
);
