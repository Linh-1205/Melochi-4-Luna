CREATE TABLE IF NOT EXISTS users (
  lc TEXT PRIMARY KEY,          -- tên đăng nhập viết thường
  name TEXT NOT NULL,           -- tên hiển thị
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  vip INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_lc TEXT NOT NULL,
  expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sheets (
  key TEXT PRIMARY KEY,         -- tên viết thường, dùng để chống trùng
  name TEXT NOT NULL,
  bpm INTEGER NOT NULL,
  cats TEXT NOT NULL DEFAULT '[]',
  notes INTEGER NOT NULL,
  body TEXT NOT NULL,
  author TEXT NOT NULL,
  locked INTEGER NOT NULL DEFAULT 0,
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_lc);
