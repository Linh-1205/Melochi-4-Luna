CREATE TABLE IF NOT EXISTS users (
  lc TEXT PRIMARY KEY,          -- tên đăng nhập viết thường
  name TEXT NOT NULL,           -- tên hiển thị
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  vip INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL,
  email TEXT                    -- đã xác thực bằng mã PIN (tuỳ chọn)
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
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL;
CREATE TABLE IF NOT EXISTS pins (
  pkey TEXT PRIMARY KEY,        -- "signup|email", "reset|email", "link|email"
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  expires INTEGER NOT NULL,
  tries INTEGER NOT NULL DEFAULT 0,
  payload TEXT NOT NULL DEFAULT '{}',
  last_sent INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS likes (
  user_lc TEXT NOT NULL,
  skey TEXT NOT NULL,
  ts INTEGER NOT NULL,
  PRIMARY KEY (user_lc, skey)
);
CREATE INDEX IF NOT EXISTS idx_likes_skey ON likes(skey);
