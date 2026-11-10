-- Chạy 1 lần trên database đã có từ trước (thêm email, mã PIN, tim yêu thích):
--   wrangler d1 execute melochi4luna --remote --file=migrate_v2.sql
ALTER TABLE users ADD COLUMN email TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL;
CREATE TABLE IF NOT EXISTS pins (
  pkey TEXT PRIMARY KEY,
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
