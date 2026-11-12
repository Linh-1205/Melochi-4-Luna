-- Mỗi tài khoản có 1 ID nội bộ cố định (không hiện ra ngoài). Chạy 1 lần, TRƯỚC khi wrangler deploy:
--   wrangler d1 execute melochi4luna --remote --file=migrate_v4.sql
-- Giữ nguyên tài khoản, sheet, tim và các phiên đăng nhập đang có.
ALTER TABLE users ADD COLUMN id TEXT;
UPDATE users SET id = lower(hex(randomblob(16))) WHERE id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_id ON users(id);

ALTER TABLE sheets ADD COLUMN author_id TEXT;
UPDATE sheets SET author_id = (SELECT u.id FROM users u WHERE u.lc = lower(sheets.author));

CREATE TABLE sessions_new (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires INTEGER NOT NULL);
INSERT INTO sessions_new(token, user_id, expires) SELECT s.token, u.id, s.expires FROM sessions s JOIN users u ON u.lc = s.user_lc;
DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE likes_new (user_id TEXT NOT NULL, skey TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (user_id, skey));
INSERT INTO likes_new(user_id, skey, ts) SELECT u.id, l.skey, l.ts FROM likes l JOIN users u ON u.lc = l.user_lc;
DROP TABLE likes;
ALTER TABLE likes_new RENAME TO likes;
CREATE INDEX IF NOT EXISTS idx_likes_skey ON likes(skey);
