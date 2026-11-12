CREATE TABLE IF NOT EXISTS users (
  id TEXT NOT NULL UNIQUE,      -- ID nội bộ cố định của tài khoản (không bao giờ gửi ra ngoài); mọi bảng khác tham chiếu id này
  lc TEXT PRIMARY KEY,          -- tên đăng nhập viết thường (đổi tên thì đổi cột này)
  name TEXT NOT NULL,           -- tên hiển thị
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  vip INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL,
  email TEXT,                   -- đã xác thực bằng mã PIN (tuỳ chọn)
  admin INTEGER NOT NULL DEFAULT 0   -- quyền admin lưu theo tài khoản (đổi tên vẫn giữ)
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sheets (
  key TEXT PRIMARY KEY,         -- tên viết thường, dùng để chống trùng
  name TEXT NOT NULL,
  bpm INTEGER NOT NULL,
  cats TEXT NOT NULL DEFAULT '[]',
  notes INTEGER NOT NULL,
  body TEXT NOT NULL,
  author TEXT NOT NULL,         -- tên người đăng lúc upload (chỉ dự phòng)
  author_id TEXT,               -- ID tài khoản người đăng (tên hiển thị lấy từ users.name)
  locked INTEGER NOT NULL DEFAULT 0,
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
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
  user_id TEXT NOT NULL,
  skey TEXT NOT NULL,
  ts INTEGER NOT NULL,
  PRIMARY KEY (user_id, skey)
);
CREATE INDEX IF NOT EXISTS idx_likes_skey ON likes(skey);
CREATE TABLE IF NOT EXISTS admin_claimed (lc TEXT PRIMARY KEY);   -- tên trong ADMIN_USERS đã được nhận quyền (không nhận lại được)
