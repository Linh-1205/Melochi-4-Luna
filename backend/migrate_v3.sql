-- Chạy 1 lần trên database đã có (cho phép admin đổi tên):
--   wrangler d1 execute melochi4luna --remote --file=migrate_v3.sql
-- PHẢI chạy TRƯỚC khi wrangler deploy.
ALTER TABLE users ADD COLUMN admin INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS admin_claimed (lc TEXT PRIMARY KEY);
