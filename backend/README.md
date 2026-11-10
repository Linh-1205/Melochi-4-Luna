# Backend Sheet library (Cloudflare Workers + D1)

Cài lần đầu (trong thư mục `backend`):
1. `npm i -g wrangler` rồi `wrangler login`
2. `wrangler d1 create melochi4luna` -> dán `database_id` vào `wrangler.toml`
3. `wrangler d1 execute melochi4luna --remote --file=schema.sql`  (tạo bảng)
4. `wrangler secret put ADMIN_USERS`  -> nhập tên tài khoản admin (nhiều tên: cách nhau dấu phẩy)
5. `wrangler deploy`
6. Dán địa chỉ `...workers.dev` vào `const API_URL` trong `index.html`

Cập nhật về sau: `git pull` rồi `wrangler deploy`.

- Tài khoản admin phải tự đăng ký bằng nút Sign up. Mật khẩu không nằm trong code.
- Admin: khoá / mở khoá / xoá sheet, mục Manager (xem tài khoản, cấp VIP).
- Sheet khoá: người thường thấy tên nhưng không xem / chép được; VIP và admin dùng bình thường.
- Trùng tên sheet (không phân biệt hoa thường): giữ bản cũ.
- Chỉ lưu dữ liệu nén đã kiểm tra, không lưu code Lua thô.
- Chưa có chống spam đăng ký: nên bật Rate Limiting / Turnstile của Cloudflare trước khi công khai.

## Cập nhật v2: email + mã PIN, quên mật khẩu, tim yêu thích, đổi username

1. Database đã có từ trước, chạy 1 lần (trong thư mục `backend`):
   `wrangler d1 execute melochi4luna --remote --file=migrate_v2.sql`
2. Gửi email (chọn 1 cách):
   - **Gmail của bạn (không cần tên miền)**: dán `mail-relay.gs` vào https://script.google.com, đổi `SECRET`, Deploy > Web app (Execute as: Me, Access: Anyone), copy URL, rồi:
     `wrangler secret put MAIL_WEBHOOK_URL` (dán URL) và `wrangler secret put MAIL_WEBHOOK_SECRET` (đúng chuỗi SECRET)
   - **Brevo**: `wrangler secret put BREVO_API_KEY` và `wrangler secret put MAIL_FROM` (email người gửi đã xác minh trong Brevo)
3. `wrangler deploy`
