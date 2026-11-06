# Backend kho sheet (Cloudflare Workers + KV)

1. `npm i -g wrangler` rồi `wrangler login`
2. `wrangler kv namespace create SHEETS` -> dán `id` vào `wrangler.toml`
3. `wrangler deploy` -> nhận địa chỉ dạng `https://melochi4luna-library.<tên>.workers.dev`
4. Mở `Midi-lua web/index.html`, gán `const API_URL = "https://...workers.dev";`

Quy tắc: trùng tên (không phân biệt hoa thường) thì giữ bản cũ. Chỉ lưu dữ liệu nén đã kiểm tra, không lưu code thô.
Chưa có chống spam / giới hạn tốc độ: nên bật Rate Limiting hoặc Turnstile của Cloudflare trước khi công khai.

## AI rút gọn tên bài (Cohere)
`wrangler secret put COHERE_API_KEY` rồi dán khoá, sau đó `wrangler deploy`.
Khoá chỉ nằm trên Worker; trình duyệt gọi `/api/clean-name` (cần đăng nhập). Không có khoá hoặc AI lỗi thì web tự dùng cách rút gọn cơ bản.

## Admin
`wrangler secret put ADMIN_USERS` rồi nhập tên tài khoản admin (nhiều tên thì cách nhau bằng dấu phẩy), sau đó `wrangler deploy`.
Tài khoản đó phải được tạo bằng nút Sign up trên web. Mật khẩu không nằm trong code. Admin có thể khoá/mở khoá và xoá sheet.
Sheet bị khoá: người thường vẫn thấy tên nhưng không xem / sao chép được.
