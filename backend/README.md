# Backend kho sheet (Cloudflare Workers + KV)

1. `npm i -g wrangler` rồi `wrangler login`
2. `wrangler kv namespace create SHEETS` -> dán `id` vào `wrangler.toml`
3. `wrangler deploy` -> nhận địa chỉ dạng `https://melochi4luna-library.<tên>.workers.dev`
4. Mở `Midi-lua web/index.html`, gán `const API_URL = "https://...workers.dev";`

Quy tắc: trùng tên (không phân biệt hoa thường) thì giữ bản cũ. Chỉ lưu dữ liệu nén đã kiểm tra, không lưu code thô.
Chưa có chống spam / giới hạn tốc độ: nên bật Rate Limiting hoặc Turnstile của Cloudflare trước khi công khai.
