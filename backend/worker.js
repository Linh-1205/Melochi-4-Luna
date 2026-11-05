// Melochi4Luna - kho sheet chung (Cloudflare Workers + KV)
//   POST /api/signup          -> { username, password } => { token, username }
//   POST /api/login           -> { username, password } => { token, username }
// Các đường /api/sheets bên dưới đều cần header  Authorization: Bearer <token>
//   POST /api/clean-name      -> { filenames:[...] } => { names:[ "Tên bài" | null, ... ] }   (AI Cohere, cần đăng nhập)
//   GET  /api/sheets          -> { sheets: [{key,name,bpm,cats,notes,by,ts}] }
//   GET  /api/sheets/:key     -> { body }
//   POST /api/sheets          -> { sheets:[{name,bpm,cats,body}] }  => { added:[], skipped:[] }
// Trùng tên (không phân biệt hoa thường): giữ bản cũ, bỏ bản mới.
// Chỉ lưu dữ liệu đã nén (token), KHÔNG lưu code Lua thô; mọi token đều được kiểm tra lại ở đây.

const KEY_OK = /^[A-Za-z0-9!@#$%^&*()]+$/;
const numOk = (v) => /^\d+\.?\d*$/.test(v) && v.length <= 12 && Number(v) <= 100000;
const MAX_BODY = 300000, MAX_BATCH = 50, MAX_SHEETS = 5000;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", ...CORS } });

export const cleanName = (s) => String(s || "").replace(/[^\p{L}\p{N}_\- ]+/gu, "").replace(/\s+/g, " ").trim().slice(0, 60);
export const keyOf = (name) => name.toLowerCase().replace(/\s+/g, " ").trim();
const cleanCats = (a) => {
  const out = [];
  for (const raw of Array.isArray(a) ? a : []) {
    const c = String(raw).replace(/[^\w\- ]+/g, "").trim().toLowerCase().slice(0, 30);
    if (c && !out.includes(c) && out.length < 8) out.push(c);
  }
  return out;
};

// trả về số token hợp lệ, hoặc 0 nếu có token lạ
export function validBody(body) {
  if (typeof body !== "string" || !body || body.length > MAX_BODY) return 0;
  const ops = body.split(";");
  for (const op of ops) {
    const t = op[0], a = op.slice(1);
    let m;
    const ok =
      (t === "k" && KEY_OK.test(a)) ||
      (t === "h" && (m = a.match(/^([^,]+),([\d.]+)$/)) && KEY_OK.test(m[1]) && numOk(m[2])) ||
      ((t === "r" || t === "v") && numOk(a)) ||
      op === "d" || op === "u";
    if (!ok) return 0;
  }
  return ops.length;
}

// ---------- Tài khoản ----------
const USER_RE = /^[A-Za-z0-9_]{3,20}$/;
const TOKEN_TTL = 60 * 60 * 24 * 30; // 30 ngày
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function hashPassword(password, saltHex) {
  const salt = Uint8Array.from(saltHex.match(/../g).map((h) => parseInt(h, 16)));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 100000 }, key, 256));
}
const randomHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
async function newSession(env, username) {
  const token = randomHex(32);
  await env.SHEETS.put("t:" + token, username, { expirationTtl: TOKEN_TTL });
  return token;
}
async function userFrom(req, env) {
  const m = (req.headers.get("Authorization") || "").match(/^Bearer ([a-f0-9]{64})$/);
  return m ? await env.SHEETS.get("t:" + m[1]) : null;
}

// ---------- AI rút gọn tên bài (Cohere) ----------
// Khoá API nằm trong secret của Worker (wrangler secret put COHERE_API_KEY), KHÔNG bao giờ gửi xuống trình duyệt.
const NAME_PROMPT =
  "You extract the song title from music file names. For each file name, return ONLY the song title: " +
  "remove the file extension, underscores, tags such as lyrics / official / MV / audio / piano / sheet / midi / cover / karaoke, " +
  "artist or singer names, 'ft.' / 'feat.' parts, track numbers and brackets. " +
  "Keep the original language and all diacritics. Write it in Title Case (capitalize each word). " +
  'Answer with JSON only, exactly: {"names": ["title 1", "title 2", ...]} with the same order and the same count as the input.';

export async function aiCleanNames(filenames, env, fetchFn = fetch) {
  if (!env.COHERE_API_KEY) return { names: filenames.map(() => null), error: "AI is not configured" };
  try {
    const r = await fetchFn("https://api.cohere.com/v2/chat", {
      method: "POST",
      headers: { Authorization: "Bearer " + env.COHERE_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: env.COHERE_MODEL || "command-r7b-12-2024",
        temperature: 0,
        max_tokens: 1200,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: NAME_PROMPT },
          { role: "user", content: JSON.stringify(filenames) },
        ],
      }),
    });
    if (!r.ok) return { names: filenames.map(() => null), error: "AI error " + r.status };
    const data = await r.json();
    const text = ((data.message && data.message.content) || []).filter((c) => c.type === "text").map((c) => c.text).join("");
    const arr = JSON.parse(text).names;
    const names = filenames.map((_, i) => {
      const n = cleanName(Array.isArray(arr) ? arr[i] : "");
      return n && n.length >= 1 ? n : null;
    });
    return { names };
  } catch (e) {
    return { names: filenames.map(() => null), error: "AI failed" };
  }
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "");

    if ((path === "/api/signup" || path === "/api/login") && req.method === "POST") {
      let d;
      try { d = await req.json(); } catch { return json({ error: "bad json" }, 400); }
      const username = String((d && d.username) || "").trim();
      const password = String((d && d.password) || "");
      if (!USER_RE.test(username)) return json({ error: "Username: 3-20 letters, numbers or _" }, 400);
      if (password.length < 6 || password.length > 100) return json({ error: "Password must be 6-100 characters" }, 400);
      const ukey = "u:" + username.toLowerCase();
      const existing = await env.SHEETS.get(ukey, "json");
      if (path === "/api/signup") {
        if (existing) return json({ error: "That username is already taken" }, 409);
        const salt = randomHex(16);
        await env.SHEETS.put(ukey, JSON.stringify({ salt, hash: await hashPassword(password, salt), name: username, ts: Date.now() }));
        return json({ token: await newSession(env, username), username });
      }
      if (!existing || (await hashPassword(password, existing.salt)) !== existing.hash) {
        return json({ error: "Wrong username or password" }, 401);
      }
      return json({ token: await newSession(env, existing.name), username: existing.name });
    }

    // từ đây trở xuống: phải đăng nhập
    if (path === "/api/clean-name" && req.method === "POST") {
      if (!(await userFrom(req, env))) return json({ error: "Please log in" }, 401);
      let d;
      try { d = await req.json(); } catch { return json({ error: "bad json" }, 400); }
      const files = (Array.isArray(d && d.filenames) ? d.filenames : []).slice(0, 30).map((f) => String(f).slice(0, 200));
      if (!files.length) return json({ names: [] });
      return json(await aiCleanNames(files, env));
    }

    if (path.startsWith("/api/sheets")) {
      var user = await userFrom(req, env);
      if (!user) return json({ error: "Please log in" }, 401);
    }

    if (path === "/api/sheets" && req.method === "GET") {
      const sheets = [];
      let cursor;
      do {
        const page = await env.SHEETS.list({ prefix: "s:", cursor, limit: 1000 });
        for (const k of page.keys) if (k.metadata) sheets.push({ key: k.name.slice(2), ...k.metadata });
        cursor = page.list_complete ? undefined : page.cursor;
      } while (cursor && sheets.length < MAX_SHEETS);
      return json({ sheets });
    }

    if (path.startsWith("/api/sheets/") && req.method === "GET") {
      const key = decodeURIComponent(path.slice("/api/sheets/".length));
      const body = await env.SHEETS.get("s:" + key);
      return body === null ? json({ error: "not found" }, 404) : json({ body });
    }

    if (path === "/api/sheets" && req.method === "POST") {
      let data;
      try { data = await req.json(); } catch { return json({ error: "bad json" }, 400); }
      const list = Array.isArray(data && data.sheets) ? data.sheets.slice(0, MAX_BATCH) : [];
      const added = [], skipped = [];
      for (const s of list) {
        const name = cleanName(s && s.name);
        const notes = validBody(s && s.body);
        if (!name || !notes) { skipped.push(String((s && s.name) || "?")); continue; }
        const key = "s:" + keyOf(name);
        if ((await env.SHEETS.get(key)) !== null) { skipped.push(name); continue; }
        const bpm = Math.min(400, Math.max(1, parseInt(s.bpm, 10) || 120));
        await env.SHEETS.put(key, s.body, {
          metadata: { name, bpm, cats: cleanCats(s.cats), notes, by: user, ts: Date.now() },
        });
        added.push(name);
      }
      return json({ added, skipped });
    }

    return json({ error: "not found" }, 404);
  },
};
