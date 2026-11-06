// Melochi4Luna - Sheet library chung (Cloudflare Workers + D1)
//   POST /api/signup | /api/login   { username, password } => { token, username, admin, vip }
//   (các đường còn lại cần  Authorization: Bearer <token>)
//   GET  /api/sheets                => { sheets:[{key,name,bpm,cats,notes,by,locked,ts}], admin, vip }
//   GET  /api/sheets/:key           => { body }        (sheet khoá: chỉ VIP / admin)
//   POST /api/sheets                { sheets:[{name,bpm,cats,body}] } => { added, skipped }   (trùng tên: giữ bản cũ)
//   POST /api/sheets/:key/lock      { locked } (admin)        DELETE /api/sheets/:key (admin)
//   GET  /api/admin/users           (admin) => { users:[{name,admin,vip,sheets,created}] }
//   POST /api/admin/users/:name/vip { vip } (admin)
// D1 (SQLite) cho dữ liệu nhất quán ngay lập tức (KV cũ bị trễ nên khoá/xoá lúc được lúc không).
// Chỉ lưu dữ liệu đã nén (token), KHÔNG lưu code Lua thô; mọi token đều được kiểm tra lại ở đây.

const KEY_OK = /^[A-Za-z0-9!@#$%^&*()]+$/;
const numOk = (v) => /^\d+\.?\d*$/.test(v) && v.length <= 12 && Number(v) <= 100000;
const MAX_BODY = 300000, MAX_BATCH = 50, MAX_SHEETS = 5000;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
};
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", ...CORS } });

export const cleanName = (s) => String(s || "").normalize("NFC").replace(/[^\p{L}\p{N}_\- ]+/gu, "").replace(/\s+/g, " ").trim().slice(0, 60);
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
const TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 30; // 30 ngày
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function hashPassword(password, saltHex) {
  const salt = Uint8Array.from(saltHex.match(/../g).map((h) => parseInt(h, 16)));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 100000 }, key, 256));
}
const randomHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
async function newSession(env, lc) {
  const token = randomHex(32);
  await env.DB.prepare("DELETE FROM sessions WHERE expires < ?").bind(Date.now()).run();
  await env.DB.prepare("INSERT INTO sessions(token, user_lc, expires) VALUES(?,?,?)").bind(token, lc, Date.now() + TOKEN_TTL_MS).run();
  return token;
}

// Admin = tên đăng nhập nằm trong biến ADMIN_USERS (secret của Worker, cách nhau bằng dấu phẩy). Mật khẩu KHÔNG nằm trong code.
export const isAdmin = (user, env) =>
  !!user && String(env.ADMIN_USERS || "").toLowerCase().split(",").map((x) => x.trim()).filter(Boolean).includes(String(user).toLowerCase());

async function userFrom(req, env) {
  const m = (req.headers.get("Authorization") || "").match(/^Bearer ([a-f0-9]{64})$/);
  if (!m) return null;
  const row = await env.DB.prepare(
    "SELECT u.name AS name, u.vip AS vip FROM sessions s JOIN users u ON u.lc = s.user_lc WHERE s.token = ? AND s.expires > ?"
  ).bind(m[1], Date.now()).first();
  if (!row) return null;
  const admin = isAdmin(row.name, env);
  return { name: row.name, admin, vip: admin || !!row.vip };
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "");
    const readJson = async () => { try { return await req.json(); } catch { return null; } };

    // ---- đăng ký / đăng nhập
    if ((path === "/api/signup" || path === "/api/login") && req.method === "POST") {
      const d = await readJson();
      if (!d) return json({ error: "bad json" }, 400);
      const username = String(d.username || "").trim();
      const password = String(d.password || "");
      if (!USER_RE.test(username)) return json({ error: "Username: 3-20 letters, numbers or _" }, 400);
      if (password.length < 6 || password.length > 100) return json({ error: "Password must be 6-100 characters" }, 400);
      const lc = username.toLowerCase();
      if (path === "/api/signup") {
        const salt = randomHex(16);
        const res = await env.DB.prepare("INSERT OR IGNORE INTO users(lc, name, salt, hash, vip, created) VALUES(?,?,?,?,0,?)")
          .bind(lc, username, salt, await hashPassword(password, salt), Date.now()).run();
        if (!res.meta.changes) return json({ error: "That username is already taken" }, 409);
        const adm = isAdmin(username, env);
        return json({ token: await newSession(env, lc), username, admin: adm, vip: adm });
      }
      const u = await env.DB.prepare("SELECT name, salt, hash, vip FROM users WHERE lc = ?").bind(lc).first();
      if (!u || (await hashPassword(password, u.salt)) !== u.hash) return json({ error: "Wrong username or password" }, 401);
      const adm = isAdmin(u.name, env);
      return json({ token: await newSession(env, lc), username: u.name, admin: adm, vip: adm || !!u.vip });
    }

    // ---- từ đây trở xuống: phải đăng nhập
    const me = await userFrom(req, env);
    if (!me) return json({ error: "Please log in" }, 401);

    // ---- danh sách sheet
    if (path === "/api/sheets" && req.method === "GET") {
      const { results } = await env.DB.prepare(
        "SELECT key, name, bpm, cats, notes, author AS by, locked, ts FROM sheets ORDER BY name COLLATE NOCASE LIMIT ?"
      ).bind(MAX_SHEETS).all();
      const sheets = results.map((r) => ({ ...r, cats: JSON.parse(r.cats || "[]"), locked: !!r.locked }));
      return json({ sheets, admin: me.admin, vip: me.vip });
    }

    // ---- thêm sheet (trùng tên: giữ bản cũ)
    if (path === "/api/sheets" && req.method === "POST") {
      const d = await readJson();
      if (!d) return json({ error: "bad json" }, 400);
      const list = Array.isArray(d.sheets) ? d.sheets.slice(0, MAX_BATCH) : [];
      const added = [], skipped = [];
      for (const s of list) {
        const name = cleanName(s && s.name);
        const notes = validBody(s && s.body);
        if (!name || !notes) { skipped.push(String((s && s.name) || "?")); continue; }
        const bpm = Math.min(400, Math.max(1, parseInt(s.bpm, 10) || 120));
        const res = await env.DB.prepare(
          "INSERT OR IGNORE INTO sheets(key, name, bpm, cats, notes, body, author, locked, ts) VALUES(?,?,?,?,?,?,?,0,?)"
        ).bind(keyOf(name), name, bpm, JSON.stringify(cleanCats(s.cats)), notes, s.body, me.name, Date.now()).run();
        (res.meta.changes ? added : skipped).push(name);
      }
      return json({ added, skipped });
    }

    // ---- đọc / khoá / xoá một sheet
    if (path.startsWith("/api/sheets/")) {
      const isLock = req.method === "POST" && path.endsWith("/lock");
      const key = decodeURIComponent(path.slice("/api/sheets/".length, isLock ? -"/lock".length : undefined));

      if (req.method === "GET") {
        const row = await env.DB.prepare("SELECT body, locked FROM sheets WHERE key = ?").bind(key).first();
        if (!row) return json({ error: "Sheet not found: " + key }, 404);
        if (row.locked && !me.vip) return json({ error: "VIP only" }, 403);
        return json({ body: row.body });
      }
      if (!me.admin) return json({ error: "Admins only" }, 403);
      if (req.method === "DELETE") {
        const res = await env.DB.prepare("DELETE FROM sheets WHERE key = ?").bind(key).run();
        return res.meta.changes ? json({ deleted: key }) : json({ error: "Sheet not found: " + key }, 404);
      }
      if (isLock) {
        const d = await readJson();
        const res = await env.DB.prepare("UPDATE sheets SET locked = ? WHERE key = ?").bind(d && d.locked ? 1 : 0, key).run();
        return res.meta.changes ? json({ key, locked: !!(d && d.locked) }) : json({ error: "Sheet not found: " + key }, 404);
      }
    }

    // ---- quản lý tài khoản (admin)
    if (path === "/api/admin/users" && req.method === "GET") {
      if (!me.admin) return json({ error: "Admins only" }, 403);
      const { results } = await env.DB.prepare(
        "SELECT u.name AS name, u.vip AS vip, u.created AS created, (SELECT COUNT(*) FROM sheets s WHERE s.author = u.name) AS sheets FROM users u ORDER BY u.created"
      ).all();
      return json({ users: results.map((u) => ({ ...u, vip: !!u.vip, admin: isAdmin(u.name, env) })) });
    }
    if (path.startsWith("/api/admin/users/") && path.endsWith("/vip") && req.method === "POST") {
      if (!me.admin) return json({ error: "Admins only" }, 403);
      const name = decodeURIComponent(path.slice("/api/admin/users/".length, -"/vip".length));
      const d = await readJson();
      const res = await env.DB.prepare("UPDATE users SET vip = ? WHERE lc = ?").bind(d && d.vip ? 1 : 0, name.toLowerCase()).run();
      return res.meta.changes ? json({ name, vip: !!(d && d.vip) }) : json({ error: "User not found" }, 404);
    }

    return json({ error: "Route not found: " + req.method + " " + path }, 404);
  },
};
