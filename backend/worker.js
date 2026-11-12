// Melochi4Luna - Sheet library chung (Cloudflare Workers + D1)
//   POST /api/signup | /api/login   { username, password } => { token, username, admin, vip }
//   (các đường còn lại cần  Authorization: Bearer <token>)
//   POST /api/signup/email/start    { email, username, password }  -> gửi mã 4 số về mail
//   POST /api/signup/email/verify   { email, code }                -> tạo tài khoản (đã xác thực mail), trả token
//   POST /api/password/forgot       { email }                      -> gửi mã 4 số (luôn trả ok, không lộ mail nào có tài khoản)
//   POST /api/password/reset        { email, code, password }
//   POST /api/me/password { current, password }
//   GET  /api/me  |  POST /api/me/username { username }  |  POST /api/me/email/start { email }  |  POST /api/me/email/verify { code }
//   POST /api/sheets/:key/like      { liked }                      (tim yêu thích)
//   GET  /api/sheets                => { sheets:[{key,name,bpm,cats,notes,by,locked,ts,likes,liked}], admin, vip }
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
async function newSession(env, id) {
  const token = randomHex(32);
  await env.DB.prepare("DELETE FROM sessions WHERE expires < ?").bind(Date.now()).run();
  await env.DB.prepare("INSERT INTO sessions(token, user_id, expires) VALUES(?,?,?)").bind(token, id, Date.now() + TOKEN_TTL_MS).run();
  return token;
}

// Admin: tên nằm trong ADMIN_USERS (secret của Worker, cách nhau bằng dấu phẩy) được "nhận quyền" 1 lần duy nhất,
// quyền đó lưu vào chính tài khoản (users.admin) nên admin đổi tên vẫn là admin, và tên cũ có người đăng ký lại cũng KHÔNG thành admin.
// Mật khẩu KHÔNG nằm trong code.
export const isAdmin = (user, env) =>
  !!user && String(env.ADMIN_USERS || "").toLowerCase().split(",").map((x) => x.trim()).filter(Boolean).includes(String(user).toLowerCase());

async function resolveAdmin(env, id, name, flag) {
  const lc = String(name).toLowerCase();
  if (flag) return true;
  if (!isAdmin(name, env)) return false;
  const c = await env.DB.prepare("INSERT OR IGNORE INTO admin_claimed(lc) VALUES(?)").bind(lc).run();
  if (!c.meta.changes) return false;               // tên này đã có người nhận quyền admin trước đó
  await env.DB.prepare("UPDATE users SET admin = 1 WHERE id = ?").bind(id).run();
  return true;
}

async function userFrom(req, env) {
  const m = (req.headers.get("Authorization") || "").match(/^Bearer ([a-f0-9]{64})$/);
  if (!m) return null;
  const row = await env.DB.prepare(
    "SELECT u.id AS id, u.name AS name, u.lc AS lc, u.vip AS vip, u.admin AS adm FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires > ?"
  ).bind(m[1], Date.now()).first();
  if (!row) return null;
  const admin = await resolveAdmin(env, row.id, row.name, row.adm);
  return { id: row.id, name: row.name, lc: row.lc, admin, vip: admin || !!row.vip };
}

// ---------- Email + mã PIN 4 số ----------
// Gửi mail qua 1 trong 2 cách (đặt secret tương ứng):
//   MAIL_WEBHOOK_URL (+ MAIL_WEBHOOK_SECRET): Google Apps Script gửi bằng Gmail của bạn  (không cần tên miền) - xem mail-relay.gs
//   BREVO_API_KEY + MAIL_FROM: Brevo (MAIL_FROM là email người gửi đã xác minh trong Brevo)
const EMAIL_RE = /^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$/;
const normEmail = (e) => String(e || "").trim().toLowerCase().slice(0, 120);
const maskEmail = (e) => (e ? e[0] + "***" + e.slice(e.indexOf("@")) : null);

export async function sendMail(env, to, subject, text) {
  // trả về true nếu gửi được, ngược lại trả về chuỗi lý do (để hiện cho người dùng / debug)
  try {
    if (env.MAIL_WEBHOOK_URL) {
      const body = JSON.stringify({ secret: env.MAIL_WEBHOOK_SECRET || "", to, subject, text });
      // Apps Script trả 302 sang script.googleusercontent.com: tự đi theo bằng GET cho chắc chắn
      let r = await fetch(env.MAIL_WEBHOOK_URL, { method: "POST", redirect: "manual", headers: { "Content-Type": "application/json" }, body });
      for (let i = 0; i < 3 && r.status >= 300 && r.status < 400 && r.headers.get("Location"); i++) {
        r = await fetch(r.headers.get("Location"), { method: "GET", redirect: "manual" });
      }
      const out = (await r.text()).trim();
      return out === "OK" ? true : "relay replied " + r.status + " " + out.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").slice(0, 80);
    }
    if (env.BREVO_API_KEY && env.MAIL_FROM) {
      const r = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST", headers: { "api-key": env.BREVO_API_KEY, "Content-Type": "application/json" },
        body: JSON.stringify({ sender: { email: env.MAIL_FROM, name: "Melochi4Luna" }, to: [{ email: to }], subject, textContent: text }),
      });
      return r.ok ? true : "brevo replied " + r.status;
    }
  } catch (e) { return "fetch failed: " + String(e && e.message || e).slice(0, 80); }
  return "not configured";
}
const mailConfigured = (env) => !!(env.MAIL_WEBHOOK_URL || (env.BREVO_API_KEY && env.MAIL_FROM));

const PIN_TTL_MS = 10 * 60 * 1000, PIN_MAX_TRIES = 5, PIN_RESEND_MS = 45 * 1000;
const rand4 = () => String(crypto.getRandomValues(new Uint32Array(1))[0] % 10000).padStart(4, "0");
const sha256hex = async (s) => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));

// purpose: signup | reset | link. Mỗi (purpose, email) chỉ có 1 mã còn hiệu lực.
async function issuePin(env, purpose, email, payload) {
  if (!mailConfigured(env)) return { error: "Email is not set up on the server yet", status: 503 };
  const pkey = purpose + "|" + email;
  const old = await env.DB.prepare("SELECT last_sent FROM pins WHERE pkey = ?").bind(pkey).first();
  if (old && Date.now() - old.last_sent < PIN_RESEND_MS) return { error: "Please wait a few seconds before asking for another code", status: 429 };
  const code = rand4(), salt = randomHex(8);
  await env.DB.prepare("INSERT OR REPLACE INTO pins(pkey, salt, hash, expires, tries, payload, last_sent) VALUES(?,?,?,?,0,?,?)")
    .bind(pkey, salt, await sha256hex(salt + code), Date.now() + PIN_TTL_MS, JSON.stringify(payload || {}), Date.now()).run();
  const sent = await sendMail(env, email, "Melochi4Luna - " + code,
    "Mã xác nhận Melochi4Luna của bạn: " + code + "\n(Có hiệu lực 10 phút. Nếu không phải bạn yêu cầu, hãy bỏ qua email này.)\n\n" +
    "Your Melochi4Luna code: " + code + "\n(Valid for 10 minutes. If you did not request it, ignore this email.)");
  if (sent !== true) { await env.DB.prepare("DELETE FROM pins WHERE pkey = ?").bind(pkey).run(); return { error: "Could not send the email (" + sent + ")", status: 502 }; }
  return { ok: true };
}
async function checkPin(env, purpose, email, code) {
  const pkey = purpose + "|" + email;
  const row = await env.DB.prepare("SELECT salt, hash, expires, tries, payload FROM pins WHERE pkey = ?").bind(pkey).first();
  if (!row || row.expires < Date.now()) return { error: "The code expired. Ask for a new one", status: 400 };
  if (row.tries >= PIN_MAX_TRIES) { await env.DB.prepare("DELETE FROM pins WHERE pkey = ?").bind(pkey).run(); return { error: "Too many wrong tries. Ask for a new code", status: 429 }; }
  if ((await sha256hex(row.salt + String(code || ""))) !== row.hash) {
    await env.DB.prepare("UPDATE pins SET tries = tries + 1 WHERE pkey = ?").bind(pkey).run();
    return { error: "Wrong code (" + (PIN_MAX_TRIES - row.tries - 1) + " tries left)", status: 400 };
  }
  await env.DB.prepare("DELETE FROM pins WHERE pkey = ?").bind(pkey).run();
  return { ok: true, payload: JSON.parse(row.payload || "{}") };
}
const pwOk = (pw) => pw.length >= 6 && pw.length <= 100;


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
        const salt = randomHex(16), id = randomHex(16);
        const res = await env.DB.prepare("INSERT OR IGNORE INTO users(id, lc, name, salt, hash, vip, created) VALUES(?,?,?,?,?,0,?)")
          .bind(id, lc, username, salt, await hashPassword(password, salt), Date.now()).run();
        if (!res.meta.changes) return json({ error: "That username is already taken" }, 409);
        const adm = await resolveAdmin(env, id, username, 0);
        return json({ token: await newSession(env, id), username, admin: adm, vip: adm });
      }
      const u = await env.DB.prepare("SELECT id, name, salt, hash, vip, admin FROM users WHERE lc = ?").bind(lc).first();
      if (!u || (await hashPassword(password, u.salt)) !== u.hash) return json({ error: "Wrong username or password" }, 401);
      const adm = await resolveAdmin(env, u.id, u.name, u.admin);
      return json({ token: await newSession(env, u.id), username: u.name, admin: adm, vip: adm || !!u.vip });
    }

    // ---- đăng ký bằng email: bước 1 (gửi mã) và bước 2 (nhập mã)
    if (path === "/api/signup/email/start" && req.method === "POST") {
      const d = await readJson();
      if (!d) return json({ error: "bad json" }, 400);
      const email = normEmail(d.email), username = String(d.username || "").trim(), password = String(d.password || "");
      if (!EMAIL_RE.test(email)) return json({ error: "Enter a valid email" }, 400);
      if (!USER_RE.test(username)) return json({ error: "Username: 3-20 letters, numbers or _" }, 400);
      if (!pwOk(password)) return json({ error: "Password must be 6-100 characters" }, 400);
      if (await env.DB.prepare("SELECT 1 AS x FROM users WHERE lc = ?").bind(username.toLowerCase()).first()) return json({ error: "That username is already taken" }, 409);
      if (await env.DB.prepare("SELECT 1 AS x FROM users WHERE email = ?").bind(email).first()) return json({ error: "That email already has an account" }, 409);
      const salt = randomHex(16);
      const r = await issuePin(env, "signup", email, { username, salt, hash: await hashPassword(password, salt) });
      return r.ok ? json({ ok: true }) : json({ error: r.error }, r.status);
    }
    if (path === "/api/signup/email/verify" && req.method === "POST") {
      const d = await readJson();
      if (!d) return json({ error: "bad json" }, 400);
      const email = normEmail(d.email);
      const r = await checkPin(env, "signup", email, d.code);
      if (!r.ok) return json({ error: r.error }, r.status);
      const { username, salt, hash } = r.payload;
      const id = randomHex(16);
      const res = await env.DB.prepare("INSERT OR IGNORE INTO users(id, lc, name, salt, hash, vip, created, email) VALUES(?,?,?,?,?,0,?,?)")
        .bind(id, username.toLowerCase(), username, salt, hash, Date.now(), email).run();
      if (!res.meta.changes) return json({ error: "That username or email was just taken. Start again" }, 409);
      const adm = await resolveAdmin(env, id, username, 0);
      return json({ token: await newSession(env, id), username, admin: adm, vip: adm });
    }

    // ---- quên mật khẩu (luôn trả ok để không lộ email nào có tài khoản)
    if (path === "/api/password/forgot" && req.method === "POST") {
      const d = await readJson();
      const email = normEmail(d && d.email);
      if (!EMAIL_RE.test(email)) return json({ error: "Enter a valid email" }, 400);
      const u = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
      if (u) { const r = await issuePin(env, "reset", email, { id: u.id }); if (r.error && r.status === 503) return json({ error: r.error }, 503); }
      return json({ ok: true });
    }
    if (path === "/api/password/reset" && req.method === "POST") {
      const d = await readJson();
      if (!d) return json({ error: "bad json" }, 400);
      const email = normEmail(d.email), password = String(d.password || "");
      if (!pwOk(password)) return json({ error: "Password must be 6-100 characters" }, 400);
      const r = await checkPin(env, "reset", email, d.code);
      if (!r.ok) return json({ error: r.error }, r.status);
      const salt = randomHex(16);
      await env.DB.prepare("UPDATE users SET salt = ?, hash = ? WHERE id = ?").bind(salt, await hashPassword(password, salt), r.payload.id).run();
      await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(r.payload.id).run();   // đăng xuất mọi nơi
      return json({ ok: true });
    }

    // ---- từ đây trở xuống: phải đăng nhập
    const me = await userFrom(req, env);
    if (!me) return json({ error: "Please log in" }, 401);

    // ---- tài khoản của tôi
    if (path === "/api/me" && req.method === "GET") {
      const u = await env.DB.prepare("SELECT email FROM users WHERE id = ?").bind(me.id).first();
      return json({ username: me.name, admin: me.admin, vip: me.vip, email: maskEmail(u && u.email), hasEmail: !!(u && u.email), mailReady: mailConfigured(env) });
    }
    if (path === "/api/me/username" && req.method === "POST") {
      const d = await readJson();
      const username = String((d && d.username) || "").trim();
      if (!USER_RE.test(username)) return json({ error: "Username: 3-20 letters, numbers or _" }, 400);
      const lc = username.toLowerCase();
      if (lc !== me.lc && (await env.DB.prepare("SELECT 1 AS x FROM users WHERE lc = ?").bind(lc).first())) return json({ error: "That username is already taken" }, 409);
      try { await env.DB.prepare("UPDATE users SET lc = ?, name = ? WHERE id = ?").bind(lc, username, me.id).run(); }   // sheet, tim, phiên đăng nhập đều theo id nên không phải sửa gì thêm
      catch (e) { return json({ error: "That username is already taken" }, 409); }
      return json({ username });
    }
    if (path === "/api/me/password" && req.method === "POST") {
      const d = await readJson();
      const cur = String((d && d.current) || ""), pw = String((d && d.password) || "");
      if (!pwOk(pw)) return json({ error: "New password must be 6-100 characters" }, 400);
      const u = await env.DB.prepare("SELECT salt, hash FROM users WHERE id = ?").bind(me.id).first();
      if (!u || (await hashPassword(cur, u.salt)) !== u.hash) return json({ error: "Current password is wrong" }, 403);
      const salt = randomHex(16), keep = (req.headers.get("Authorization") || "").slice(7);
      await env.DB.batch([
        env.DB.prepare("UPDATE users SET salt = ?, hash = ? WHERE id = ?").bind(salt, await hashPassword(pw, salt), me.id),
        env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND token != ?").bind(me.id, keep),   // đăng xuất các thiết bị khác
      ]);
      return json({ ok: true });
    }
    if (path === "/api/me/email/start" && req.method === "POST") {
      const d = await readJson();
      const email = normEmail(d && d.email);
      if (!EMAIL_RE.test(email)) return json({ error: "Enter a valid email" }, 400);
      const have = await env.DB.prepare("SELECT email FROM users WHERE id = ?").bind(me.id).first();
      if (have && have.email) return json({ error: "An email is already linked to this account" }, 409);
      if (await env.DB.prepare("SELECT 1 AS x FROM users WHERE email = ?").bind(email).first()) return json({ error: "That email already has an account" }, 409);
      const r = await issuePin(env, "link", email, { id: me.id });
      return r.ok ? json({ ok: true }) : json({ error: r.error }, r.status);
    }
    if (path === "/api/me/email/verify" && req.method === "POST") {
      const d = await readJson();
      const email = normEmail(d && d.email);
      const r = await checkPin(env, "link", email, d && d.code);
      if (!r.ok) return json({ error: r.error }, r.status);
      if (r.payload.id !== me.id) return json({ error: "This code belongs to another account" }, 403);
      const res = await env.DB.prepare("UPDATE users SET email = ? WHERE id = ? AND email IS NULL AND NOT EXISTS (SELECT 1 FROM users WHERE email = ?)").bind(email, me.id, email).run();
      return res.meta.changes ? json({ email: maskEmail(email) }) : json({ error: "Could not link that email" }, 409);
    }

    // ---- danh sách sheet
    if (path === "/api/sheets" && req.method === "GET") {
      const { results } = await env.DB.prepare(
        `SELECT key, name, bpm, cats, notes, COALESCE((SELECT u.name FROM users u WHERE u.id = sheets.author_id), author) AS by, locked, ts,
          instr(';' || body, ';h') > 0 AS has_hold,
          instr(';' || body, ';v') > 0 AS has_vel,
          (instr(';' || body, ';d') > 0 OR instr(';' || body, ';u;') > 0) AS has_pedal,
          (SELECT COUNT(*) FROM likes l WHERE l.skey = sheets.key) AS likes,
          EXISTS(SELECT 1 FROM likes l WHERE l.skey = sheets.key AND l.user_id = ?) AS liked
         FROM sheets ORDER BY name COLLATE NOCASE LIMIT ?`
      ).bind(me.id, MAX_SHEETS).all();
      const sheets = results.map((r) => ({ ...r, cats: JSON.parse(r.cats || "[]"), locked: !!r.locked, has_hold: !!r.has_hold, has_vel: !!r.has_vel, has_pedal: !!r.has_pedal, liked: !!r.liked }));
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
          "INSERT OR IGNORE INTO sheets(key, name, bpm, cats, notes, body, author, author_id, locked, ts) VALUES(?,?,?,?,?,?,?,?,0,?)"
        ).bind(keyOf(name), name, bpm, JSON.stringify(cleanCats(s.cats)), notes, s.body, me.name, me.id, Date.now()).run();
        (res.meta.changes ? added : skipped).push(name);
      }
      return json({ added, skipped });
    }

    // ---- đọc / khoá / xoá một sheet
    if (path.startsWith("/api/sheets/")) {
      const isLock = req.method === "POST" && path.endsWith("/lock");
      const isLike = req.method === "POST" && path.endsWith("/like");
      const key = decodeURIComponent(path.slice("/api/sheets/".length, isLock ? -"/lock".length : isLike ? -"/like".length : undefined));

      if (isLike) {
        const d = await readJson();
        if (!(await env.DB.prepare("SELECT 1 AS x FROM sheets WHERE key = ?").bind(key).first())) return json({ error: "Sheet not found: " + key }, 404);
        if (d && d.liked) await env.DB.prepare("INSERT OR IGNORE INTO likes(user_id, skey, ts) VALUES(?,?,?)").bind(me.id, key, Date.now()).run();
        else await env.DB.prepare("DELETE FROM likes WHERE user_id = ? AND skey = ?").bind(me.id, key).run();
        const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM likes WHERE skey = ?").bind(key).first();
        return json({ key, liked: !!(d && d.liked), likes: c.n });
      }

      if (req.method === "GET") {
        const row = await env.DB.prepare("SELECT body, locked FROM sheets WHERE key = ?").bind(key).first();
        if (!row) return json({ error: "Sheet not found: " + key }, 404);
        if (row.locked && !me.vip) return json({ error: "VIP only" }, 403);
        return json({ body: row.body });
      }
      if (!me.admin) return json({ error: "Admins only" }, 403);
      if (req.method === "DELETE") {
        const res = await env.DB.prepare("DELETE FROM sheets WHERE key = ?").bind(key).run();
        await env.DB.prepare("DELETE FROM likes WHERE skey = ?").bind(key).run();
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
        "SELECT u.name AS name, u.vip AS vip, u.admin AS adm, u.created AS created, (SELECT COUNT(*) FROM sheets s WHERE s.author_id = u.id) AS sheets FROM users u ORDER BY u.created"
      ).all();
      return json({ users: results.map(({ adm, ...u }) => ({ ...u, vip: !!u.vip || !!adm, admin: !!adm })) });
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
