// Melochi4Luna - kho sheet chung (Cloudflare Workers + KV)
//   GET  /api/sheets          -> { sheets: [{key,name,bpm,cats,notes,ts}] }
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

export const cleanName = (s) => String(s || "").replace(/[^\w\- ]+/g, "").trim().slice(0, 60);
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

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "");

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
          metadata: { name, bpm, cats: cleanCats(s.cats), notes, ts: Date.now() },
        });
        added.push(name);
      }
      return json({ added, skipped });
    }

    return json({ error: "not found" }, 404);
  },
};
