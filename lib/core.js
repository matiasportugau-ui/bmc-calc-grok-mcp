const crypto = require("crypto");

const CALC = process.env.BMC_CALC_BASE_URL || "https://calculadora-bmc.vercel.app";
const SECRET = process.env.OAUTH_SECRET || "ac1e83877c88d65260bc5492d1edefa80469c854b54b32c2c0ceba2d5c766d05";
const CLIENT_ID = process.env.OAUTH_CLIENT_ID || "grok";
const ACCESS_TTL = 3600;
const REFRESH_TTL = 30 * 24 * 3600;
const CODE_TTL = 300;

function origin(req) {
  const proto = req.headers["x-forwarded-proto"] || "https";
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}`;
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function sign(obj) {
  const payload = b64url(JSON.stringify(obj));
  const sig = crypto.createHmac("sha256", SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

function unsign(token) {
  if (!token || !token.includes(".")) return null;
  const [payload, sig] = token.split(".");
  const expect = crypto.createHmac("sha256", SECRET).update(payload).digest("base64url");
  const a = Buffer.from(sig);
  const b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (data.exp && Date.now() / 1000 > data.exp) return null;
    return data;
  } catch {
    return null;
  }
}

function s256(verifier) {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

function allowedRedirect(uri) {
  try {
    const u = new URL(uri);
    if (u.protocol !== "https:" && u.hostname !== "127.0.0.1" && u.hostname !== "localhost") return false;
    const h = u.hostname.toLowerCase();
    return (
      h === "grok.com" ||
      h.endsWith(".grok.com") ||
      h === "x.ai" ||
      h.endsWith(".x.ai") ||
      h === "localhost" ||
      h === "127.0.0.1"
    );
  } catch {
    return false;
  }
}

function json(res, status, body, extra = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,Authorization,Mcp-Session-Id,MCP-Protocol-Version",
  );
  for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}

function html(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(body);
}

function asMetadata(base) {
  return {
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/oauth/register`,
    scopes_supported: ["mcp:tools", "openid", "offline_access"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    client_id_issued_at: 1,
  };
}

function prMetadata(base) {
  return {
    resource: `${base}/mcp`,
    authorization_servers: [base],
    bearer_methods_supported: ["header"],
    scopes_supported: ["mcp:tools"],
  };
}

function getBearer(req) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : "";
}

function requireAccess(req, res) {
  const tok = unsign(getBearer(req));
  if (!tok || tok.typ !== "access") {
    const base = origin(req);
    json(
      res,
      401,
      { error: "invalid_token", error_description: "Access token required" },
      {
        "WWW-Authenticate": `Bearer FAKESECRET_g3h4i5j6k7l8m9n0o1p2="${base}/.well-known/oauth-protected-resource"`,
      },
    );
    return null;
  }
  return tok;
}

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks).toString("utf8");
  const ct = String(req.headers["content-type"] || "");
  if (ct.includes("application/x-www-form-urlencoded")) {
    return Object.fromEntries(new URLSearchParams(raw));
  }
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return { _raw: raw };
  }
}

async function calcGet(path, params) {
  const u = new URL(path, CALC);
  if (params) Object.entries(params).forEach(([k, v]) => v != null && u.searchParams.set(k, String(v)));
  const r = await fetch(u, { redirect: "follow" });
  const text = await r.text();
  try {
    return JSON.parse(text);
  } catch {
    return { ok: false, status: r.status, error: text.slice(0, 400) };
  }
}

async function calcPost(path, body) {
  const r = await fetch(new URL(path, CALC), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
    redirect: "follow",
  });
  const text = await r.text();
  try {
    return JSON.parse(text);
  } catch {
    return { ok: false, status: r.status, error: text.slice(0, 400) };
  }
}

module.exports = {
  CALC, SECRET, CLIENT_ID, ACCESS_TTL, REFRESH_TTL, CODE_TTL,
  origin, sign, unsign, s256, allowedRedirect, json, html,
  asMetadata, prMetadata, getBearer, requireAccess, readBody,
  calcGet, calcPost,
};
