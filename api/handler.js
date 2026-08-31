const {
  CLIENT_ID, ACCESS_TTL, REFRESH_TTL, CODE_TTL,
  origin, sign, unsign, s256, allowedRedirect, json, html,
  asMetadata, prMetadata, requireAccess, readBody,
  calcGet, calcPost,
} = require("../lib/core");
const crypto = require("crypto");

const TOOLS = [
  {
    name: "obtener_escenarios",
    description: "Escenarios BMC (solo_techo, solo_fachada, techo_fachada, camara_frig) y campos requeridos.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "obtener_catalogo",
    description: "Catalogo de familias, espesores, colores y precios. lista=venta|web.",
    inputSchema: {
      type: "object",
      properties: { lista: { type: "string", enum: ["venta", "web"], default: "venta" } },
    },
  },
  {
    name: "obtener_informe",
    description: "Precios, fijaciones, selladores, formulas y reglas de asesoria.",
    inputSchema: {
      type: "object",
      properties: { lista: { type: "string", enum: ["venta", "web"], default: "venta" } },
    },
  },
  {
    name: "cotizar",
    description: "Cotizacion completa BOM + IVA 22%. No inventar precios.",
    inputSchema: {
      type: "object",
      required: ["escenario"],
      properties: {
        escenario: { type: "string", enum: ["solo_techo", "solo_fachada", "techo_fachada", "camara_frig"] },
        lista: { type: "string", enum: ["venta", "web"], default: "venta" },
        techo: { type: "object" },
        pared: { type: "object" },
        camara: { type: "object" },
        flete: { type: "number", default: 0 },
      },
    },
  },
  {
    name: "presupuesto_libre",
    description: "Presupuesto por lineas manuales.",
    inputSchema: {
      type: "object",
      properties: {
        lista: { type: "string", enum: ["venta", "web"], default: "venta" },
        librePanelLines: { type: "array", items: { type: "object" } },
        librePerfilQty: { type: "object" },
        libreFijQty: { type: "object" },
        libreSellQty: { type: "object" },
        flete: { type: "number" },
        libreExtra: { type: "object" },
      },
    },
  },
  {
    name: "generar_pdf",
    description: "Genera link HTML/PDF de cotizacion (~24h).",
    inputSchema: {
      type: "object",
      required: ["escenario"],
      properties: {
        escenario: { type: "string" },
        lista: { type: "string", enum: ["venta", "web"], default: "venta" },
        techo: { type: "object" },
        pared: { type: "object" },
        camara: { type: "object" },
        flete: { type: "number" },
        cliente: { type: "object" },
      },
    },
  },
];

async function runTool(name, args) {
  args = args || {};
  switch (name) {
    case "obtener_escenarios": return calcGet("/calc/escenarios");
    case "obtener_catalogo": return calcGet("/calc/catalogo", { lista: args.lista || "venta" });
    case "obtener_informe": return calcGet("/calc/informe", { lista: args.lista || "venta" });
    case "cotizar": return calcPost("/calc/cotizar", args);
    case "presupuesto_libre": return calcPost("/calc/cotizar/presupuesto-libre", args);
    case "generar_pdf": return calcPost("/calc/cotizar/pdf", args);
    default: return { ok: false, error: "Unknown tool " + name };
  }
}

function mcpResult(id, result) { return { jsonrpc: "2.0", id, result }; }
function mcpError(id, code, message) { return { jsonrpc: "2.0", id, error: { code, message } }; }

async function handleMcp(req, body) {
  const method = body.method;
  const id = body.id ?? null;
  if (method === "initialize") {
    return mcpResult(id, {
      protocolVersion: body.params?.protocolVersion || "2025-03-26",
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: "bmc-calculadora", version: "1.0.0" },
      instructions: "Cotizador BMC Uruguay. Flujo: obtener_escenarios, catalogo, cotizar. Nunca inventar USD.",
    });
  }
  if (method === "notifications/initialized" || method === "notifications/cancelled") return null;
  if (method === "ping") return mcpResult(id, {});
  if (method === "tools/list") return mcpResult(id, { tools: TOOLS });
  if (method === "tools/call") {
    try {
      const out = await runTool(body.params?.name, body.params?.arguments || {});
      return mcpResult(id, { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] });
    } catch (e) {
      return mcpResult(id, { content: [{ type: "text", text: String(e.message || e) }], isError: true });
    }
  }
  return mcpError(id, -32601, "Method not found: " + method);
}

function authorizePage(q) {
  const esc = (s) => String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");
  return "<!doctype html><html lang=es><head><meta charset=utf-8><title>Autorizar BMC Calc</title><style>body{font-family:system-ui;background:#0f172a;color:#e2e8f0;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}.c{background:#1e293b;padding:28px;border-radius:16px;max-width:420px;width:92%}button{background:#2563eb;color:#fff;border:0;padding:12px 16px;border-radius:10px;font-weight:600;width:100%;cursor:pointer}</style></head><body><div class=c><h1>BMC Calculadora</h1><p>Grok pide acceso de solo lectura al cotizador BMC.</p><form method=POST><input type=hidden name=response_type value=\"" + esc(q.response_type) + "\"><input type=hidden name=client_id value=\"" + esc(q.client_id) + "\"><input type=hidden name=redirect_uri value=\"" + esc(q.redirect_uri) + "\"><input type=hidden name=state value=\"" + esc(q.state) + "\"><input type=hidden name=scope value=\"" + esc(q.scope) + "\"><input type=hidden name=code_challenge value=\"" + esc(q.code_challenge) + "\"><input type=hidden name=code_challenge_method value=\"" + esc(q.code_challenge_method) + "\"><button type=submit>Autorizar</button></form></div></body></html>";
}

module.exports = async (req, res) => {
  const base = origin(req);
  const url = new URL(req.url, base);
  const path = url.pathname.replace(/\/$/, "") || "/";

  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,Mcp-Session-Id,MCP-Protocol-Version");
    return res.end();
  }

  if (path === "/.well-known/oauth-authorization-server") return json(res, 200, asMetadata(base));
  if (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-protected-resource/mcp") {
    return json(res, 200, prMetadata(base));
  }
  if (path === "/" || path === "/health") {
    return json(res, 200, { ok: true, name: "bmc-calc-grok-mcp", mcp: base + "/mcp", authorize: base + "/oauth/authorize", token: base + "/oauth/token", client_id: CLIENT_ID });
  }
  if (path === "/oauth/register" && req.method === "POST") {
    const body = await readBody(req);
    return json(res, 201, {
      client_id: CLIENT_ID,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: body.redirect_uris || [],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      client_name: body.client_name || "Grok",
    });
  }
  if (path === "/oauth/authorize") {
    const src = req.method === "POST" ? await readBody(req) : Object.fromEntries(url.searchParams);
    const redirect = src.redirect_uri;
    const challenge = src.code_challenge;
    const method = (src.code_challenge_method || "S256").toUpperCase();
    if (src.client_id !== CLIENT_ID && src.client_id !== "bmc-calc") return json(res, 400, { error: "invalid_client" });
    if (!allowedRedirect(redirect)) return json(res, 400, { error: "invalid_request", error_description: "redirect_uri not allowed" });
    if (src.response_type !== "code") return json(res, 400, { error: "unsupported_response_type" });
    if (!challenge || method !== "S256") return json(res, 400, { error: "invalid_request", error_description: "S256 PKCE required" });
    if (req.method === "GET") return html(res, 200, authorizePage(src));
    const code = sign({ typ: "code", cid: CLIENT_ID, redir: redirect, ch: challenge, method, scope: src.scope || "mcp:tools", exp: Math.floor(Date.now() / 1000) + CODE_TTL, nonce: crypto.randomBytes(8).toString("hex") });
    const loc = new URL(redirect);
    loc.searchParams.set("code", code);
    if (src.state) loc.searchParams.set("state", src.state);
    res.statusCode = 302;
    res.setHeader("Location", loc.toString());
    return res.end();
  }
  if (path === "/oauth/token" && req.method === "POST") {
    const body = await readBody(req);
    const now = Math.floor(Date.now() / 1000);
    if (body.grant_type === "refresh_token") {
      const rt = unsign(body.refresh_token);
      if (!rt || rt.typ !== "refresh") return json(res, 400, { error: "invalid_grant" });
      return json(res, 200, { token_type: "Bearer", access_token: sign({ typ: "access", cid: CLIENT_ID, scope: rt.scope, exp: now + ACCESS_TTL }), expires_in: ACCESS_TTL, refresh_token: sign({ typ: "refresh", cid: CLIENT_ID, scope: rt.scope, exp: now + REFRESH_TTL }), scope: rt.scope || "mcp:tools" });
    }
    if (body.grant_type !== "authorization_code") return json(res, 400, { error: "unsupported_grant_type" });
    const code = unsign(body.code);
    if (!code || code.typ !== "code") return json(res, 400, { error: "invalid_grant" });
    if (body.redirect_uri && body.redirect_uri !== code.redir) return json(res, 400, { error: "invalid_grant", error_description: "redirect_uri mismatch" });
    if (!body.code_verifier || s256(body.code_verifier) !== code.ch) return json(res, 400, { error: "invalid_grant", error_description: "pkce failed" });
    return json(res, 200, { token_type: "Bearer", access_token: sign({ typ: "access", cid: CLIENT_ID, scope: code.scope, exp: now + ACCESS_TTL }), expires_in: ACCESS_TTL, refresh_token: sign({ typ: "refresh", cid: CLIENT_ID, scope: code.scope, exp: now + REFRESH_TTL }), scope: code.scope || "mcp:tools" });
  }
  if (path === "/mcp") {
    if (req.method === "GET") {
      if (!requireAccess(req, res)) return;
      return json(res, 200, { ok: true, transport: "streamable-http-json" });
    }
    if (req.method !== "POST") return json(res, 405, { error: "method_not_allowed" });
    if (!requireAccess(req, res)) return;
    const body = await readBody(req);
    const out = await handleMcp(req, body);
    if (out == null) { res.statusCode = 204; return res.end(); }
    return json(res, 200, out);
  }
  return json(res, 404, { error: "not_found", path });
};
