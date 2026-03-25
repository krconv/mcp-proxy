#!/usr/bin/env node
/**
 * MCP Proxy — aggregates multiple upstream MCP servers into one endpoint.
 *
 * Upstream servers and their headers are configured via the HA add-on UI
 * and passed in as the UPSTREAMS_JSON environment variable.
 *
 * On first start an API key is generated at /data/api_key and logged once.
 * Add it to your MCP client as: Authorization: Bearer <key>
 *
 * All tools are prefixed with the upstream name:
 *   copilot__get_accounts, simplifi__list_transactions, etc.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  type Tool,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import express, { type Request, type Response, type NextFunction } from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import {
  discoverAuthServer,
  resolveClientCredentials,
  buildAuthorizationUrl,
  exchangeCodeForTokens,
  saveTokens,
  loadTokens,
  deleteTokens,
  connectOAuthUpstream,
  type OAuthUpstreamAuth,
  type AuthServerMetadata,
  type ClientCredentials,
  type StoredTokens,
} from "./upstream-auth.js";

// ── Types ─────────────────────────────────────────────────────────────────────

interface RawHeader {
  name: string;
  value: string;
}

interface RawAuthConfig {
  type?: string;
  client_id?: string;
  client_secret?: string;
  scopes?: string;
}

// Shape coming from HA config (headers as {name,value} list)
interface RawUpstreamConfig {
  name: string;
  url: string;
  headers?: RawHeader[];
  auth?: RawAuthConfig;
}

// Normalised internal shape (headers as Record)
interface UpstreamConfig {
  name: string;
  url: string;
  headers: Record<string, string>;
  auth?: OAuthUpstreamAuth;
}

interface ConnectedUpstream {
  config: UpstreamConfig;
  client: Client;
  tools: Tool[];
}

type UpstreamStatus = "connected" | "needs_auth" | "error" | "refreshing";

interface UpstreamState {
  config: UpstreamConfig;
  status: UpstreamStatus;
  error?: string;
  toolCount: number;
}

interface AuthCode {
  challenge: string;
  redirectUri: string;
  expiresAt: number;
}

// In-flight PKCE state for OAuth authorize flows (keyed by state param)
interface PendingOAuthFlow {
  upstreamName: string;
  codeVerifier: string;
  asMetadata: AuthServerMetadata;
  clientCreds: ClientCredentials;
  redirectUri: string;
  resource: string;
  expiresAt: number;
}

// ── Auth code store (authorization code + PKCE flow) ──────────────────────────

const authCodes = new Map<string, AuthCode>();

function pruneAuthCodes(): void {
  const now = Date.now();
  for (const [code, data] of authCodes) {
    if (data.expiresAt < now) authCodes.delete(code);
  }
}

function verifyS256(verifier: string, challenge: string): boolean {
  const hash = crypto.createHash("sha256").update(verifier).digest("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  return hash === challenge;
}

function escHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ── Constants ─────────────────────────────────────────────────────────────────

const DATA_DIR = process.env.DATA_DIR ?? "/data";
const PORT = parseInt(process.env.PORT ?? "9000", 10);
const API_KEY_FILE = path.join(DATA_DIR, "api_key");
const EXTERNAL_URL = process.env.EXTERNAL_URL || "";
const OAUTH_CALLBACK_URI = "http://localhost:19983/callback";

// ── Shared state ──────────────────────────────────────────────────────────────

const upstreamStates = new Map<string, UpstreamState>();
const pendingOAuthFlows = new Map<string, PendingOAuthFlow>();

// Reference to connected upstreams (set in main, used by routes)
let connectedUpstreams: Map<string, ConnectedUpstream>;
let allConfigs: UpstreamConfig[];

// ── API key management ────────────────────────────────────────────────────────

function loadOrCreateApiKey(): string {
  fs.mkdirSync(DATA_DIR, { recursive: true });

  if (fs.existsSync(API_KEY_FILE)) {
    return fs.readFileSync(API_KEY_FILE, "utf8").trim();
  }

  const key = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(API_KEY_FILE, key, { mode: 0o600 });
  console.log("Generated new API key, saved to:", API_KEY_FILE);
  return key;
}

// ── Config management ─────────────────────────────────────────────────────────

function parseHeaders(headers?: RawHeader[]): Record<string, string> {
  if (!headers || headers.length === 0) return {};
  return Object.fromEntries(headers.map((h) => [h.name, h.value]));
}

function parseAuthConfig(raw?: RawAuthConfig): OAuthUpstreamAuth | undefined {
  if (!raw || raw.type !== "oauth") return undefined;
  return {
    type: "oauth",
    client_id: raw.client_id,
    client_secret: raw.client_secret,
    scopes: raw.scopes,
  };
}

function loadConfig(): UpstreamConfig[] {
  const raw = process.env.UPSTREAMS_JSON;
  if (!raw) {
    console.warn("UPSTREAMS_JSON is not set — no upstreams configured.");
    return [];
  }
  try {
    const parsed = JSON.parse(raw) as RawUpstreamConfig[];
    return parsed.map((u) => ({
      name: u.name,
      url: u.url,
      headers: parseHeaders(u.headers),
      auth: parseAuthConfig(u.auth),
    }));
  } catch (err) {
    console.error("Failed to parse UPSTREAMS_JSON:", err);
    return [];
  }
}

// ── Upstream connections ──────────────────────────────────────────────────────

async function connectUpstream(config: UpstreamConfig): Promise<ConnectedUpstream> {
  const client = new Client({ name: "mcp-proxy", version: "1.0.0" });

  const transport = new StreamableHTTPClientTransport(new URL(config.url), {
    requestInit: { headers: config.headers },
  });

  await client.connect(transport);

  const { tools } = await client.listTools();
  console.log(`[${config.name}] Connected — ${tools.length} tool(s) available`);

  return { config, client, tools };
}

async function connectAll(
  configs: UpstreamConfig[]
): Promise<Map<string, ConnectedUpstream>> {
  const upstreams = new Map<string, ConnectedUpstream>();

  for (const config of configs) {
    // Skip OAuth upstreams — they are connected separately after token retrieval
    if (config.auth?.type === "oauth") continue;

    try {
      const upstream = await connectUpstream(config);
      upstreams.set(config.name, upstream);
      upstreamStates.set(config.name, {
        config,
        status: "connected",
        toolCount: upstream.tools.length,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[${config.name}] Failed to connect to ${config.url}:`, msg);
      console.error(`[${config.name}] Tools from this upstream will not be available.`);
      upstreamStates.set(config.name, {
        config,
        status: "error",
        error: msg,
        toolCount: 0,
      });
    }
  }

  return upstreams;
}

async function connectOAuthUpstreams(
  configs: UpstreamConfig[],
  upstreams: Map<string, ConnectedUpstream>,
): Promise<void> {
  const oauthConfigs = configs.filter((c) => c.auth?.type === "oauth");

  for (const config of oauthConfigs) {
    try {
      const tokens = await loadTokens(config.name);
      if (!tokens) {
        console.log(`[${config.name}] OAuth upstream needs authorization`);
        upstreamStates.set(config.name, {
          config,
          status: "needs_auth",
          toolCount: 0,
        });
        continue;
      }

      const upstream = await connectOAuthUpstream(config, tokens);
      upstreams.set(config.name, upstream);
      upstreamStates.set(config.name, {
        config,
        status: "connected",
        toolCount: upstream.tools.length,
      });
      console.log(`[${config.name}] Connected via stored OAuth tokens`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[${config.name}] OAuth connect failed:`, msg);
      upstreamStates.set(config.name, {
        config,
        status: "needs_auth",
        error: msg,
        toolCount: 0,
      });
    }
  }
}

// ── MCP proxy server ──────────────────────────────────────────────────────────

function buildMcpServer(upstreams: Map<string, ConnectedUpstream>): Server {
  const server = new Server(
    { name: "mcp-proxy", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  // Aggregate tools from all upstreams, prefixed with upstream name
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const tools: Tool[] = [];
    for (const [name, upstream] of upstreams) {
      for (const tool of upstream.tools) {
        tools.push({
          ...tool,
          name: `${name}__${tool.name}`,
          description: `[${name}] ${tool.description ?? ""}`.trim(),
        });
      }
    }
    return { tools };
  });

  // Route tool calls to the correct upstream
  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
    const toolName = request.params.name;
    const sep = toolName.indexOf("__");

    if (sep === -1) {
      return {
        isError: true,
        content: [{
          type: "text",
          text: `Error: Tool "${toolName}" has no upstream prefix. Expected format: <upstream>__<tool>`,
        }],
      };
    }

    const upstreamName = toolName.slice(0, sep);
    const upstreamTool = toolName.slice(sep + 2);
    const upstream = upstreams.get(upstreamName);

    if (!upstream) {
      return {
        isError: true,
        content: [{
          type: "text",
          text: `Error: Unknown upstream "${upstreamName}". Available: ${[...upstreams.keys()].join(", ")}`,
        }],
      };
    }

    try {
      const result = await upstream.client.callTool({
        name: upstreamTool,
        arguments: request.params.arguments,
      });
      return result as CallToolResult;
    } catch (err) {
      return {
        isError: true,
        content: [{
          type: "text",
          text: `Error calling "${upstreamTool}" on "${upstreamName}": ${err instanceof Error ? err.message : String(err)}`,
        }],
      };
    }
  });

  return server;
}

// ── Dashboard HTML ────────────────────────────────────────────────────────────

function renderDashboard(baseUrl: string): string {
  const rows: string[] = [];

  for (const [name, state] of upstreamStates) {
    const isOAuth = state.config.auth?.type === "oauth";
    const statusClass = state.status === "connected" ? "ok"
      : state.status === "needs_auth" ? "warn"
      : state.status === "refreshing" ? "info"
      : "err";
    const statusLabel = state.status.replace("_", " ");

    let actions = "";
    const encodedName = encodeURIComponent(name);
    if (isOAuth && state.status === "needs_auth") {
      actions = `<a class="btn" href="${escHtml(baseUrl)}/upstream/${escHtml(encodedName)}/authorize" target="_blank">Authorize</a>
        <form method="POST" action="${escHtml(baseUrl)}/upstream/${escHtml(encodedName)}/complete" style="margin-top:6px">
          <input type="text" name="callback_url" placeholder="Paste callback URL here" style="width:100%;box-sizing:border-box;padding:6px 8px;font-size:.8rem;border:1px solid #ccc;border-radius:4px;margin-bottom:4px">
          <button class="btn" type="submit" style="font-size:.75rem;padding:4px 10px">Complete</button>
        </form>`;
    } else if (isOAuth && state.status === "connected") {
      actions = `<form method="POST" action="${escHtml(baseUrl)}/upstream/${escHtml(encodedName)}/disconnect" style="display:inline">
        <button class="btn btn-danger" type="submit">Disconnect</button>
      </form>`;
    }

    const toolInfo = state.status === "connected" ? `${state.toolCount} tool(s)` : "&mdash;";

    rows.push(`<tr>
      <td>${escHtml(name)}</td>
      <td><span class="badge ${statusClass}">${escHtml(statusLabel)}</span></td>
      <td>${toolInfo}</td>
      <td>${actions}</td>
    </tr>`);
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MCP Proxy — Dashboard</title>
  <style>
    body{font-family:system-ui,sans-serif;max-width:700px;margin:40px auto;padding:0 20px}
    h1{font-size:1.3rem;margin-bottom:.25rem}
    p.sub{font-size:.85rem;color:#666;margin-bottom:1.5rem}
    table{width:100%;border-collapse:collapse}
    th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #eee;font-size:.9rem}
    th{font-size:.75rem;text-transform:uppercase;color:#999;font-weight:600}
    .badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.75rem;font-weight:600}
    .ok{background:#d4edda;color:#155724}
    .warn{background:#fff3cd;color:#856404}
    .err{background:#f8d7da;color:#721c24}
    .info{background:#d1ecf1;color:#0c5460}
    .btn{display:inline-block;padding:6px 14px;font-size:.8rem;background:#111;color:#fff;border:none;border-radius:6px;cursor:pointer;text-decoration:none}
    .btn:hover{background:#333}
    .btn-danger{background:#c0392b}
    .btn-danger:hover{background:#e74c3c}
  </style>
</head>
<body>
  <h1>MCP Proxy Dashboard</h1>
  <p class="sub">Manage your upstream MCP server connections.</p>
  <table>
    <thead><tr><th>Upstream</th><th>Status</th><th>Tools</th><th>Actions</th></tr></thead>
    <tbody>${rows.join("")}</tbody>
  </table>
</body>
</html>`;
}

// ── HTTP server ───────────────────────────────────────────────────────────────

// Derive the externally-visible base URL from the incoming request.
// Respects X-Forwarded-Proto so reverse proxies (HA ingress, nginx, etc.) work correctly.
function getBaseUrl(req: Request): string {
  if (EXTERNAL_URL) return EXTERNAL_URL.replace(/\/$/, "");
  const proto = (req.headers["x-forwarded-proto"] as string | undefined)?.split(",")[0].trim() ?? "http";
  const host = req.headers["host"] ?? `localhost:${PORT}`;
  return `${proto}://${host}`;
}

function serverMetadata(base: string): object {
  return {
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    registration_endpoint: `${base}/register`,
    grant_types_supported: ["authorization_code"],
    response_types_supported: ["code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
  };
}

function startHttpServer(mcpServer: Server, apiKey: string): void {
  const app = express();

  // CORS — allow any origin (MCP clients may run on different ports/origins)
  app.use((_req: Request, res: Response, next: NextFunction): void => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.set("Access-Control-Expose-Headers", "WWW-Authenticate");
    next();
  });
  app.options("*", (_req: Request, res: Response): void => {
    res.sendStatus(204);
  });

  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));

  // OAuth 2.0 protected resource metadata (RFC 9728) — root variant
  app.get("/.well-known/oauth-protected-resource", (req: Request, res: Response): void => {
    const base = getBaseUrl(req);
    res.json({ resource: base, authorization_servers: [base], bearer_methods_supported: ["header"] });
  });

  // OAuth 2.0 protected resource metadata (RFC 9728) — path-qualified for /mcp
  app.get("/.well-known/oauth-protected-resource/mcp", (req: Request, res: Response): void => {
    const base = getBaseUrl(req);
    res.json({ resource: `${base}/mcp`, authorization_servers: [base], bearer_methods_supported: ["header"] });
  });

  // OAuth 2.0 authorization server metadata (RFC 8414)
  app.get("/.well-known/oauth-authorization-server", (req: Request, res: Response): void => {
    res.json(serverMetadata(getBaseUrl(req)));
  });

  // OpenID Connect discovery — used by claude.ai as a fallback
  app.get("/.well-known/openid-configuration", (req: Request, res: Response): void => {
    res.json(serverMetadata(getBaseUrl(req)));
  });

  // Client ID Metadata Document for upstream OAuth servers to discover us
  app.get("/oauth/client-metadata.json", (req: Request, res: Response): void => {
    const base = getBaseUrl(req);
    res.json({
      client_name: "MCP Proxy",
      client_uri: base,
      redirect_uris: [OAUTH_CALLBACK_URI],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    });
  });

  // Dynamic Client Registration (RFC 7591) — public, no auth needed
  app.post("/register", (req: Request, res: Response): void => {
    const body = req.body as Record<string, unknown>;
    const clientId = crypto.randomUUID();
    res.status(201).json({
      client_id: clientId,
      client_name: body.client_name ?? "MCP Client",
      redirect_uris: body.redirect_uris ?? [],
      grant_types: body.grant_types ?? ["authorization_code"],
      response_types: body.response_types ?? ["code"],
      token_endpoint_auth_method: "none",
    });
  });

  // Authorization endpoint — browser-based Authorization Code + PKCE flow (used by claude.ai)
  app.get("/authorize", (req: Request, res: Response): void => {
    const q = req.query as Record<string, string>;
    if (q.response_type !== "code") {
      res.status(400).json({ error: "unsupported_response_type" });
      return;
    }
    if (q.code_challenge_method && q.code_challenge_method !== "S256") {
      res.status(400).json({ error: "invalid_request", error_description: "Only S256 supported" });
      return;
    }
    const fields = ["response_type", "client_id", "redirect_uri", "code_challenge",
      "code_challenge_method", "state", "scope", "resource"];
    const hiddenInputs = fields
      .filter((f) => q[f] != null)
      .map((f) => `<input type="hidden" name="${escHtml(f)}" value="${escHtml(q[f])}">`)
      .join("\n    ");
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MCP Proxy — Authorize</title>
  <style>
    body{font-family:system-ui,sans-serif;max-width:380px;margin:80px auto;padding:0 20px}
    h1{font-size:1.2rem;margin-bottom:.5rem}
    p{font-size:.875rem;color:#555;margin-bottom:1.5rem}
    label{display:block;font-size:.8rem;font-weight:600;margin-bottom:4px}
    input[type=password]{width:100%;box-sizing:border-box;padding:8px 10px;font-size:1rem;border:1px solid #ccc;border-radius:6px}
    button{margin-top:14px;width:100%;padding:10px;font-size:1rem;background:#111;color:#fff;border:none;border-radius:6px;cursor:pointer}
    button:hover{background:#333}
    .hint{font-size:.75rem;color:#999;margin-top:20px}
  </style>
</head>
<body>
  <h1>Authorize MCP Proxy</h1>
  <p>Enter your API key to grant access to this MCP server.</p>
  <form method="POST" action="/authorize">
    ${hiddenInputs}
    <label for="api_key">API Key</label>
    <input type="password" id="api_key" name="api_key" autocomplete="current-password" autofocus>
    <button type="submit">Authorize</button>
  </form>
  <p class="hint">Find your API key in the MCP Proxy add-on logs in Home Assistant.</p>
</body>
</html>`);
  });

  app.post("/authorize", (req: Request, res: Response): void => {
    const body = req.body as Record<string, string>;
    const { redirect_uri, code_challenge, state, api_key } = body;

    if (!redirect_uri) {
      res.status(400).json({ error: "invalid_request", error_description: "redirect_uri required" });
      return;
    }

    let redirectUrl: URL;
    try {
      redirectUrl = new URL(redirect_uri);
    } catch {
      res.status(400).json({ error: "invalid_request", error_description: "invalid redirect_uri" });
      return;
    }

    if (api_key !== apiKey) {
      redirectUrl.searchParams.set("error", "access_denied");
      if (state) redirectUrl.searchParams.set("state", state);
      res.redirect(redirectUrl.toString());
      return;
    }

    pruneAuthCodes();
    const code = crypto.randomBytes(32).toString("hex");
    authCodes.set(code, {
      challenge: code_challenge,
      redirectUri: redirect_uri,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    redirectUrl.searchParams.set("code", code);
    if (state) redirectUrl.searchParams.set("state", state);
    res.redirect(redirectUrl.toString());
  });

  // Token endpoint — authorization_code + PKCE only
  app.post("/token", (req: Request, res: Response): void => {
    const body = req.body as Record<string, string>;

    if (body.grant_type !== "authorization_code") {
      res.status(400).json({ error: "unsupported_grant_type" });
      return;
    }

    const { code, code_verifier, redirect_uri } = body;
    const stored = authCodes.get(code);

    if (!stored || stored.expiresAt < Date.now()) {
      res.status(400).json({ error: "invalid_grant", error_description: "Code not found or expired" });
      return;
    }
    if (stored.redirectUri !== redirect_uri) {
      res.status(400).json({ error: "invalid_grant", error_description: "redirect_uri mismatch" });
      return;
    }
    if (!verifyS256(code_verifier, stored.challenge)) {
      res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
      return;
    }

    authCodes.delete(code);
    res.json({ access_token: apiKey, token_type: "bearer", expires_in: 3600 });
  });

  // ── Browser-accessible routes (cookie-gated with API key) ────────────────

  // Cookie-based auth for dashboard routes — validates API key, sets session cookie
  const COOKIE_NAME = "mcp_session";
  function sessionHash(): string {
    return crypto.createHmac("sha256", apiKey).update("mcp-proxy-session").digest("hex");
  }

  app.get("/login", (_req: Request, res: Response): void => {
    res.send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP Proxy — Login</title>
<style>body{font-family:system-ui,sans-serif;max-width:380px;margin:80px auto;padding:0 20px}
h1{font-size:1.2rem}label{display:block;font-size:.8rem;font-weight:600;margin-bottom:4px}
input[type=password]{width:100%;box-sizing:border-box;padding:8px 10px;font-size:1rem;border:1px solid #ccc;border-radius:6px}
button{margin-top:14px;width:100%;padding:10px;font-size:1rem;background:#111;color:#fff;border:none;border-radius:6px;cursor:pointer}
button:hover{background:#333}</style>
</head><body><h1>MCP Proxy Login</h1>
<form method="POST" action="/login">
  <label for="api_key">API Key</label>
  <input type="password" id="api_key" name="api_key" autocomplete="current-password" autofocus>
  <button type="submit">Login</button>
</form></body></html>`);
  });

  app.post("/login", (req: Request, res: Response): void => {
    const { api_key } = req.body as Record<string, string>;
    if (api_key !== apiKey) {
      res.redirect("/login");
      return;
    }
    res.setHeader("Set-Cookie", `${COOKIE_NAME}=${sessionHash()}; Path=/; HttpOnly; SameSite=Lax`);
    res.redirect("/dashboard");
  });

  // Guard all dashboard/management routes behind the session cookie
  app.use(["/dashboard", "/upstream"], (req: Request, res: Response, next: NextFunction): void => {
    const cookies = (req.headers.cookie || "").split(";").reduce((acc, c) => {
      const [k, ...v] = c.trim().split("=");
      if (k) acc[k] = v.join("=");
      return acc;
    }, {} as Record<string, string>);
    if (cookies[COOKIE_NAME] === sessionHash()) {
      next();
      return;
    }
    res.redirect("/login");
  });

  // Dashboard HTML page
  app.get("/dashboard", (req: Request, res: Response): void => {
    res.send(renderDashboard(getBaseUrl(req)));
  });

  // Complete OAuth flow — user pastes the callback URL from the failed redirect
  app.post("/upstream/:name/complete", async (req: Request, res: Response): Promise<void> => {
    const { name } = req.params;
    const { callback_url } = req.body as Record<string, string>;

    if (!callback_url) {
      res.status(400).send("Missing callback URL.");
      return;
    }

    let parsed: URL;
    try {
      parsed = new URL(callback_url);
    } catch {
      res.status(400).send("Invalid URL. Paste the full URL from the browser address bar.");
      return;
    }

    const error = parsed.searchParams.get("error");
    if (error) {
      const desc = parsed.searchParams.get("error_description") || "Unknown error";
      res.status(400).send(`<!DOCTYPE html>
<html><head><title>OAuth Error</title>
<style>body{font-family:system-ui,sans-serif;max-width:400px;margin:80px auto;padding:0 20px}h1{font-size:1.2rem;color:#c0392b}</style>
</head><body><h1>Authorization Failed</h1><p>${escHtml(error)}: ${escHtml(desc)}</p>
<a href="/dashboard">Back to Dashboard</a></body></html>`);
      return;
    }

    const code = parsed.searchParams.get("code");
    const state = parsed.searchParams.get("state");

    if (!code || !state) {
      res.status(400).send("URL is missing code or state parameters. Make sure you copied the full URL.");
      return;
    }

    const pending = pendingOAuthFlows.get(state);
    if (!pending) {
      res.status(400).send("Unknown or expired OAuth state. Please try authorizing again from the dashboard.");
      return;
    }

    if (pending.upstreamName !== name) {
      res.status(400).send("OAuth state does not match this upstream.");
      return;
    }

    if (pending.expiresAt < Date.now()) {
      pendingOAuthFlows.delete(state);
      res.status(400).send("OAuth flow expired. Please try authorizing again.");
      return;
    }

    pendingOAuthFlows.delete(state);

    try {
      const tokens = await exchangeCodeForTokens(
        code,
        pending.codeVerifier,
        pending.redirectUri,
        pending.asMetadata,
        pending.clientCreds,
        pending.resource,
      );

      saveTokens(name, tokens);

      const config = allConfigs.find((c) => c.name === name);
      if (config) {
        try {
          const upstream = await connectOAuthUpstream(config, tokens);
          connectedUpstreams.set(name, upstream);
          upstreamStates.set(name, {
            config,
            status: "connected",
            toolCount: upstream.tools.length,
          });
        } catch (connErr) {
          const msg = connErr instanceof Error ? connErr.message : String(connErr);
          upstreamStates.set(name, { config, status: "error", error: msg, toolCount: 0 });
        }
      }

      res.redirect("/dashboard");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[${name}] Token exchange failed:`, msg);
      res.status(500).send(`<!DOCTYPE html>
<html><head><title>Token Exchange Failed</title>
<style>body{font-family:system-ui,sans-serif;max-width:400px;margin:80px auto;padding:0 20px}h1{font-size:1.2rem;color:#c0392b}</style>
</head><body><h1>Token Exchange Failed</h1><p>${escHtml(msg)}</p>
<a href="/dashboard">Back to Dashboard</a></body></html>`);
    }
  });

  // Start OAuth flow for an upstream
  app.get("/upstream/:name/authorize", async (req: Request, res: Response): Promise<void> => {
    const { name } = req.params;
    const config = allConfigs.find((c) => c.name === name);

    if (!config) {
      res.status(404).json({ error: `Upstream "${name}" not found` });
      return;
    }
    if (config.auth?.type !== "oauth") {
      res.status(400).json({ error: `Upstream "${name}" does not use OAuth` });
      return;
    }

    try {
      const asMetadata = await discoverAuthServer(config.url);
      const redirectUri = OAUTH_CALLBACK_URI;
      const clientCreds = await resolveClientCredentials(
        name, config.auth, asMetadata, redirectUri,
      );

      const resource = config.url;

      const { url: authUrl, codeVerifier, state } = buildAuthorizationUrl({
        asMetadata,
        clientId: clientCreds.client_id,
        redirectUri,
        scopes: config.auth.scopes,
        resource,
      });

      // Store PKCE + state for the callback (keyed by state for CSRF safety)
      pendingOAuthFlows.set(state, {
        upstreamName: name,
        codeVerifier,
        asMetadata,
        clientCreds,
        redirectUri,
        resource,
        expiresAt: Date.now() + 10 * 60 * 1000,
      });

      res.redirect(authUrl);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[${name}] OAuth discovery/authorize failed:`, msg);
      res.status(500).json({ error: msg });
    }
  });

  // Disconnect an OAuth upstream
  app.post("/upstream/:name/disconnect", async (req: Request, res: Response): Promise<void> => {
    const { name } = req.params;
    const config = allConfigs.find((c) => c.name === name);

    if (!config) {
      res.status(404).json({ error: `Upstream "${name}" not found` });
      return;
    }

    // Close the MCP client if connected
    const existing = connectedUpstreams.get(name);
    if (existing) {
      try {
        await existing.client.close();
      } catch {
        // ignore close errors
      }
      connectedUpstreams.delete(name);
    }

    // Clear stored tokens
    deleteTokens(name);

    upstreamStates.set(name, {
      config,
      status: "needs_auth",
      toolCount: 0,
    });

    // Redirect back to dashboard if this was a form submission
    const accept = req.headers["accept"] || "";
    if (accept.includes("text/html")) {
      res.redirect("/dashboard");
    } else {
      res.json({ ok: true, status: "disconnected" });
    }
  });

  // ── Bearer token auth for API/MCP routes ────────────────────────────────

  app.use((req: Request, res: Response, next: NextFunction): void => {
    const auth = req.headers["authorization"];
    if (!auth || auth !== `Bearer ${apiKey}`) {
      const base = getBaseUrl(req);
      res.set(
        "WWW-Authenticate",
        `Bearer realm="${base}", resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"`
      );
      res.status(401).json({ error: "Unauthorized" });
      return;
    }
    next();
  });

  // ── Authenticated routes ──────────────────────────────────────────────────

  // JSON list of all upstreams with status
  app.get("/upstreams", (_req: Request, res: Response): void => {
    const result: Array<{
      name: string;
      url: string;
      status: UpstreamStatus;
      error?: string;
      toolCount: number;
      authType?: string;
    }> = [];

    for (const [name, state] of upstreamStates) {
      result.push({
        name,
        url: state.config.url,
        status: state.status,
        error: state.error,
        toolCount: state.toolCount,
        authType: state.config.auth?.type,
      });
    }

    res.json(result);
  });

  // Stateless MCP endpoint — new transport per request
  app.post("/mcp", async (req: Request, res: Response): Promise<void> => {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    res.on("close", () => transport.close());
    await mcpServer.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  app.listen(PORT, () => {
    console.log(`MCP proxy listening on http://localhost:${PORT}/mcp`);
    console.log(`OAuth authorize endpoint: http://localhost:${PORT}/authorize`);
    console.log(`Dashboard: http://localhost:${PORT}/dashboard`);
  });
}

// ── Entry point ───────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const apiKey = loadOrCreateApiKey();
  console.log("=".repeat(64));
  console.log("MCP client auth header:");
  console.log(`  Authorization: Bearer ${apiKey}`);
  console.log("=".repeat(64));

  allConfigs = loadConfig();

  // Connect static-header upstreams
  connectedUpstreams = await connectAll(allConfigs);

  // Connect OAuth upstreams that already have stored tokens
  await connectOAuthUpstreams(allConfigs, connectedUpstreams);

  if (connectedUpstreams.size === 0) {
    console.warn("No upstreams connected — proxy will serve an empty tool list.");
  }

  // Log which OAuth upstreams need authorization
  const baseUrl = EXTERNAL_URL || `http://localhost:${PORT}`;
  for (const [name, state] of upstreamStates) {
    if (state.status === "needs_auth") {
      console.log(`[${name}] Needs OAuth authorization: ${baseUrl}/upstream/${name}/authorize`);
    }
  }

  const mcpServer = buildMcpServer(connectedUpstreams);
  startHttpServer(mcpServer, apiKey);

  console.log(
    `Aggregating tools from: ${[...connectedUpstreams.keys()].join(", ") || "(none)"}`
  );
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
