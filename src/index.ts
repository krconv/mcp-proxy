#!/usr/bin/env node
/**
 * MCP Proxy — aggregates multiple upstream MCP servers into one endpoint.
 *
 * Upstream servers are configured via the UPSTREAMS_JSON environment variable.
 * Each upstream can use static headers or OAuth for authentication.
 *
 * On first start an API key is generated at $DATA_DIR/api_key.
 * MCP clients authenticate with: Authorization: Bearer <key>
 *
 * All tools are prefixed with the upstream name:
 *   linear__list_issues, github__search_repos, etc.
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
import crypto from "crypto";

import { DATA_DIR, PORT, EXTERNAL_URL, OAUTH_CALLBACK_URI, loadOrCreateApiKey, loadConfig, getBaseUrl } from "./config.js";
import {
  discoverAuthServer,
  resolveClientCredentials,
  buildAuthorizationUrl,
  exchangeCodeForTokens,
  saveTokens,
  loadTokens,
  deleteTokens,
  connectOAuthUpstream,
} from "./upstream-auth.js";
import { escHtml, renderDashboard, renderLogin, renderAuthorize, renderError } from "./templates.js";
import type {
  UpstreamConfig,
  ConnectedUpstream,
  UpstreamState,
  UpstreamStatus,
  AuthCode,
  PendingOAuthFlow,
} from "./types.js";

// ── Shared state ─────────────────────────────────────────────────────────────

const upstreamStates = new Map<string, UpstreamState>();
const pendingOAuthFlows = new Map<string, PendingOAuthFlow>();
const authCodes = new Map<string, AuthCode>();

let connectedUpstreams: Map<string, ConnectedUpstream>;
let allConfigs: UpstreamConfig[];

// ── Auth helpers ─────────────────────────────────────────────────────────────

function pruneExpired(): void {
  const now = Date.now();
  for (const [code, data] of authCodes) {
    if (data.expiresAt < now) authCodes.delete(code);
  }
  for (const [state, flow] of pendingOAuthFlows) {
    if (flow.expiresAt < now) pendingOAuthFlows.delete(state);
  }
}

function verifyS256(verifier: string, challenge: string): boolean {
  const hash = crypto.createHash("sha256").update(verifier).digest("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  return hash === challenge;
}

// ── Upstream connections ─────────────────────────────────────────────────────

async function connectUpstream(config: UpstreamConfig): Promise<ConnectedUpstream> {
  const client = new Client({ name: "mcp-proxy", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(config.url), {
    requestInit: { headers: config.headers },
  });
  await client.connect(transport);
  const { tools } = await client.listTools();
  console.log(`[${config.name}] Connected — ${tools.length} tool(s)`);
  return { config, client, tools };
}

async function connectAllUpstreams(configs: UpstreamConfig[]): Promise<Map<string, ConnectedUpstream>> {
  const upstreams = new Map<string, ConnectedUpstream>();

  for (const config of configs) {
    if (config.auth?.type === "oauth") continue; // handled separately

    try {
      const upstream = await connectUpstream(config);
      upstreams.set(config.name, upstream);
      upstreamStates.set(config.name, { config, status: "connected", toolCount: upstream.tools.length });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[${config.name}] Connection failed: ${msg}`);
      upstreamStates.set(config.name, { config, status: "error", error: msg, toolCount: 0 });
    }
  }

  return upstreams;
}

async function connectOAuthUpstreams(
  configs: UpstreamConfig[],
  upstreams: Map<string, ConnectedUpstream>,
): Promise<void> {
  for (const config of configs.filter((c) => c.auth?.type === "oauth")) {
    try {
      const tokens = await loadTokens(config.name);
      if (!tokens) {
        console.log(`[${config.name}] Needs OAuth authorization`);
        upstreamStates.set(config.name, { config, status: "needs_auth", toolCount: 0 });
        continue;
      }

      const upstream = await connectOAuthUpstream(config, tokens);
      upstreams.set(config.name, upstream);
      upstreamStates.set(config.name, { config, status: "connected", toolCount: upstream.tools.length });
      console.log(`[${config.name}] Connected via stored OAuth tokens`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[${config.name}] OAuth connect failed: ${msg}`);
      upstreamStates.set(config.name, { config, status: "needs_auth", error: msg, toolCount: 0 });
    }
  }
}

// ── MCP proxy server ─────────────────────────────────────────────────────────

function buildMcpServer(upstreams: Map<string, ConnectedUpstream>): Server {
  const server = new Server(
    { name: "mcp-proxy", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );

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

  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
    const toolName = request.params.name;
    const sep = toolName.indexOf("__");

    if (sep === -1) {
      return { isError: true, content: [{ type: "text", text: `Unknown tool "${toolName}". Expected format: <upstream>__<tool>` }] };
    }

    const upstreamName = toolName.slice(0, sep);
    const upstreamTool = toolName.slice(sep + 2);
    const upstream = upstreams.get(upstreamName);

    if (!upstream) {
      return { isError: true, content: [{ type: "text", text: `Unknown upstream "${upstreamName}". Available: ${[...upstreams.keys()].join(", ")}` }] };
    }

    try {
      return await upstream.client.callTool({ name: upstreamTool, arguments: request.params.arguments }) as CallToolResult;
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: `Error calling ${upstreamName}/${upstreamTool}: ${err instanceof Error ? err.message : String(err)}` }] };
    }
  });

  return server;
}

// ── HTTP server ──────────────────────────────────────────────────────────────

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

  // CORS — only on MCP/discovery/OAuth endpoints (not dashboard/upstream management)
  const corsRoutes = ["/mcp", "/.well-known", "/oauth", "/register", "/authorize", "/token"];
  app.use(corsRoutes, (_req: Request, res: Response, next: NextFunction): void => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.set("Access-Control-Expose-Headers", "WWW-Authenticate");
    next();
  });
  app.options(corsRoutes, (_req: Request, res: Response): void => { res.sendStatus(204); });

  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));

  // ── Public: OAuth/MCP discovery ──────────────────────────────────────────

  app.get("/.well-known/oauth-protected-resource", (req: Request, res: Response): void => {
    const base = getBaseUrl(req);
    res.json({ resource: base, authorization_servers: [base], bearer_methods_supported: ["header"] });
  });

  app.get("/.well-known/oauth-protected-resource/mcp", (req: Request, res: Response): void => {
    const base = getBaseUrl(req);
    res.json({ resource: `${base}/mcp`, authorization_servers: [base], bearer_methods_supported: ["header"] });
  });

  app.get("/.well-known/oauth-authorization-server", (req: Request, res: Response): void => {
    res.json(serverMetadata(getBaseUrl(req)));
  });

  app.get("/.well-known/openid-configuration", (req: Request, res: Response): void => {
    res.json(serverMetadata(getBaseUrl(req)));
  });

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

  // ── Public: Dynamic Client Registration (RFC 7591) ───────────────────────

  app.post("/register", (req: Request, res: Response): void => {
    const body = req.body as Record<string, unknown>;
    res.status(201).json({
      client_id: crypto.randomUUID(),
      client_name: body.client_name ?? "MCP Client",
      redirect_uris: body.redirect_uris ?? [],
      grant_types: body.grant_types ?? ["authorization_code"],
      response_types: body.response_types ?? ["code"],
      token_endpoint_auth_method: "none",
    });
  });

  // ── Public: Proxy's own OAuth endpoints (for MCP client auth) ────────────

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
    res.send(renderAuthorize(hiddenInputs));
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

    pruneExpired();
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

  // ── Cookie-gated: Dashboard & upstream management ────────────────────────

  const COOKIE_NAME = "mcp_session";
  const sessionHash = (): string =>
    crypto.createHmac("sha256", apiKey).update("mcp-proxy-session").digest("hex");

  app.get("/login", (_req: Request, res: Response): void => {
    res.send(renderLogin());
  });

  app.post("/login", (req: Request, res: Response): void => {
    const { api_key } = req.body as Record<string, string>;
    if (api_key !== apiKey) {
      res.redirect("/login");
      return;
    }
    const secure = EXTERNAL_URL.startsWith("https") ? "; Secure" : "";
    res.setHeader("Set-Cookie", `${COOKIE_NAME}=${sessionHash()}; Path=/; HttpOnly; SameSite=Lax${secure}`);
    res.redirect("/dashboard");
  });

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

  app.get("/dashboard", (req: Request, res: Response): void => {
    res.send(renderDashboard(getBaseUrl(req), upstreamStates));
  });

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
      res.status(400).send(renderError("Authorization Failed", `${error}: ${desc}`));
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
        code, pending.codeVerifier, pending.redirectUri,
        pending.asMetadata, pending.clientCreds, pending.resource,
      );
      saveTokens(name, tokens);

      const config = allConfigs.find((c) => c.name === name);
      if (config) {
        try {
          const upstream = await connectOAuthUpstream(config, tokens);
          connectedUpstreams.set(name, upstream);
          upstreamStates.set(name, { config, status: "connected", toolCount: upstream.tools.length });
        } catch (connErr) {
          const msg = connErr instanceof Error ? connErr.message : String(connErr);
          upstreamStates.set(name, { config, status: "error", error: msg, toolCount: 0 });
        }
      }
      res.redirect("/dashboard");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[${name}] Token exchange failed: ${msg}`);
      res.status(500).send(renderError("Token Exchange Failed", msg));
    }
  });

  app.get("/upstream/:name/authorize", async (req: Request, res: Response): Promise<void> => {
    const { name } = req.params;
    const config = allConfigs.find((c) => c.name === name);

    if (!config) { res.status(404).json({ error: `Upstream "${name}" not found` }); return; }
    if (config.auth?.type !== "oauth") { res.status(400).json({ error: `Upstream "${name}" does not use OAuth` }); return; }

    try {
      const asMetadata = await discoverAuthServer(config.url);
      const redirectUri = OAUTH_CALLBACK_URI;
      const clientCreds = await resolveClientCredentials(name, config.auth, asMetadata, redirectUri);
      const { url: authUrl, codeVerifier, state } = buildAuthorizationUrl({
        asMetadata, clientId: clientCreds.client_id, redirectUri,
        scopes: config.auth.scopes, resource: config.url,
      });

      pruneExpired();
      pendingOAuthFlows.set(state, {
        upstreamName: name, codeVerifier, asMetadata, clientCreds,
        redirectUri, resource: config.url, expiresAt: Date.now() + 10 * 60 * 1000,
      });

      res.redirect(authUrl);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[${name}] OAuth discovery failed: ${msg}`);
      res.status(500).json({ error: msg });
    }
  });

  app.post("/upstream/:name/disconnect", async (req: Request, res: Response): Promise<void> => {
    const { name } = req.params;
    const config = allConfigs.find((c) => c.name === name);
    if (!config) { res.status(404).json({ error: `Upstream "${name}" not found` }); return; }

    const existing = connectedUpstreams.get(name);
    if (existing) {
      try { await existing.client.close(); } catch { /* ignore */ }
      connectedUpstreams.delete(name);
    }

    deleteTokens(name);
    upstreamStates.set(name, { config, status: "needs_auth", toolCount: 0 });

    const accept = req.headers["accept"] || "";
    if (accept.includes("text/html")) {
      res.redirect("/dashboard");
    } else {
      res.json({ ok: true, status: "disconnected" });
    }
  });

  // ── Bearer-gated: MCP endpoint & API ─────────────────────────────────────

  app.use((req: Request, res: Response, next: NextFunction): void => {
    const auth = req.headers["authorization"];
    if (!auth || auth !== `Bearer ${apiKey}`) {
      const base = getBaseUrl(req);
      res.set("WWW-Authenticate", `Bearer realm="${base}", resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"`);
      res.status(401).json({ error: "Unauthorized" });
      return;
    }
    next();
  });

  app.get("/upstreams", (_req: Request, res: Response): void => {
    const result: Array<{ name: string; url: string; status: UpstreamStatus; error?: string; toolCount: number; authType?: string }> = [];
    for (const [name, state] of upstreamStates) {
      result.push({ name, url: state.config.url, status: state.status, error: state.error, toolCount: state.toolCount, authType: state.config.auth?.type });
    }
    res.json(result);
  });

  app.post("/mcp", async (req: Request, res: Response): Promise<void> => {
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on("close", () => transport.close());
    await mcpServer.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  app.listen(PORT, () => {
    console.log(`[proxy] Listening on http://localhost:${PORT}/mcp`);
    console.log(`[proxy] Dashboard: http://localhost:${PORT}/dashboard`);
  });
}

// ── Entry point ──────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const apiKey = loadOrCreateApiKey();
  console.log(`[proxy] API key: ${apiKey.slice(0, 8)}...(see ${DATA_DIR}/api_key)`);

  allConfigs = loadConfig();
  connectedUpstreams = await connectAllUpstreams(allConfigs);
  await connectOAuthUpstreams(allConfigs, connectedUpstreams);

  for (const [name, state] of upstreamStates) {
    if (state.status === "needs_auth") {
      const base = EXTERNAL_URL || `http://localhost:${PORT}`;
      console.log(`[${name}] Authorize at: ${base}/dashboard`);
    }
  }

  const mcpServer = buildMcpServer(connectedUpstreams);
  startHttpServer(mcpServer, apiKey);

  const connected = [...connectedUpstreams.keys()];
  console.log(`[proxy] Aggregating tools from: ${connected.join(", ") || "(none)"}`);
}

main().catch((err) => {
  console.error("[proxy] Fatal:", err);
  process.exit(1);
});
