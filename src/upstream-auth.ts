/**
 * Upstream OAuth Authentication
 *
 * Provides OAuth client functionality for connecting to upstream MCP servers
 * that require OAuth authorization. Uses the MCP SDK's built-in discovery
 * and registration helpers, with file-backed persistence for tokens and
 * client registrations.
 *
 * The proxy acts as an OAuth client to each upstream's authorization server.
 * Flow: discover AS metadata -> register client (if needed) -> redirect user
 * to authorize -> exchange code for tokens -> connect with Bearer token.
 */

import {
  discoverOAuthProtectedResourceMetadata,
  discoverAuthorizationServerMetadata,
  exchangeAuthorization,
  refreshAuthorization,
  registerClient,
} from "@modelcontextprotocol/sdk/client/auth.js";
import type {
  OAuthClientInformationFull,
  OAuthClientInformationMixed,
  OAuthTokens,
  OAuthClientMetadata,
  OAuthProtectedResourceMetadata,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import fs from "fs";
import path from "path";
import crypto from "crypto";

// ── Types ─────────────────────────────────────────────────────────────────────

/** Auth configuration for an upstream that uses OAuth. */
export interface OAuthUpstreamAuth {
  type: "oauth";
  client_id?: string;
  client_secret?: string;
  scopes?: string;
}

/** Token set returned from token exchange / stored on disk. */
export interface StoredTokens {
  access_token: string;
  token_type: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
}

/** Authorization server metadata returned from discovery. */
export interface AuthServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  registration_endpoint?: string;
  scopes_supported?: string[];
  code_challenge_methods_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
}

/** Client credentials returned from resolveClientCredentials. */
export interface ClientCredentials {
  client_id: string;
  client_secret?: string;
}

/** Upstream config shape used by this module. */
export interface UpstreamConfigForOAuth {
  name: string;
  url: string;
  headers: Record<string, string>;
  auth?: OAuthUpstreamAuth;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const DATA_DIR = process.env.DATA_DIR ?? "/data";
const TOKENS_DIR = path.join(DATA_DIR, "tokens");
const REGISTRATIONS_DIR = path.join(DATA_DIR, "registrations");

// ── Internal helpers ──────────────────────────────────────────────────────────

function ensureDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true });
}

function safeName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_-]/g, "_");
}

/**
 * Build a minimal AS metadata object suitable for the SDK helpers.
 * The SDK types use URL objects for endpoints; our AuthServerMetadata
 * uses plain strings.
 */
function buildSdkMetadata(meta: AuthServerMetadata): unknown {
  return {
    issuer: meta.issuer,
    authorization_endpoint: new URL(meta.authorization_endpoint),
    token_endpoint: new URL(meta.token_endpoint),
    response_types_supported: ["code"],
    ...(meta.registration_endpoint
      ? { registration_endpoint: new URL(meta.registration_endpoint) }
      : {}),
    ...(meta.token_endpoint_auth_methods_supported
      ? { token_endpoint_auth_methods_supported: meta.token_endpoint_auth_methods_supported }
      : {}),
  };
}

function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString("base64url");
}

function generateCodeChallenge(verifier: string): string {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

function generateState(): string {
  return crypto.randomBytes(16).toString("hex");
}

function oauthTokensToStoredTokens(tokens: OAuthTokens): StoredTokens {
  return {
    access_token: tokens.access_token,
    token_type: tokens.token_type,
    refresh_token: tokens.refresh_token,
    expires_in: tokens.expires_in,
    scope: tokens.scope,
  };
}

// ── Token storage ─────────────────────────────────────────────────────────────

/** Load stored tokens for an upstream, or return null if none exist. */
export function loadTokens(upstreamName: string): StoredTokens | null {
  const file = path.join(TOKENS_DIR, `${safeName(upstreamName)}.json`);
  try {
    return JSON.parse(fs.readFileSync(file, "utf8")) as StoredTokens;
  } catch {
    return null;
  }
}

/** Persist tokens for an upstream. */
export function saveTokens(upstreamName: string, tokens: StoredTokens): void {
  ensureDir(TOKENS_DIR);
  const file = path.join(TOKENS_DIR, `${safeName(upstreamName)}.json`);
  fs.writeFileSync(file, JSON.stringify(tokens, null, 2), { mode: 0o600 });
}

/** Remove stored tokens for an upstream. */
export function deleteTokens(upstreamName: string): void {
  const file = path.join(TOKENS_DIR, `${safeName(upstreamName)}.json`);
  try {
    fs.unlinkSync(file);
  } catch {
    // Already gone
  }
}

// ── Client registration storage ───────────────────────────────────────────────

/** Load stored client registration for an upstream. */
export function loadRegistration(
  upstreamName: string
): OAuthClientInformationMixed | null {
  const file = path.join(REGISTRATIONS_DIR, `${safeName(upstreamName)}.json`);
  try {
    return JSON.parse(fs.readFileSync(file, "utf8")) as OAuthClientInformationMixed;
  } catch {
    return null;
  }
}

/** Persist client registration for an upstream. */
export function saveRegistration(
  upstreamName: string,
  reg: OAuthClientInformationMixed
): void {
  ensureDir(REGISTRATIONS_DIR);
  const file = path.join(REGISTRATIONS_DIR, `${safeName(upstreamName)}.json`);
  fs.writeFileSync(file, JSON.stringify(reg, null, 2), { mode: 0o600 });
}

// ── OAuth metadata discovery ──────────────────────────────────────────────────

/**
 * Discover the authorization server for an upstream MCP server.
 *
 * 1. Fetches Protected Resource Metadata (RFC 9728) from the upstream to find
 *    the authorization server URL.
 * 2. Fetches Authorization Server Metadata (RFC 8414, with OIDC fallback) from
 *    that URL.
 *
 * @param upstreamUrl - The upstream MCP server URL
 * @returns Authorization server metadata with endpoints
 */
export async function discoverAuthServer(
  upstreamUrl: string
): Promise<AuthServerMetadata> {
  let resourceMetadata: OAuthProtectedResourceMetadata | undefined;
  let authorizationServerUrl: string;

  try {
    resourceMetadata = await discoverOAuthProtectedResourceMetadata(upstreamUrl);
  } catch {
    // Resource metadata not available — fall back to treating upstream as AS
  }

  if (resourceMetadata?.authorization_servers?.length) {
    authorizationServerUrl = resourceMetadata.authorization_servers[0].toString();
  } else {
    authorizationServerUrl = upstreamUrl;
  }

  const asMeta = await discoverAuthorizationServerMetadata(authorizationServerUrl);

  if (!asMeta) {
    throw new Error(
      `Failed to discover authorization server metadata at ${authorizationServerUrl}`
    );
  }

  return {
    issuer: asMeta.issuer,
    authorization_endpoint: asMeta.authorization_endpoint.toString(),
    token_endpoint: asMeta.token_endpoint.toString(),
    registration_endpoint: asMeta.registration_endpoint?.toString(),
    scopes_supported: asMeta.scopes_supported,
    code_challenge_methods_supported: asMeta.code_challenge_methods_supported,
    token_endpoint_auth_methods_supported: asMeta.token_endpoint_auth_methods_supported,
  };
}

// ── Client registration ───────────────────────────────────────────────────────

/**
 * Resolve client credentials for an upstream, trying in priority order:
 * 1. Pre-registered client_id/secret from config
 * 2. Previously stored dynamic registration
 * 3. Dynamic Client Registration (RFC 7591)
 *
 * @param upstreamName - Name of the upstream
 * @param auth - OAuth auth config from the upstream definition
 * @param serverMeta - Authorization server metadata (needed for dynamic registration)
 * @param redirectUri - Redirect URI (needed for dynamic registration)
 * @returns Client credentials with client_id and optional client_secret
 */
export async function resolveClientCredentials(
  upstreamName: string,
  auth: OAuthUpstreamAuth,
  serverMeta?: AuthServerMetadata,
  redirectUri?: string
): Promise<ClientCredentials> {
  // 1. Pre-registered credentials from config
  if (auth.client_id) {
    return {
      client_id: auth.client_id,
      client_secret: auth.client_secret,
    };
  }

  // 2. Previously stored dynamic registration
  const stored = loadRegistration(upstreamName);
  if (stored) {
    // Check if the client secret has expired (RFC 7591 client_secret_expires_at)
    const full = stored as OAuthClientInformationFull;
    if (
      full.client_secret_expires_at &&
      full.client_secret_expires_at > 0 &&
      full.client_secret_expires_at < Math.floor(Date.now() / 1000)
    ) {
      console.log(
        `[${upstreamName}] Stored client registration has expired, will re-register`
      );
      // Fall through to dynamic registration
    } else {
      return {
        client_id: stored.client_id,
        client_secret: stored.client_secret,
      };
    }
  }

  // 3. Dynamic Client Registration (RFC 7591)
  if (!serverMeta?.registration_endpoint) {
    throw new Error(
      `[${upstreamName}] No client_id configured and server does not support dynamic registration`
    );
  }

  if (!redirectUri) {
    throw new Error(
      `[${upstreamName}] redirectUri is required for dynamic client registration`
    );
  }

  const clientMetadata: OAuthClientMetadata = {
    redirect_uris: [redirectUri],
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    client_name: `MCP Proxy (${upstreamName})`,
    ...(auth.scopes ? { scope: auth.scopes } : {}),
  };

  const sdkMeta = buildSdkMetadata(serverMeta);

  const registered: OAuthClientInformationFull = await registerClient(
    serverMeta.issuer,
    {
      metadata: sdkMeta as Parameters<typeof registerClient>[1]["metadata"],
      clientMetadata,
    }
  );

  saveRegistration(upstreamName, registered);

  console.log(
    `[${upstreamName}] Dynamically registered OAuth client: ${registered.client_id}`
  );

  return {
    client_id: registered.client_id,
    client_secret: registered.client_secret,
  };
}

// ── Authorization flow helpers ────────────────────────────────────────────────

/**
 * Build the authorization URL for an upstream OAuth flow.
 *
 * Generates PKCE (code_verifier + code_challenge) and state internally,
 * constructs the full authorization URL, and returns all values needed
 * by the caller to store and complete the flow later.
 *
 * @returns The authorization URL string, code verifier, and state
 */
export function buildAuthorizationUrl(params: {
  asMetadata: AuthServerMetadata;
  clientId: string;
  redirectUri: string;
  scopes?: string;
  resource?: string;
}): { url: string; codeVerifier: string; state: string } {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = generateState();

  const url = new URL(params.asMetadata.authorization_endpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", params.clientId);
  url.searchParams.set("redirect_uri", params.redirectUri);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", state);

  if (params.scopes) {
    url.searchParams.set("scope", params.scopes);
  }
  if (params.resource) {
    url.searchParams.set("resource", params.resource);
  }

  return { url: url.toString(), codeVerifier, state };
}

/**
 * Exchange an authorization code for tokens.
 *
 * Uses the MCP SDK's exchangeAuthorization helper, which handles client
 * authentication method selection automatically.
 *
 * @param code - The authorization code received from the callback
 * @param codeVerifier - The PKCE code verifier from the original request
 * @param redirectUri - The redirect URI used in the authorization request
 * @param asMetadata - Authorization server metadata from discoverAuthServer
 * @param clientCreds - Client credentials from resolveClientCredentials
 * @param resource - Optional resource parameter (RFC 8707)
 */
export async function exchangeCodeForTokens(
  code: string,
  codeVerifier: string,
  redirectUri: string,
  asMetadata: AuthServerMetadata,
  clientCreds: ClientCredentials,
  resource?: string
): Promise<StoredTokens> {
  const clientInformation: OAuthClientInformationMixed = {
    client_id: clientCreds.client_id,
    ...(clientCreds.client_secret
      ? { client_secret: clientCreds.client_secret }
      : {}),
  };

  const sdkMeta = buildSdkMetadata(asMetadata);

  const oauthTokens: OAuthTokens = await exchangeAuthorization(
    asMetadata.issuer,
    {
      metadata: sdkMeta as Parameters<typeof exchangeAuthorization>[1]["metadata"],
      clientInformation,
      authorizationCode: code,
      codeVerifier,
      redirectUri,
      ...(resource ? { resource: new URL(resource) } : {}),
    }
  );

  return oauthTokensToStoredTokens(oauthTokens);
}

/**
 * Refresh an access token using a refresh token.
 *
 * @param asMetadata - Authorization server metadata
 * @param clientCreds - Client credentials
 * @param refreshToken - The refresh token to use
 * @param resource - Optional resource parameter (RFC 8707)
 */
export async function refreshAccessToken(
  asMetadata: AuthServerMetadata,
  clientCreds: ClientCredentials,
  refreshToken: string,
  resource?: string
): Promise<StoredTokens> {
  const clientInformation: OAuthClientInformationMixed = {
    client_id: clientCreds.client_id,
    ...(clientCreds.client_secret
      ? { client_secret: clientCreds.client_secret }
      : {}),
  };

  const sdkMeta = buildSdkMetadata(asMetadata);

  const oauthTokens: OAuthTokens = await refreshAuthorization(
    asMetadata.issuer,
    {
      metadata: sdkMeta as Parameters<typeof refreshAuthorization>[1]["metadata"],
      clientInformation,
      refreshToken,
      ...(resource ? { resource: new URL(resource) } : {}),
    }
  );

  return oauthTokensToStoredTokens(oauthTokens);
}

// ── Token-aware upstream connection ───────────────────────────────────────────

/**
 * Connect to an upstream MCP server using OAuth tokens as Bearer auth.
 *
 * Injects the access_token as a Bearer Authorization header into the
 * StreamableHTTPClientTransport.
 *
 * NOTE: The Bearer token is injected statically. If the token expires
 * mid-session, the transport will not automatically refresh it — the
 * connection will fail with 401. The caller should catch this and
 * trigger a token refresh + reconnect flow.
 */
export async function connectOAuthUpstream(
  config: UpstreamConfigForOAuth,
  tokens: StoredTokens
): Promise<{ config: UpstreamConfigForOAuth; client: Client; tools: Tool[] }> {
  const client = new Client({ name: "mcp-proxy", version: "1.0.0" });

  // Intentionally override any existing Authorization header from config.headers
  // since OAuth tokens take precedence over static auth headers.
  const headers: Record<string, string> = {
    ...config.headers,
    Authorization: `Bearer ${tokens.access_token}`,
  };

  const transport = new StreamableHTTPClientTransport(new URL(config.url), {
    requestInit: { headers },
  });

  await client.connect(transport);

  const { tools } = await client.listTools();
  console.log(
    `[${config.name}] OAuth upstream connected — ${tools.length} tool(s) available`
  );

  return { config, client, tools };
}
