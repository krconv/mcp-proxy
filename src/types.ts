import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { OAuthUpstreamAuth, AuthServerMetadata, ClientCredentials } from "./upstream-auth.js";

// ── Raw config shapes (from UPSTREAMS_JSON) ──────────────────────────────────

export interface RawHeader {
  name: string;
  value: string;
}

export interface RawAuthConfig {
  type?: string;
  client_id?: string;
  client_secret?: string;
  scopes?: string;
}

export interface RawUpstreamConfig {
  name: string;
  url: string;
  headers?: RawHeader[];
  auth?: RawAuthConfig;
}

// ── Normalised internal shapes ───────────────────────────────────────────────

export interface UpstreamConfig {
  name: string;
  url: string;
  headers: Record<string, string>;
  auth?: OAuthUpstreamAuth;
}

export interface ConnectedUpstream {
  config: UpstreamConfig;
  client: Client;
  tools: Tool[];
}

export type UpstreamStatus = "connected" | "needs_auth" | "error" | "refreshing";

export interface UpstreamState {
  config: UpstreamConfig;
  status: UpstreamStatus;
  error?: string;
  toolCount: number;
}

// ── Auth flow state ──────────────────────────────────────────────────────────

export interface AuthCode {
  challenge: string;
  redirectUri: string;
  expiresAt: number;
}

/** In-flight PKCE state for upstream OAuth authorize flows (keyed by state param). */
export interface PendingOAuthFlow {
  upstreamName: string;
  codeVerifier: string;
  asMetadata: AuthServerMetadata;
  clientCreds: ClientCredentials;
  redirectUri: string;
  resource: string;
  expiresAt: number;
}
