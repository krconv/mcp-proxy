import fs from "fs";
import path from "path";
import crypto from "crypto";
import type { OAuthUpstreamAuth } from "./upstream-auth.js";
import type { RawHeader, RawAuthConfig, RawUpstreamConfig, UpstreamConfig } from "./types.js";

// ── Environment ──────────────────────────────────────────────────────────────

export const DATA_DIR = process.env.DATA_DIR ?? "/data";
export const PORT = parseInt(process.env.PORT ?? "9000", 10);
export const EXTERNAL_URL = process.env.EXTERNAL_URL || "";
export const OAUTH_CALLBACK_URI = "http://localhost:19983/callback";

const API_KEY_FILE = path.join(DATA_DIR, "api_key");

// ── API key management ───────────────────────────────────────────────────────

export function loadOrCreateApiKey(): string {
  fs.mkdirSync(DATA_DIR, { recursive: true });

  if (fs.existsSync(API_KEY_FILE)) {
    return fs.readFileSync(API_KEY_FILE, "utf8").trim();
  }

  const key = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(API_KEY_FILE, key, { mode: 0o600 });
  console.log("[proxy] Generated new API key:", API_KEY_FILE);
  return key;
}

// ── Upstream config parsing ──────────────────────────────────────────────────

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

export function loadConfig(): UpstreamConfig[] {
  const raw = process.env.UPSTREAMS_JSON;
  if (!raw) {
    console.warn("[proxy] UPSTREAMS_JSON is not set — no upstreams configured.");
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
    console.error("[proxy] Failed to parse UPSTREAMS_JSON:", err);
    return [];
  }
}

// ── URL helpers ──────────────────────────────────────────────────────────────

/**
 * Derive the externally-visible base URL from an incoming request.
 * Respects X-Forwarded-Proto so reverse proxies (ingress, nginx, etc.) work.
 */
export function getBaseUrl(req: { headers: Record<string, string | string[] | undefined> }): string {
  if (EXTERNAL_URL) return EXTERNAL_URL.replace(/\/$/, "");
  const proto = (req.headers["x-forwarded-proto"] as string | undefined)?.split(",")[0].trim() ?? "http";
  const host = (req.headers["host"] as string) ?? `localhost:${PORT}`;
  return `${proto}://${host}`;
}
