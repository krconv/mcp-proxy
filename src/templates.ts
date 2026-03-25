import type { UpstreamState } from "./types.js";

// ── Helpers ──────────────────────────────────────────────────────────────────

export function escHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

const PAGE_STYLE = `
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
`.trim();

const FORM_STYLE = `
  body{font-family:system-ui,sans-serif;max-width:380px;margin:80px auto;padding:0 20px}
  h1{font-size:1.2rem}
  label{display:block;font-size:.8rem;font-weight:600;margin-bottom:4px}
  input[type=password]{width:100%;box-sizing:border-box;padding:8px 10px;font-size:1rem;border:1px solid #ccc;border-radius:6px}
  button{margin-top:14px;width:100%;padding:10px;font-size:1rem;background:#111;color:#fff;border:none;border-radius:6px;cursor:pointer}
  button:hover{background:#333}
  .hint{font-size:.75rem;color:#999;margin-top:20px}
`.trim();

function page(title: string, style: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escHtml(title)}</title>
  <style>${style}</style>
</head>
<body>${body}</body>
</html>`;
}

// ── Pages ────────────────────────────────────────────────────────────────────

export function renderDashboard(
  baseUrl: string,
  upstreamStates: Map<string, UpstreamState>,
): string {
  const rows: string[] = [];

  for (const [name, state] of upstreamStates) {
    const isOAuth = state.config.auth?.type === "oauth";
    const statusClass =
      state.status === "connected" ? "ok"
      : state.status === "needs_auth" ? "warn"
      : state.status === "refreshing" ? "info"
      : "err";
    const statusLabel = state.status.replace("_", " ");

    let actions = "";
    const encodedName = encodeURIComponent(name);
    if (isOAuth && state.status === "needs_auth") {
      actions = `
        <a class="btn" href="${escHtml(baseUrl)}/upstream/${escHtml(encodedName)}/authorize" target="_blank">Authorize</a>
        <form method="POST" action="${escHtml(baseUrl)}/upstream/${escHtml(encodedName)}/complete" style="margin-top:6px">
          <input type="text" name="callback_url" placeholder="Paste callback URL here"
            style="width:100%;box-sizing:border-box;padding:6px 8px;font-size:.8rem;border:1px solid #ccc;border-radius:4px;margin-bottom:4px">
          <button class="btn" type="submit" style="font-size:.75rem;padding:4px 10px">Complete</button>
        </form>`;
    } else if (isOAuth && state.status === "connected") {
      actions = `
        <form method="POST" action="${escHtml(baseUrl)}/upstream/${escHtml(encodedName)}/disconnect" style="display:inline">
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

  return page("MCP Proxy — Dashboard", PAGE_STYLE, `
  <h1>MCP Proxy Dashboard</h1>
  <p class="sub">Manage your upstream MCP server connections.</p>
  <table>
    <thead><tr><th>Upstream</th><th>Status</th><th>Tools</th><th>Actions</th></tr></thead>
    <tbody>${rows.join("")}</tbody>
  </table>`);
}

export function renderLogin(): string {
  return page("MCP Proxy — Login", FORM_STYLE, `
  <h1>MCP Proxy Login</h1>
  <form method="POST" action="/login">
    <label for="api_key">API Key</label>
    <input type="password" id="api_key" name="api_key" autocomplete="current-password" autofocus>
    <button type="submit">Login</button>
  </form>`);
}

export function renderAuthorize(hiddenInputs: string): string {
  return page("MCP Proxy — Authorize", FORM_STYLE, `
  <h1>Authorize MCP Proxy</h1>
  <p>Enter your API key to grant access to this MCP server.</p>
  <form method="POST" action="/authorize">
    ${hiddenInputs}
    <label for="api_key">API Key</label>
    <input type="password" id="api_key" name="api_key" autocomplete="current-password" autofocus>
    <button type="submit">Authorize</button>
  </form>
  <p class="hint">Find your API key in the add-on logs or the data directory.</p>`);
}

export function renderError(title: string, message: string): string {
  return page(title, `
  body{font-family:system-ui,sans-serif;max-width:400px;margin:80px auto;padding:0 20px}
  h1{font-size:1.2rem;color:#c0392b}`, `
  <h1>${escHtml(title)}</h1>
  <p>${escHtml(message)}</p>
  <a href="/dashboard">Back to Dashboard</a>`);
}
