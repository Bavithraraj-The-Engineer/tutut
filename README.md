# tutut

**Monitor and control MCP (Model Context Protocol) tool calls from Claude Desktop and Claude Web, with real-time user approval.**

tutut sits in the path between Claude and MCP servers and intercepts every `tools/call` request. The request is **held** until you decide: an always-on-top popup shows the server, the tool and its arguments, and you **Allow** it (it is forwarded) or **Block** it (Claude gets a "blocked by the user" result and the tool never runs). Every decision is written to an audit log.

```
Path 1  Claude Desktop ──stdio──▶ tutut stdio ──▶ local MCP server (filesystem, github, …)
Path 2  Claude Desktop ──stdio──▶ tutut stdio ──▶ mcp-remote ──HTTPS──▶ remote MCP server
Path 3  claude.ai / Desktop / mobile ──▶ Anthropic cloud ──HTTPS──▶ Cloudflare tunnel
                                     ──▶ tutut web gateway ──▶ remote MCP server
                     ▲ every path: rules → popup (Allow / Block) → audit log
```

---

## Features

- **Three interception paths** — local Desktop servers, remote servers used from Desktop, and claude.ai connectors (via a public gateway)
- **Hold-until-decided** — the call is not forwarded until you answer; other traffic keeps flowing meanwhile
- **Concurrent requests** — each call is decided independently; popups queue (one at a time, "2/3 pending")
- **Modern approval popup** — always on top: where the call came from, server, tool, a **risk badge** (Destructive / Modifies data / Read-only, from the server's MCP tool annotations and the tool name), syntax-highlighted arguments, a "remember my choice" switch and an auto-block countdown
- **Safe by default** — Block has keyboard focus (a stray Enter blocks), Allow is armed only after a short delay so keystrokes already in flight can't approve; `Y` = Allow, `N` / `Esc` = Block
- **Fail closed** — no display, a full queue, a timeout or an internal error all mean *block*
- **Cancellation aware** — if Claude cancels a pending call (or disconnects), its popup is withdrawn
- **Rules engine** — glob rules to auto-allow / auto-block; "Remember this decision" saves a rule
- **Audit trail in SQLite** — one indexed row per call, safe with many tutut processes writing at once, 90-day retention, fast queries at 100k+ records; secret-looking arguments are masked (`tutut log -f` to watch live)
- **Live dashboard** — `tutut dashboard`: local web view of every decision, stats and coverage, updated in real time
- **Background service** — a watcher routes every Claude Desktop MCP server through tutut automatically, including ones added later
- **Graceful shutdown** — follows the MCP stdio shutdown sequence; SIGTERM never orphans the wrapped server or the tunnel
- **No required dependencies for Desktop** — the stdio proxy uses only the standard library (`aiohttp` for the web gateway)

---

## Table of Contents

- [What can be intercepted](#what-can-be-intercepted)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Demo walkthrough](#demo-walkthrough)
- [Configuration](#configuration)
- [Rules Engine](#rules-engine)
- [Audit Log](#audit-log)
- [Dashboard](#dashboard)
- [CLI Reference](#cli-reference)
- [Platform Support](#platform-support)
- [Security Considerations](#security-considerations)
- [Known Limitations & Trade-offs](#known-limitations--trade-offs)
- [Testing](#testing)
- [How It Works — Deep Dive](#how-it-works--deep-dive)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)

---

## What can be intercepted

tutut works with **any** MCP server — it intercepts the standard `tools/call` message, not server-specific traffic. What matters is *where the MCP traffic flows*:

| How the server is connected | Claude Desktop | claude.ai |
|---|---|---|
| Local server in `claude_desktop_config.json` (filesystem, GitHub, a local Calendar/Jira MCP, …) | ✅ Path 1 — every server, wrapped automatically | n/a |
| Remote server with a URL, no auth or an API key | ✅ Path 2 — `tutut add-remote` | ✅ Path 3 — `tutut web` |
| Remote server with OAuth (Atlassian, Asana, Linear, …) | ✅ Path 2 — mcp-remote does the browser login | ⚠️ Path 3 best effort (see limitations) |
| Anthropic's built-in connectors (Google Drive/Gmail/Calendar from the connector directory) | ❌ | ❌ |
| Claude's built-in tools (its own file access, web search, code execution) | ❌ not MCP | ❌ not MCP |

**Why:** for claude.ai and for Desktop's *account* connectors, the MCP client is Anthropic's cloud, which calls the MCP server directly — that traffic never touches your computer, so no local proxy can see it. tutut handles that by **becoming the server Anthropic calls** (Path 3) or by **moving the connection onto your machine** (Path 2). Built-in connectors have no URL to route through, and built-in tools don't use MCP at all.

**Within an MCP connection tutut sits on:**

| Message | What tutut does |
|---|---|
| `tools/call` (Claude asks the server to run a tool) | **Held** until allowed or blocked; recorded in the audit log |
| `tools/list` responses | Passed through; tool annotations (read-only / destructive hints) are read for the risk badge |
| Everything else — `initialize`, `resources/read`, `prompts/get`, `completion/complete`, notifications, and server→client requests (sampling, elicitation, roots) | Passed through **without approval** (the gateway's request log still records each HTTP request and its JSON-RPC method) |
| Tool **results** (what the server sends back) | Passed through unchanged; **not inspected or stored** |

---

## Architecture

### Path 1 — Claude Desktop, local servers (stdio proxy)

```
┌──────────────────────────────────────────────────────────────────┐
│ Claude Desktop   claude_desktop_config.json:                      │
│   "filesystem": { "command": "~/.local/share/tutut/venv/bin/tutut",│
│                   "args": ["stdio", "--server-name", "filesystem", │
│                            "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "~/Downloads"] }
└───────────────────────────┬──────────────────────────────────────┘
                            │ stdin/stdout, JSON-RPC 2.0 (one message per line)
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ tutut stdio                                                       │
│   client→server reader ── tools/call? ──▶ task: Interceptor.decide│
│        │ (everything else forwarded at once)    rules → popup     │
│        ▼                                        ↓ allow  ↓ block  │
│   real MCP server (child process) ◀── forward ──┘  "blocked" result → Claude
│   server→client pipe ──▶ Claude;  server stderr ──▶ Desktop's log │
└──────────────────────────────────────────────────────────────────┘
```

Claude Desktop runs tutut as the "server"; tutut runs the real server as a child process and relays every message. A `tools/call` is decided in its own task, so while one call waits for you, pings, cancellations and other calls keep flowing. The background watcher (`tutut install`) rewrites `claude_desktop_config.json` so every server — including ones added later — starts through tutut.

### Path 2 — Claude Desktop, remote servers (mcp-remote)

```
Claude Desktop ─stdio─▶ tutut stdio ─stdio─▶ npx mcp-remote <url> ─HTTPS─▶ remote MCP server
```

`tutut add-remote NAME URL` adds the remote server as a *local* entry that runs [mcp-remote](https://www.npmjs.com/package/mcp-remote) (a stdio↔HTTP bridge), already wrapped by tutut. From then on it is intercepted exactly like Path 1 — with full visibility of tool names and arguments. mcp-remote handles OAuth logins in the browser. Turn off the account connector for the same service, or Claude sees the tools twice and may use the copy tutut can't see.

### Path 3 — claude.ai (web gateway + tunnel)

```
claude.ai ──▶ Anthropic cloud (160.79.104.0/21, 153.61.208.0/20)
                │ HTTPS
                ▼
        https://<random-words>.trycloudflare.com/mcp      (Cloudflare quick tunnel)
                │ cloudflared → 127.0.0.1:8019
                ▼
        tutut web gateway ── caller IP allowlisted? ── no → 403
                │ yes
                ├─ tools/call → Interceptor.decide → allow: forward │ block: "blocked" result
                └─ everything else (initialize, tools/list, …) → forward
                ▼
        upstream MCP server (Streamable HTTP)
```

`tutut web --upstream URL` starts the gateway on localhost, opens a Cloudflare quick tunnel (no account needed), checks the public URL end to end and prints it; you add it on claude.ai as a **custom connector**. Anthropic's cloud then calls tutut instead of the real server. Because connectors sync across your account, Claude Desktop and mobile use the same gated connector. The popup appears on the machine running the gateway.

### Shared core

| Component | Role |
|-----------|------|
| `Interceptor` (`interceptor.py`) | One decision engine for all paths: rules → popup → fail-closed fallbacks → cancellation → audit record |
| `PopupManager` / popup (`gui.py`) | Thread-safe FIFO queue, one always-on-top tkinter window at a time; closes itself if the call is cancelled |
| `RulesEngine` (`rules.py`) | Ordered glob rules on server + tool, first match wins, default ASK |
| `AuditLog` / `SQLiteStore` (`audit.py`, `store.py`) | Audit trail in SQLite (WAL, indexed, retention); secret-looking values masked; owner-only files |
| `blocked_response` (`models.py`) | The tool result Claude receives for a blocked call |
| `GuardianConfig` (`config.py`) | `~/.config/tutut/config.json` (owner-only) |

---

## Installation

### Prerequisites

- **Python 3.9+** with **tkinter** (for the popup)
  - Ubuntu/Debian: `sudo apt install python3-tk python3-venv`
  - macOS: included with Python from python.org / Homebrew (`brew install python-tk`)
  - Windows: included with the standard installer
- **Node.js 18+** — only for Path 2 (`mcp-remote` runs via `npx`)
- **cloudflared** — only for Path 3 ([download](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/); a single binary, no account needed for quick tunnels)

### One-command install (Linux, recommended)

```bash
git clone https://github.com/Bavithraraj-The-Engineer/tutut.git
cd tutut
./install.sh
```

This installs tutut (with `aiohttp`) into `~/.local/share/tutut`, links `~/.local/bin/tutut`, creates a default config (ask before every tool call, auto-block after 45 s), and starts the background watcher now and at every login. Restart Claude Desktop once. `./install.sh --uninstall` restores everything.

### From source (any OS)

```bash
pip install -e ".[http]"     # [http] adds aiohttp for the web gateway
tutut --version
```

---

## Quick Start

### Path 1 — Claude Desktop, local servers

With `./install.sh` there is nothing else to do: every server in `claude_desktop_config.json` is routed through tutut within ~2 seconds of being added (you get a notification to restart Claude Desktop).

```bash
tutut status          # watcher state, guarded / unguarded servers
```

To keep a server out of tutut, add its name to `autowrap_exclude` in `~/.config/tutut/config.json`.

<details>
<summary>Manual setup (without the watcher)</summary>

```bash
tutut setup                       # wrap all servers
tutut setup --dry-run             # preview
tutut setup --servers filesystem  # only some
tutut teardown                    # undo
```

Or edit `claude_desktop_config.json` yourself:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/absolute/path/to/tutut",
      "args": ["stdio", "--server-name", "filesystem",
               "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

| OS | Config path |
|----|-------------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |
</details>

### Path 2 — Claude Desktop, remote servers

```bash
tutut add-remote jira https://mcp.example.com/mcp               # OAuth: browser login on first use
tutut add-remote redmine https://redmine.example.com/mcp \
      --header "X-Redmine-API-Key: <key>"                        # API-key servers
tutut remove-remote jira
```

Restart Claude Desktop. tutut picks the newest Node.js ≥ 18 it can find (or `--npx /path/to/npx`). Plain `http://` is only accepted for localhost unless you pass `--allow-http`.

### Path 3 — claude.ai

```bash
tutut web --upstream https://mcp.example.com/mcp --server-name my-server
tutut web --upstream https://mcp.example.com/mcp --header "Authorization: Bearer <token>"   # credentials stay local
```

It prints something like:

```
  tutut web gateway for 'my-server'  →  https://mcp.example.com/mcp
  Status: reachable from the internet ✓

  Add this URL as a custom connector on claude.ai
  (Settings → Connectors → Add custom connector):

    https://random-words-here.trycloudflare.com/mcp

  Callers: only Anthropic's servers (160.79.104.0/21, 153.61.208.0/20); others get 403.
```

On claude.ai: **Settings → Connectors → Add custom connector**, paste the URL, **Connect**, then enable it in a chat. Quick-tunnel URLs change on every run — re-add the connector after a restart (or use your own stable tunnel with `--no-tunnel --public-url https://…`).

---

## Demo walkthrough

`examples/demo_server.py` is a small no-auth MCP server (Streamable HTTP) with four tools — `list_notes`, `read_note` (reads), `add_note`, `delete_note` (writes) — ideal for showing one approved and one blocked call.

```bash
python examples/demo_server.py                       # http://127.0.0.1:8931/mcp
tutut dashboard                                      # in another terminal: live dashboard (or `tutut log -f`)

# Claude Desktop (Path 2)
tutut add-remote demo-notes http://127.0.0.1:8931/mcp   # then restart Claude Desktop

# claude.ai (Path 3)
tutut web --upstream http://127.0.0.1:8931/mcp --server-name demo-notes
```

In a chat: *"List my notes"* → popup → **Allow**; *"Delete the note called secrets"* → popup → **Block** → Claude reports the call was blocked, and the demo server's log shows it never received it.

> Claude Desktop may show its own permission prompt first. That one is inside the app, before the call is sent; tutut's popup comes after, when the request is actually on its way to the server. Choosing "Always allow" in Claude's prompt makes tutut the single approval point — and shows that tutut still holds the request even when the client has been told to allow it.

---

## Configuration

`~/.config/tutut/config.json` (created by `tutut install` / `tutut config --init`, owner-only permissions):

| Option | Default | Description |
|--------|---------|-------------|
| `rules` | `[]` | Ordered allow/block rules |
| `block_when_headless` | `true` | Block ASK requests when no popup can be shown |
| `popup_timeout` | `0` (`45` via install) | Auto-block after N seconds (0 = wait forever) |
| `audit_db` | `~/.config/tutut/audit.db` | Audit database (SQLite) |
| `audit_retention_days` | `90` | Delete records older than this (0 = keep forever) |
| `audit_file` | `~/.config/tutut/audit.jsonl` | Previous (JSON-lines) audit file — imported into `audit_db` automatically, then renamed `.migrated` |
| `log_file` / `log_level` | `~/.config/tutut/tutut.log` / `INFO` | Diagnostic log |
| `log_payloads` | `false` | Log full JSON-RPC payloads (may contain sensitive data) |
| `http_proxy_host` / `http_proxy_port` | `127.0.0.1` / `8019` | Gateway bind address |
| `autowrap_exclude` | `[]` | Desktop servers the watcher must not wrap |
| `web_secret` | (generated) | Passphrase for `tutut web --path-secret` |

```bash
tutut config --show     # web_secret is masked
```

---

## Rules Engine

Rules are evaluated in order — **first match wins**; no match means **ASK** (popup). Both patterns are globs (`fnmatch`).

```bash
tutut rules list
tutut rules add --server filesystem --tool "read_*" --action allow
tutut rules add --server "*" --tool "delete_*" --action block
tutut rules remove 0
```

Ticking **"Remember this decision for this tool"** in the popup saves a rule. It applies immediately in that process and is merged into the config file without overwriting changes other tutut processes made.

> On a public gateway (Path 3), an *allow* rule lets any caller that passes the IP allowlist run that tool without a popup — keep allow rules to harmless read-only tools.

---

## Audit Log

Every intercepted call becomes one row in the SQLite database `~/.config/tutut/audit.db`. As JSON (what `tutut log --json` and the dashboard API return):

```json
{"ts": "2026-11-18T20:16:29.432+00:00", "transport": "stdio",
 "source": "Claude Desktop → mcp-remote → http://127.0.0.1:8931/mcp",
 "server": "demo-notes", "tool": "delete_note", "arguments": {"title": "secrets"},
 "decision": "block", "decided_by": "user", "wait_ms": 6909, "request_id": 3}
```

`decision` is `allow`, `block` or `cancelled`; `decided_by` is `user`, `rule`, `timeout`, `headless`, `queue_full`, `error` or `client`; `risk` is `high`, `medium`, `low` or `unknown`. Values of keys that look secret (`password`, `token`, `api_key`, `authorization`, …) are replaced by `***`, long values are truncated.

```bash
tutut log                 # last 20 decisions, local time
tutut log -n 0            # everything
tutut log -f              # follow live
tutut log --json | jq …   # JSON lines, e.g. jq -c 'select(.decision=="block")'
```

**Why SQLite.** Every wrapped Desktop server runs its own tutut process, plus the web gateway, all recording at once; SQLite (standard library — no new dependency, no server) handles that safely and stays fast as history grows:

- **Concurrency:** WAL mode — the dashboard reads while proxies write; writers queue on a 5 s busy timeout. Tested with 4 processes writing 1 000 records at once: none lost.
- **Speed:** indexes on time, decision, server/tool and path; all filtering and aggregation is SQL. With 100 000 records: dashboard stats for 24 h ≈ 25 ms, 7 d ≈ 0.2 s, all ≈ 0.5 s; a search ≈ 0.1 s.
- **Retention:** records older than `audit_retention_days` (default 90) are pruned hourly; space is reclaimed incrementally.
- **Safety:** every query is parameterised (tool names and arguments can be attacker-controlled); the database and its `-wal`/`-shm` files are owner-only; a failed write is logged and never breaks proxying.
- **Migration:** an existing `audit.jsonl` is imported automatically (records already present are skipped, so nothing is duplicated — or stranded if an old tutut process writes one more line before it restarts) and renamed `audit.jsonl.migrated`.
- **Schema versioning:** `PRAGMA user_version`, for future migrations.

`tutut.log` (diagnostics) is rotated at start-up once it exceeds 10 MB, keeping 5 old files — rotating at start rather than mid-run, because several processes share it.

The web gateway additionally logs every HTTP request (method, path with any secret masked, status, caller IP, JSON-RPC method, user agent) to `tutut.log`.

---

## Dashboard

```bash
tutut dashboard            # opens http://127.0.0.1:8020/?token=… in your browser
tutut dashboard --port 8030 --no-browser
```

A live, read-only web view of everything tutut does, served locally:

- **Live feed** — every intercepted call appears as it is decided (Server-Sent Events), colour-coded allow / block / cancelled, with path (Desktop local, Desktop via mcp-remote, claude.ai gateway), who decided and how long you took; click a row for the full arguments
- **Totals and charts** — calls, allowed, blocked, cancelled, block rate, your median / p95 decision time, calls over time, top tools, breakdown by path and by decider; windows of 1 h / 24 h / 7 d / all
- **Filters** — decision, path, server, free-text search over tools and arguments
- **Coverage** — watcher state, guarded Desktop servers (and which go through mcp-remote), servers *not* guarded, the running web gateway (connector URL, upstream, allowed callers), popup timeout and rules

It queries the same audit database every tutut process writes to; all filtering and aggregation run in SQL, so it stays responsive as history grows. Security: it binds to `127.0.0.1` only and refuses requests whose `Host` isn't localhost (DNS-rebinding protection); the printed link carries a one-time token that is swapped for an `HttpOnly`, `SameSite=Strict` cookie; a strict Content-Security-Policy allows only its own script; all audit data is rendered as text, never HTML, because tool arguments can contain prompt-injected content. No third-party JavaScript — charts are plain SVG.

---

## CLI Reference

```
tutut [--version] [--config PATH] COMMAND

  stdio          Run as a stdio proxy wrapping an MCP server          (Path 1/2)
  add-remote     Add a remote server to Claude Desktop via mcp-remote (Path 2)
  remove-remote  Remove it again
  web            Gateway + Cloudflare tunnel for claude.ai             (Path 3)
  http           Local HTTP proxy only (no tunnel, no allowlist)
  log            Show / follow the audit log
  dashboard      Local live web dashboard (read-only)
  install        One-time setup: watcher + autostart + wrap all Desktop servers (Linux)
  uninstall      Stop the watcher, remove autostart, restore original entries
  status         Watcher state and guarded servers
  watch          Run the watcher in the foreground
  setup/teardown Wrap/unwrap Desktop servers once (no watcher)
  config         Show or initialise the config
  rules          list / add / remove rules

stdio:       tutut stdio --server-name NAME [--display D] [--xauthority F] -- COMMAND [ARGS...]
add-remote:  tutut add-remote NAME URL [--header "K: V"]... [--allow-http] [--npx PATH] [--force]
web:         tutut web --upstream URL [--server-name NAME] [--port P] [--header "K: V"]...
                       [--allow-ip CIDR]... [--allow-any-ip] [--path-secret [--rotate-secret]]
                       [--no-tunnel --public-url URL]
http:        tutut http --upstream URL [--server-name NAME] [--host H] [--port P] [--header "K: V"]...
log:         tutut log [-f] [-n N (0 = all)] [--json]
dashboard:   tutut dashboard [--port 8020] [--no-browser]
```

| File | Path |
|------|------|
| Config | `~/.config/tutut/config.json` |
| Audit database | `~/.config/tutut/audit.db` (+ `-wal`, `-shm`) |
| Diagnostic log | `~/.config/tutut/tutut.log` |
| Installed copy (install.sh) | `~/.local/share/tutut/venv` |

---

## Platform Support

| Platform | Path 1/2 (stdio) | Path 3 (gateway) | Popup | Background watcher | Tested |
|----------|:---:|:---:|:---:|:---:|:---:|
| Linux (Ubuntu 24.04, Claude Desktop Linux build) | ✓ | ✓ | ✓ tkinter | ✓ XDG autostart | **yes** |
| macOS | ✓ | ✓ | ✓ (osascript brings it to front) | run `tutut watch` yourself | not tested |
| Windows | ✓ (thread-based stdin reader) | ✓ | ✓ | run `tutut watch` yourself | not tested |

---

## Security Considerations

**Interception guarantees**
- **Decision before execution** — a `tools/call` is never forwarded until it is allowed; blocked calls never reach the server (verified end to end: the server's own log shows only the allowed calls).
- **Fail closed** — no display (`block_when_headless`), popup timeout, a full queue (10 pending), a popup that fails to open, or an internal error all block.
- **Client-independent** — tutut sits outside the Claude app, so the app's own "always allow" setting does not bypass it.
- **No server changes** — servers run unmodified; tutut only relays and holds messages.

**Web gateway (Path 3)**
- **Caller allowlist** — only Anthropic's published outbound ranges (`160.79.104.0/21`, `153.61.208.0/20`, from [platform.claude.com/docs/en/api/ip-addresses](https://platform.claude.com/docs/en/api/ip-addresses)) are accepted; anyone else gets 403 and cannot even list the tools.
- **Unspoofable caller IP** — the gateway listens on `127.0.0.1` only; `CF-Connecting-IP` is trusted only on loopback connections (i.e. from cloudflared), and Cloudflare's edge overwrites any value a caller sends.
- **Unguessable hostname** — quick-tunnel hostnames are random and served with the wildcard certificate `*.trycloudflare.com`, so individual hostnames don't appear in certificate-transparency logs.
- **Local credentials** — `--header` credentials are added by the gateway; they never pass through Anthropic or the tunnel.
- **No secrets in logs** — no aiohttp access log; the request log masks any path secret.
- **Header hygiene** — hop-by-hop and CDN headers (`cf-*`, `x-forwarded-*`, `cdn-loop`) aren't forwarded upstream; the client's `Authorization` is replaced when static credentials are configured.

**General**
- Config, audit database (including its `-wal`/`-shm` files) and log are owner-only (`0600`); looser existing files are tightened.
- Oversized messages are rejected with an error response (32 MB stdio, 10 MB HTTP) instead of exhausting memory or silently hanging.
- The wrapped server is terminated on shutdown (SIGTERM, then SIGKILL after 5 s); SIGTERM to tutut itself runs the same cleanup.

---

## Known Limitations & Trade-offs

tutut really intercepts MCP traffic — wherever it sits on the connection, every `tools/call` is held before it reaches the server, and blocked calls never arrive. The limits are about *where* it can sit and *what* within MCP it gates.

### 1. Coverage — where tutut can sit

1. **Only connections routed through tutut.** Covered: Claude Desktop's local servers (Path 1), remote servers added with `tutut add-remote` (Path 2), and claude.ai custom connectors routed through `tutut web` (Path 3).
2. **Never coverable:** Anthropic's built-in connectors (Google Drive / Gmail / Calendar — no URL to route through) and Claude's built-in tools (its own file access, web search, code execution, Chrome integration — not MCP). No interceptor on your side can be in front of this traffic.
3. **Not covered unless re-added through tutut:** Claude Desktop's *account* connectors (called from Anthropic's cloud — use `add-remote` or `tutut web` and turn the account connector off) and **Desktop Extensions** (`.mcpb`), which are not in `claude_desktop_config.json`, so the watcher doesn't wrap them.
4. **Claude may pick an unguarded route.** If a built-in tool or an account connector can do the job, Claude may use it instead of a guarded server (observed: "list my Downloads folder" used Desktop's built-in file access).
5. **Other MCP clients** (Claude Code, Cursor, …) can be wrapped by hand with `tutut stdio`, but the watcher only manages Claude Desktop's config.

### 2. What is intercepted within MCP

6. **Only `tools/call` is gated.** `resources/read` (which can read data), `prompts/get`, `completion/complete` and server→client requests (sampling, elicitation, roots) pass through without approval.
7. **Tool results are not inspected or stored.** Whatever a tool returns — including prompt-injection text or sensitive data — is passed back to Claude unchanged; the audit log records the request and the decision, not the output.

### 3. Decision quality

8. **Rules match server and tool names only**, not argument values — "allow `read_file` only under `~/Documents`" can't be expressed (the popup does show the full arguments).
9. **Risk badges are hints.** They come from the tool name and the server's own annotations; the worse of the two wins (a server can't make a delete tool look read-only), but oddly named tools may be labelled "Unknown effect" or misjudged.
10. **Approval fatigue.** Every un-ruled call needs a click, which pushes users towards "remember" rules that widen access.

### 4. claude.ai path (`tutut web`)

11. **Needs a tunnel and this machine online.** If the gateway or tunnel stops, the connector fails on every client. Quick-tunnel URLs change on each run (re-add the connector), and it depends on Cloudflare.
12. **No SSE through quick tunnels.** The gateway collects a streamed POST response into a single JSON response (allowed by the spec), which drops progress notifications.
13. **claude.ai rejects secret URL paths.** Its connector client refuses URLs with a secret path segment (both random tokens and word passphrases were tested: the validator gets a 200 on `initialize`, then the real client never connects). So the gateway URL is `https://<host>/mcp`, protected by the Anthropic-only IP allowlist, the random hostname and the popup. **Residual risk:** another claude.ai user who obtains the URL could add it — their calls also come from Anthropic's ranges. They could see the tool list and trigger popups on your screen, and any tool you've auto-allowed with a rule would run for them. The proper fix is OAuth on the gateway (not implemented).
14. **OAuth upstreams are best effort.** The gateway forwards discovery and rewrites the protected-resource metadata to its own URL, but tokens are bound to the original server's audience and some servers will reject them. Path 2 (mcp-remote) handles OAuth fully.
15. **The popup appears on the gateway machine**, even when the call was made from your phone.

### 5. Claude Desktop path

16. **Two approval prompts.** Claude Desktop's own permission prompt runs inside the app before the call is sent; denying there means tutut never sees it.
17. **Restarts.** Config changes (new or re-wrapped servers) take effect after a Claude Desktop restart.
18. **Client timeouts.** If the popup isn't answered quickly, Claude may give up first; tutut then withdraws the popup. Keep `popup_timeout` below the client's timeout (45 s works in practice).
19. **Not a sandbox.** Anything that can edit `claude_desktop_config.json` can remove the wrapper (the watcher re-wraps it within ~2 s). tutut is a monitoring and approval layer, not a security boundary against local malware.

### 6. Monitoring & storage

20. **Per machine.** The SQLite database suits one user's machine (millions of rows); there is no central or multi-user view. A central store (e.g. Postgres) would need a network service — the `SQLiteStore` interface is where another backend would plug in.
21. **Not tamper-proof.** You — or anything running as you — can edit or delete the audit database.
22. **Not a forensic copy.** Arguments are redacted and truncated by design, results aren't stored, and records older than `audit_retention_days` (90) are deleted.
23. **Dashboard:** local only and read-only; no alerting or notifications. Its "All" window scans the whole table (≈ 0.5 s at 100k records); retention keeps it bounded.

### 7. Platform

24. **Tested on Linux only** (Ubuntu 24.04 with the Claude Desktop Linux build); macOS and Windows should work but are untested.
25. **The background watcher is Linux-only** (XDG autostart). On macOS/Windows, run `tutut watch` from a login item or use `tutut setup`.
26. **One popup at a time** (max 10 queued; more are auto-blocked), and the Tk popup is not screen-reader friendly.

---

## Testing

```bash
pip install -e ".[http]" pytest
python -m pytest tests/ -v
```

**189 tests** (6 of them open real windows and run only with `TUTUT_GUI_TESTS=1`, e.g. `TUTUT_GUI_TESTS=1 xvfb-run -a python -m pytest tests/test_popup.py`). Besides unit tests, several run real processes and servers:

| Test | What it proves |
|------|----------------|
| `test_stdio_end_to_end` | real `tutut stdio` + a real server process: allowed call runs, blocked call returns a blocked result, a **1 MB** message passes, audit records written |
| `test_pending_call_does_not_block_other_messages` | while one call waits for the user, other calls and `tools/list` go through |
| `test_client_cancel_withdraws_pending_call` | `notifications/cancelled` closes the popup; no response is sent |
| `test_stdio_sigterm_stops_wrapped_server` | SIGTERM to tutut doesn't orphan the server |
| `test_stdio_server_crash_with_client_still_connected` | clean exit, no interpreter abort |
| `test_gateway_secret_path_and_forwarding` | gateway → real demo server: allow forwards, block never reaches it |
| `test_gateway_ip_allowlist` / `test_client_ip_trusts_header_only_from_loopback` | 403 for non-Anthropic callers; header spoofing ignored |
| `test_gateway_header_handling`, `…buffers_sse…`, `…rewrites_oauth_discovery` | header hygiene, SSE→JSON for tunnels, OAuth metadata rewriting |
| `TestRemote` | `add-remote` entries, Node ≥ 18 detection, URL validation |
| `test_store.py` | SQLite store: WAL + owner-only files, every field round-trips, SQL-injection strings stay data, 4 processes writing 1 000 records concurrently, JSONL import (no duplicates, no stranded records, 4 processes opening at once), retention, 100k-record query timings, log rotation |
| `test_popup.py` | risk classification (incl. a server lying about a delete tool), JSON highlighting, annotations learned by both proxies; window behaviour under Xvfb: Allow ignored until armed, Enter/Esc block, remember switch, countdown timeout, cancellation closes the window |
| `test_dashboard.py` | token → cookie login, DNS-rebinding refusal, CSP, stats and filters, coverage status, live SSE push of a newly appended record |

Manually verified on Ubuntu 24.04: Claude Desktop with a local filesystem server (Path 1), Claude Desktop with a remote server through mcp-remote (Path 2), and claude.ai through `tutut web` and a Cloudflare quick tunnel (Path 3) — Allow and Block on each.

---

## How It Works — Deep Dive

### What is intercepted

MCP uses [JSON-RPC 2.0](https://www.jsonrpc.org/specification). tutut holds only `method == "tools/call"`. Everything else — `initialize`, `tools/list`, notifications, responses — passes through untouched, so the proxy is invisible during the handshake.

### Blocked response

A blocked call gets a **tool result marked as an error** rather than a JSON-RPC protocol error. Per the MCP spec, tool-execution failures belong in the result so the model can read them; Claude then tells the user the call was blocked instead of reporting a broken server:

```json
{"jsonrpc": "2.0", "id": 3, "result": {"isError": true, "content": [{"type": "text",
  "text": "Blocked by tutut: the call to tool 'delete_note' on MCP server 'demo-notes' was not executed. The user denied this request. Do not retry this call unless the user asks you to."}]}}
```

The reason text distinguishes user, rule, timeout, headless and queue-full decisions.

### Concurrency and cancellation (stdio)

stdin is read on a thread (portable, including Windows) into an asyncio stream. Each `tools/call` gets its own task; the reader never waits for a popup. If Claude sends `notifications/cancelled` for a pending call, its task is cancelled, the popup closes, the audit log records `cancelled`, and no response is sent (as the spec requires). If the server exits, every request still waiting on it gets an error response and tutut exits so the client sees the disconnect. When the client closes stdin, in-flight decisions get 2 s to finish, then the server's stdin is closed and it gets 5 s to answer and exit.

### The popup

`popup_ui.py` (tkinter, standard library only — no extra dependency, starts instantly inside Claude Desktop's environment). Rounded panels, buttons, switch, badge and countdown are drawn on Tk canvases.

- **Hierarchy:** source → tool and server → risk badge with the reason ("The server marks it destructive", "Its name (“write”) suggests it changes something") → arguments → decision.
- **Risk:** server annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`, learned from `tools/list` responses by both proxies) and the tool name are combined pessimistically — a server can't make `delete_everything` look read-only. The risk level is also written to the audit log.
- **Arguments:** pretty-printed, syntax-highlighted JSON, sized by displayed (wrapped) lines with a scrollbar when long, truncated beyond 12 000 characters.
- **Safety:** Block is focused, so Enter blocks; Allow (button or `Y`) only works after 0.7 s; `N`, `Esc` and closing the window block at once.
- **Countdown:** a bar that turns amber at 10 s and red at 5 s, then auto-blocks.

Preview it with sample requests: `python -m tutut.popup_ui`.

`PopupManager` serialises popups on a worker thread (max 10 pending, "2 of 4" shown). Results reach asyncio through a callback (no thread parked per call). A request cancelled while queued is skipped; one cancelled while shown closes its own window.

### Web gateway details

- `/mcp` (and `/`) map to the configured upstream URL; `/.well-known/…` maps to the upstream origin (OAuth discovery).
- JSON responses use a bare `application/json` content type (`charset` stripped; RFC 8259 defines none).
- Batch requests: each `tools/call` is decided independently; blocked items are answered locally and merged with the upstream results.
- Client disconnects cancel the handler (`handler_cancellation`), which withdraws the popup.

---

## Project Structure

```
tutut/
├── tutut/
│   ├── cli.py            # CLI entry point and subcommands
│   ├── interceptor.py    # Shared decision engine (rules → popup → audit)
│   ├── stdio_proxy.py    # Path 1/2: stdio proxy for Claude Desktop
│   ├── remote.py         # Path 2: add-remote / remove-remote (mcp-remote entries)
│   ├── http_proxy.py     # Path 3: HTTP gateway (Streamable HTTP, allowlist, SSE)
│   ├── web_gateway.py    # Path 3: `tutut web` (gateway + Cloudflare quick tunnel)
│   ├── gui.py            # PopupManager queue, PopupResult (thread-safe layer)
│   ├── popup_ui.py       # the approval window (tkinter)
│   ├── risk.py           # risk hints from annotations + tool names; JSON tokens
│   ├── audit.py          # AuditLog (redaction), `tutut log` reading/following
│   ├── store.py          # SQLite audit store: schema, queries, retention, JSONL import
│   ├── dashboard.py      # `tutut dashboard` (aiohttp API + SSE)
│   ├── dashboard_static/ # dashboard page: index.html, app.js, style.css
│   ├── rules.py          # Rules engine
│   ├── models.py         # JSON-RPC model, rules, blocked_response
│   ├── config.py         # Config file and logging
│   ├── autowrap.py       # Wrap/unwrap claude_desktop_config.json entries
│   ├── service.py        # install / uninstall / status / watch
│   └── setup_helper.py   # setup / teardown
├── examples/demo_server.py   # Demo remote MCP server (notes)
├── tests/                    # 189 tests (unit + real-process end-to-end + GUI)
├── install.sh                # One-command Linux installer
├── ARCHITECTURE.md
└── README.md
```

---

## Troubleshooting

**Popup not appearing** — check `tutut status` (is the server guarded?) and `tutut log`. If nothing was recorded, the call didn't reach tutut: Claude may have used a built-in tool or an account connector instead, or you denied Claude's own prompt. On Linux the popup needs a display; the watcher records `--display/--xauthority` in wrapped entries for this.

**claude.ai: "Couldn't reach …"** — the connector URL must be exactly what `tutut web` prints (`https://<host>/mcp`). Don't use `--path-secret` with claude.ai. Check `~/.config/tutut/tutut.log`: requests from `160.79.x.x` with `ua='Claude-User'` mean claude.ai is connected; `-> 403` from another IP means a non-Anthropic caller was rejected.

**`tutut add-remote` says Node.js is too old** — install Node 18+ (`nvm install --lts`) or pass `--npx /path/to/newer/npx`.

**"tkinter not available"** — `sudo apt install python3-tk` (Debian/Ubuntu), `sudo dnf install python3-tkinter` (Fedora), `brew install python-tk` (macOS).

**Server not starting** — Claude Desktop's per-server log (`~/.config/Claude/logs/mcp-server-NAME.log`) contains the server's stderr, which tutut passes through.

---

## License

MIT License. See [LICENSE](LICENSE).
