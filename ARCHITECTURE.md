# tutut — Architecture

## 1. The problem: where does MCP traffic actually flow?

To hold a tool call until the user decides, tutut has to sit **on the path of the MCP messages**. That path differs by client:

| Client & server | Who is the MCP client? | Where the traffic flows | Interceptable locally? |
|---|---|---|---|
| Claude Desktop + local server (`claude_desktop_config.json`) | Claude Desktop | stdio pipes on this machine | ✅ yes |
| Claude Desktop + **account connector** | Anthropic's cloud | Anthropic → server, over the internet | ❌ never touches this machine |
| claude.ai + connector | Anthropic's cloud | Anthropic → server, over the internet | ❌ never touches this machine |
| Claude's built-in tools / built-in Google connectors | not MCP / no URL | inside Anthropic or the app | ❌ |

A local proxy (tutut, mcp-intercept, Burp, mitmproxy…) can only see the first row. tutut therefore uses three paths, sharing one decision engine:

```
Path 1  Claude Desktop ──stdio──▶ tutut stdio ──▶ local server
Path 2  Claude Desktop ──stdio──▶ tutut stdio ──▶ mcp-remote ──HTTPS──▶ remote server        (move the connection onto this machine)
Path 3  claude.ai/Desktop/mobile ──▶ Anthropic ──▶ tunnel ──▶ tutut web ──▶ remote server    (become the server Anthropic calls)
```

## 2. Path 1 — stdio proxy (Claude Desktop, local servers)

The wrapped entry in `claude_desktop_config.json`:

```json
"filesystem": {
  "command": "/home/me/.local/share/tutut/venv/bin/tutut",
  "args": ["stdio", "--server-name", "filesystem", "--display", ":0", "--xauthority", "…",
           "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/me/Downloads"]
}
```

Claude Desktop starts tutut as the server; tutut starts the real server as a child process.

```
stdin (thread) ─▶ StreamReader ─▶ client→server loop
                                     ├─ tools/call ─▶ new task: Interceptor.decide()
                                     │                   ├ allow → write to server stdin
                                     │                   └ block → write "blocked" result to stdout
                                     ├─ notifications/cancelled ─▶ cancel that task (popup closes)
                                     └─ anything else ─▶ server stdin immediately
server stdout ─▶ server→client loop ─▶ stdout (Claude)
server stderr ─▶ passed through to Claude Desktop's per-server log
```

Design decisions:
- **One task per `tools/call`.** The reader never waits for a popup, so concurrent calls, pings and cancellations keep flowing; replies are matched by JSON-RPC id, so reordering is safe.
- **Cancellation per the spec.** A `notifications/cancelled` for a pending call cancels its task, closes its popup and sends no response.
- **Large messages.** Readers accept up to 32 MB per line (asyncio's 64 KiB default broke on large file reads). A larger request gets an error response instead of disappearing.
- **Server death.** Every request still waiting on the server gets an error response, then tutut exits so the client sees the disconnect.
- **Graceful shutdown.** On stdin EOF, in-flight decisions get 2 s, then the server's stdin is closed and it gets 5 s to answer and exit (the MCP stdio shutdown sequence). SIGTERM runs the same cleanup, so the child is never orphaned.
- **Portable stdin.** Read on a thread with `os.read` (works on Windows, and doesn't hold the buffered-stdin lock at interpreter exit).
- **Automatic coverage.** A background watcher (`tutut install` → XDG autostart) keeps every server in the config wrapped, including servers added later, and only touches `command`/`args` so unwrapping restores the original exactly.

## 3. Path 2 — remote servers in Claude Desktop (mcp-remote)

`tutut add-remote NAME URL` writes a local entry `npx -y mcp-remote URL` — already wrapped by tutut — so a remote server becomes a local stdio process:

```
Claude Desktop ─stdio─▶ tutut stdio ─stdio─▶ mcp-remote ─HTTPS─▶ remote MCP server
```

Interception is then identical to Path 1, with full visibility of tool names and arguments; mcp-remote handles OAuth in the browser. tutut picks a Node.js ≥ 18 (Claude Desktop starts servers with a minimal PATH, so the entry uses an absolute `npx` and sets `PATH`). The account connector for the same service must be turned off, otherwise Claude may use that unguarded copy.

## 4. Path 3 — claude.ai (web gateway)

claude.ai's MCP client runs in Anthropic's cloud. tutut becomes the server it calls:

```
claude.ai → Anthropic cloud (160.79.104.0/21, 153.61.208.0/20)
         → https://<random>.trycloudflare.com/mcp → cloudflared → tutut gateway on 127.0.0.1:8019
         → [IP allowlist] → tools/call? hold for decision : forward → upstream MCP server
```

`tutut web` starts the gateway, opens a Cloudflare quick tunnel (no account), checks the public URL end to end and prints the URL to add as a custom connector. Connectors sync across the account, so Desktop and mobile go through the same gate.

Gateway details:
- **Streamable HTTP.** POST (single or batch JSON-RPC), GET (SSE stream) and DELETE (end session) are forwarded with `Mcp-Session-Id`. Only `tools/call` is held; in a batch each call is decided independently.
- **Caller allowlist.** Only Anthropic's published outbound ranges are accepted, so others get 403. The caller IP comes from `CF-Connecting-IP`, trusted only on loopback connections (the gateway listens on 127.0.0.1, and Cloudflare overwrites the header at its edge), so it can't be spoofed.
- **SSE through quick tunnels.** Cloudflare quick tunnels don't carry SSE, so a streamed POST response is collected and returned as one JSON response, which the spec allows.
- **Bare `application/json`.** `charset` parameters are stripped (RFC 8259 defines none).
- **Upstream credentials.** `--header "Authorization: …"` is added locally, so it never passes through Anthropic or the tunnel.
- **Client disconnect.** If the client disconnects while a popup is open, the aiohttp handler is cancelled and the popup withdrawn.
- **OAuth upstreams (best effort).** `/.well-known/…` is forwarded, and the `resource_metadata` and `resource` values are rewritten to the gateway's URL.

**Finding during testing:** claude.ai's connector setup first validates the URL with an `initialize` request, then its real client (`Claude-User`) connects. With a secret path segment in the URL, either a random token (`/YgeF…Uj/mcp`) or a word passphrase (`/mugo-fupa-…/mcp`), validation succeeded (200), but the real client never sent a request. The same server connected at `https://<host>/mcp`. That's why the gateway's access control is the IP allowlist plus a random hostname rather than a URL secret (`--path-secret` remains available for other clients).

## 5. The shared decision engine

```
tools/call ─▶ Interceptor.decide(msg)
              ├─ rules (first glob match on server+tool) ── ALLOW/BLOCK ─▶ decided_by="rule"
              ├─ no display ─▶ block (block_when_headless) ─▶ "headless"
              └─ PopupManager.request_decision()
                    queue (max 10; overflow → block "queue_full")
                    always-on-top window: source, tool + server, risk badge, highlighted arguments,
                    [remember] switch, countdown; Block focused, Allow armed after 0.7 s
                    ├─ Allow / Block ─▶ "user"   (Remember → rule merged into config file)
                    ├─ countdown ─▶ block "timeout"
                    ├─ window fails ─▶ block "error"
                    └─ caller cancelled ─▶ window closes, audit "cancelled"
              ─▶ AuditLog.record(...)   one row in SQLite (audit.db), secrets masked
```

- **Async bridge.** The popup thread completes a `PopupResult`, whose callback resolves an asyncio future via `call_soon_threadsafe`. No thread is parked per pending call, and cancelling the awaiting task withdraws the popup.
- **Blocked reply.** A blocked call returns a tool result with `isError: true` ("Blocked by tutut: … The user denied this request. Do not retry…") rather than a JSON-RPC error. Per MCP, tool-level failures belong in the result where the model reads them, so Claude tells the user it was blocked instead of reporting a broken server.
- **Fail closed everywhere.** Every path that can't get an explicit "allow" blocks.

## 6. Security model

| Threat | Mitigation |
|---|---|
| Tool runs without consent | Held before forwarding; only an explicit allow (user or rule) forwards; everything else blocks |
| Client app settings bypass ("always allow") | tutut sits outside the app; the app's setting doesn't reach it |
| Stranger calls the public gateway | IP allowlist (Anthropic ranges only) and an unguessable hostname (wildcard cert, so it's not in CT logs) |
| Spoofed caller IP | Header trusted only from loopback; the gateway listens only on localhost |
| Credential leakage | Upstream credentials injected locally; config and audit files are 0600; the audit log masks secret-looking values; no access log |
| Resource exhaustion | 32 MB / 10 MB message limits with error responses; popup queue capped at 10 |
| Orphaned processes | SIGTERM handled; child terminated, then killed after 5 s |

**Residual risks.** Another claude.ai user who obtains the gateway URL can add it, because their calls also come from Anthropic's ranges. They could list tools, but each call still needs approval on the owner's screen. OAuth on the gateway would close this. Also, local software that can edit `claude_desktop_config.json` can remove the wrapper, so tutut is an approval layer, not a sandbox.

## 7. Module map

| Module | Responsibility |
|---|---|
| `interceptor.py` | Shared decision engine |
| `stdio_proxy.py` | Paths 1 and 2: stdio relay, concurrency, cancellation, shutdown |
| `remote.py` | Path 2: `add-remote` / `remove-remote`, Node ≥ 18 discovery |
| `http_proxy.py` | Path 3: Streamable HTTP gateway, allowlist, SSE buffering, OAuth rewriting, request log |
| `web_gateway.py` | Path 3: `tutut web` (gateway + quick tunnel, health check, secret handling) |
| `gui.py` | `PopupManager` queue and `PopupResult` (thread-safe layer) |
| `popup_ui.py` | The approval window: rounded canvas components, risk badge, highlighted JSON, arming delay, countdown |
| `risk.py` | Risk level from MCP tool annotations (learned from `tools/list`) and tool names, combined pessimistically |
| `audit.py` | `AuditLog` (redaction, never breaks proxying), `tutut log` |
| `store.py` | SQLite audit store: WAL for concurrent writers, indexed queries, SQL aggregates for the dashboard, retention, schema versioning, JSONL import |
| `dashboard.py`, `dashboard_static/` | `tutut dashboard`: local read-only web UI — JSON API over the audit log, live feed via Server-Sent Events, token→cookie auth, localhost-only Host check, strict CSP |
| `rules.py`, `models.py`, `config.py` | Rules, JSON-RPC model / blocked reply, configuration |
| `autowrap.py`, `service.py`, `setup_helper.py` | Desktop config wrapping, background watcher, install/uninstall |
| `examples/demo_server.py` | Demo remote MCP server for testing and the demo video |
