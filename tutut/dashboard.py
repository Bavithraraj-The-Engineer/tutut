"""
`tutut dashboard` - a local, read-only web dashboard for tutut.

Queries the audit database every tutut process writes to (stdio proxies and
the web gateway) - all filtering and aggregation happens in SQL, so it stays
fast as history grows - plus the watcher / Claude Desktop / gateway status,
and serves them on http://127.0.0.1:<port>:

    GET /             the page (static HTML/JS/CSS, no third-party code)
    GET /api/events   recent decisions (filters: window, decision, path, server, q)
    GET /api/stats    totals, timeline, top tools, decision times
    GET /api/status   watcher, guarded Desktop servers, web gateway, rules
    GET /api/stream   Server-Sent Events: each new audit record, live

Security - the page shows tool arguments, so:
  - binds to 127.0.0.1 only; requests whose Host isn't localhost are
    refused (defeats DNS rebinding from a malicious web page);
  - a random token is printed at start; opening /?token=… swaps it for an
    HttpOnly, SameSite=Strict cookie and redirects (token leaves the URL);
  - strict Content-Security-Policy: only the dashboard's own script runs;
  - the frontend renders all audit data as text, never HTML (tool
    arguments can carry prompt-injected content).
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hmac
import json
import logging
import os
import secrets
from pathlib import Path
from typing import Any

from aiohttp import web

from . import autowrap
from .config import GuardianConfig
from .store import SQLiteStore, path_of  # noqa: F401  (path_of re-exported)

logger = logging.getLogger(__name__)

DEFAULT_PORT = 8020
STATIC_DIR = Path(__file__).parent / "dashboard_static"
COOKIE = "tutut_dashboard"
_STATIC = {  # exact paths only - nothing else is served from disk
    "/": ("index.html", "text/html"),
    "/app.js": ("app.js", "application/javascript"),
    "/style.css": ("style.css", "text/css"),
}
_LOCAL_HOSTNAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

# window -> (length, number of timeline buckets); "all" is bucketed by day
WINDOWS: dict[str, tuple[dt.timedelta | None, int]] = {
    "1h": (dt.timedelta(hours=1), 12),
    "24h": (dt.timedelta(hours=24), 24),
    "7d": (dt.timedelta(days=7), 28),
    "all": (None, 0),
}
MAX_ALL_DAYS = 60
DECISIONS = ("allow", "block", "cancelled")


# -- data -----------------------------------------------------------------------


def _iso(ms: int, tz: dt.tzinfo | None) -> str:
    return dt.datetime.fromtimestamp(ms / 1000, tz or dt.timezone.utc).isoformat()


def window_bounds(store: SQLiteStore, *, now: dt.datetime, window: str) -> dict[str, Any]:
    """since_ms (None = no lower bound) and the timeline grid for a window."""
    now_ms = int(now.timestamp() * 1000)
    length, count = WINDOWS.get(window, WINDOWS["24h"])
    if length is not None:
        span = int(length.total_seconds() * 1000)
        return {"since_ms": now_ms - span, "start_ms": now_ms - span,
                "bucket_ms": span // count, "buckets": count}
    first = store.first_ts_ms()  # "all": one bucket per day, at most MAX_ALL_DAYS
    if first is None:
        return {"since_ms": None, "start_ms": now_ms, "bucket_ms": 86_400_000, "buckets": 0}
    first_day = dt.datetime.fromtimestamp(first / 1000, now.tzinfo).replace(
        hour=0, minute=0, second=0, microsecond=0)
    days = max(1, min((now - first_day).days + 1, MAX_ALL_DAYS))  # >=1 even with clock skew
    return {"since_ms": None, "start_ms": now_ms - days * 86_400_000,
            "bucket_ms": 86_400_000, "buckets": days}


def compute_stats(store: SQLiteStore, *, now: dt.datetime, window: str = "24h") -> dict[str, Any]:
    window = window if window in WINDOWS else "24h"
    b = window_bounds(store, now=now, window=window)
    s = store.stats(since_ms=b["since_ms"], start_ms=b["start_ms"],
                    bucket_ms=b["bucket_ms"], buckets=max(b["buckets"], 1))
    totals = {d: s["totals"].get(d, 0) for d in DECISIONS}
    total = sum(s["totals"].values())
    buckets = [] if not b["buckets"] else [
        {"start": _iso(b["start_ms"] + i * b["bucket_ms"], now.tzinfo), **counts}
        for i, counts in enumerate(s["timeline"][: b["buckets"]])
    ]
    return {
        "window": window,
        "now": now.isoformat(),
        "totals": {"total": total, **totals},
        "block_rate": round(totals["block"] / total, 3) if total else None,
        "by_path": s["by_path"],
        "decided_by": s["decided_by"],
        "servers": s["servers"],
        "top_tools": s["top_tools"],
        "user_wait_ms": s["user_wait_ms"],
        "timeline": {"bucket_seconds": b["bucket_ms"] // 1000, "buckets": buckets},
    }


def query_events(store: SQLiteStore, *, now: dt.datetime, window: str = "24h", decision: str = "",
                 path: str = "", server: str = "", q: str = "", limit: int = 200,
                 before_id: int | None = None) -> tuple[int, list[dict[str, Any]]]:
    """(total matching, newest-first page)."""
    since = window_bounds(store, now=now, window=window)["since_ms"] if window != "all" else None
    return store.events(limit=limit, since_ms=since, decision=decision, path=path,
                        server=server, q=q, before_id=before_id)


# -- status ---------------------------------------------------------------------


def _pid_alive(pid: Any) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError, TypeError):
        return False


def collect_status(
    config: GuardianConfig,
    *,
    claude_config: Path | None = None,
    gateway_state: Path | None = None,
    store: SQLiteStore | None = None,
) -> dict[str, Any]:
    from .service import autostart_path, running_watcher_pid
    from .setup_helper import get_claude_config_path
    from .web_gateway import GATEWAY_STATE_FILE

    pid = running_watcher_pid()
    cfg_path = claude_config or get_claude_config_path()
    text = autowrap.read_config_text(cfg_path)
    desktop = autowrap.parse_config(text, cfg_path) if text else None
    servers = (desktop or {}).get("mcpServers") or {}
    guarded = autowrap.wrapped_servers(desktop or {})
    unguarded = [n for n, e in servers.items()
                 if n not in guarded and isinstance(e, dict) and e.get("command")]
    remote = []
    for name in guarded:
        original = autowrap.unwrap_entry(servers[name]) or {}
        args = original.get("args") or []
        if "mcp-remote" in args:
            remote.append(name)

    gateway: dict[str, Any] = {"running": False}
    state_path = gateway_state or GATEWAY_STATE_FILE
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if _pid_alive(state.get("pid")):
            gateway = {"running": True, **{k: state.get(k) for k in (
                "server_name", "upstream", "public_url", "reachable", "allowlist", "tunnel", "started")}}
    except (OSError, ValueError):
        pass

    return {
        "watcher": {"running": pid is not None, "pid": pid, "autostart": autostart_path().exists()},
        "desktop": {
            "config_path": str(cfg_path),
            "found": text is not None,
            "guarded": guarded,
            "remote": remote,
            "unguarded": unguarded,
        },
        "gateway": gateway,
        "policy": {
            "popup_timeout": config.popup_timeout,
            "block_when_headless": config.block_when_headless,
            "rules": [
                {"server": r.server_pattern, "tool": r.tool_pattern,
                 "action": r.action.value, "description": r.description}
                for r in config.rules
            ],
        },
        "audit": {
            "path": str(config.audit_db),
            "records": store.count() if store else None,
            "size_bytes": store.size_bytes() if store else 0,
            "retention_days": config.audit_retention_days,
        },
    }


# -- web app --------------------------------------------------------------------


class Dashboard:
    def __init__(
        self,
        config: GuardianConfig,
        *,
        token: str,
        claude_config: Path | None = None,
        gateway_state: Path | None = None,
        poll_interval: float = 0.5,
        heartbeat: float = 15.0,
        clock: Any = None,
    ) -> None:
        self._clock = clock or (lambda: dt.datetime.now().astimezone())
        self.config = config
        self.token = token
        self.claude_config = claude_config
        self.gateway_state = gateway_state
        # Readers never prune; the first open imports a legacy audit.jsonl.
        self.store = SQLiteStore(config.audit_db, retention_days=0, legacy_jsonl=config.audit_file)
        self.poll_interval = poll_interval
        self.heartbeat = heartbeat

    # -- middleware --

    @web.middleware
    async def guard(self, request: web.Request, handler: Any) -> web.StreamResponse:
        hostname = request.host.rsplit(":", 1)[0] if not request.host.startswith("[") else request.host.split("]")[0] + "]"
        if hostname.lower() not in _LOCAL_HOSTNAMES:
            return web.Response(status=403, text="Forbidden: the dashboard only answers on localhost")

        given = request.query.get("token")
        if request.path == "/" and given is not None:
            if not hmac.compare_digest(given, self.token):
                return self._unauthorized()
            resp = web.HTTPFound("/")
            resp.set_cookie(COOKIE, self.token, httponly=True, samesite="Strict", path="/")
            raise resp

        if not hmac.compare_digest(request.cookies.get(COOKIE, ""), self.token):
            return self._unauthorized()

        resp = await handler(request)
        if not resp.prepared:  # streamed responses set their own headers
            resp.headers["Content-Security-Policy"] = CSP
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Referrer-Policy"] = "no-referrer"
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @staticmethod
    def _unauthorized() -> web.Response:
        return web.Response(
            status=401,
            text="Unauthorized. Open the link printed by `tutut dashboard` (it includes a one-time token).",
            headers={"Content-Security-Policy": CSP},
        )

    # -- handlers --

    async def static(self, request: web.Request) -> web.Response:
        name, ctype = _STATIC[request.path]
        body = (STATIC_DIR / name).read_bytes()
        return web.Response(body=body, content_type=ctype, charset="utf-8")

    def _now(self) -> dt.datetime:
        return self._clock()

    async def events(self, request: web.Request) -> web.Response:
        q = request.query
        try:
            limit = max(1, min(int(q.get("limit", "200")), 1000))
            before = int(q["before"]) if q.get("before") else None
        except ValueError:
            limit, before = 200, None
        total, rows = query_events(
            self.store, now=self._now(), window=q.get("window", "24h"),
            decision=q.get("decision", ""), path=q.get("path", ""),
            server=q.get("server", ""), q=q.get("q", ""), limit=limit, before_id=before,
        )
        return web.json_response({"count": total, "events": rows})

    async def stats(self, request: web.Request) -> web.Response:
        return web.json_response(
            compute_stats(self.store, now=self._now(), window=request.query.get("window", "24h"))
        )

    async def status(self, request: web.Request) -> web.Response:
        return web.json_response(collect_status(
            self.config, claude_config=self.claude_config,
            gateway_state=self.gateway_state, store=self.store,
        ))

    async def stream(self, request: web.Request) -> web.StreamResponse:
        """Push each newly recorded audit row as an SSE event (polls by id)."""
        resp = web.StreamResponse(headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": CSP,
        })
        await resp.prepare(request)
        last = self.store.max_id()
        loop = asyncio.get_running_loop()
        last_beat = loop.time()
        try:
            await resp.write(b"retry: 3000\n: connected\n\n")
            while True:
                for entry in self.store.since_id(last):
                    last = entry["id"]
                    data = json.dumps(entry, ensure_ascii=False)
                    await resp.write(f"event: audit\ndata: {data}\n\n".encode("utf-8"))
                if loop.time() - last_beat >= self.heartbeat:
                    await resp.write(b": ping\n\n")
                    last_beat = loop.time()
                await asyncio.sleep(self.poll_interval)
        except (ConnectionResetError, ConnectionError):
            pass  # browser tab closed
        return resp


def build_app(dash: Dashboard) -> web.Application:
    app = web.Application(middlewares=[dash.guard])
    for route in _STATIC:
        app.router.add_get(route, dash.static)
    app.router.add_get("/api/events", dash.events)
    app.router.add_get("/api/stats", dash.stats)
    app.router.add_get("/api/status", dash.status)
    app.router.add_get("/api/stream", dash.stream)
    return app


async def run_dashboard(config: GuardianConfig, *, port: int = DEFAULT_PORT, open_browser: bool = True) -> None:
    from .stdio_proxy import install_sigterm_handler

    install_sigterm_handler(asyncio.get_running_loop())
    token = secrets.token_urlsafe(24)
    dash = Dashboard(config, token=token)
    runner = web.AppRunner(build_app(dash), access_log=None, handler_cancellation=True)
    await runner.setup()
    try:
        await web.TCPSite(runner, host="127.0.0.1", port=port).start()
    except OSError as exc:
        await runner.cleanup()
        raise SystemExit(f"Error: can't listen on 127.0.0.1:{port} ({exc.strerror}). Try --port.")

    url = f"http://127.0.0.1:{port}/?token={token}"
    print(f"\n  tutut dashboard:  {url}\n", flush=True)
    print("  Local only; the link's token is the password (it's swapped for a cookie on first open).")
    print("  Ctrl+C to stop.\n", flush=True)
    if open_browser:
        import webbrowser

        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()
