"""
Tests for the local dashboard (`tutut dashboard`).

Run with: python -m pytest tests/test_dashboard.py -v
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

pytest.importorskip("aiohttp")
from aiohttp.test_utils import TestClient, TestServer  # noqa: E402

from tutut import autowrap  # noqa: E402
from tutut.config import GuardianConfig  # noqa: E402
from tutut.dashboard import (  # noqa: E402
    COOKIE, Dashboard, build_app, collect_status, compute_stats, path_of, query_events,
)
from tutut.store import SQLiteStore  # noqa: E402
from tutut.models import Rule, RuleAction  # noqa: E402

TOKEN = "test-token-123"
NOW = dt.datetime(2026, 11, 19, 12, 0, tzinfo=dt.timezone.utc)


def record(minutes_ago, decision, *, server="notes", tool="list_notes", by="user", wait=1000,
           transport="stdio", source="Claude Desktop (local server)", args=None):
    return {
        "ts": (NOW - dt.timedelta(minutes=minutes_ago)).isoformat(timespec="milliseconds"),
        "transport": transport, "source": source, "server": server, "tool": tool,
        "arguments": args or {}, "decision": decision, "decided_by": by, "wait_ms": wait,
    }


ENTRIES = [
    record(3 * 24 * 60, "allow", tool="old_tool"),                       # outside 24h
    record(300, "allow", wait=2000),
    record(200, "block", tool="delete_note", wait=6000, args={"title": "secrets"}),
    record(100, "allow", transport="http", source="claude.ai / Anthropic cloud (via tunnel)", wait=4000),
    record(50, "block", by="rule", tool="delete_note", wait=0,
           source="Claude Desktop → mcp-remote → http://127.0.0.1:8931/mcp"),
    record(10, "cancelled", by="client", tool="add_note", wait=30000),
]


def make_store(tmp_path: Path, entries) -> SQLiteStore:
    store = SQLiteStore(tmp_path / "audit.db", retention_days=0)
    store.insert_many(entries)
    return store


# -- pure functions --------------------------------------------------------------


def test_path_of():
    assert [path_of(e) for e in ENTRIES[1:5]] == ["local", "local", "web", "remote"]


def test_query_events(tmp_path):
    store = make_store(tmp_path, ENTRIES)
    count = lambda **kw: query_events(store, now=NOW, **kw)[0]  # noqa: E731
    assert count(window="24h") == 5
    assert count(window="all") == 6
    total, rows = query_events(store, now=NOW, decision="block")
    assert total == 2 and [e["tool"] for e in rows] == ["delete_note"] * 2
    assert count(path="web") == 1
    assert count(q="SECRETS") == 1   # searches arguments, case-insensitive
    assert count(window="1h") == 2
    # paging: newest first, then older than the last id seen
    _, page1 = query_events(store, now=NOW, window="all", limit=4)
    _, page2 = query_events(store, now=NOW, window="all", limit=4, before_id=page1[-1]["id"])
    assert [e["id"] for e in page1 + page2] == sorted((e["id"] for e in page1 + page2), reverse=True)
    assert len(page1) == 4 and len(page2) == 2


def test_compute_stats_24h(tmp_path):
    s = compute_stats(make_store(tmp_path, ENTRIES), now=NOW, window="24h")
    assert s["totals"] == {"total": 5, "allow": 2, "block": 2, "cancelled": 1}
    assert s["block_rate"] == 0.4
    assert s["by_path"] == {"local": 3, "web": 1, "remote": 1}
    assert s["decided_by"] == {"user": 3, "rule": 1, "client": 1}
    assert s["top_tools"][0]["tool"] == "delete_note" and s["top_tools"][0]["block"] == 2
    assert s["user_wait_ms"] == {"count": 3, "median": 4000, "p95": 6000, "max": 6000}
    buckets = s["timeline"]["buckets"]
    assert len(buckets) == 24 and s["timeline"]["bucket_seconds"] == 3600
    assert sum(b["allow"] + b["block"] + b["cancelled"] for b in buckets) == 5


def test_compute_stats_all_days_and_empty(tmp_path):
    s = compute_stats(make_store(tmp_path, ENTRIES), now=NOW, window="all")
    assert s["timeline"]["bucket_seconds"] == 86400
    assert sum(sum(b[d] for d in ("allow", "block", "cancelled")) for b in s["timeline"]["buckets"]) == 6
    empty = compute_stats(SQLiteStore(tmp_path / "empty.db"), now=NOW, window="7d")
    assert empty["totals"]["total"] == 0 and empty["block_rate"] is None
    assert len(empty["timeline"]["buckets"]) == 28
    # A record from slightly in the future (clock skew between processes) must not break "all".
    (tmp_path / "skew").mkdir()
    skew = compute_stats(make_store(tmp_path / "skew", [record(-5, "allow")]), now=NOW, window="all")
    assert sum(b["allow"] for b in skew["timeline"]["buckets"]) == 1


def test_collect_status(tmp_path):
    claude = tmp_path / "claude_desktop_config.json"
    local = autowrap.wrap_entry("fs", {"command": "npx", "args": ["server-filesystem"]}, command="/x/tutut", gui=[])
    remote = autowrap.wrap_entry("notes", {"command": "npx", "args": ["-y", "mcp-remote", "http://h/mcp"]},
                                 command="/x/tutut", gui=[])
    claude.write_text(json.dumps({"mcpServers": {"fs": local, "notes": remote,
                                                 "raw": {"command": "uvx", "args": ["thing"]}}}))
    state = tmp_path / "web_gateway.json"
    state.write_text(json.dumps({"pid": os.getpid(), "public_url": "https://x.trycloudflare.com/mcp",
                                 "upstream": "http://u/mcp", "server_name": "notes", "allowlist": ["160.79.104.0/21"]}))
    config = GuardianConfig(rules=[Rule("fs", "read_*", RuleAction.ALLOW)], audit_db=str(tmp_path / "a.db"))

    st = collect_status(config, claude_config=claude, gateway_state=state)
    assert st["desktop"]["guarded"] == ["fs", "notes"]
    assert st["desktop"]["remote"] == ["notes"]
    assert st["desktop"]["unguarded"] == ["raw"]
    assert st["gateway"]["running"] and st["gateway"]["public_url"].endswith("/mcp")
    assert st["policy"]["rules"][0] == {"server": "fs", "tool": "read_*", "action": "allow", "description": ""}

    state.write_text(json.dumps({"pid": 999_999_999}))  # dead process
    assert collect_status(config, claude_config=claude, gateway_state=state)["gateway"] == {"running": False}


# -- HTTP ----------------------------------------------------------------------------


async def _client(tmp_path, entries=ENTRIES):
    audit = tmp_path / "audit.db"
    make_store(tmp_path, entries).close()
    config = GuardianConfig(audit_db=str(audit), audit_file=str(tmp_path / "none.jsonl"))
    dash = Dashboard(config, token=TOKEN, claude_config=tmp_path / "none.json",
                     gateway_state=tmp_path / "none-gw.json", poll_interval=0.05, clock=lambda: NOW)
    client = TestClient(TestServer(build_app(dash)))
    await client.start_server()
    return client, audit


AUTH = {"Cookie": f"{COOKIE}={TOKEN}"}


def test_auth_flow_and_security_headers(tmp_path):
    async def scenario():
        client, _ = await _client(tmp_path)
        try:
            out = {}
            out["no_cookie"] = (await client.get("/")).status
            out["api_no_cookie"] = (await client.get("/api/stats")).status
            out["bad_token"] = (await client.get("/?token=nope", allow_redirects=False)).status
            r = await client.get(f"/?token={TOKEN}", allow_redirects=False)
            out["good_token"] = r.status
            out["location"] = r.headers.get("Location")
            out["set_cookie"] = r.headers.get("Set-Cookie", "")
            page = await client.get("/", headers=AUTH)
            out["page"] = page.status
            out["csp"] = page.headers.get("Content-Security-Policy", "")
            out["nosniff"] = page.headers.get("X-Content-Type-Options")
            out["html"] = await page.text()
            out["css_type"] = (await client.get("/style.css", headers=AUTH)).headers["Content-Type"]
            out["traversal"] = (await client.get("/dashboard_static/../dashboard.py", headers=AUTH)).status
            out["rebinding"] = (await client.get("/api/stats", headers={**AUTH, "Host": "evil.example:8020"})).status
            return out
        finally:
            await client.close()

    out = asyncio.run(scenario())
    assert (out["no_cookie"], out["api_no_cookie"], out["bad_token"]) == (401, 401, 401)
    assert out["good_token"] == 302 and out["location"] == "/"
    assert "HttpOnly" in out["set_cookie"] and "SameSite=Strict" in out["set_cookie"]
    assert out["page"] == 200 and "app.js" in out["html"]
    assert "script-src 'self'" in out["csp"] and "frame-ancestors 'none'" in out["csp"]
    assert out["nosniff"] == "nosniff"
    assert out["css_type"].startswith("text/css")
    assert out["traversal"] == 404
    assert out["rebinding"] == 403


def test_events_and_stats_api(tmp_path):
    async def scenario():
        client, _ = await _client(tmp_path)
        try:
            ev = await (await client.get("/api/events?window=24h&decision=block", headers=AUTH)).json()
            st = await (await client.get("/api/stats?window=24h", headers=AUTH)).json()
            status = await (await client.get("/api/status", headers=AUTH)).json()
            return ev, st, status
        finally:
            await client.close()

    ev, st, status = asyncio.run(scenario())
    assert ev["count"] == 2 and [e["path"] for e in ev["events"]] == ["remote", "local"]  # newest first
    assert st["totals"]["total"] == 5
    assert status["desktop"]["found"] is False and status["audit"]["records"] == 6


def test_stream_pushes_new_records(tmp_path):
    async def scenario():
        client, audit = await _client(tmp_path)
        try:
            resp = await client.get("/api/stream", headers=AUTH)
            assert resp.headers["Content-Type"].startswith("text/event-stream")
            await asyncio.sleep(0.2)
            writer = SQLiteStore(audit)  # another process/connection appending
            writer.record(record(0, "block", tool="live_tool", transport="http"))
            writer.close()
            buf = b""
            async def read_event():
                nonlocal buf
                while b"event: audit" not in buf or not buf.endswith(b"\n\n"):
                    buf += await resp.content.readany()
            await asyncio.wait_for(read_event(), timeout=5)
            resp.close()
            return buf.decode()
        finally:
            await client.close()

    text = asyncio.run(scenario())
    data = json.loads(text.split("event: audit\ndata: ", 1)[1].split("\n", 1)[0])
    assert data["tool"] == "live_tool" and data["path"] == "web"
