"""
Tests for the three interception paths and the shared core:

  - audit log (redaction, JSONL records)
  - Interceptor (rules, popup decisions, "remember", cancellation)
  - stdio proxy: concurrency, cancellation, oversized messages, server exit,
    and an end-to-end run of `tutut stdio` against a real server process
  - HTTP gateway: secret path, path mapping, header handling, SSE, OAuth
    metadata rewriting - forwarding to the real demo server
  - mcp-remote entries (add-remote / remove-remote)
  - web gateway helpers (secret, quick tunnel URL detection)

Run with: python -m pytest tests/test_paths.py -v
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import subprocess
import sys
import textwrap
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "examples"))

from tutut.audit import AuditLog, format_entry, read_entries, redact  # noqa: E402
from tutut.config import GuardianConfig  # noqa: E402
from tutut.gui import PopupResult  # noqa: E402
from tutut.interceptor import Interceptor, Verdict  # noqa: E402
from tutut.models import Decision, JsonRpcMessage, Rule, RuleAction  # noqa: E402
from tutut.stdio_proxy import StdioProxy, describe_source, read_message  # noqa: E402


def tool_call(name: str, msg_id=1, arguments=None) -> JsonRpcMessage:
    return JsonRpcMessage(raw={
        "jsonrpc": "2.0", "id": msg_id, "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    })


# =============================================================================
# Audit log
# =============================================================================


class TestAudit:
    def test_redacts_secret_keys_recursively(self):
        out = redact({
            "path": "/tmp/x",
            "api_key": "sk-123",
            "nested": {"Authorization": "Bearer abc", "password": "hunter2", "ok": 1},
            "token": "",  # empty values aren't masked (nothing to hide)
        })
        assert out["path"] == "/tmp/x"
        assert out["api_key"] == "***"
        assert out["nested"] == {"Authorization": "***", "password": "***", "ok": 1}
        assert out["token"] == ""

    def test_truncates_long_values(self):
        out = redact({"content": "x" * 1000})
        assert out["content"].startswith("x" * 300)
        assert "+700 chars" in out["content"]

    def test_record_writes_owner_only_db(self, tmp_path):
        path = tmp_path / "audit.db"
        log = AuditLog(path)
        log.record(transport="stdio", source="s", server="fs", tool="read_file",
                   arguments={"path": "/a"}, decision="allow", decided_by="user", wait_ms=12)
        log.record(transport="http", source="s", server="fs", tool="write_file",
                   arguments={"secret": "x"}, decision="block", decided_by="rule")
        entries = read_entries(path)
        assert [e["decision"] for e in entries] == ["allow", "block"]
        assert entries[1]["arguments"] == {"secret": "***"}
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert "BLOCK" in format_entry(entries[1]) and "fs/write_file" in format_entry(entries[1])

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    def test_existing_world_readable_files_are_made_private(self, tmp_path):
        from tutut.audit import follow

        loose = tmp_path / "audit.db"
        loose.write_text("")
        loose.chmod(0o664)  # e.g. created by an older `tutut log -f`
        AuditLog(loose).record(transport="stdio", source="", server="s", tool="t",
                               arguments={}, decision="allow", decided_by="rule")
        assert stat.S_IMODE(loose.stat().st_mode) == 0o600

        fresh = tmp_path / "followed.jsonl"
        gen = follow(fresh, poll=0.01)  # creates the file on first next()
        import threading as _t
        _t.Timer(0.05, lambda: AuditLog(fresh).record(transport="stdio", source="", server="s", tool="t",
                                                      arguments={}, decision="block", decided_by="rule")).start()
        assert next(gen)["decision"] == "block"
        assert stat.S_IMODE(fresh.stat().st_mode) == 0o600

        from tutut.config import setup_logging
        log = tmp_path / "tutut.log"
        log.write_text("")
        log.chmod(0o664)
        setup_logging(GuardianConfig(log_file=str(log)), stderr=False)
        assert stat.S_IMODE(log.stat().st_mode) == 0o600

    def test_disabled_log_writes_nothing(self, tmp_path):
        entry = AuditLog(None).record(transport="stdio", source="", server="s", tool="t",
                                      arguments={}, decision="allow", decided_by="rule")
        assert entry["tool"] == "t"
        assert list(tmp_path.iterdir()) == []


# =============================================================================
# Interceptor (shared decision engine)
# =============================================================================


class FakePopups:
    """Stands in for PopupManager: decides from another thread."""

    def __init__(self, decision=Decision.ALLOW, remember=False, delay=0.05, reason="user"):
        self.decision, self.remember, self.delay, self.reason = decision, remember, delay, reason
        self.requests, self.cancelled = [], []
        self._results = {}

    def request_decision(self, request):
        self.requests.append(request)
        result = PopupResult()
        self._results[request.id] = result
        if self.delay is not None:
            threading.Timer(
                self.delay, result.set, args=(self.decision, self.remember, self.reason)
            ).start()
        return result

    def cancel(self, request_id):
        self.cancelled.append(request_id)
        return self._results[request_id].set(Decision.BLOCK, reason="cancelled")


def make_interceptor(tmp_path, rules=(), popups=None, gui=True, config=None):
    config = config or GuardianConfig(rules=list(rules))
    return Interceptor(
        config, server_name="srv", transport="stdio", source="test",
        popup_manager=popups or FakePopups(), gui_available=gui,
        audit=AuditLog(tmp_path / "audit.db"),
    )


class TestInterceptor:
    def test_rules_decide_without_popup(self, tmp_path):
        popups = FakePopups()
        icp = make_interceptor(tmp_path, rules=[
            Rule("srv", "safe", RuleAction.ALLOW), Rule("srv", "rm", RuleAction.BLOCK),
        ], popups=popups)
        assert asyncio.run(icp.decide(tool_call("safe"))) .allowed
        verdict = asyncio.run(icp.decide(tool_call("rm")))
        assert not verdict.allowed and verdict.decided_by == "rule"
        assert popups.requests == []
        assert [e["decided_by"] for e in read_entries(tmp_path / "audit.db")] == ["rule", "rule"]

    def test_user_decision_via_popup(self, tmp_path):
        popups = FakePopups(Decision.BLOCK)
        icp = make_interceptor(tmp_path, popups=popups)
        verdict = asyncio.run(icp.decide(tool_call("write_file", arguments={"path": "/x"})))
        assert not verdict.allowed and verdict.decided_by == "user"
        assert popups.requests[0].source == "test"
        entry = read_entries(tmp_path / "audit.db")[-1]
        assert (entry["tool"], entry["decision"], entry["arguments"]) == ("write_file", "block", {"path": "/x"})

    def test_timeout_reason_propagates(self, tmp_path):
        icp = make_interceptor(tmp_path, popups=FakePopups(Decision.BLOCK, reason="timeout"))
        assert asyncio.run(icp.decide(tool_call("t"))).decided_by == "timeout"

    def test_headless_fails_closed(self, tmp_path):
        icp = make_interceptor(tmp_path, gui=False)
        verdict = asyncio.run(icp.decide(tool_call("t")))
        assert (verdict.allowed, verdict.decided_by) == (False, "headless")

    def test_remember_persists_without_clobbering_other_settings(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        GuardianConfig(web_secret="keep-me").save(cfg_path)
        stale = GuardianConfig.load(cfg_path)
        # Another process changes the file after this one loaded it.
        other = GuardianConfig.load(cfg_path)
        other.popup_timeout = 30
        other.save(cfg_path)

        icp = make_interceptor(tmp_path, popups=FakePopups(Decision.ALLOW, remember=True), config=stale)
        asyncio.run(icp.decide(tool_call("read_file")))
        saved = GuardianConfig.load(cfg_path)
        assert saved.web_secret == "keep-me" and saved.popup_timeout == 30
        assert (saved.rules[0].tool_pattern, saved.rules[0].action) == ("read_file", RuleAction.ALLOW)
        # ...and it applies at once in this process.
        assert icp.rules.evaluate("srv", "read_file") == RuleAction.ALLOW

    def test_cancellation_withdraws_popup(self, tmp_path):
        popups = FakePopups(delay=None)  # never answered

        async def scenario():
            task = asyncio.create_task(make_interceptor(tmp_path, popups=popups).decide(tool_call("t")))
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        asyncio.run(scenario())
        assert len(popups.cancelled) == 1
        assert read_entries(tmp_path / "audit.db")[-1]["decision"] == "cancelled"


class TestPopupResult:
    def test_first_set_wins_and_callbacks_fire(self):
        r = PopupResult()
        seen = []
        r.add_done_callback(lambda res: seen.append(res.decision))
        assert r.set(Decision.ALLOW, reason="user")
        assert not r.set(Decision.BLOCK, reason="timeout")
        assert (r.decision, r.reason, seen) == (Decision.ALLOW, "user", [Decision.ALLOW])
        late = []
        r.add_done_callback(lambda res: late.append(res.reason))
        assert late == ["user"]


# =============================================================================
# stdio proxy - in process
# =============================================================================


class FakeServerStdin:
    def __init__(self):
        self.lines: list[bytes] = []
        self._closed = False

    def write(self, data):
        self.lines.append(data)

    async def drain(self):
        pass

    def is_closing(self):
        return self._closed

    def close(self):
        self._closed = True

    def ids(self):
        return [json.loads(l).get("id") for l in self.lines if l.strip().startswith(b"{")]


class GatedInterceptor:
    """decide(): 'slow' waits for release(); everything else is allowed at once."""

    def __init__(self):
        self.gate = asyncio.Event()
        self.cancelled = []
        self.gui_available = True
        self.rules = None

    async def decide(self, msg, extra=None):
        if msg.tool_name == "slow":
            try:
                await self.gate.wait()
            except asyncio.CancelledError:
                self.cancelled.append(msg.id)
                raise
        return Verdict(True, "rule")


def make_stdio_proxy(interceptor):
    proxy = StdioProxy(["server"], "srv", GuardianConfig(), interceptor=interceptor)
    proxy._process = MagicMock()
    proxy._process.stdin = FakeServerStdin()
    proxy._server_write_lock = asyncio.Lock()
    return proxy


def line(obj) -> bytes:
    return json.dumps(obj).encode() + b"\n"


class TestStdioProxyConcurrency:
    def test_pending_call_does_not_block_other_messages(self):
        async def scenario():
            icp = GatedInterceptor()
            proxy = make_stdio_proxy(icp)
            reader = asyncio.StreamReader()
            reader.feed_data(line(tool_call("slow", 1).raw))
            reader.feed_data(line(tool_call("fast", 2).raw))
            reader.feed_data(line({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}))
            pipe = asyncio.create_task(proxy._pipe_client_to_server(reader))
            await asyncio.sleep(0.05)
            before = proxy._process.stdin.ids()
            icp.gate.set()
            await asyncio.sleep(0.05)
            after = proxy._process.stdin.ids()
            reader.feed_eof()
            await pipe
            return before, after

        before, after = asyncio.run(scenario())
        # id 1 still waiting for the user; 2 and 3 went through meanwhile
        # (in either order - replies are matched by id).
        assert sorted(before) == [2, 3]
        assert sorted(after) == [1, 2, 3]

    def test_client_cancel_withdraws_pending_call(self):
        async def scenario():
            icp = GatedInterceptor()
            proxy = make_stdio_proxy(icp)
            reader = asyncio.StreamReader()
            pipe = asyncio.create_task(proxy._pipe_client_to_server(reader))
            reader.feed_data(line(tool_call("slow", 5).raw))
            await asyncio.sleep(0.05)  # the popup is now open
            reader.feed_data(line({"jsonrpc": "2.0", "method": "notifications/cancelled",
                                   "params": {"requestId": 5, "reason": "timeout"}}))
            reader.feed_eof()
            await pipe
            await asyncio.sleep(0.05)
            return icp, proxy

        with patch("sys.stdout") as out:
            icp, proxy = asyncio.run(scenario())
        assert icp.cancelled == [5]
        sent = [json.loads(l) for l in proxy._process.stdin.lines]
        assert [m.get("method") for m in sent] == ["notifications/cancelled"]  # call 5 never forwarded
        out.buffer.write.assert_not_called()  # and never answered (MCP spec)

    def test_oversized_request_gets_error_not_silence(self):
        async def scenario():
            proxy = make_stdio_proxy(GatedInterceptor())
            reader = asyncio.StreamReader(limit=1024)
            big = tool_call("write_file", 7, {"content": "x" * 5000}).raw
            reader.feed_data(line(big))
            reader.feed_data(line(tool_call("fast", 8).raw))  # stream stays in sync
            reader.feed_eof()
            await proxy._pipe_client_to_server(reader)
            await asyncio.sleep(0.05)
            return proxy

        with patch("sys.stdout") as out:
            proxy = asyncio.run(scenario())
        written = json.loads(out.buffer.write.call_args_list[0][0][0])
        assert written["id"] == 7 and written["error"]["code"] == -32600
        assert proxy._process.stdin.ids() == [8]

    def test_server_exit_fails_waiting_requests(self):
        proxy = make_stdio_proxy(GatedInterceptor())
        proxy._awaiting_server = {'"a"': "a", "9": 9}
        with patch("sys.stdout") as out:
            asyncio.run(proxy._fail_pending("MCP server process exited"))
        ids = sorted(str(json.loads(c[0][0])["id"]) for c in out.buffer.write.call_args_list)
        assert ids == ["9", "a"]

    def test_read_message_handles_partial_last_line(self):
        async def scenario():
            r = asyncio.StreamReader()
            r.feed_data(b'{"a":1}\n{"b":2}')
            r.feed_eof()
            return [await read_message(r) for _ in range(3)]

        assert asyncio.run(scenario()) == [(b'{"a":1}\n', None), (b'{"b":2}\n', None), (None, None)]

    def test_describe_source(self):
        assert describe_source(["npx", "-y", "mcp-remote", "https://x.dev/mcp"]) == \
            "Claude Desktop → mcp-remote → https://x.dev/mcp"
        assert describe_source(["npx", "server-filesystem"]) == "Claude Desktop (local server)"


# =============================================================================
# stdio proxy - end to end (real `tutut stdio` process + real server process)
# =============================================================================

ECHO_SERVER = textwrap.dedent("""
    import json, sys
    for raw in sys.stdin:
        msg = json.loads(raw)
        if "id" not in msg:
            continue
        if msg["method"] == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "echo", "version": "1"}}
        else:
            args = msg.get("params", {}).get("arguments", {})
            result = {"content": [{"type": "text",
                                   "text": "ran %s with %d bytes" % (msg["params"]["name"], len(json.dumps(args)))}]}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\\n")
        sys.stdout.flush()
""")


def test_stdio_end_to_end(tmp_path):
    server = tmp_path / "echo_server.py"
    server.write_text(ECHO_SERVER)
    config = tmp_path / "config.json"
    GuardianConfig(
        rules=[Rule("e2e", "read_*", RuleAction.ALLOW), Rule("e2e", "*", RuleAction.BLOCK)],
        audit_db=str(tmp_path / "audit.db"),
        log_file=str(tmp_path / "tutut.log"),
    ).save(config)

    requests = [
        {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        tool_call("read_file", 1, {"path": "/etc/hostname"}).raw,
        tool_call("delete_file", 2, {"path": "/important"}).raw,
        # ~1 MB argument: used to kill the proxy (asyncio's 64 KiB line limit)
        tool_call("read_big", 3, {"blob": "x" * 1_000_000}).raw,
    ]
    proc = subprocess.run(
        [sys.executable, "-m", "tutut", "--config", str(config), "stdio",
         "--server-name", "e2e", "--", sys.executable, str(server)],
        input=b"".join(line(r) for r in requests),
        capture_output=True, timeout=60, cwd=ROOT,
    )
    replies = {r["id"]: r for r in (json.loads(l) for l in proc.stdout.splitlines() if l.strip())}
    assert set(replies) == {0, 1, 2, 3}, proc.stderr.decode()[-2000:]
    assert replies[1]["result"]["content"][0]["text"].startswith("ran read_file")
    assert replies[2]["result"]["isError"] is True                       # blocked, never ran
    assert "delete_file" in replies[2]["result"]["content"][0]["text"]
    assert "ran read_big with 10000" in replies[3]["result"]["content"][0]["text"]
    decisions = [(e["tool"], e["decision"]) for e in read_entries(tmp_path / "audit.db")]
    assert decisions == [("read_file", "allow"), ("delete_file", "block"), ("read_big", "allow")]


def test_stdio_server_crash_with_client_still_connected(tmp_path):
    """
    The server dies while the client keeps stdin open (e.g. mcp-remote
    can't reach its URL). tutut must exit cleanly - it used to abort with
    "could not acquire lock for <stdin> at interpreter shutdown".
    """
    config = tmp_path / "config.json"
    GuardianConfig(audit_db=str(tmp_path / "audit.db"),
                   log_file=str(tmp_path / "tutut.log")).save(config)
    proc = subprocess.Popen(
        [sys.executable, "-m", "tutut", "--config", str(config), "stdio",
         "--server-name", "crash", "--", sys.executable, "-c", "import sys; sys.exit(3)"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT,
    )
    try:
        proc.wait(timeout=30)  # our end of its stdin stays open throughout
        err = proc.stderr.read()
    finally:
        proc.kill()
        proc.stdin.close()
    assert b"Fatal Python error" not in err, err.decode()[-1500:]
    assert proc.returncode == 3


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_stdio_sigterm_stops_wrapped_server(tmp_path):
    """SIGTERM to tutut must not leave the wrapped server running."""
    import signal
    import time

    config = tmp_path / "config.json"
    GuardianConfig(audit_db=str(tmp_path / "audit.db"),
                   log_file=str(tmp_path / "tutut.log")).save(config)
    # Marker built at runtime: tutut logs the command line, which must not match.
    server = ("import os, sys, time; print('CHILD' + '_PID=%d' % os.getpid(), "
              "file=sys.stderr, flush=True); time.sleep(60)")
    proc = subprocess.Popen(
        [sys.executable, "-m", "tutut", "--config", str(config), "stdio",
         "--server-name", "sleepy", "--", sys.executable, "-c", server],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT,
    )
    try:
        child = None
        deadline = time.time() + 20
        while child is None and time.time() < deadline:
            text = proc.stderr.readline().decode()
            if "CHILD_PID=" in text:
                child = int(text.split("CHILD_PID=")[1].split()[0])
        assert child, "server never started"
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=15)
        with pytest.raises(ProcessLookupError):
            os.kill(child, 0)
    finally:
        proc.kill()
        proc.stdin.close()


# =============================================================================
# HTTP gateway (forwarding to the real demo server)
# =============================================================================

aiohttp = pytest.importorskip("aiohttp")
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestClient, TestServer  # noqa: E402

import demo_server  # noqa: E402
from tutut.http_proxy import HEALTH_PATH, HttpProxy, build_app, parse_sse_messages  # noqa: E402

SECRET = "s3cr3t-path"
GATEWAY_RULES = [Rule("notes", "list_notes", RuleAction.ALLOW), Rule("notes", "*", RuleAction.BLOCK)]


async def _gateway(upstream_url, **kwargs):
    config = GuardianConfig(rules=list(GATEWAY_RULES))
    proxy = HttpProxy(upstream_url, "notes", config, secret=SECRET, **kwargs)
    proxy._gui_available = False
    client = TestClient(TestServer(build_app(proxy)))
    await client.start_server()
    return client


def _rpc(method, msg_id=1, **params):
    return {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params}


def test_gateway_secret_path_and_forwarding():
    async def scenario():
        upstream = TestServer(demo_server.build_app())
        await upstream.start_server()
        client = await _gateway(str(upstream.make_url("/mcp")))
        try:
            out = {}
            out["root"] = (await client.post("/", json=_rpc("tools/list"))).status
            out["wrong"] = (await client.post("/nope/mcp", json=_rpc("tools/list"))).status
            out["health_no_secret"] = (await client.get(HEALTH_PATH)).status
            out["health"] = (await client.get(f"/{SECRET}{HEALTH_PATH}")).status
            init = await client.post(f"/{SECRET}/mcp", json=_rpc("initialize", 0, protocolVersion="2025-06-18"))
            out["init"] = (await init.json())["result"]["serverInfo"]["name"]
            out["session"] = init.headers.get("Mcp-Session-Id")
            tools = await (await client.post(f"/{SECRET}/mcp", json=_rpc("tools/list", 2))).json()
            out["tools"] = [t["name"] for t in tools["result"]["tools"]]
            allowed = await (await client.post(
                f"/{SECRET}/mcp", json=_rpc("tools/call", 3, name="list_notes", arguments={}))).json()
            out["allowed"] = allowed["result"]["content"][0]["text"]
            blocked = await (await client.post(
                f"/{SECRET}/mcp", json=_rpc("tools/call", 4, name="delete_note", arguments={"title": "secrets"}))).json()
            out["blocked"] = blocked["result"]
            out["notes_after"] = sorted(demo_server.NOTES)
            return out
        finally:
            await client.close()
            await upstream.close()

    out = asyncio.run(scenario())
    assert (out["root"], out["wrong"], out["health_no_secret"], out["health"]) == (404, 404, 404, 200)
    assert out["init"] == "tutut-demo-notes" and out["session"]
    assert "delete_note" in out["tools"]
    assert out["allowed"].startswith("Notes:")
    assert out["blocked"]["isError"] is True
    assert "secrets" in out["notes_after"]  # the blocked delete never reached the server


def _header_echo_app(sse=False, www_auth=None, resource_meta=False):
    async def handler(request):
        if request.path.startswith("/.well-known/oauth-protected-resource"):
            return web.json_response({"resource": "https://up.example/mcp",
                                      "authorization_servers": ["https://auth.example"]})
        body = {"jsonrpc": "2.0", "id": 1, "result": {"headers": dict(request.headers), "path": request.path}}
        if www_auth:
            return web.Response(status=401, headers={"WWW-Authenticate": www_auth})
        if sse:
            text = ('event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n\n'
                    f"event: message\ndata: {json.dumps(body)}\n\n")
            return web.Response(text=text, content_type="text/event-stream")
        return web.json_response(body)

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    return app


def _run_against(app_factory, path, method="post", headers=None, **gateway_kwargs):
    async def scenario():
        upstream = TestServer(app_factory())
        await upstream.start_server()
        client = await _gateway(str(upstream.make_url("/mcp")), **gateway_kwargs)
        try:
            resp = await client.request(method, path, json=_rpc("tools/list") if method == "post" else None,
                                        headers=headers or {})
            return resp.status, dict(resp.headers), await resp.read(), str(upstream.make_url("/"))
        finally:
            await client.close()
            await upstream.close()

    return asyncio.run(scenario())


def test_gateway_header_handling():
    status, _, body, _ = _run_against(
        _header_echo_app, f"/{SECRET}/mcp",
        headers={"Authorization": "Bearer from-claude", "CF-Ray": "abc", "CDN-Loop": "cloudflare",
                 "X-Forwarded-For": "1.2.3.4", "Mcp-Session-Id": "sess-1"},
        upstream_headers={"Authorization": "Bearer local-api-key"},
    )
    seen = {k.lower(): v for k, v in json.loads(body)["result"]["headers"].items()}
    assert status == 200
    assert seen["authorization"] == "Bearer local-api-key"  # injected, client's replaced
    assert seen["mcp-session-id"] == "sess-1"                # end-to-end header kept
    assert "cf-ray" not in seen and "cdn-loop" not in seen and "x-forwarded-for" not in seen
    assert seen["accept-encoding"] == "identity"
    assert json.loads(body)["result"]["path"] == "/mcp"      # not /mcp/mcp


def test_gateway_buffers_sse_into_json_for_tunnels():
    status, headers, body, _ = _run_against(lambda: _header_echo_app(sse=True), f"/{SECRET}/mcp", buffer_sse=True)
    assert status == 200 and headers["Content-Type"].startswith("application/json")
    assert json.loads(body)["id"] == 1  # progress notification dropped, response kept

    status, headers, body, _ = _run_against(lambda: _header_echo_app(sse=True), f"/{SECRET}/mcp")
    assert headers["Content-Type"].startswith("text/event-stream")  # streamed when not buffering


def test_gateway_rewrites_oauth_discovery():
    async def handler(request):
        origin = f"http://{request.host}"  # the upstream's own address
        if request.path.startswith("/.well-known/"):
            return web.json_response({"resource": f"{origin}/mcp", "authorization_servers": ["https://a"]})
        return web.Response(status=401, headers={
            "WWW-Authenticate": f'Bearer resource_metadata="{origin}/.well-known/oauth-protected-resource/mcp"'})

    async def scenario():
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", handler)
        upstream = TestServer(app)
        await upstream.start_server()
        origin = str(upstream.make_url("")).rstrip("/")
        client = await _gateway(f"{origin}/mcp")
        try:
            r1 = await client.post(f"/{SECRET}/mcp", json=_rpc("tools/list"),
                                   headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "t.example"})
            r2 = await client.get(f"/{SECRET}/.well-known/oauth-protected-resource/mcp",
                                  headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "t.example"})
            return r1.status, r1.headers["WWW-Authenticate"], await r2.json()
        finally:
            await client.close()
            await upstream.close()

    status, www, meta = asyncio.run(scenario())
    assert status == 401
    assert www == f'Bearer resource_metadata="https://t.example/{SECRET}/.well-known/oauth-protected-resource/mcp"'
    assert meta["resource"] == f"https://t.example/{SECRET}/mcp"


def test_gateway_ip_allowlist():
    """Only allowlisted callers (CF-Connecting-IP via the local tunnel) get in."""
    async def scenario():
        upstream = TestServer(demo_server.build_app())
        await upstream.start_server()
        client = await _gateway(str(upstream.make_url("/mcp")), allowed_networks=["160.79.104.0/21"])
        try:
            body = _rpc("tools/list")

            async def status(**headers):
                return (await client.post(f"/{SECRET}/mcp", json=body, headers=headers)).status

            return {
                "anthropic": await status(**{"CF-Connecting-IP": "160.79.106.187"}),
                "stranger": await status(**{"CF-Connecting-IP": "203.0.113.9"}),
                "no_header": await status(),  # 127.0.0.1 itself isn't allowlisted
                "garbage": await status(**{"CF-Connecting-IP": "not-an-ip"}),
                "health": (await client.get(f"/{SECRET}{HEALTH_PATH}",
                                            headers={"CF-Connecting-IP": "203.0.113.9"})).status,
            }
        finally:
            await client.close()
            await upstream.close()

    assert asyncio.run(scenario()) == {
        "anthropic": 200, "stranger": 403, "no_header": 403, "garbage": 403, "health": 200,
    }


def test_client_ip_trusts_header_only_from_loopback():
    from tutut.http_proxy import client_ip

    def req(remote, header=None):
        r = MagicMock()
        r.remote = remote
        r.headers = {"CF-Connecting-IP": header} if header else {}
        return r

    assert client_ip(req("127.0.0.1", "160.79.106.1")) == "160.79.106.1"   # via cloudflared
    assert client_ip(req("::1", "160.79.106.1")) == "160.79.106.1"
    assert client_ip(req("198.51.100.7", "160.79.106.1")) == "198.51.100.7"  # spoof attempt
    assert client_ip(req("198.51.100.7")) == "198.51.100.7"


def test_parse_sse_messages():
    text = 'event: message\ndata: {"a": 1}\n\n: comment\ndata: {"b":\ndata: 2}\n\ndata: not json\n\n'
    assert parse_sse_messages(text) == [{"a": 1}, {"b": 2}]


# =============================================================================
# Demo server
# =============================================================================


def test_demo_server_tools():
    init = demo_server.handle_message(_rpc("initialize", 0, protocolVersion="2025-03-26"))
    assert init["result"]["protocolVersion"] == "2025-03-26"
    names = [t["name"] for t in demo_server.handle_message(_rpc("tools/list"))["result"]["tools"]]
    assert names == ["list_notes", "read_note", "add_note", "delete_note"]
    assert demo_server.handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert demo_server.handle_message(_rpc("nope"))["error"]["code"] == -32601


# =============================================================================
# mcp-remote entries (Claude Desktop path 2)
# =============================================================================

from tutut import remote  # noqa: E402


def _fake_node_dir(tmp_path, version):
    bin_dir = tmp_path / f"node-{version}" / "bin"
    bin_dir.mkdir(parents=True)
    node = bin_dir / "node"
    node.write_text(f"#!/bin/sh\necho v{version}\n")
    node.chmod(0o755)
    npx = bin_dir / "npx"
    npx.write_text("#!/bin/sh\nexit 0\n")
    npx.chmod(0o755)
    return npx


@pytest.mark.skipif(sys.platform == "win32", reason="uses shell-script fakes")
class TestRemote:
    def test_find_npx_rejects_old_node(self, tmp_path):
        with pytest.raises(remote.RemoteError):
            remote.find_npx(str(_fake_node_dir(tmp_path, "16.17.0")))
        npx, node_dir = remote.find_npx(str(_fake_node_dir(tmp_path, "22.20.0")))
        assert npx.endswith("/npx") and node_dir.endswith("node-22.20.0/bin")

    def test_validate_url(self):
        remote.validate_url("https://mcp.example.com/mcp", False)
        remote.validate_url("http://127.0.0.1:9000/mcp", False)
        with pytest.raises(remote.RemoteError):
            remote.validate_url("http://mcp.example.com/mcp", False)
        with pytest.raises(remote.RemoteError):
            remote.validate_url("ftp://x", True)

    def test_add_and_remove_remote(self, tmp_path):
        from tutut import autowrap

        claude_cfg = tmp_path / "claude_desktop_config.json"
        claude_cfg.write_text(json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["fs"]}}}))
        npx = str(_fake_node_dir(tmp_path, "22.20.0"))

        remote.add_remote("notes", "http://127.0.0.1:9000/mcp", headers=["X-Key: abc"],
                          claude_config=claude_cfg, npx=npx)
        servers = json.loads(claude_cfg.read_text())["mcpServers"]
        entry = servers["notes"]
        assert autowrap.is_wrapped(entry)
        original = autowrap.unwrap_entry(entry)
        assert original["command"] == npx
        assert original["args"] == ["-y", "mcp-remote", "http://127.0.0.1:9000/mcp", "--header", "X-Key: abc"]
        assert entry["env"]["PATH"].startswith(str(Path(npx).parent))
        assert servers["fs"] == {"command": "npx", "args": ["fs"]}  # others untouched

        with pytest.raises(remote.RemoteError):
            remote.add_remote("notes", "https://x.dev/mcp", claude_config=claude_cfg, npx=npx)
        remote.add_remote("notes", "https://x.dev/mcp", claude_config=claude_cfg, npx=npx, force=True)

        remote.remove_remote("notes", claude_config=claude_cfg)
        assert "notes" not in json.loads(claude_cfg.read_text())["mcpServers"]
        with pytest.raises(remote.RemoteError):
            remote.remove_remote("notes", claude_config=claude_cfg)


# =============================================================================
# Web gateway helpers
# =============================================================================

from tutut import web_gateway  # noqa: E402


def test_secret_created_once_and_rotated(tmp_path):
    import re

    cfg_path = tmp_path / "config.json"
    config = GuardianConfig.load(cfg_path)
    first = web_gateway.ensure_secret(config)
    # Word passphrase, not a random token (claude.ai rejects token-like paths).
    assert re.fullmatch(r"[a-z]{4}(-[a-z]{4}){4}", first), first
    assert web_gateway.ensure_secret(GuardianConfig.load(cfg_path)) == first
    assert stat.S_IMODE(cfg_path.stat().st_mode) == 0o600
    rotated = web_gateway.ensure_secret(GuardianConfig.load(cfg_path), rotate=True)
    assert rotated != first and GuardianConfig.load(cfg_path).web_secret == rotated
    # An old-format token secret is replaced.
    old = GuardianConfig.load(cfg_path)
    old.web_secret = "YgeFLxgXoRfaNkP_a0GrNcb_ekcKl1Uj"
    old.save()
    assert re.fullmatch(r"[a-z]{4}(-[a-z]{4}){4}", web_gateway.ensure_secret(GuardianConfig.load(cfg_path)))


def test_anthropic_ranges_cover_observed_claude_ai_ips():
    from tutut.http_proxy import parse_networks

    nets = parse_networks(web_gateway.ANTHROPIC_OUTBOUND_RANGES)
    import ipaddress
    for ip in ("160.79.106.132", "160.79.106.134", "160.79.106.143", "160.79.106.187"):
        assert any(ipaddress.ip_address(ip) in n for n in nets)
    assert not any(ipaddress.ip_address("27.5.164.115") in n for n in nets)


@pytest.mark.skipif(sys.platform == "win32", reason="uses a shell-script fake")
def test_quick_tunnel_reports_url(tmp_path):
    fake = tmp_path / "cloudflared"
    fake.write_text(textwrap.dedent(f"""\
        #!{sys.executable}
        import sys, time
        print("INF Requesting new quick Tunnel on trycloudflare.com...", file=sys.stderr, flush=True)
        print("INF |  https://brave-otter-12-tunnel.trycloudflare.com  |", file=sys.stderr, flush=True)
        time.sleep(30)
    """))
    fake.chmod(0o755)

    async def scenario():
        tunnel = web_gateway.QuickTunnel(str(fake))
        url = await tunnel.start(8019)
        await tunnel.stop()
        return url

    assert asyncio.run(scenario()) == "https://brave-otter-12-tunnel.trycloudflare.com"
