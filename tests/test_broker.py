"""
Tests for the approval broker (one window and one queue for every tutut
process). No real windows are opened: the broker's UI is replaced by a fake
that records what would be shown and answers like a user.

Run with: python -m pytest tests/test_broker.py -v
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from tutut import broker as B  # noqa: E402
from tutut.audit import AuditLog  # noqa: E402
from tutut.config import GuardianConfig  # noqa: E402
from tutut.gui import PopupResult  # noqa: E402
from tutut.interceptor import Interceptor  # noqa: E402
from tutut.models import Decision, InterceptedRequest, JsonRpcMessage  # noqa: E402

pytestmark = pytest.mark.skipif(not B.supported(), reason="needs Unix sockets")


class FakeConn:
    def __init__(self):
        self.sent = []

    def send(self, obj):
        self.sent.append(obj)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def req(rid, tool="list_notes", server="notes", timeout=0, **more):
    return {"type": "request", "id": rid, "server": server, "tool": tool, "arguments": {"n": rid},
            "source": "test", "timeout": timeout, **more}


def decisions(conn):
    return [(m["id"], m["decision"], m["reason"]) for m in conn.sent if m.get("type") == "decision"]


# -- queue logic -------------------------------------------------------------------------


def test_one_global_queue_in_arrival_order():
    br = B.Broker(ui=lambda item, b: None)
    c1, c2 = FakeConn(), FakeConn()
    br.submit(c1, req("a"))
    br.submit(c2, req("b", tool="delete_note"))
    br.submit(c1, req("c"))
    first = br.next_item(wait=0)
    assert first.id == "a"
    snap = br.snapshot(exclude_id="a")
    assert snap["total"] == 3 and [o["id"] for o in snap["others"]] == ["b", "c"]
    assert snap["others"][0]["risk"] == "high"            # delete_note
    first.result.set(Decision.ALLOW, reason="user")
    assert decisions(c1) == [("a", "allow", "user")] and decisions(c2) == []
    second = br.next_item(wait=0)
    assert second.id == "b"                               # from the *other* process
    second.result.set(Decision.BLOCK, reason="user")
    assert decisions(c2) == [("b", "block", "user")]


def test_cancel_and_disconnect_send_nothing():
    br = B.Broker(ui=lambda item, b: None)
    c1, c2 = FakeConn(), FakeConn()
    br.submit(c1, req("a"))
    br.submit(c1, req("b"))
    br.submit(c2, req("x"))
    br.cancel(c1, "b")                 # queued -> withdrawn silently
    br.cancel(c2, "a")                 # someone else's request: ignored
    assert [o["id"] for o in br.snapshot()["others"]] == ["a", "x"]
    br.disconnect(c1)                  # process gone: its requests disappear
    assert [o["id"] for o in br.snapshot()["others"]] == ["x"]
    assert c1.sent == [] and c2.sent == []


def test_deadlines_run_from_arrival_even_while_queued():
    clock = Clock()
    br = B.Broker(ui=lambda item, b: None, clock=clock)
    c = FakeConn()
    br.submit(c, req("a", timeout=45))
    clock.t += 20
    br.submit(c, req("b", timeout=45))
    assert br.next_item(wait=0).id == "a"   # a is on screen, b waits
    snap = br.snapshot(exclude_id="a")
    assert snap["others"][0]["remaining"] == 45
    clock.t += 26                            # a: 46 s old, b: 26 s
    assert br.expire() == 1
    assert decisions(c) == [("a", "block", "timeout")]
    clock.t += 20                            # b expires although never shown
    br.expire()
    assert decisions(c)[-1] == ("b", "block", "timeout")


def test_remember_answers_identical_waiting_requests():
    br = B.Broker(ui=lambda item, b: None)
    c1, c2 = FakeConn(), FakeConn()
    br.submit(c1, req("a", tool="read_note"))
    br.submit(c2, req("b", tool="read_note"))     # same server + tool, other session
    br.submit(c2, req("c", tool="delete_note"))
    br.next_item(wait=0).result.set(Decision.ALLOW, remember=True, reason="user")
    assert decisions(c1) == [("a", "allow", "user")]
    assert decisions(c2) == [("b", "allow", "rule")]   # answered without a popup
    assert [o["id"] for o in br.snapshot()["others"]] == ["c"]


def test_block_all():
    br = B.Broker(ui=lambda item, b: None)
    c = FakeConn()
    for rid in "abc":
        br.submit(c, req(rid))
    br.next_item(wait=0)
    br.block_all()
    assert sorted(decisions(c)) == [("a", "block", "user"), ("b", "block", "user"), ("c", "block", "user")]
    assert br.snapshot()["total"] == 0


def test_queue_is_bounded():
    br = B.Broker(ui=lambda item, b: None)
    c = FakeConn()
    for i in range(B.MAX_PENDING):
        br.submit(c, req(f"r{i}"))
    br.submit(c, req("one-too-many"))
    assert decisions(c) == [("one-too-many", "block", "queue_full")]
    assert br.snapshot()["total"] == B.MAX_PENDING


def test_ui_failure_fails_closed():
    def broken(item, b):
        raise RuntimeError("no display")

    br = B.Broker(ui=broken)
    c = FakeConn()
    br.submit(c, req("a"))
    br.run_ui(br.next_item(wait=0))
    assert decisions(c) == [("a", "block", "error")]


# -- over a real socket ---------------------------------------------------------------


def _short_tmp():
    # AF_UNIX paths are limited to ~108 bytes; pytest's tmp dirs can be long.
    import tempfile
    return Path(tempfile.mkdtemp(prefix="tb-"))


class Running:
    """A broker serving on a temporary socket, with a fake user."""

    def __init__(self, decide):
        self.dir = _short_tmp()
        self.path = self.dir / "b.sock"
        self.shown, self.max_open, self._open = [], 0, 0
        self._decide = decide
        self.broker = B.Broker(ui=self._ui)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=B.serve, args=(self.broker, self.path, self.stop), daemon=True)
        self.thread.start()
        for _ in range(100):
            if self.path.exists():
                break
            time.sleep(0.01)

    def _ui(self, item, broker):
        self._open += 1
        self.max_open = max(self.max_open, self._open)
        self.shown.append((item.request.tool_name, item.request.client))
        try:
            time.sleep(0.05)
            outcome = self._decide(item)
            if outcome is not None:
                item.result.set(outcome, reason="user")
            else:  # wait like a user who hasn't answered yet
                while not item.result.is_set and not self.stop.is_set():
                    time.sleep(0.02)
        finally:
            self._open -= 1

    def close(self):
        self.stop.set()
        self.thread.join(timeout=5)


class FakeFallback:
    def __init__(self, decision=Decision.ALLOW):
        self.decision, self.requests, self.cancelled = decision, [], []
        self.results = {}

    def request_decision(self, request):
        self.requests.append(request.tool_name)
        r = PopupResult()
        self.results[request.id] = r
        if self.decision is not None:
            r.set(self.decision, reason="user")
        return r

    def cancel(self, rid):
        self.cancelled.append(rid)
        return self.results[rid].set(Decision.BLOCK, reason="cancelled")


def intercepted(rid, tool, client=""):
    msg = JsonRpcMessage(raw={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": tool, "arguments": {}}})
    return InterceptedRequest(id=rid, message=msg, server_name="notes", tool_name=tool,
                              arguments={}, source="test", client=client)


def test_two_processes_share_one_window():
    run = Running(lambda item: Decision.ALLOW if item.request.tool_name.startswith("list") else Decision.BLOCK)
    try:
        a = B.BrokerClient(timeout=45, fallback=FakeFallback(None), socket_path=run.path, spawn=False)
        b = B.BrokerClient(timeout=45, fallback=FakeFallback(None), socket_path=run.path, spawn=False)
        results = []
        # Requests from different processes arrive on different connections;
        # space them a little so "arrival order" is well defined for the test.
        for client, rid, tool, who in [(a, "1", "list_notes", "session-A"), (b, "2", "delete_note", "session-B"),
                                       (a, "3", "list_files", "session-A")]:
            results.append(client.request_decision(intercepted(rid, tool, who)))
            time.sleep(0.02)
        for r in results:
            assert r.wait(5) is not Decision.PENDING
        assert [r.decision for r in results] == [Decision.ALLOW, Decision.BLOCK, Decision.ALLOW]
        assert run.max_open == 1                          # never two windows at once
        assert [t for t, _ in run.shown] == ["list_notes", "delete_note", "list_files"]
        assert run.shown[1][1] == "session-B"             # who asked travels with it
    finally:
        run.close()


def test_falls_back_to_own_popup_without_broker():
    fb = FakeFallback(Decision.ALLOW)
    client = B.BrokerClient(timeout=45, fallback=fb, socket_path=_short_tmp() / "none.sock", spawn=False)
    r = client.request_decision(intercepted("1", "read_note"))
    assert r.wait(2) == Decision.ALLOW and fb.requests == ["read_note"]


def test_broker_dying_mid_request_reroutes_to_own_popup():
    run = Running(lambda item: None)      # the user never answers
    fb = FakeFallback(Decision.BLOCK)
    try:
        client = B.BrokerClient(timeout=45, fallback=fb, socket_path=run.path, spawn=False)
        r = client.request_decision(intercepted("1", "write_file"))
        time.sleep(0.2)
        assert not r.is_set
        for conn in list(run.broker._conns):   # simulate the broker crashing
            conn.sock.shutdown(socket.SHUT_RDWR)
        assert r.wait(3) == Decision.BLOCK and fb.requests == ["write_file"]
    finally:
        run.close()


def test_client_cancel_withdraws_from_broker_queue():
    run = Running(lambda item: None)
    try:
        client = B.BrokerClient(timeout=45, fallback=FakeFallback(None), socket_path=run.path, spawn=False)
        client.request_decision(intercepted("1", "slow_one"))
        r2 = client.request_decision(intercepted("2", "queued_one"))
        time.sleep(0.2)
        assert client.cancel("2") and r2.reason == "cancelled"
        time.sleep(0.2)
        assert [o["tool"] for o in run.broker.snapshot()["others"]] in ([], ["slow_one"])
        assert all(o["tool"] != "queued_one" for o in run.broker.snapshot()["others"])
    finally:
        run.close()


def test_interceptor_uses_broker_and_sends_client_label(tmp_path):
    run = Running(lambda item: Decision.ALLOW)
    try:
        client = B.BrokerClient(timeout=45, fallback=FakeFallback(None), socket_path=run.path, spawn=False)
        icp = Interceptor(GuardianConfig(), server_name="notes", transport="http", source="t",
                          popup_manager=client, gui_available=True, audit=AuditLog(None))
        msg = JsonRpcMessage(raw={"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                                  "params": {"name": "list_notes", "arguments": {}}})
        verdict = asyncio.run(icp.decide(msg, extra={"client": "session 3f2a91bc"}))
        assert verdict.allowed and verdict.decided_by == "user"
        assert run.shown == [("list_notes", "session 3f2a91bc")]
    finally:
        run.close()


# -- singleton & CLI ------------------------------------------------------------------


def test_only_one_broker_can_hold_the_lock(tmp_path):
    lock = tmp_path / "broker.lock"
    fd = B.acquire_singleton(lock)
    assert fd is not None
    try:
        assert B.acquire_singleton(lock) is None
        # `tutut broker` started while one is running exits at once, cleanly
        proc = subprocess.run([sys.executable, "-c",
                               "import sys; sys.path.insert(0, sys.argv[1]); from pathlib import Path; "
                               "from tutut.broker import run_broker; "
                               "sys.exit(run_broker(lock_path=Path(sys.argv[2]), socket_path=Path(sys.argv[3])))",
                               str(ROOT), str(lock), str(_short_tmp() / "b.sock")],
                              capture_output=True, timeout=30)
        assert proc.returncode == 0
    finally:
        os.close(fd)
    assert B.acquire_singleton(lock) is not None


def test_rules_saved_by_another_process_apply_without_restart(tmp_path):
    from tutut.models import Rule, RuleAction

    cfg_path = tmp_path / "config.json"
    GuardianConfig().save(cfg_path)
    icp = Interceptor(GuardianConfig.load(cfg_path), server_name="notes", transport="stdio", source="t",
                      popup_manager=FakeFallback(Decision.BLOCK), gui_available=True, audit=AuditLog(None))
    msg = JsonRpcMessage(raw={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": "read_note", "arguments": {}}})
    assert asyncio.run(icp.decide(msg)).decided_by == "user"     # asks
    other = GuardianConfig.load(cfg_path)                         # e.g. "remember" in another process
    other.rules.insert(0, Rule("notes", "read_note", RuleAction.ALLOW))
    time.sleep(0.01)
    other.save(cfg_path)
    verdict = asyncio.run(icp.decide(msg))
    assert verdict.allowed and verdict.decided_by == "rule"
