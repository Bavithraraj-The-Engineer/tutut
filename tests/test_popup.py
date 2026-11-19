"""
Tests for the approval popup: risk hints, argument rendering, annotation
learning, and the window's behaviour.

The window tests open real Tk windows, so they only run when
TUTUT_GUI_TESTS=1 (use a virtual display):

    TUTUT_GUI_TESTS=1 xvfb-run -a python -m pytest tests/test_popup.py -v
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from tutut.audit import AuditLog, read_entries  # noqa: E402
from tutut.config import GuardianConfig  # noqa: E402
from tutut.interceptor import Interceptor  # noqa: E402
from tutut.models import Decision, JsonRpcMessage  # noqa: E402
from tutut.risk import classify, json_tokens, name_words  # noqa: E402


# -- risk hints ------------------------------------------------------------------


@pytest.mark.parametrize("tool, ann, level", [
    ("delete_note", None, "high"),
    ("deleteNote", None, "high"),
    ("list_and_delete", None, "high"),          # worst word wins
    ("write_file", None, "medium"),
    ("get_or_create", None, "medium"),
    ("list_notes", None, "low"),
    ("read_file", None, "low"),
    ("frobnicate", None, "unknown"),
    ("frobnicate", {"readOnlyHint": True}, "low"),
    ("frobnicate", {"destructiveHint": True}, "high"),
    ("frobnicate", {"destructiveHint": False}, "medium"),
    ("frobnicate", {"title": "x"}, "unknown"),  # no explicit hints: spec defaults are ignored
])
def test_classify_levels(tool, ann, level):
    assert classify(tool, ann).level == level


def test_classify_is_pessimistic_and_explains_conflicts():
    lying = classify("delete_everything", {"readOnlyHint": True})
    assert lying.level == "high" and lying.label == "Destructive"
    assert "delete" in lying.reason and "read-only" in lying.reason
    assert classify("list_x", {"openWorldHint": True}).reason.endswith("reaches external systems")
    assert classify("list_x").reason[0].isupper()


def test_name_words():
    assert name_words("HTTPGetFile") == ["http", "get", "file"]
    assert name_words("files.delete-all_v2") == ["files", "delete", "all", "v", "2"]


def test_json_tokens_roundtrip_and_kinds():
    text = json.dumps({"path": "/tmp/a \"b\"", "n": -1.5e3, "ok": True, "x": None, "l": [1, 2]}, indent=2)
    toks = json_tokens(text)
    assert "".join(t for _, t in toks) == text
    kinds = {k for k, t in toks}
    assert {"key", "string", "number", "literal", "punct", "space"} <= kinds
    assert ("key", '"path"') in toks and ("string", '"/tmp/a \\"b\\""') in toks
    truncated = text[:20]  # cut mid-string: still round-trips
    assert "".join(t for _, t in json_tokens(truncated)) == truncated


def test_format_arguments_truncates():
    pytest.importorskip("tkinter")
    from tutut.popup_ui import MAX_ARG_CHARS, format_arguments

    assert format_arguments({}) == ("", "")
    text, summary = format_arguments({"a": 1})
    assert summary == "1 field" and '"a": 1' in text
    big, summary = format_arguments({"content": "x" * (MAX_ARG_CHARS * 2)})
    assert summary == "1 field · truncated" and "more characters not shown" in big
    assert len(big) < MAX_ARG_CHARS + 100


# -- annotations reach the popup and the audit log ---------------------------------------


class _CapturePopups:
    def __init__(self):
        self.requests = []

    def request_decision(self, request):
        from tutut.gui import PopupResult

        self.requests.append(request)
        r = PopupResult()
        r.set(Decision.BLOCK, reason="user")
        return r

    def cancel(self, _):
        return False


def test_interceptor_learns_annotations(tmp_path):
    popups = _CapturePopups()
    icp = Interceptor(GuardianConfig(), server_name="notes", transport="stdio", source="t",
                      popup_manager=popups, gui_available=True, audit=AuditLog(tmp_path / "a.db"))
    icp.learn_tools({"tools": [
        {"name": "frob", "annotations": {"destructiveHint": True}},
        {"name": "plain"},
        "garbage",
    ]})
    icp.learn_tools(None)  # ignored
    msg = JsonRpcMessage(raw={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "frob"}})
    asyncio.run(icp.decide(msg))
    assert popups.requests[0].annotations == {"destructiveHint": True}
    assert read_entries(tmp_path / "a.db")[0]["risk"] == "high"
    assert icp.tool_annotations["plain"] == {}


def test_stdio_proxy_learns_from_tools_list_response():
    from unittest.mock import MagicMock

    from tutut.stdio_proxy import StdioProxy

    proxy = StdioProxy(["server"], "notes", GuardianConfig())
    proxy._tools_list_ids.add(json.dumps(7))

    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data(json.dumps({"jsonrpc": "2.0", "id": 7, "result": {"tools": [
            {"name": "delete_note", "annotations": {"destructiveHint": True}}]}}).encode() + b"\n")
        reader.feed_eof()
        proxy._process = MagicMock()
        proxy._process.stdout = reader
        await proxy._pipe_server_to_client()

    with patch("sys.stdout"):
        asyncio.run(scenario())
    assert proxy._interceptor.tool_annotations == {"delete_note": {"destructiveHint": True}}
    assert not proxy._tools_list_ids


def test_gateway_learns_from_tools_list_response():
    pytest.importorskip("aiohttp")
    sys.path.insert(0, str(Path(__file__).parent.parent / "examples"))
    import demo_server
    from aiohttp.test_utils import TestClient, TestServer

    from tutut.http_proxy import HttpProxy, build_app

    async def scenario():
        upstream = TestServer(demo_server.build_app())
        await upstream.start_server()
        proxy = HttpProxy(str(upstream.make_url("/mcp")), "notes", GuardianConfig())
        client = TestClient(TestServer(build_app(proxy)))
        await client.start_server()
        try:
            await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            return proxy._interceptor.tool_annotations
        finally:
            await client.close()
            await upstream.close()

    ann = asyncio.run(scenario())
    assert ann["delete_note"]["destructiveHint"] is True and ann["list_notes"]["readOnlyHint"] is True


# -- the window (needs a display) ------------------------------------------------------

gui = pytest.mark.skipif(
    not os.environ.get("TUTUT_GUI_TESTS"),
    reason="opens real windows; run with TUTUT_GUI_TESTS=1 under xvfb-run",
)


def _window(i=0, timeout=0, arm=150):
    from tutut.gui import PopupResult
    from tutut.popup_ui import PopupWindow, sample_request

    result = PopupResult()
    return PopupWindow(sample_request(i), result, timeout=timeout, arm_delay_ms=arm), result


def _pump(w, seconds):
    end = time.time() + seconds
    while time.time() < end and not w.closed:
        w.root.update()
        time.sleep(0.01)


@gui
def test_allow_needs_arming():
    w, res = _window(arm=300)
    w.root.update()
    w.root.event_generate("<Key-y>")
    w.allow_btn.command()  # a click that lands too early
    _pump(w, 0.05)
    assert not res.is_set and not w.allow_btn.enabled
    _pump(w, 0.4)
    assert w.armed and w.allow_btn.enabled
    w.root.event_generate("<Key-y>")
    _pump(w, 0.1)
    assert (res.decision, res.reason, w.closed) == (Decision.ALLOW, "user", True)


@gui
def test_block_is_immediate_and_the_keyboard_default():
    w, res = _window(arm=5000)
    w.root.update()
    w.block_btn.event_generate("<Key-Return>")  # Block has focus by default
    _pump(w, 0.1)
    assert (res.decision, res.reason) == (Decision.BLOCK, "user")

    w, res = _window(arm=5000)
    w.root.update()
    w.root.event_generate("<Escape>")
    _pump(w, 0.1)
    assert res.decision == Decision.BLOCK


@gui
def test_remember_switch():
    w, res = _window(arm=50)
    w.toggle.toggle()
    _pump(w, 0.15)
    w.allow_btn.command()
    _pump(w, 0.05)
    assert res.decision == Decision.ALLOW and res.remember is True


@gui
def test_countdown_blocks_with_timeout_reason():
    w, res = _window(timeout=0.4)
    _pump(w, 1.0)
    assert (res.decision, res.reason, w.closed) == (Decision.BLOCK, "timeout", True)


@gui
def test_closes_when_cancelled_elsewhere():
    w, res = _window()
    res.set(Decision.BLOCK, reason="cancelled")
    _pump(w, 0.5)
    assert w.closed and res.reason == "cancelled"


@gui
def test_window_close_blocks():
    w, res = _window()
    w.root.update()
    w.root.tk.call(w.root.protocol("WM_DELETE_WINDOW"))
    assert res.decision == Decision.BLOCK and w.closed
