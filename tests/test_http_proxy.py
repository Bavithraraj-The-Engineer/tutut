"""
Tests for HTTP proxy module.

Tests the HttpProxy handler logic without spinning up a real network server.
Uses aiohttp.test_utils for request simulation.

Run with: python -m pytest tests/test_http_proxy.py -v
"""

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from tutut.config import GuardianConfig
from tutut.models import Rule, RuleAction

# Skip all tests if aiohttp is not installed
aiohttp = pytest.importorskip("aiohttp")
from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase

from tutut.http_proxy import HttpProxy, MAX_BODY_SIZE


class TestHttpProxyUnit(unittest.TestCase):
    """Unit tests for HttpProxy logic that don't require a running server."""

    def test_max_body_size_constant(self):
        self.assertEqual(MAX_BODY_SIZE, 10 * 1024 * 1024)

    def test_proxy_initialization(self):
        config = GuardianConfig()
        proxy = HttpProxy(
            upstream_url="http://localhost:9999/mcp",
            server_name="test-server",
            config=config,
        )
        self.assertEqual(proxy._upstream, "http://localhost:9999/mcp")
        self.assertEqual(proxy._server_name, "test-server")

    def test_upstream_url_trailing_slash_stripped(self):
        config = GuardianConfig()
        proxy = HttpProxy(
            upstream_url="http://localhost:9999/",
            server_name="test",
            config=config,
        )
        self.assertEqual(proxy._upstream, "http://localhost:9999")


class HttpProxyFunctionalTest(AioHTTPTestCase):
    """
    Functional tests using aiohttp test client.

    Mocks the upstream server to test proxy behavior without network calls.
    """

    def setUp(self):
        """Set up config with explicit allow/block rules (no popups needed)."""
        self.config = GuardianConfig(
            rules=[
                Rule(
                    server_pattern="test-server",
                    tool_pattern="allowed_tool",
                    action=RuleAction.ALLOW,
                ),
                Rule(
                    server_pattern="test-server",
                    tool_pattern="blocked_tool",
                    action=RuleAction.BLOCK,
                ),
                Rule(
                    server_pattern="test-server",
                    tool_pattern="*",
                    action=RuleAction.BLOCK,
                ),
            ],
            block_when_headless=True,
        )
        self.proxy = HttpProxy(
            upstream_url="http://mock-upstream:9999",
            server_name="test-server",
            config=self.config,
        )
        super().setUp()

    async def get_application(self):
        app = web.Application(client_max_size=MAX_BODY_SIZE)
        app.router.add_route("*", "/{path_info:.*}", self.proxy.handle_request)
        app.router.add_route("*", "/", self.proxy.handle_request)
        return app

    async def tearDownAsync(self):
        if self.proxy._session and not self.proxy._session.closed:
            await self.proxy._session.close()

    # --- Single JSON-RPC Tests ---

    async def test_blocked_single_tool_call(self):
        """A tool call matching a BLOCK rule should return a JSON-RPC error."""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "blocked_tool", "arguments": {}},
        }

        resp = await self.client.post(
            "/", json=payload, headers={"Content-Type": "application/json"}
        )
        self.assertEqual(resp.status, 200)

        body = await resp.json()
        self.assertEqual(body["jsonrpc"], "2.0")
        self.assertEqual(body["id"], 1)
        self.assertTrue(body["result"]["isError"])
        self.assertIn("blocked_tool", body["result"]["content"][0]["text"])

    async def test_allowed_tool_call_forwarded(self):
        """An allowed tool call should be forwarded to upstream."""
        payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "allowed_tool", "arguments": {"path": "/tmp"}},
        }

        upstream_response = {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"content": [{"type": "text", "text": "ok"}]},
        }

        # Mock the upstream request
        with patch.object(self.proxy, "_forward_raw", new_callable=AsyncMock) as mock_forward:
            mock_forward.return_value = web.json_response(upstream_response)
            resp = await self.client.post(
                "/", json=payload, headers={"Content-Type": "application/json"}
            )

            self.assertEqual(resp.status, 200)
            mock_forward.assert_called_once()

    async def test_non_tool_call_passes_through(self):
        """Non-tool-call messages (like tools/list) should pass through."""
        payload = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
        }

        with patch.object(self.proxy, "_forward_raw", new_callable=AsyncMock) as mock_forward:
            mock_forward.return_value = web.json_response(
                {"jsonrpc": "2.0", "id": 3, "result": {"tools": []}}
            )
            resp = await self.client.post(
                "/", json=payload, headers={"Content-Type": "application/json"}
            )

            self.assertEqual(resp.status, 200)
            mock_forward.assert_called_once()

    async def test_initialize_passes_through(self):
        """The initialize handshake should pass through without interception."""
        payload = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "claude-web", "version": "1.0"},
            },
        }

        with patch.object(self.proxy, "_forward_raw", new_callable=AsyncMock) as mock_forward:
            mock_forward.return_value = web.json_response(
                {"jsonrpc": "2.0", "id": 0, "result": {"serverInfo": {}}}
            )
            resp = await self.client.post(
                "/", json=payload, headers={"Content-Type": "application/json"}
            )
            mock_forward.assert_called_once()

    # --- Batch JSON-RPC Tests ---

    async def test_batch_all_blocked(self):
        """A batch where ALL items are blocked tool calls should return all errors."""
        batch = [
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {"name": "blocked_tool", "arguments": {}},
            },
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {"name": "another_blocked", "arguments": {}},
            },
        ]

        resp = await self.client.post(
            "/", json=batch, headers={"Content-Type": "application/json"}
        )
        self.assertEqual(resp.status, 200)

        body = await resp.json()
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 2)
        for item in body:
            self.assertTrue(item["result"]["isError"])

    async def test_batch_mixed_allowed_and_blocked(self):
        """A batch with mixed allow/block should forward allowed ones and block the rest."""
        batch = [
            {
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": {"name": "allowed_tool", "arguments": {}},
            },
            {
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": {"name": "blocked_tool", "arguments": {}},
            },
            {
                "jsonrpc": "2.0",
                "id": 22,
                "method": "tools/list",
            },
        ]

        # Mock _forward_raw to return upstream results for the forwarded items
        upstream_results = [
            {"jsonrpc": "2.0", "id": 20, "result": {"content": []}},
            {"jsonrpc": "2.0", "id": 22, "result": {"tools": []}},
        ]

        with patch.object(self.proxy, "_forward_raw", new_callable=AsyncMock) as mock_forward:
            mock_resp = web.Response(
                body=json.dumps(upstream_results).encode(),
                content_type="application/json",
            )
            mock_forward.return_value = mock_resp

            resp = await self.client.post(
                "/", json=batch, headers={"Content-Type": "application/json"}
            )

            self.assertEqual(resp.status, 200)
            body = await resp.json()
            self.assertIsInstance(body, list)
            # Should have 3 total: 2 from upstream + 1 blocked
            self.assertEqual(len(body), 3)

            # Verify the blocked one is marked as an error result
            blocked = [r for r in body if r.get("id") == 21]
            self.assertEqual(len(blocked), 1)
            self.assertTrue(blocked[0]["result"]["isError"])

    # --- Method routing ---

    async def test_unsupported_method(self):
        """PATCH/PUT should return 405."""
        resp = await self.client.request("PATCH", "/")
        self.assertEqual(resp.status, 405)
        body = await resp.json()
        self.assertIn("error", body)

    async def test_body_size_enforcement(self):
        """Content-Length exceeding MAX_BODY_SIZE should be rejected."""
        # We test the proxy logic by passing a Content-Length header
        # that exceeds the max. The proxy checks content_length before reading.
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(MAX_BODY_SIZE + 1),
        }
        # We can't actually send that much data, but the proxy checks the header
        resp = await self.client.post("/", data=b"{}", headers=headers)
        self.assertEqual(resp.status, 413)

    async def test_malformed_json_forwarded(self):
        """Non-JSON POST bodies should be forwarded transparently."""
        with patch.object(self.proxy, "_forward_raw", new_callable=AsyncMock) as mock_forward:
            mock_forward.return_value = web.Response(text="ok")
            resp = await self.client.post(
                "/",
                data=b"not json at all {{",
                headers={"Content-Type": "text/plain"},
            )
            mock_forward.assert_called_once()


class TestHttpProxyHeadless(unittest.TestCase):
    """Test headless behavior when GUI is not available."""

    def test_block_when_headless_true(self):
        """With block_when_headless=True and no GUI, ASK rules should block."""
        config = GuardianConfig(
            rules=[],  # no rules -> ASK
            block_when_headless=True,
        )
        proxy = HttpProxy("http://localhost", "test", config)

        # Mock gui availability to False
        proxy._gui_available = False

        from tutut.models import JsonRpcMessage

        msg = JsonRpcMessage(
            raw={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "some_tool"},
            }
        )

        result = asyncio.run(proxy._check_tool_call(msg))
        self.assertFalse(result)

    def test_allow_when_headless_false(self):
        """With block_when_headless=False and no GUI, ASK rules should allow."""
        config = GuardianConfig(
            rules=[],
            block_when_headless=False,
        )
        proxy = HttpProxy("http://localhost", "test", config)
        proxy._gui_available = False

        from tutut.models import JsonRpcMessage

        msg = JsonRpcMessage(
            raw={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "some_tool"},
            }
        )

        result = asyncio.run(proxy._check_tool_call(msg))
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
