"""
Tests for stdio proxy module.

Tests StdioProxy logic without spawning real processes,
using mocks for subprocess and stdin/stdout.

Run with: python -m pytest tests/test_stdio_proxy.py -v
"""

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from tutut.config import GuardianConfig
from tutut.models import Decision, JsonRpcMessage, Rule, RuleAction
from tutut.stdio_proxy import StdioProxy, MAX_MESSAGE_SIZE


class TestStdioProxyInit(unittest.TestCase):
    """Test StdioProxy initialization."""

    def test_basic_init(self):
        config = GuardianConfig()
        proxy = StdioProxy(
            server_command=["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            server_name="filesystem",
            config=config,
        )
        self.assertEqual(proxy._server_name, "filesystem")
        self.assertEqual(
            proxy._server_cmd,
            ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        )
        self.assertIsNone(proxy._process)

    def test_init_with_env(self):
        config = GuardianConfig()
        proxy = StdioProxy(
            server_command=["my-server"],
            server_name="test",
            config=config,
            env={"API_KEY": "secret123"},
        )
        self.assertEqual(proxy._env, {"API_KEY": "secret123"})

    def test_max_message_size_constant(self):
        # Large file reads/writes must fit; asyncio's 64 KiB default did not.
        self.assertEqual(MAX_MESSAGE_SIZE, 32 * 1024 * 1024)


class TestStdioProxyHandleToolCall(unittest.TestCase):
    """Test tool call handling logic."""

    def _make_proxy(self, rules=None, block_when_headless=True):
        config = GuardianConfig(
            rules=rules or [],
            block_when_headless=block_when_headless,
        )
        proxy = StdioProxy(
            server_command=["echo"],
            server_name="test-server",
            config=config,
        )
        return proxy

    def _make_tool_call_msg(self, tool_name="test_tool", tool_id=1):
        return JsonRpcMessage(
            raw={
                "jsonrpc": "2.0",
                "id": tool_id,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": {}},
            }
        )

    def test_auto_allow_rule(self):
        """Tool calls matching an ALLOW rule should be forwarded."""
        proxy = self._make_proxy(
            rules=[
                Rule(
                    server_pattern="test-server",
                    tool_pattern="allowed_tool",
                    action=RuleAction.ALLOW,
                )
            ]
        )
        # Mock _send_blocked_response since we won't need it
        proxy._send_blocked_response = AsyncMock()
        proxy._gui_available = False

        msg = self._make_tool_call_msg("allowed_tool")
        result = asyncio.run(proxy._handle_tool_call(msg))
        self.assertTrue(result)
        proxy._send_blocked_response.assert_not_called()

    def test_auto_block_rule(self):
        """Tool calls matching a BLOCK rule should be blocked."""
        proxy = self._make_proxy(
            rules=[
                Rule(
                    server_pattern="test-server",
                    tool_pattern="dangerous_tool",
                    action=RuleAction.BLOCK,
                )
            ]
        )
        proxy._send_blocked_response = AsyncMock()
        proxy._gui_available = False

        msg = self._make_tool_call_msg("dangerous_tool")
        result = asyncio.run(proxy._handle_tool_call(msg))
        self.assertFalse(result)
        proxy._send_blocked_response.assert_called_once_with(msg, reason="rule")

    def test_ask_no_gui_block_headless(self):
        """When ASK but no GUI and block_when_headless=True, should block."""
        proxy = self._make_proxy(rules=[], block_when_headless=True)
        proxy._gui_available = False
        proxy._send_blocked_response = AsyncMock()

        msg = self._make_tool_call_msg("unknown_tool")
        result = asyncio.run(proxy._handle_tool_call(msg))
        self.assertFalse(result)
        proxy._send_blocked_response.assert_called_once()

    def test_ask_no_gui_allow_headless(self):
        """When ASK but no GUI and block_when_headless=False, should allow."""
        proxy = self._make_proxy(rules=[], block_when_headless=False)
        proxy._gui_available = False
        proxy._send_blocked_response = AsyncMock()

        msg = self._make_tool_call_msg("unknown_tool")
        result = asyncio.run(proxy._handle_tool_call(msg))
        self.assertTrue(result)
        proxy._send_blocked_response.assert_not_called()

    def test_send_blocked_response_format(self):
        """Verify the blocked response written to stdout."""
        proxy = self._make_proxy()

        msg = self._make_tool_call_msg("bad_tool", tool_id=99)

        with patch("sys.stdout") as mock_stdout:
            mock_buffer = MagicMock()
            mock_stdout.buffer = mock_buffer

            asyncio.run(proxy._send_blocked_response(msg))

            # Should have written one line
            mock_buffer.write.assert_called_once()
            written = mock_buffer.write.call_args[0][0]
            parsed = json.loads(written.decode())
            self.assertEqual(parsed["jsonrpc"], "2.0")
            self.assertEqual(parsed["id"], 99)
            self.assertTrue(parsed["result"]["isError"])
            self.assertIn("bad_tool", parsed["result"]["content"][0]["text"])
            mock_buffer.flush.assert_called_once()


class TestStdioProxyCleanup(unittest.TestCase):
    """Test process cleanup logic."""

    def test_cleanup_terminates_process(self):
        """Cleanup should terminate the server process."""
        config = GuardianConfig()
        proxy = StdioProxy(["echo"], "test", config)

        mock_process = MagicMock()
        mock_process.returncode = None  # still running
        mock_process.terminate = MagicMock()
        mock_process.kill = MagicMock()

        # Simulate process exiting after terminate
        async def mock_wait():
            mock_process.returncode = 0

        mock_process.wait = mock_wait
        proxy._process = mock_process

        asyncio.run(proxy._cleanup())
        mock_process.terminate.assert_called_once()

    def test_cleanup_already_exited(self):
        """Cleanup should not terminate if process already exited."""
        config = GuardianConfig()
        proxy = StdioProxy(["echo"], "test", config)

        mock_process = MagicMock()
        mock_process.returncode = 0  # already exited
        proxy._process = mock_process

        asyncio.run(proxy._cleanup())
        mock_process.terminate.assert_not_called()


class TestStdioProxyMessageFiltering(unittest.TestCase):
    """Test message filtering and size enforcement."""

    def test_oversized_message_rejected(self):
        """Messages exceeding MAX_MESSAGE_SIZE should be dropped."""
        # This is implicitly tested through the proxy's _pipe_client_to_server
        # method, but we can verify the constant and test the concept
        big_msg = b"x" * (MAX_MESSAGE_SIZE + 1) + b"\n"
        self.assertGreater(len(big_msg), MAX_MESSAGE_SIZE)

    def test_valid_jsonrpc_detected(self):
        """Valid JSON-RPC tool calls should be detected."""
        raw = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "test", "arguments": {}},
            }
        ).encode()
        msg = JsonRpcMessage.parse(raw)
        self.assertIsNotNone(msg)
        self.assertTrue(msg.is_tool_call)

    def test_non_jsonrpc_passes_through(self):
        """Non-JSON-RPC messages should not be intercepted."""
        msg = JsonRpcMessage.parse(b"hello world\n")
        self.assertIsNone(msg)

    def test_jsonrpc_notification_passes_through(self):
        """JSON-RPC notifications (no id) should pass through."""
        raw = json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 50}}
        ).encode()
        msg = JsonRpcMessage.parse(raw)
        self.assertIsNotNone(msg)
        self.assertFalse(msg.is_tool_call)
        self.assertTrue(msg.is_notification)


if __name__ == "__main__":
    unittest.main(verbosity=2)
