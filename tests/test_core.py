"""
Tests for tutut core functionality.

Run with: python -m pytest tests/ -v
Or simply: python -m unittest tests.test_core -v
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tutut.models import (
    Decision,
    InterceptedRequest,
    JsonRpcMessage,
    Rule,
    RuleAction,
)
from tutut.config import GuardianConfig
from tutut.rules import RulesEngine
from tutut.setup_helper import (
    wrap_server_config,
    unwrap_server_config,
    is_already_wrapped,
)


# =============================================================================
# JSON-RPC Message Parsing
# =============================================================================


class TestJsonRpcMessage(unittest.TestCase):
    """Test JSON-RPC 2.0 message parsing and property detection."""

    def test_parse_tool_call(self):
        raw = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "/etc/passwd"},
                },
            }
        ).encode()
        msg = JsonRpcMessage.parse(raw)
        self.assertIsNotNone(msg)
        self.assertTrue(msg.is_request)
        self.assertTrue(msg.is_tool_call)
        self.assertEqual(msg.tool_name, "read_file")
        self.assertEqual(msg.tool_arguments, {"path": "/etc/passwd"})
        self.assertEqual(msg.id, 1)

    def test_parse_tools_list(self):
        """Non-tool-call methods should not be intercepted."""
        raw = json.dumps(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        ).encode()
        msg = JsonRpcMessage.parse(raw)
        self.assertIsNotNone(msg)
        self.assertTrue(msg.is_request)
        self.assertFalse(msg.is_tool_call)

    def test_parse_initialize(self):
        """The initialize handshake should pass through."""
        raw = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "claude", "version": "1.0"},
                },
            }
        ).encode()
        msg = JsonRpcMessage.parse(raw)
        self.assertIsNotNone(msg)
        self.assertTrue(msg.is_request)
        self.assertFalse(msg.is_tool_call)
        self.assertEqual(msg.method, "initialize")

    def test_parse_response(self):
        raw = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"content": [{"type": "text", "text": "hello"}]},
            }
        ).encode()
        msg = JsonRpcMessage.parse(raw)
        self.assertIsNotNone(msg)
        self.assertTrue(msg.is_response)
        self.assertFalse(msg.is_request)
        self.assertFalse(msg.is_tool_call)

    def test_parse_notification(self):
        raw = json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}
        ).encode()
        msg = JsonRpcMessage.parse(raw)
        self.assertIsNotNone(msg)
        self.assertTrue(msg.is_notification)
        self.assertFalse(msg.is_request)  # no id = notification, not request

    def test_parse_error_response(self):
        raw = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "error": {"code": -32600, "message": "Invalid Request"},
            }
        ).encode()
        msg = JsonRpcMessage.parse(raw)
        self.assertTrue(msg.is_response)

    def test_parse_invalid_json(self):
        self.assertIsNone(JsonRpcMessage.parse(b"not json at all"))

    def test_parse_json_array(self):
        """Arrays are valid JSON but not valid single JSON-RPC messages."""
        self.assertIsNone(JsonRpcMessage.parse(b"[1, 2, 3]"))

    def test_parse_empty(self):
        self.assertIsNone(JsonRpcMessage.parse(b""))

    def test_to_bytes_roundtrip(self):
        original = {"jsonrpc": "2.0", "id": 1, "method": "test"}
        msg = JsonRpcMessage(raw=original)
        data = msg.to_bytes()
        self.assertTrue(data.endswith(b"\n"))
        parsed = json.loads(data)
        self.assertEqual(parsed["method"], "test")

    def test_tool_call_with_complex_arguments(self):
        """Tool calls may have deeply nested arguments."""
        raw = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "query_database",
                    "arguments": {
                        "query": "SELECT * FROM users WHERE active = true",
                        "params": [1, 2, 3],
                        "options": {"limit": 100, "offset": 0},
                    },
                },
            }
        ).encode()
        msg = JsonRpcMessage.parse(raw)
        self.assertTrue(msg.is_tool_call)
        self.assertEqual(msg.tool_name, "query_database")
        self.assertIn("query", msg.tool_arguments)

    def test_tool_name_none_when_no_params(self):
        msg = JsonRpcMessage(
            raw={"jsonrpc": "2.0", "id": 1, "method": "tools/call"}
        )
        self.assertTrue(msg.is_tool_call)
        self.assertIsNone(msg.tool_name)
        self.assertIsNone(msg.tool_arguments)

    def test_string_id(self):
        """JSON-RPC allows string IDs."""
        msg = JsonRpcMessage(
            raw={
                "jsonrpc": "2.0",
                "id": "abc-123",
                "method": "tools/call",
                "params": {"name": "test"},
            }
        )
        self.assertEqual(msg.id, "abc-123")


# =============================================================================
# Intercepted Request
# =============================================================================


class TestInterceptedRequest(unittest.TestCase):
    """Test InterceptedRequest model and blocked response generation."""

    def test_blocked_response_format(self):
        msg = JsonRpcMessage(
            raw={
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {"name": "dangerous_tool", "arguments": {}},
            }
        )
        req = InterceptedRequest(
            id="abc",
            message=msg,
            server_name="test-server",
            tool_name="dangerous_tool",
            arguments={},
        )
        resp = req.make_blocked_response()

        # A tool result with isError=true (MCP: tool-level failures go in the
        # result so the model can read them), not a JSON-RPC protocol error.
        self.assertEqual(resp["jsonrpc"], "2.0")
        self.assertEqual(resp["id"], 42)
        self.assertNotIn("error", resp)
        self.assertTrue(resp["result"]["isError"])
        text = resp["result"]["content"][0]["text"]
        self.assertIn("dangerous_tool", text)
        self.assertIn("test-server", text)
        self.assertIn("denied", text)

    def test_blocked_response_reason_text(self):
        from tutut.models import blocked_response

        for reason, phrase in [("rule", "rule"), ("timeout", "in time"), ("headless", "popup")]:
            text = blocked_response(1, "t", "s", reason)["result"]["content"][0]["text"]
            self.assertIn(phrase, text)
        # Unknown reasons fall back to the user wording.
        text = blocked_response(1, "t", "s", "???")["result"]["content"][0]["text"]
        self.assertIn("user denied", text)

    def test_blocked_response_preserves_string_id(self):
        msg = JsonRpcMessage(
            raw={
                "jsonrpc": "2.0",
                "id": "req-uuid-123",
                "method": "tools/call",
                "params": {"name": "test"},
            }
        )
        req = InterceptedRequest(
            id="x",
            message=msg,
            server_name="s",
            tool_name="test",
            arguments={},
        )
        resp = req.make_blocked_response()
        self.assertEqual(resp["id"], "req-uuid-123")

    def test_default_decision_is_pending(self):
        msg = JsonRpcMessage(raw={"jsonrpc": "2.0", "id": 1, "method": "tools/call"})
        req = InterceptedRequest(
            id="x", message=msg, server_name="s", tool_name="t", arguments={}
        )
        self.assertEqual(req.decision, Decision.PENDING)


# =============================================================================
# Rules Engine
# =============================================================================


class TestRule(unittest.TestCase):
    """Test individual rule matching."""

    def test_exact_match(self):
        rule = Rule(
            server_pattern="github", tool_pattern="create_issue", action=RuleAction.ALLOW
        )
        self.assertTrue(rule.matches("github", "create_issue"))
        self.assertFalse(rule.matches("github", "delete_repo"))
        self.assertFalse(rule.matches("filesystem", "create_issue"))

    def test_glob_star(self):
        rule = Rule(server_pattern="*", tool_pattern="read_*", action=RuleAction.ALLOW)
        self.assertTrue(rule.matches("filesystem", "read_file"))
        self.assertTrue(rule.matches("github", "read_issues"))
        self.assertFalse(rule.matches("filesystem", "write_file"))

    def test_glob_question_mark(self):
        rule = Rule(
            server_pattern="db-?", tool_pattern="*", action=RuleAction.ALLOW
        )
        self.assertTrue(rule.matches("db-1", "anything"))
        self.assertTrue(rule.matches("db-a", "anything"))
        self.assertFalse(rule.matches("db-10", "anything"))

    def test_wildcard_all(self):
        rule = Rule(server_pattern="*", tool_pattern="*", action=RuleAction.BLOCK)
        self.assertTrue(rule.matches("anything", "anything_else"))

    def test_case_sensitive(self):
        """Glob matching should be case-sensitive."""
        rule = Rule(
            server_pattern="GitHub", tool_pattern="*", action=RuleAction.ALLOW
        )
        self.assertTrue(rule.matches("GitHub", "test"))
        self.assertFalse(rule.matches("github", "test"))


class TestRulesEngine(unittest.TestCase):
    """Test rules engine evaluation logic."""

    def test_first_match_wins(self):
        config = GuardianConfig(
            rules=[
                Rule(server_pattern="github", tool_pattern="*", action=RuleAction.ALLOW),
                Rule(server_pattern="*", tool_pattern="*", action=RuleAction.BLOCK),
            ]
        )
        engine = RulesEngine(config)
        self.assertEqual(engine.evaluate("github", "anything"), RuleAction.ALLOW)
        self.assertEqual(engine.evaluate("filesystem", "read"), RuleAction.BLOCK)

    def test_no_rules_defaults_to_ask(self):
        config = GuardianConfig(rules=[])
        engine = RulesEngine(config)
        self.assertEqual(engine.evaluate("any", "tool"), RuleAction.ASK)

    def test_add_rule_at_top(self):
        config = GuardianConfig(
            rules=[
                Rule(server_pattern="*", tool_pattern="*", action=RuleAction.BLOCK),
            ]
        )
        engine = RulesEngine(config)
        # Initially everything is blocked
        self.assertEqual(engine.evaluate("test", "tool"), RuleAction.BLOCK)

        # Add a higher-priority allow rule
        engine.add_rule(
            Rule(server_pattern="test", tool_pattern="*", action=RuleAction.ALLOW)
        )
        self.assertEqual(engine.evaluate("test", "tool"), RuleAction.ALLOW)
        # Other servers still blocked
        self.assertEqual(engine.evaluate("other", "tool"), RuleAction.BLOCK)

    def test_reload(self):
        config1 = GuardianConfig(rules=[])
        engine = RulesEngine(config1)
        self.assertEqual(engine.evaluate("s", "t"), RuleAction.ASK)

        config2 = GuardianConfig(
            rules=[Rule(server_pattern="*", tool_pattern="*", action=RuleAction.ALLOW)]
        )
        engine.reload(config2)
        self.assertEqual(engine.evaluate("s", "t"), RuleAction.ALLOW)

    def test_specific_before_wildcard(self):
        """More specific rules should be listed before wildcards for first-match to work."""
        config = GuardianConfig(
            rules=[
                Rule(
                    server_pattern="filesystem",
                    tool_pattern="write_file",
                    action=RuleAction.BLOCK,
                ),
                Rule(
                    server_pattern="filesystem",
                    tool_pattern="read_*",
                    action=RuleAction.ALLOW,
                ),
                Rule(server_pattern="*", tool_pattern="*", action=RuleAction.ASK),
            ]
        )
        engine = RulesEngine(config)
        self.assertEqual(
            engine.evaluate("filesystem", "write_file"), RuleAction.BLOCK
        )
        self.assertEqual(
            engine.evaluate("filesystem", "read_file"), RuleAction.ALLOW
        )
        self.assertEqual(
            engine.evaluate("filesystem", "delete_file"), RuleAction.ASK
        )

    def test_rules_property_returns_copy(self):
        config = GuardianConfig(rules=[Rule(action=RuleAction.ALLOW)])
        engine = RulesEngine(config)
        rules = engine.rules
        rules.append(Rule(action=RuleAction.BLOCK))
        self.assertEqual(len(engine.rules), 1)  # original unchanged


# =============================================================================
# Configuration
# =============================================================================


class TestConfig(unittest.TestCase):
    """Test configuration loading, saving, and serialization."""

    def test_default_config(self):
        config = GuardianConfig()
        self.assertEqual(config.rules, [])
        self.assertTrue(config.block_when_headless)
        self.assertEqual(config.popup_timeout, 0)
        self.assertEqual(config.http_proxy_port, 8019)

    def test_roundtrip(self):
        config = GuardianConfig(
            rules=[Rule("server1", "tool1", RuleAction.ALLOW, "test rule")],
            popup_timeout=30,
            log_level="DEBUG",
            block_when_headless=False,
        )
        data = config._to_dict()
        loaded = GuardianConfig._from_dict(data)
        self.assertEqual(len(loaded.rules), 1)
        self.assertEqual(loaded.rules[0].server_pattern, "server1")
        self.assertEqual(loaded.rules[0].action, RuleAction.ALLOW)
        self.assertEqual(loaded.popup_timeout, 30)
        self.assertFalse(loaded.block_when_headless)

    def test_save_load_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            config = GuardianConfig(popup_timeout=42)
            config.save(path)

            self.assertTrue(path.exists())

            loaded = GuardianConfig.load(path)
            self.assertEqual(loaded.popup_timeout, 42)

    def test_load_missing_file(self):
        """Loading from a non-existent file should return defaults."""
        config = GuardianConfig.load(Path("/tmp/nonexistent_config_12345.json"))
        self.assertEqual(config.rules, [])
        self.assertEqual(config.popup_timeout, 0)

    def test_load_corrupt_file(self):
        """Loading from a corrupt file should return defaults."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {{{")
            f.flush()
            config = GuardianConfig.load(Path(f.name))
            self.assertEqual(config.rules, [])

    def test_multiple_rules_serialization(self):
        config = GuardianConfig(
            rules=[
                Rule("s1", "t1", RuleAction.ALLOW, "allow s1"),
                Rule("s2", "t2", RuleAction.BLOCK, "block s2"),
                Rule("*", "*", RuleAction.ASK, "default ask"),
            ]
        )
        data = config._to_dict()
        loaded = GuardianConfig._from_dict(data)
        self.assertEqual(len(loaded.rules), 3)
        self.assertEqual(loaded.rules[0].action, RuleAction.ALLOW)
        self.assertEqual(loaded.rules[1].action, RuleAction.BLOCK)
        self.assertEqual(loaded.rules[2].action, RuleAction.ASK)


# =============================================================================
# Setup Helper (Claude Desktop config wrapping)
# =============================================================================


class TestSetupHelper(unittest.TestCase):
    """Test Claude Desktop config wrapping and unwrapping."""

    def test_wrap_basic_config(self):
        original = {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        }
        wrapped = wrap_server_config("filesystem", original)
        self.assertEqual(wrapped["command"], "tutut")
        self.assertIn("--server-name", wrapped["args"])
        self.assertIn("filesystem", wrapped["args"])
        self.assertIn("--", wrapped["args"])
        self.assertIn("npx", wrapped["args"])

    def test_wrap_preserves_env(self):
        original = {
            "command": "npx",
            "args": ["-y", "@some/mcp-server"],
            "env": {"NODE_ENV": "production", "API_KEY": "secret"},
        }
        wrapped = wrap_server_config("test", original)
        self.assertEqual(wrapped["env"], original["env"])

    def test_is_already_wrapped(self):
        self.assertTrue(
            is_already_wrapped({"command": "tutut", "args": ["stdio"]})
        )
        self.assertFalse(is_already_wrapped({"command": "npx", "args": []}))
        self.assertFalse(is_already_wrapped({"command": "python", "args": ["-m", "server"]}))

    def test_unwrap_roundtrip(self):
        original = {
            "command": "npx",
            "args": ["-y", "@some/server"],
            "env": {"KEY": "val"},
        }
        wrapped = wrap_server_config("test", original)
        unwrapped = unwrap_server_config(wrapped)

        self.assertIsNotNone(unwrapped)
        self.assertEqual(unwrapped["command"], "npx")
        self.assertEqual(unwrapped["args"], ["-y", "@some/server"])
        self.assertEqual(unwrapped["env"], {"KEY": "val"})

    def test_unwrap_not_wrapped(self):
        self.assertIsNone(unwrap_server_config({"command": "npx", "args": []}))

    def test_wrap_no_args(self):
        """Server config with no args should still work."""
        original = {"command": "my-mcp-server"}
        wrapped = wrap_server_config("test", original)
        self.assertEqual(wrapped["command"], "tutut")
        # Should have: stdio, --server-name, test, --, my-mcp-server
        self.assertIn("my-mcp-server", wrapped["args"])

    def test_wrap_python_server(self):
        original = {
            "command": "python",
            "args": ["-m", "my_mcp_server", "--port", "3000"],
        }
        wrapped = wrap_server_config("my-python-server", original)
        self.assertEqual(wrapped["command"], "tutut")
        unwrapped = unwrap_server_config(wrapped)
        self.assertEqual(unwrapped["command"], "python")
        self.assertEqual(unwrapped["args"], ["-m", "my_mcp_server", "--port", "3000"])


# =============================================================================
# Security Edge Cases
# =============================================================================


class TestSecurityEdgeCases(unittest.TestCase):
    """Test security-relevant edge cases."""

    def test_oversized_json(self):
        """Very large JSON messages should still parse correctly."""
        large_args = {"data": "x" * 10000}
        raw = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "upload", "arguments": large_args},
            }
        ).encode()
        msg = JsonRpcMessage.parse(raw)
        self.assertIsNotNone(msg)
        self.assertTrue(msg.is_tool_call)
        self.assertEqual(msg.tool_name, "upload")

    def test_unicode_in_tool_name(self):
        """Tool names with unicode should be handled safely."""
        raw = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "tool_éèê", "arguments": {}},
            }
        ).encode()
        msg = JsonRpcMessage.parse(raw)
        self.assertTrue(msg.is_tool_call)
        self.assertEqual(msg.tool_name, "tool_éèê")

    def test_null_id(self):
        """JSON-RPC allows null id (unusual but valid)."""
        msg = JsonRpcMessage(
            raw={"jsonrpc": "2.0", "id": None, "method": "tools/call", "params": {"name": "t"}}
        )
        self.assertTrue(msg.is_tool_call)
        resp = InterceptedRequest(
            id="x", message=msg, server_name="s", tool_name="t", arguments={}
        ).make_blocked_response()
        self.assertIsNone(resp["id"])

    def test_nested_params_injection(self):
        """Ensure deeply nested params don't cause issues."""
        deep = {"level": 0}
        current = deep
        for i in range(1, 50):
            current["nested"] = {"level": i}
            current = current["nested"]

        raw = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "deep_tool", "arguments": deep},
            }
        ).encode()
        msg = JsonRpcMessage.parse(raw)
        self.assertTrue(msg.is_tool_call)

    def test_rule_glob_injection(self):
        """Glob patterns should not be vulnerable to injection."""
        rule = Rule(
            server_pattern="server[!a-z]",
            tool_pattern="tool[*]",
            action=RuleAction.ALLOW,
        )
        # These should not match arbitrary strings
        self.assertFalse(rule.matches("server_normal", "tool_normal"))


# =============================================================================
# Batch JSON-RPC
# =============================================================================


class TestBatchJsonRpc(unittest.TestCase):
    """Test handling of batch JSON-RPC messages."""

    def test_parse_batch_items(self):
        """Each item in a batch should be parseable individually."""
        batch = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "tool_a", "arguments": {}},
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
            },
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "tool_b", "arguments": {"key": "val"}},
            },
        ]

        tool_calls = []
        for item in batch:
            msg = JsonRpcMessage(raw=item)
            if msg.is_tool_call:
                tool_calls.append(msg.tool_name)

        self.assertEqual(tool_calls, ["tool_a", "tool_b"])

    def test_blocked_response_per_item(self):
        """Each blocked tool call should get its own error response with correct id."""
        ids = [10, 20, 30]
        responses = []
        for rid in ids:
            msg = JsonRpcMessage(
                raw={
                    "jsonrpc": "2.0",
                    "id": rid,
                    "method": "tools/call",
                    "params": {"name": f"tool_{rid}"},
                }
            )
            req = InterceptedRequest(
                id=str(rid),
                message=msg,
                server_name="s",
                tool_name=f"tool_{rid}",
                arguments={},
            )
            responses.append(req.make_blocked_response())

        self.assertEqual(len(responses), 3)
        for i, resp in enumerate(responses):
            self.assertEqual(resp["id"], ids[i])
            self.assertTrue(resp["result"]["isError"])


# =============================================================================
# Decision & PopupResult
# =============================================================================


class TestDecision(unittest.TestCase):
    """Test Decision enum."""

    def test_enum_values(self):
        self.assertEqual(Decision.PENDING.value, "pending")
        self.assertEqual(Decision.ALLOW.value, "allow")
        self.assertEqual(Decision.BLOCK.value, "block")


class TestPopupResult(unittest.TestCase):
    """Test PopupResult thread-safety."""

    def test_set_and_wait(self):
        from tutut.gui import PopupResult

        result = PopupResult()
        self.assertFalse(result.is_set)

        result.set(Decision.ALLOW, remember=True)
        self.assertTrue(result.is_set)
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertTrue(result.remember)

    def test_wait_timeout(self):
        from tutut.gui import PopupResult

        result = PopupResult()
        # Should return quickly (timeout)
        decision = result.wait(timeout=0.01)
        self.assertEqual(decision, Decision.PENDING)

    def test_threaded_set(self):
        import threading
        from tutut.gui import PopupResult

        result = PopupResult()

        def _setter():
            import time
            time.sleep(0.05)
            result.set(Decision.BLOCK)

        t = threading.Thread(target=_setter)
        t.start()
        decision = result.wait(timeout=1.0)
        self.assertEqual(decision, Decision.BLOCK)
        t.join()


if __name__ == "__main__":
    unittest.main(verbosity=2)
