"""
Data models for tutut.

Defines the structures used throughout the application for representing
JSON-RPC messages, interception decisions, and configuration rules.
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any


class Decision(enum.Enum):
    """User decision on an intercepted request."""
    PENDING = "pending"
    ALLOW = "allow"
    BLOCK = "block"


class RuleAction(enum.Enum):
    """Automatic action for a matching rule."""
    ALLOW = "allow"
    BLOCK = "block"
    ASK = "ask"


@dataclass
class JsonRpcMessage:
    """A parsed JSON-RPC 2.0 message."""

    raw: dict[str, Any]

    @property
    def jsonrpc(self) -> str:
        return self.raw.get("jsonrpc", "")

    @property
    def method(self) -> str | None:
        return self.raw.get("method")

    @property
    def params(self) -> dict[str, Any] | None:
        return self.raw.get("params")

    @property
    def id(self) -> Any:
        return self.raw.get("id")

    @property
    def is_request(self) -> bool:
        return "method" in self.raw and "id" in self.raw

    @property
    def is_notification(self) -> bool:
        return "method" in self.raw and "id" not in self.raw

    @property
    def is_response(self) -> bool:
        return "result" in self.raw or "error" in self.raw

    @property
    def is_tool_call(self) -> bool:
        return self.method == "tools/call"

    @property
    def tool_name(self) -> str | None:
        if self.params:
            return self.params.get("name")
        return None

    @property
    def tool_arguments(self) -> dict[str, Any] | None:
        if self.params:
            return self.params.get("arguments")
        return None

    def to_bytes(self) -> bytes:
        """Serialize back to newline-delimited JSON bytes."""
        import json
        return json.dumps(self.raw).encode("utf-8") + b"\n"

    @staticmethod
    def parse(data: bytes) -> JsonRpcMessage | None:
        """Parse a single JSON-RPC message from bytes."""
        import json
        try:
            obj = json.loads(data)
            if isinstance(obj, dict):
                return JsonRpcMessage(raw=obj)
        except (json.JSONDecodeError, ValueError):
            pass
        return None


@dataclass
class InterceptedRequest:
    """An MCP request that has been intercepted and is pending user decision."""

    id: str
    message: JsonRpcMessage
    server_name: str
    tool_name: str
    arguments: dict[str, Any]
    decision: Decision = Decision.PENDING
    timestamp: float = field(default_factory=time.time)
    # Where the call came from, shown in the popup and the audit log,
    # e.g. "Claude Desktop (local)" or "claude.ai via tunnel".
    source: str = ""
    # MCP tool annotations the server declared in tools/list (readOnlyHint,
    # destructiveHint, ...), if seen. Hints only - the server may be wrong.
    annotations: dict[str, Any] | None = None

    def make_blocked_response(self, reason: str = "user") -> dict[str, Any]:
        """Create the response sent back to the client for a blocked request."""
        return blocked_response(self.message.id, self.tool_name, self.server_name, reason)


# Why a call was blocked, in words the model can relay to the user.
_BLOCK_REASONS = {
    "user": "The user denied this request",
    "rule": "A tutut block rule denied this request",
    "timeout": "The user did not respond in time, so the request was denied",
    "headless": "No approval popup could be shown, so the request was denied",
    "queue_full": "Too many requests were waiting for approval, so the request was denied",
    "error": "tutut could not get a decision, so the request was denied",
}


def blocked_response(
    msg_id: Any, tool_name: str | None, server_name: str, reason: str = "user"
) -> dict[str, Any]:
    """
    Response for a blocked tools/call.

    Sent as a tool *result* with isError=true rather than a JSON-RPC error:
    per the MCP spec, tool-level failures belong in the result so the model
    can read them, and Claude then tells the user the call was blocked
    instead of reporting a protocol failure.
    """
    why = _BLOCK_REASONS.get(reason, _BLOCK_REASONS["user"])
    text = (
        f"Blocked by tutut: the call to tool '{tool_name or '(unknown)'}' on MCP "
        f"server '{server_name}' was not executed. {why}. "
        "Do not retry this call unless the user asks you to."
    )
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "content": [{"type": "text", "text": text}],
            "isError": True,
        },
    }


@dataclass
class Rule:
    """An allow/block rule for automatic decisions on tool calls."""

    server_pattern: str = "*"      # glob pattern for server name
    tool_pattern: str = "*"        # glob pattern for tool name
    action: RuleAction = RuleAction.ASK
    description: str = ""

    def matches(self, server_name: str, tool_name: str) -> bool:
        """Check if this rule matches the given server and tool."""
        import fnmatch
        return (
            fnmatch.fnmatch(server_name, self.server_pattern)
            and fnmatch.fnmatch(tool_name, self.tool_pattern)
        )
