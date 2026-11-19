"""
Decision engine shared by every interception path.

The stdio proxy (Claude Desktop, local and mcp-remote servers) and the HTTP
gateway (claude.ai and other remote clients via a tunnel) both hand each
intercepted tools/call to `Interceptor.decide()`, which:

  1. applies the allow/block rules (first match wins),
  2. otherwise asks the user with the always-on-top popup and waits
     *asynchronously* - other requests keep flowing meanwhile,
  3. fails closed: no display, a full queue, a timeout or a popup error
     all mean "block",
  4. withdraws the popup if the caller is cancelled (the client gave up),
  5. writes one audit record per call.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .audit import AuditLog
from .config import GuardianConfig
from .models import Decision, InterceptedRequest, JsonRpcMessage, Rule, RuleAction
from .risk import classify
from .rules import RulesEngine

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Verdict:
    """Outcome of one intercepted call."""

    allowed: bool
    # "rule", "user", "timeout", "headless", "queue_full" or "error"
    decided_by: str
    wait_ms: int = 0


class Interceptor:
    """Decides whether an intercepted tools/call may proceed."""

    def __init__(
        self,
        config: GuardianConfig,
        *,
        server_name: str,
        transport: str,
        source: str,
        popup_manager: Any = None,
        gui_available: bool | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self._config = config
        self.server_name = server_name
        self.transport = transport
        self.source = source
        self._rules = RulesEngine(config)
        self._popup_mgr = popup_manager
        self._gui_available = gui_available
        # Only configs loaded from disk (real runs) write the audit file by
        # default; in-memory configs (tests, embedding) need an explicit log.
        self.audit = audit if audit is not None else AuditLog(
            config.audit_db if config.source_path is not None else None,
            retention_days=config.audit_retention_days,
            legacy_jsonl=config.audit_file,
        )
        # tool name -> MCP annotations, learned from tools/list responses
        self.tool_annotations: dict[str, dict[str, Any]] = {}

    def learn_tools(self, result: Any) -> None:
        """Remember each tool's annotations from a tools/list result."""
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            return
        for tool in tools:
            if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                ann = tool.get("annotations")
                self.tool_annotations[tool["name"]] = ann if isinstance(ann, dict) else {}

    # -- lazily initialised UI -------------------------------------------------

    @property
    def gui_available(self) -> bool:
        if self._gui_available is None:
            from .gui import is_gui_available

            self._gui_available = is_gui_available()
        return self._gui_available

    @gui_available.setter
    def gui_available(self, value: bool) -> None:
        self._gui_available = value

    @property
    def popup_manager(self) -> Any:
        if self._popup_mgr is None:
            from .gui import PopupManager

            self._popup_mgr = PopupManager(timeout=self._config.popup_timeout)
        return self._popup_mgr

    @property
    def rules(self) -> RulesEngine:
        return self._rules

    # -- the decision ----------------------------------------------------------

    async def decide(
        self, msg: JsonRpcMessage, *, extra: dict[str, Any] | None = None
    ) -> Verdict:
        """
        Decide on one tools/call. Raises CancelledError (after withdrawing
        the popup and auditing it) if the caller is cancelled while waiting.
        """
        tool = msg.tool_name or "(unknown)"
        arguments = msg.tool_arguments or {}
        start = time.monotonic()
        extra = {**(extra or {}), "risk": classify(tool, self.tool_annotations.get(tool)).level}
        logger.info(
            "Intercepted tool call: transport=%s server=%s tool=%s",
            self.transport, self.server_name, tool,
        )

        try:
            verdict = await self._decide(msg, tool, arguments)
        except asyncio.CancelledError:
            self._record(msg, tool, arguments, "cancelled", "client", start, extra)
            logger.info("Tool call cancelled by the client while pending: %s", tool)
            raise

        verdict = Verdict(verdict.allowed, verdict.decided_by,
                          int((time.monotonic() - start) * 1000))
        self._record(
            msg, tool, arguments,
            "allow" if verdict.allowed else "block", verdict.decided_by, start, extra,
        )
        logger.info(
            "%s tool call %s on %s (decided by %s)",
            "Allowed" if verdict.allowed else "Blocked",
            tool, self.server_name, verdict.decided_by,
        )
        return verdict

    async def _decide(self, msg: JsonRpcMessage, tool: str, arguments: dict[str, Any]) -> Verdict:
        action = self._rules.evaluate(self.server_name, tool)
        if action == RuleAction.ALLOW:
            return Verdict(True, "rule")
        if action == RuleAction.BLOCK:
            return Verdict(False, "rule")

        if not self.gui_available:
            allowed = not self._config.block_when_headless
            logger.warning(
                "No GUI available; %s tool call: %s", "allowing" if allowed else "blocking", tool
            )
            return Verdict(allowed, "headless")

        return await self._ask_user(msg, tool, arguments)

    async def _ask_user(self, msg: JsonRpcMessage, tool: str, arguments: dict[str, Any]) -> Verdict:
        request = InterceptedRequest(
            id=str(uuid.uuid4()),
            message=msg,
            server_name=self.server_name,
            tool_name=tool,
            arguments=arguments,
            source=self.source,
            annotations=self.tool_annotations.get(tool),
        )
        result = self.popup_manager.request_decision(request)

        # Bridge the popup thread to asyncio without parking a thread per call.
        loop = asyncio.get_running_loop()
        done = loop.create_future()

        def _wake(_result: Any) -> None:
            try:
                loop.call_soon_threadsafe(lambda: done.done() or done.set_result(None))
            except RuntimeError:
                pass  # loop already closed (shutting down)

        result.add_done_callback(_wake)
        try:
            await done
        except asyncio.CancelledError:
            self.popup_manager.cancel(request.id)
            raise

        allowed = result.decision == Decision.ALLOW
        reason = result.reason or "user"
        if result.remember and reason == "user":
            self._remember(tool, allowed)
        return Verdict(allowed, reason)

    # -- helpers ---------------------------------------------------------------

    def _remember(self, tool: str, allowed: bool) -> None:
        """Persist the user's "remember this decision" choice as a rule."""
        rule = Rule(
            server_pattern=self.server_name,
            tool_pattern=tool,
            action=RuleAction.ALLOW if allowed else RuleAction.BLOCK,
            description=f"Auto-created: {'allow' if allowed else 'block'} {tool} on {self.server_name}",
        )
        self._rules.add_rule(rule)  # effective immediately in this process
        path = self._config.source_path
        if path is None:
            return
        try:
            # Re-read first: other tutut processes may have changed the file
            # (e.g. the web gateway's secret) since this one started.
            fresh = GuardianConfig.load(path)
            fresh.rules.insert(0, rule)
            fresh.save(path)
            logger.info("Saved %s rule for %s/%s", rule.action.value, self.server_name, tool)
        except Exception:
            logger.exception("Could not save rule to %s", path)

    def _record(
        self,
        msg: JsonRpcMessage,
        tool: str,
        arguments: dict[str, Any],
        decision: str,
        decided_by: str,
        start: float,
        extra: dict[str, Any] | None,
    ) -> None:
        self.audit.record(
            transport=self.transport,
            source=self.source,
            server=self.server_name,
            tool=tool,
            arguments=arguments,
            decision=decision,
            decided_by=decided_by,
            wait_ms=int((time.monotonic() - start) * 1000),
            request_id=msg.id,
            extra=extra,
        )
