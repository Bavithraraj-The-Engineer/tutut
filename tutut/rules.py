"""
Rules engine for tutut.

Evaluates intercepted requests against configured rules to determine
whether to auto-allow, auto-block, or prompt the user.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .models import Decision, Rule, RuleAction

if TYPE_CHECKING:
    from .config import GuardianConfig

logger = logging.getLogger(__name__)


class RulesEngine:
    """Evaluates tool calls against a list of ordered rules."""

    def __init__(self, config: GuardianConfig) -> None:
        self._rules = list(config.rules)

    def reload(self, config: GuardianConfig) -> None:
        """Hot-reload rules from updated config."""
        self._rules = list(config.rules)

    def evaluate(self, server_name: str, tool_name: str) -> RuleAction:
        """
        Return the action for the first matching rule.

        If no rule matches, the default is ASK (prompt the user).
        """
        for rule in self._rules:
            if rule.matches(server_name, tool_name):
                logger.debug(
                    "Rule matched: server=%s tool=%s -> %s (%s)",
                    server_name,
                    tool_name,
                    rule.action.value,
                    rule.description,
                )
                return rule.action

        logger.debug(
            "No rule matched for server=%s tool=%s -> ASK",
            server_name,
            tool_name,
        )
        return RuleAction.ASK

    def add_rule(self, rule: Rule, *, persist: bool = False, config: GuardianConfig | None = None) -> None:
        """
        Add a rule at the beginning of the list (highest priority).

        If persist=True and config is provided, saves to disk.
        """
        self._rules.insert(0, rule)
        if persist and config is not None:
            config.rules = list(self._rules)
            config.save()

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)
