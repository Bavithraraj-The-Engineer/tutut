"""
Configuration management for tutut.

Handles loading and saving of rules, settings, and persistent state.
Configuration is stored in a JSON file at ~/.config/tutut/config.json.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Rule, RuleAction

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "tutut"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"
DEFAULT_LOG_FILE = DEFAULT_CONFIG_DIR / "tutut.log"
DEFAULT_AUDIT_FILE = DEFAULT_CONFIG_DIR / "audit.jsonl"   # legacy format, imported once
DEFAULT_AUDIT_DB = DEFAULT_CONFIG_DIR / "audit.db"


@dataclass
class GuardianConfig:
    """Application configuration."""

    # Rules applied in order; first match wins.
    rules: list[Rule] = field(default_factory=list)

    # If True, block requests when the GUI cannot be shown.
    block_when_headless: bool = True

    # Timeout in seconds for user to respond to a popup (0 = no timeout).
    popup_timeout: int = 0

    # HTTP proxy settings (for intercepting remote MCP servers).
    http_proxy_host: str = "127.0.0.1"
    http_proxy_port: int = 8019

    # Logging
    log_file: str = str(DEFAULT_LOG_FILE)
    log_level: str = "INFO"

    # Whether to log full request/response payloads.
    log_payloads: bool = False

    # Audit trail: SQLite database with one row per intercepted tool call.
    audit_db: str = str(DEFAULT_AUDIT_DB)
    # Records older than this are deleted (0 = keep forever).
    audit_retention_days: int = 90
    # Legacy JSON-lines audit file; imported into audit_db once, then renamed.
    audit_file: str = str(DEFAULT_AUDIT_FILE)

    # Secret path segment for the public (tunnelled) web gateway. Generated
    # on first use of `tutut web`; anyone without it gets a 404.
    web_secret: str = ""

    # Claude Desktop servers the background watcher must NOT route through
    # tutut (by their name in claude_desktop_config.json).
    autowrap_exclude: list[str] = field(default_factory=list)

    # File this config was loaded from (not serialized). None for configs
    # built in memory, e.g. in tests: those are never written implicitly.
    source_path: Path | None = field(default=None, repr=False, compare=False)

    @classmethod
    def load(cls, path: Path | None = None) -> GuardianConfig:
        """Load configuration from disk, or create defaults."""
        path = path or DEFAULT_CONFIG_FILE
        config = cls()
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                config = cls._from_dict(data)
            except Exception as exc:
                logger.warning("Failed to load config from %s: %s", path, exc)
        config.source_path = path
        return config

    def save(self, path: Path | None = None) -> None:
        """Persist configuration to disk."""
        path = path or self.source_path or DEFAULT_CONFIG_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        # Owner-only: the file may hold the web gateway secret.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(self._to_dict(), indent=2) + "\n")
        try:
            os.chmod(path, 0o600)  # tighten files created by older versions
        except OSError:
            pass

    # -- serialization helpers ------------------------------------------------

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> GuardianConfig:
        rules = []
        for r in data.get("rules", []):
            rules.append(
                Rule(
                    server_pattern=r.get("server_pattern", "*"),
                    tool_pattern=r.get("tool_pattern", "*"),
                    action=RuleAction(r.get("action", "ask")),
                    description=r.get("description", ""),
                )
            )
        return cls(
            rules=rules,
            block_when_headless=data.get("block_when_headless", True),
            popup_timeout=data.get("popup_timeout", 0),
            http_proxy_host=data.get("http_proxy_host", "127.0.0.1"),
            http_proxy_port=data.get("http_proxy_port", 8019),
            log_file=data.get("log_file", str(DEFAULT_LOG_FILE)),
            log_level=data.get("log_level", "INFO"),
            log_payloads=data.get("log_payloads", False),
            audit_db=data.get("audit_db", str(DEFAULT_AUDIT_DB)),
            audit_retention_days=int(data.get("audit_retention_days", 90) or 0),
            audit_file=data.get("audit_file", str(DEFAULT_AUDIT_FILE)),
            web_secret=str(data.get("web_secret", "") or ""),
            autowrap_exclude=[
                str(name) for name in data.get("autowrap_exclude", []) if name
            ],
        )

    def _to_dict(self) -> dict[str, Any]:
        return {
            "rules": [
                {
                    "server_pattern": r.server_pattern,
                    "tool_pattern": r.tool_pattern,
                    "action": r.action.value,
                    "description": r.description,
                }
                for r in self.rules
            ],
            "block_when_headless": self.block_when_headless,
            "popup_timeout": self.popup_timeout,
            "http_proxy_host": self.http_proxy_host,
            "http_proxy_port": self.http_proxy_port,
            "log_file": self.log_file,
            "log_level": self.log_level,
            "log_payloads": self.log_payloads,
            "audit_db": self.audit_db,
            "audit_retention_days": self.audit_retention_days,
            "audit_file": self.audit_file,
            "web_secret": self.web_secret,
            "autowrap_exclude": list(self.autowrap_exclude),
        }


MAX_LOG_BYTES = 10 * 1024 * 1024
LOG_BACKUPS = 5


def rotate_log_if_large(path: Path, max_bytes: int = MAX_LOG_BYTES, backups: int = LOG_BACKUPS) -> bool:
    """
    tutut.log -> tutut.log.1 -> ... -> tutut.log.<backups> when it exceeds
    max_bytes. Done at process start rather than with RotatingFileHandler:
    several tutut processes share the file, and rotating it mid-run from
    more than one process is unsafe.
    """
    try:
        if path.stat().st_size < max_bytes:
            return False
    except OSError:
        return False
    try:
        for i in range(backups - 1, 0, -1):
            older = path.with_name(f"{path.name}.{i}")
            if older.exists():
                os.replace(older, path.with_name(f"{path.name}.{i + 1}"))
        os.replace(path, path.with_name(f"{path.name}.1"))
        return True
    except OSError:
        return False


def setup_logging(config: GuardianConfig, *, stderr: bool = True) -> None:
    """Configure application logging (log file, plus stderr unless disabled)."""
    log_path = Path(config.log_file)
    from .audit import ensure_private_file

    rotate_log_if_large(log_path)
    try:
        ensure_private_file(log_path)  # owner-only: holds tool names, caller IPs
    except OSError:
        log_path.parent.mkdir(parents=True, exist_ok=True)

    handlers: list[logging.Handler] = [
        logging.FileHandler(str(log_path), encoding="utf-8"),
    ]
    if stderr:
        handlers.append(logging.StreamHandler())  # stderr, won't interfere with stdio

    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )
    # Quiet noisy libraries
    logging.getLogger("asyncio").setLevel(logging.WARNING)
