"""
Setup helper for tutut.

Provides utilities to automatically configure Claude Desktop's
claude_desktop_config.json to route MCP servers through tutut.
"""

from __future__ import annotations

import json
import logging
import platform
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def get_claude_config_path() -> Path:
    """Return the path to Claude Desktop's config file for the current OS."""
    system = platform.system()
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    elif system == "Windows":
        appdata = Path(str(Path.home()).replace("\\", "/"))
        # Use APPDATA env var if available
        import os
        appdata_dir = os.environ.get("APPDATA")
        if appdata_dir:
            return Path(appdata_dir) / "Claude" / "claude_desktop_config.json"
        return Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
    else:
        # Linux
        return Path.home() / ".config" / "Claude" / "claude_desktop_config.json"


def read_claude_config(config_path: Path | None = None) -> dict[str, Any]:
    """Read and parse the Claude Desktop config file."""
    path = config_path or get_claude_config_path()
    if not path.exists():
        return {"mcpServers": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def wrap_server_config(
    server_name: str,
    original_config: dict[str, Any],
) -> dict[str, Any]:
    """
    Transform an MCP server config entry to route through tutut.

    Uses the same implementation as the background watcher (autowrap), so
    `tutut setup` and `tutut install` write identical entries: tutut's
    absolute path (Claude Desktop starts servers with a minimal PATH), the
    display options the popup needs on Linux, and every other key kept.

        {"command": "npx", "args": ["-y", "@some/mcp-server"]}
    becomes
        {"command": "/home/me/.local/share/tutut/venv/bin/tutut",
         "args": ["stdio", "--server-name", "my-server", "--display", ":0", …,
                  "--", "npx", "-y", "@some/mcp-server"]}
    """
    from . import autowrap

    return autowrap.wrap_entry(
        server_name, original_config,
        command=autowrap.tutut_executable(), gui=autowrap.gui_args(),
    )


def is_already_wrapped(config: dict[str, Any]) -> bool:
    """Whether an entry already starts through `tutut stdio` (any install path)."""
    from . import autowrap

    return autowrap.is_wrapped(config)


def setup_claude_desktop(
    config_path: Path | None = None,
    server_names: list[str] | None = None,
    dry_run: bool = False,
) -> dict[str, str]:
    """
    Set up tutut for Claude Desktop by modifying its config.

    Args:
        config_path: Path to claude_desktop_config.json (auto-detected if None).
        server_names: Specific servers to wrap (all if None).
        dry_run: If True, show changes without applying.

    Returns:
        Dict mapping server names to their status ('wrapped', 'skipped', 'error').
    """
    path = config_path or get_claude_config_path()
    results: dict[str, str] = {}

    if not path.exists():
        logger.error("Claude Desktop config not found at %s", path)
        return {"_error": f"Config file not found: {path}"}

    config = read_claude_config(path)
    servers = config.get("mcpServers", {})

    if not servers:
        logger.info("No MCP servers configured in Claude Desktop.")
        return {"_info": "No servers found"}

    # Back up the original config
    if not dry_run:
        backup_path = path.with_suffix(
            f".backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        )
        shutil.copy2(path, backup_path)
        logger.info("Backed up config to %s", backup_path)

    targets = server_names or list(servers.keys())

    for name in targets:
        if name not in servers:
            results[name] = "not_found"
            continue

        if is_already_wrapped(servers[name]):
            results[name] = "already_wrapped"
            continue

        try:
            servers[name] = wrap_server_config(name, servers[name])
            results[name] = "wrapped"
        except Exception as exc:
            results[name] = f"error: {exc}"

    if not dry_run:
        config["mcpServers"] = servers
        path.write_text(
            json.dumps(config, indent=2) + "\n",
            encoding="utf-8",
        )
        logger.info("Updated Claude Desktop config at %s", path)

    return results


def unwrap_server_config(config: dict[str, Any]) -> dict[str, Any] | None:
    """
    Reverse a tutut-wrapped entry back to the original (every key kept).

    Returns None if the entry isn't wrapped by tutut.
    """
    from . import autowrap

    return autowrap.unwrap_entry(config)


def teardown_claude_desktop(
    config_path: Path | None = None,
    server_names: list[str] | None = None,
) -> dict[str, str]:
    """Remove tutut wrapping from Claude Desktop config."""
    path = config_path or get_claude_config_path()
    results: dict[str, str] = {}

    if not path.exists():
        return {"_error": f"Config file not found: {path}"}

    config = read_claude_config(path)
    servers = config.get("mcpServers", {})
    targets = server_names or list(servers.keys())

    # Backup
    backup_path = path.with_suffix(
        f".backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    )
    shutil.copy2(path, backup_path)

    for name in targets:
        if name not in servers:
            results[name] = "not_found"
            continue

        original = unwrap_server_config(servers[name])
        if original is None:
            results[name] = "not_wrapped"
            continue

        servers[name] = original
        results[name] = "unwrapped"

    config["mcpServers"] = servers
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    return results
