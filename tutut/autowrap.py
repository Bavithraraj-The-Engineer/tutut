"""
Automatic wrapping of Claude Desktop MCP servers.

Used by the background watcher (`tutut watch`) and by `tutut install` /
`tutut uninstall`. Every server in claude_desktop_config.json that Claude
Desktop starts as a local command is rewritten to start through
`tutut stdio`, so each of its tool calls shows tutut's approval popup:

    {"command": "npx", "args": ["-y", "@some/server"]}

becomes

    {"command": "/home/me/.local/share/tutut/venv/bin/tutut",
     "args": ["stdio", "--server-name", "my-server",
              "--display", ":0", "--xauthority", "/run/user/1000/gdm/Xauthority",
              "--", "npx", "-y", "@some/server"]}

Design rules:
  - The tutut path is absolute. Claude Desktop starts servers with its own
    PATH, where a bare "tutut" may be a different Python without tkinter.
  - Display info is passed as tutut options (before "--"), never in the
    server's "env", so unwrapping restores the original entry exactly.
  - Entries without a "command" (e.g. URL-based) are left alone.
  - Writes are atomic, keep file permissions, and are skipped if the file
    changed while we were computing (Claude Desktop writes this file too).
"""

from __future__ import annotations

import copy
import json
import logging
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping

logger = logging.getLogger(__name__)

TUTUT_EXECUTABLE_NAMES = ("tutut", "tutut.exe")
_GUI_OPTIONS = ("--display", "--xauthority")


# -- environment ---------------------------------------------------------------


def tutut_executable() -> str:
    """
    Absolute path of the tutut executable belonging to this installation.

    Prefers the console script next to the running interpreter (the venv
    tutut was installed into), without resolving symlinks.
    """
    bin_dir = Path(sys.executable).parent
    for name in TUTUT_EXECUTABLE_NAMES:
        candidate = bin_dir / name
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("tutut")
    return str(Path(found).absolute()) if found else "tutut"


def gui_args(environ: Mapping[str, str] | None = None) -> list[str]:
    """
    `tutut stdio` options that let the popup reach the user's display.

    Only needed on Linux, where MCP clients may start servers without
    DISPLAY/XAUTHORITY. Empty if the current environment has no display.
    """
    if platform.system() != "Linux":
        return []
    env = os.environ if environ is None else environ
    args: list[str] = []
    display = env.get("DISPLAY")
    if display:
        args += ["--display", display]
        xauthority = env.get("XAUTHORITY")
        if xauthority:
            args += ["--xauthority", xauthority]
    return args


# -- single entries ------------------------------------------------------------


def is_wrapped(entry: Any) -> bool:
    """Whether a server entry already starts through `tutut stdio`."""
    if not isinstance(entry, dict):
        return False
    command = entry.get("command")
    args = entry.get("args")
    return (
        isinstance(command, str)
        and Path(command).name in TUTUT_EXECUTABLE_NAMES
        and isinstance(args, list)
        and args[:1] == ["stdio"]
        and "--" in args
    )


def _proxy_args(entry: dict[str, Any]) -> list[str]:
    """The tutut options of a wrapped entry (everything before "--")."""
    args = entry["args"]
    return args[: args.index("--")]


def _existing_gui_args(entry: dict[str, Any]) -> list[str]:
    """--display/--xauthority options already present in a wrapped entry."""
    proxy = _proxy_args(entry)
    found: list[str] = []
    for i, arg in enumerate(proxy[:-1]):
        if arg in _GUI_OPTIONS:
            found += [arg, proxy[i + 1]]
    return found


def unwrap_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Return the original entry of a wrapped one, or None if not wrapped."""
    if not is_wrapped(entry):
        return None
    args = entry["args"]
    sep = args.index("--")
    if sep + 1 >= len(args):
        return None
    original = copy.deepcopy(entry)
    original["command"] = args[sep + 1]
    original["args"] = list(args[sep + 2:])
    return original


def wrap_entry(
    name: str,
    entry: dict[str, Any],
    *,
    command: str,
    gui: list[str],
) -> dict[str, Any]:
    """Wrap an (unwrapped) entry. Other keys, including "env", are kept."""
    wrapped = copy.deepcopy(entry)
    wrapped["command"] = command
    wrapped["args"] = (
        ["stdio", "--server-name", name]
        + list(gui)
        + ["--", entry["command"]]
        + list(entry.get("args") or [])
    )
    return wrapped


def desired_entry(
    name: str,
    entry: Any,
    *,
    command: str,
    gui: list[str],
) -> dict[str, Any] | None:
    """
    The entry as it should be, or None if it should be left unchanged.

    If `gui` is empty (e.g. the watcher runs without a display), display
    options already recorded in a wrapped entry are kept rather than dropped.
    """
    if not isinstance(entry, dict):
        return None
    if is_wrapped(entry):
        original = unwrap_entry(entry)
        if original is None:
            return None
        target = wrap_entry(
            name, original, command=command, gui=gui or _existing_gui_args(entry)
        )
        return target if target != entry else None
    if not isinstance(entry.get("command"), str) or not entry["command"]:
        return None  # URL-based or malformed: nothing to wrap
    if not isinstance(entry.get("args", []), list):
        return None
    return wrap_entry(name, entry, command=command, gui=gui)


# -- whole config --------------------------------------------------------------


def reconcile(
    config: dict[str, Any],
    *,
    command: str,
    gui: list[str],
    exclude: Iterable[str] = (),
) -> tuple[dict[str, Any], dict[str, str]]:
    """
    Compute the config with every eligible server wrapped.

    Servers named in `exclude` are unwrapped instead. Returns the new config
    and {server_name: "wrapped" | "updated" | "unwrapped"} for changed entries.
    """
    excluded = set(exclude)
    new_config = copy.deepcopy(config)
    servers = new_config.get("mcpServers")
    changes: dict[str, str] = {}
    if not isinstance(servers, dict):
        return new_config, changes

    for name, entry in list(servers.items()):
        if name in excluded:
            original = unwrap_entry(entry) if is_wrapped(entry) else None
            if original is not None:
                servers[name] = original
                changes[name] = "unwrapped"
            continue
        target = desired_entry(name, entry, command=command, gui=gui)
        if target is not None:
            changes[name] = "updated" if is_wrapped(entry) else "wrapped"
            servers[name] = target
    return new_config, changes


def unwrap_all(config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """Unwrap every tutut-wrapped server. Returns (new_config, changes)."""
    new_config = copy.deepcopy(config)
    servers = new_config.get("mcpServers")
    changes: dict[str, str] = {}
    if isinstance(servers, dict):
        for name, entry in list(servers.items()):
            original = unwrap_entry(entry) if is_wrapped(entry) else None
            if original is not None:
                servers[name] = original
                changes[name] = "unwrapped"
    return new_config, changes


def wrapped_servers(config: dict[str, Any]) -> list[str]:
    """Names of servers currently routed through tutut."""
    servers = config.get("mcpServers")
    if not isinstance(servers, dict):
        return []
    return [name for name, entry in servers.items() if is_wrapped(entry)]


# -- file I/O ------------------------------------------------------------------


def read_config_text(path: Path) -> str | None:
    """Raw config text, or None if the file does not exist or can't be read."""
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        logger.warning("Cannot read %s: %s", path, exc)
        return None


def parse_config(text: str, path: Path) -> dict[str, Any] | None:
    """Parse config JSON; None (and a log line) if it's not a JSON object."""
    try:
        data = json.loads(text)
    except ValueError as exc:
        # Possibly caught mid-write by another program; retried next round.
        logger.warning("Cannot parse %s: %s", path, exc)
        return None
    return data if isinstance(data, dict) else None


def write_config_if_unchanged(path: Path, data: dict[str, Any], expected_text: str) -> bool:
    """
    Atomically replace the config, unless it changed since `expected_text`.

    Keeps the file's permissions. Returns True if written.
    """
    if read_config_text(path) != expected_text:
        logger.info("%s changed while updating; will retry", path)
        return False
    mode = path.stat().st_mode & 0o777
    tmp = path.with_name(f".{path.name}.tutut-tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    return True


def apply_to_file(
    path: Path,
    *,
    unwrap: bool = False,
    command: str | None = None,
    gui: list[str] | None = None,
    exclude: Iterable[str] = (),
) -> dict[str, str]:
    """
    Reconcile (or, with unwrap=True, unwrap) the config file in place.

    Returns the changes made; empty if the file is missing, unparseable,
    already correct, or was modified concurrently (try again later).
    """
    text = read_config_text(path)
    if text is None:
        return {}
    config = parse_config(text, path)
    if config is None:
        return {}
    if unwrap:
        new_config, changes = unwrap_all(config)
    else:
        new_config, changes = reconcile(
            config,
            command=command or tutut_executable(),
            gui=gui_args() if gui is None else gui,
            exclude=exclude,
        )
    if not changes:
        return {}
    if not write_config_if_unchanged(path, new_config, text):
        return {}
    logger.info("Updated %s: %s", path, changes)
    return changes
