"""
Background service for tutut: the config watcher plus install/uninstall.

`tutut install` sets everything up once:
  1. creates tutut's config with safe defaults (if missing),
  2. registers `tutut watch` to start at login (XDG autostart on Linux, so it
     runs inside the desktop session and can reach the display),
  3. wraps all current Claude Desktop MCP servers and starts the watcher.

`tutut watch` keeps claude_desktop_config.json wrapped: whenever a server is
added or changed, it is routed through tutut within a couple of seconds and
the user gets a desktop notification to restart Claude Desktop.

`tutut uninstall` stops the watcher, removes the autostart entry and restores
every server entry to its original form.
"""

from __future__ import annotations

import contextlib
import logging
import os
import platform
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Iterator

from . import autowrap
from .config import DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_FILE, GuardianConfig
from .setup_helper import get_claude_config_path

logger = logging.getLogger(__name__)

PID_FILE = DEFAULT_CONFIG_DIR / "watch.pid"
AUTOSTART_NAME = "tutut-watch.desktop"
DEFAULT_POPUP_TIMEOUT = 45  # seconds; below typical MCP client request timeouts
WATCH_INTERVAL = 2.0  # seconds between config checks


def autostart_path() -> Path:
    """Location of the XDG autostart entry for the watcher."""
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "autostart" / AUTOSTART_NAME


# -- desktop notifications -----------------------------------------------------


def notify(title: str, body: str) -> None:
    """Best-effort desktop notification; never raises."""
    try:
        if platform.system() == "Linux" and shutil.which("notify-send"):
            subprocess.Popen(
                ["notify-send", "--app-name=tutut", title, body],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except Exception:
        logger.debug("Notification failed", exc_info=True)


def _describe_changes(changes: dict[str, str]) -> str:
    wrapped = [n for n, s in changes.items() if s in ("wrapped", "updated")]
    unwrapped = [n for n, s in changes.items() if s == "unwrapped"]
    parts = []
    if wrapped:
        parts.append("Now guarding: " + ", ".join(sorted(wrapped)) + ".")
    if unwrapped:
        parts.append("No longer guarding: " + ", ".join(sorted(unwrapped)) + ".")
    parts.append("Restart Claude Desktop to apply.")
    return " ".join(parts)


# -- single-instance pid file --------------------------------------------------


def _read_pid() -> int | None:
    try:
        return int(PID_FILE.read_text().strip())
    except (OSError, ValueError):
        return None


def _is_watcher_process(pid: int) -> bool:
    """True if `pid` is a running `tutut watch` process (Linux /proc check)."""
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    except OSError:
        return False
    cmdline_file = Path(f"/proc/{pid}/cmdline")
    if cmdline_file.exists():
        try:
            parts = cmdline_file.read_bytes().split(b"\0")
        except OSError:
            return False
        names = [Path(p.decode(errors="replace")).name for p in parts if p]
        return "watch" in names and any(n.startswith("tutut") for n in names)
    return True  # no /proc: trust the pid file


def running_watcher_pid() -> int | None:
    """PID of the running watcher, if any."""
    pid = _read_pid()
    if pid is not None and pid != os.getpid() and _is_watcher_process(pid):
        return pid
    return None


@contextlib.contextmanager
def _pid_lock() -> Iterator[bool]:
    """
    Hold the watcher's pid file with an exclusive lock.

    Yields False if another watcher already holds it.
    """
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    handle = open(PID_FILE, "a+")
    try:
        try:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:  # non-POSIX: fall back to the pid check
            if running_watcher_pid() is not None:
                yield False
                return
        except OSError:
            yield False
            return
        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()))
        handle.flush()
        try:
            yield True
        finally:
            with contextlib.suppress(OSError):
                handle.seek(0)
                handle.truncate()
    finally:
        handle.close()


# -- the watcher ---------------------------------------------------------------


def _file_signature(path: Path) -> tuple[int, int] | None:
    try:
        st = path.stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


def reconcile_once(claude_config: Path, config_path: Path | None = None) -> dict[str, str]:
    """Wrap every eligible server now. Returns the changes made."""
    config = GuardianConfig.load(config_path)
    return autowrap.apply_to_file(claude_config, exclude=config.autowrap_exclude)


def watch(
    claude_config: Path | None = None,
    *,
    config_path: Path | None = None,
    interval: float = WATCH_INTERVAL,
    stop: threading.Event | None = None,
) -> int:
    """
    Keep the Claude Desktop config wrapped until stopped (SIGTERM/SIGINT).

    Returns a process exit code.
    """
    path = claude_config or get_claude_config_path()
    stop = stop or threading.Event()

    with _pid_lock() as acquired:
        if not acquired:
            logger.info("Another tutut watcher is already running; exiting")
            return 0

        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, lambda *_: stop.set())

        tutut_config = config_path or DEFAULT_CONFIG_FILE
        logger.info("Watching %s (pid %d)", path, os.getpid())
        last_seen: Any = object()  # force a first pass
        while not stop.is_set():
            # React to Claude Desktop's config and to tutut's own exclusions.
            signature = (_file_signature(path), _file_signature(tutut_config))
            if signature != last_seen:
                try:
                    changes = reconcile_once(path, config_path)
                except Exception:
                    logger.exception("Error updating %s", path)
                    changes = {}
                if changes:
                    notify("tutut", _describe_changes(changes))
                    # Our own write changed the file; don't treat it as new.
                    signature = (_file_signature(path), _file_signature(tutut_config))
                last_seen = signature
            stop.wait(interval)
        logger.info("Watcher stopped")
    return 0


def start_watcher_background(tutut_cmd: str) -> int | None:
    """Start `tutut watch` detached from this process. Returns its pid."""
    if running_watcher_pid() is not None:
        return running_watcher_pid()
    proc = subprocess.Popen(
        [tutut_cmd, "watch"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    # Give it a moment to take the lock so `status` is accurate right away.
    for _ in range(20):
        if running_watcher_pid() == proc.pid:
            break
        time.sleep(0.1)
    return proc.pid


def stop_watcher(timeout: float = 5.0) -> bool:
    """Stop the running watcher. Returns True if one was stopped."""
    pid = running_watcher_pid()
    if pid is None:
        return False
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _is_watcher_process(pid):
            return True
        time.sleep(0.1)
    return False


# -- install / uninstall / status ------------------------------------------------


def _autostart_entry(tutut_cmd: str) -> str:
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=tutut\n"
        "Comment=Ask before Claude Desktop runs any MCP tool\n"
        f'Exec="{tutut_cmd}" watch\n'
        "Terminal=false\n"
        "NoDisplay=true\n"
        "X-GNOME-Autostart-enabled=true\n"
    )


class InstallError(RuntimeError):
    """Raised when tutut can't be installed on this system."""


def install(
    *,
    claude_config: Path | None = None,
    start: bool = True,
) -> list[str]:
    """
    One-time setup. Safe to run again (it updates paths and restarts nothing
    that is already correct). Returns human-readable status lines.
    """
    if platform.system() != "Linux":
        raise InstallError(
            "Automatic install currently supports Linux only. On other systems "
            "run 'tutut watch' yourself (e.g. from a login item)."
        )
    from .gui import _TK_AVAILABLE

    if not _TK_AVAILABLE:
        raise InstallError(
            f"tkinter is not available in {sys.executable}, so tutut could not "
            "show its popup and would block every tool call. Install tkinter "
            "(Ubuntu/Debian: sudo apt install python3-tk) or reinstall tutut "
            "with a Python that has it."
        )

    lines: list[str] = []
    tutut_cmd = autowrap.tutut_executable()

    if not DEFAULT_CONFIG_FILE.exists():
        GuardianConfig(popup_timeout=DEFAULT_POPUP_TIMEOUT).save()
        lines.append(
            f"Created {DEFAULT_CONFIG_FILE} (ask for every tool call; "
            f"auto-block after {DEFAULT_POPUP_TIMEOUT}s)"
        )
    else:
        lines.append(f"Keeping existing {DEFAULT_CONFIG_FILE}")

    entry_path = autostart_path()
    entry_path.parent.mkdir(parents=True, exist_ok=True)
    entry_path.write_text(_autostart_entry(tutut_cmd), encoding="utf-8")
    lines.append(f"Watcher starts at login: {entry_path}")

    path = claude_config or get_claude_config_path()
    if path.exists():
        changes = reconcile_once(path)
        guarded = autowrap.wrapped_servers(
            autowrap.parse_config(autowrap.read_config_text(path) or "{}", path) or {}
        )
        lines.append(
            "Guarding Claude Desktop servers: "
            + (", ".join(guarded) if guarded else "(none yet - new ones are picked up automatically)")
        )
        if changes:
            lines.append("Restart Claude Desktop to apply.")
    else:
        lines.append(f"Claude Desktop config not found yet ({path}); the watcher will pick it up")

    if start:
        # Restart so an upgrade (re-running the installer) takes effect.
        restarted = stop_watcher()
        pid = start_watcher_background(tutut_cmd)
        lines.append(f"Watcher {'restarted' if restarted else 'running'} (pid {pid})")
    return lines


def uninstall(*, claude_config: Path | None = None) -> list[str]:
    """Stop the watcher, remove autostart, unwrap all servers."""
    lines: list[str] = []
    if stop_watcher():
        lines.append("Stopped the watcher")
    entry_path = autostart_path()
    if entry_path.exists():
        entry_path.unlink()
        lines.append(f"Removed {entry_path}")
    path = claude_config or get_claude_config_path()
    changes = autowrap.apply_to_file(path, unwrap=True)
    if changes:
        lines.append("Restored original entries: " + ", ".join(sorted(changes)))
        lines.append("Restart Claude Desktop to apply.")
    lines.append(f"Kept {DEFAULT_CONFIG_DIR} (your rules and log)")
    return lines


def status(*, claude_config: Path | None = None) -> list[str]:
    """Human-readable status lines."""
    pid = running_watcher_pid()
    path = claude_config or get_claude_config_path()
    text = autowrap.read_config_text(path)
    config = autowrap.parse_config(text, path) if text else None
    guarded = autowrap.wrapped_servers(config or {})
    servers = (config or {}).get("mcpServers") or {}
    unguarded = [
        n for n, e in servers.items()
        if n not in guarded and isinstance(e, dict) and e.get("command")
    ]
    return [
        f"Watcher:   {'running (pid %d)' % pid if pid else 'not running'}",
        f"Autostart: {'enabled' if autostart_path().exists() else 'not installed'}",
        f"Config:    {path}{'' if text is not None else ' (not found)'}",
        f"Guarded:   {', '.join(guarded) if guarded else '(none)'}",
        f"Unguarded: {', '.join(unguarded) if unguarded else '(none)'}",
    ]
