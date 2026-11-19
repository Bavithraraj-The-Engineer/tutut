"""
Remote MCP servers in Claude Desktop, through mcp-remote (path 2).

Claude Desktop's account connectors are called from Anthropic's cloud, so
nothing on this machine sees their traffic. A remote server can instead be
added to claude_desktop_config.json as a *local* process:

    npx -y mcp-remote https://mcp.example.com/mcp

mcp-remote speaks stdio to Claude Desktop and HTTP to the server. tutut
wraps that process like any other local server, so every call to the remote
server is held for approval:

    Claude Desktop ─stdio─▶ tutut stdio ─stdio─▶ mcp-remote ─HTTPS─▶ remote MCP server

`tutut add-remote NAME URL` writes such an entry (already wrapped), picking
a Node.js >= 18 for npx. Turn off any account connector for the same server
in Claude Desktop, or Claude sees the tools twice and may use the unguarded
copy.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import autowrap
from .setup_helper import get_claude_config_path

MIN_NODE_MAJOR = 18
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class RemoteError(Exception):
    """A user-facing problem adding or removing a remote server."""


# -- Node.js discovery ---------------------------------------------------------


def node_major(node: str) -> int | None:
    """Major version of a node binary, or None if it doesn't run."""
    try:
        out = subprocess.run(
            [node, "--version"], capture_output=True, text=True, timeout=10
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.match(r"v?(\d+)\.", out)
    return int(match.group(1)) if match else None


def _sibling_node(npx: Path) -> Path:
    name = "node.exe" if platform.system() == "Windows" else "node"
    return npx.with_name(name)


def _version_key(path: Path) -> tuple[int, ...]:
    match = re.search(r"v(\d+)\.(\d+)\.(\d+)", str(path))
    return tuple(int(x) for x in match.groups()) if match else (0,)


def _npx_candidates() -> list[Path]:
    found: list[Path] = []
    for name in ("npx", "npx.cmd"):
        which = shutil.which(name)
        if which:
            found.append(Path(which))
    nvm = Path(os.environ.get("NVM_DIR", Path.home() / ".nvm")) / "versions" / "node"
    if nvm.is_dir():
        found += sorted(nvm.glob("v*/bin/npx"), key=_version_key, reverse=True)
    found += [
        Path("/opt/homebrew/bin/npx"),
        Path("/usr/local/bin/npx"),
        Path("/usr/bin/npx"),
    ]
    unique: list[Path] = []
    for p in found:
        if p.is_file() and p not in unique:
            unique.append(p)
    return unique


def find_npx(explicit: str | None = None) -> tuple[str, str]:
    """
    (npx path, its bin directory) for a Node.js >= MIN_NODE_MAJOR.

    Claude Desktop starts servers with its own minimal PATH, so the entry
    must name npx by absolute path and put that node first on PATH.
    """
    candidates = [Path(explicit)] if explicit else _npx_candidates()
    for npx in candidates:
        node = _sibling_node(npx)
        major = node_major(str(node)) if node.is_file() else node_major("node")
        if major is not None and major >= MIN_NODE_MAJOR:
            return str(npx), str(npx.parent)
    if explicit:
        raise RemoteError(f"{explicit} does not belong to Node.js {MIN_NODE_MAJOR}+.")
    raise RemoteError(
        f"mcp-remote needs Node.js {MIN_NODE_MAJOR} or newer and none was found. "
        "Install it (e.g. `nvm install --lts`) or pass --npx /path/to/npx."
    )


# -- config entries ------------------------------------------------------------


def validate_url(url: str, allow_http: bool) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise RemoteError(f"Not an http(s) URL: {url}")
    if parts.scheme == "http" and parts.hostname not in _LOCAL_HOSTS and not allow_http:
        raise RemoteError(
            f"{url} is plain http on a non-local host; credentials would travel "
            "unencrypted. Use https, or pass --allow-http if you really mean it."
        )


def build_entry(
    url: str,
    *,
    headers: list[str],
    npx: str,
    node_dir: str,
    allow_http: bool = False,
) -> dict[str, Any]:
    """The (unwrapped) claude_desktop_config.json entry for a remote server."""
    args = ["-y", "mcp-remote", url]
    for header in headers:
        if ":" not in header:
            raise RemoteError(f'Header must look like "Name: value", got {header!r}')
        args += ["--header", header]
    if allow_http and urlsplit(url).hostname not in _LOCAL_HOSTS:
        args.append("--allow-http")
    system_path = (
        os.environ.get("PATH", "") if platform.system() == "Windows" else "/usr/local/bin:/usr/bin:/bin"
    )
    return {"command": npx, "args": args, "env": {"PATH": os.pathsep.join([node_dir, system_path])}}


def _load(path: Path) -> tuple[dict[str, Any], str | None]:
    text = autowrap.read_config_text(path)
    if text is None:
        return {"mcpServers": {}}, None
    config = autowrap.parse_config(text, path)
    if config is None:
        raise RemoteError(f"{path} is not valid JSON; fix it first.")
    return config, text


def _save(path: Path, config: dict[str, Any], original_text: str | None) -> None:
    if original_text is None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        return
    if not autowrap.write_config_if_unchanged(path, config, original_text):
        raise RemoteError(f"{path} changed while updating it; please run the command again.")


def add_remote(
    name: str,
    url: str,
    *,
    headers: list[str] | None = None,
    claude_config: Path | None = None,
    npx: str | None = None,
    allow_http: bool = False,
    force: bool = False,
) -> list[str]:
    """Add a remote server to Claude Desktop, routed through tutut."""
    validate_url(url, allow_http)
    npx_path, node_dir = find_npx(npx)
    path = claude_config or get_claude_config_path()
    config, text = _load(path)
    servers = config.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise RemoteError(f"'mcpServers' in {path} is not an object.")
    if name in servers and not force:
        raise RemoteError(f"A server named '{name}' already exists (use --force to replace it).")

    entry = build_entry(url, headers=headers or [], npx=npx_path, node_dir=node_dir, allow_http=allow_http)
    servers[name] = autowrap.wrap_entry(
        name, entry, command=autowrap.tutut_executable(), gui=autowrap.gui_args()
    )
    _save(path, config, text)
    return [
        f"Added '{name}' → {url} (via mcp-remote, guarded by tutut) to {path}",
        f"Node.js: {node_dir}",
        "Restart Claude Desktop to load it. The first call may open your browser to sign in.",
        "If this server is also an account connector (Settings → Connectors), turn that one off -",
        "otherwise Claude sees its tools twice and may use the copy tutut can't see.",
    ]


def remove_remote(name: str, *, claude_config: Path | None = None) -> list[str]:
    """Remove a server entry added with add_remote (or any entry by name)."""
    path = claude_config or get_claude_config_path()
    config, text = _load(path)
    servers = config.get("mcpServers") or {}
    if name not in servers:
        raise RemoteError(f"No server named '{name}' in {path}.")
    del servers[name]
    _save(path, config, text)
    return [f"Removed '{name}' from {path}. Restart Claude Desktop to apply."]
