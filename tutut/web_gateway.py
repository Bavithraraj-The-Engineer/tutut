"""
`tutut web` - intercept claude.ai (and other cloud-side clients).

claude.ai's connectors are called from Anthropic's cloud, never from your
machine, so a local proxy can't see them. Instead tutut becomes the server
they call:

    claude.ai ─▶ Anthropic cloud ─▶ https://<random>.trycloudflare.com/mcp
                                   ─▶ cloudflared ─▶ tutut gateway (127.0.0.1) ─▶ upstream MCP server

This module starts the gateway on localhost, opens a Cloudflare quick
tunnel to it (no account needed), waits until the public URL answers, and
prints the URL to register as a custom connector. Because connectors sync
across your account, Claude Desktop and mobile then use the same gated
connector too.

Protection: only Anthropic's published outbound IP ranges may call the
gateway (others get 403), the tunnel hostname is random, and every
tools/call needs the user's approval (failing closed).

With your own stable tunnel or reverse proxy, use --no-tunnel and
--public-url instead.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import secrets
import shutil
import sys
import time
from pathlib import Path

from .config import GuardianConfig
from .http_proxy import HEALTH_PATH, HttpProxy, start_http_proxy

logger = logging.getLogger(__name__)

_QUICK_TUNNEL_URL = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")
TUNNEL_START_TIMEOUT = 45.0
REACHABLE_TIMEOUT = 60.0

# Where Anthropic's servers call MCP servers from ("Outbound IP addresses":
# "when making MCP tool calls to external servers"). claude.ai's connector
# traffic was observed coming from 160.79.106.x.
# Source: https://platform.claude.com/docs/en/api/ip-addresses (checked 2026-11-19)
ANTHROPIC_OUTBOUND_RANGES = ("160.79.104.0/21", "153.61.208.0/20")

# Optional path passphrase (--path-secret): 5 pronounceable lowercase "words",
# 14*5*14*5 = 4900 per word -> ~61 bits. Off by default: claude.ai's connector
# client refuses URLs with *any* secret path segment (tested: a random token
# and this word form both fail; only https://<host>/mcp connects). Useful for
# other HTTP clients.
_CONSONANTS = "bdfgklmnprstvz"
_VOWELS = "aeiou"
_PASSPHRASE_WORDS = 5
_PASSPHRASE_RE = re.compile(rf"^[{_CONSONANTS}][{_VOWELS}][{_CONSONANTS}][{_VOWELS}]"
                            rf"(?:-[{_CONSONANTS}][{_VOWELS}][{_CONSONANTS}][{_VOWELS}]){{{_PASSPHRASE_WORDS - 1}}}$")


class GatewayError(Exception):
    """A user-facing problem starting the web gateway."""


def new_passphrase(words: int = _PASSPHRASE_WORDS) -> str:
    def word() -> str:
        return "".join(secrets.choice(chars) for chars in (_CONSONANTS, _VOWELS, _CONSONANTS, _VOWELS))

    return "-".join(word() for _ in range(words))


def ensure_secret(config: GuardianConfig, rotate: bool = False) -> str:
    """
    The gateway's path passphrase, created (and saved) on first use.
    Secrets in the old token format are replaced (claude.ai rejects them).
    """
    if rotate or not _PASSPHRASE_RE.match(config.web_secret or ""):
        config.web_secret = new_passphrase()
        config.save()
    return config.web_secret


def find_cloudflared() -> str | None:
    """Locate the cloudflared binary (PATH first, then common user installs)."""
    found = shutil.which("cloudflared")
    if found:
        return found
    for candidate in (
        Path.home() / ".local" / "bin" / "cloudflared",
        Path("/usr/local/bin/cloudflared"),
        Path("/opt/homebrew/bin/cloudflared"),
    ):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


class QuickTunnel:
    """A Cloudflare quick tunnel (random *.trycloudflare.com URL)."""

    def __init__(self, binary: str) -> None:
        self._binary = binary
        self._proc: asyncio.subprocess.Process | None = None
        self._drain: asyncio.Task[None] | None = None

    async def start(self, port: int) -> str:
        """Start cloudflared and return the public base URL."""
        self._proc = await asyncio.create_subprocess_exec(
            self._binary, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{port}",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        stderr = self._proc.stderr
        assert stderr

        async def _read_url() -> str | None:
            while True:
                line = await stderr.readline()
                if not line:
                    return None  # cloudflared exited
                text = line.decode(errors="replace").rstrip()
                logger.debug("cloudflared: %s", text)
                match = _QUICK_TUNNEL_URL.search(text)
                if match:
                    return match.group(0)

        try:
            url = await asyncio.wait_for(_read_url(), TUNNEL_START_TIMEOUT)
        except asyncio.TimeoutError:
            url = None
        if url is None:
            await self.stop()
            raise GatewayError(
                "cloudflared did not report a tunnel URL. Check your internet "
                "connection, or run `cloudflared tunnel --url http://127.0.0.1:"
                f"{port}` yourself to see why."
            )
        self._drain = asyncio.create_task(self._drain_stderr())
        return url

    async def _drain_stderr(self) -> None:
        assert self._proc and self._proc.stderr
        while True:
            line = await self._proc.stderr.readline()
            if not line:
                return
            logger.debug("cloudflared: %s", line.decode(errors="replace").rstrip())

    async def wait(self) -> int:
        assert self._proc
        return await self._proc.wait()

    async def stop(self) -> None:
        if self._drain:
            self._drain.cancel()
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._proc.kill()
                await self._proc.wait()


async def _wait_until_reachable(url: str, timeout: float = REACHABLE_TIMEOUT) -> bool:
    """Poll the gateway's health endpoint through the public URL."""
    from aiohttp import ClientSession, ClientTimeout

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    async with ClientSession(timeout=ClientTimeout(total=10)) as session:
        while loop.time() < deadline:
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        return True
            except Exception:
                pass  # DNS for a fresh quick tunnel takes a few seconds
            await asyncio.sleep(2)
    return False


async def _check_upstream(url: str, headers: dict[str, str]) -> str | None:
    """None if the upstream answers HTTP at all, else a short error."""
    from aiohttp import ClientSession, ClientTimeout

    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(url, headers=headers, allow_redirects=False):
                return None  # any status (even 401/405) means it's there
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


async def run_web_gateway(
    upstream_url: str,
    server_name: str,
    config: GuardianConfig,
    *,
    port: int,
    upstream_headers: dict[str, str] | None = None,
    use_tunnel: bool = True,
    public_url: str | None = None,
    rotate_secret: bool = False,
    path_secret: bool = False,
    allow_any_ip: bool = False,
    extra_allowed: list[str] | tuple[str, ...] = (),
) -> None:
    """Run the gateway (+ tunnel) until Ctrl+C, SIGTERM or the tunnel dies."""
    from .stdio_proxy import install_sigterm_handler

    install_sigterm_handler(asyncio.get_running_loop())
    allowed = None if allow_any_ip else [*ANTHROPIC_OUTBOUND_RANGES, *extra_allowed]
    if allowed is not None:
        from .http_proxy import parse_networks

        try:
            parse_networks(allowed)
        except ValueError as exc:
            raise GatewayError(f"Bad --allow-ip value: {exc}") from None
    binary = None
    if use_tunnel:
        binary = find_cloudflared()
        if binary is None:
            raise GatewayError(
                "cloudflared is not installed. Get it from "
                "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/ "
                "(or use --no-tunnel --public-url with your own tunnel)."
            )

    secret = ensure_secret(config, rotate=rotate_secret) if path_secret else ""
    mount = f"/{secret}" if secret else ""
    problem = await _check_upstream(upstream_url, upstream_headers or {})
    if problem:
        print(f"  ! Upstream {upstream_url} is not reachable yet ({problem}).", file=sys.stderr)

    proxy = HttpProxy(
        upstream_url,
        server_name,
        config,
        secret=secret,
        upstream_headers=upstream_headers,
        buffer_sse=use_tunnel,  # quick tunnels don't carry SSE
        allowed_networks=allowed,
        source="claude.ai / Anthropic cloud (via tunnel)",
    )
    runner = await start_http_proxy(proxy, "127.0.0.1", port)
    tunnel: QuickTunnel | None = None
    try:
        if use_tunnel:
            assert binary
            print("  Opening a Cloudflare quick tunnel…", file=sys.stderr)
            tunnel = QuickTunnel(binary)
            base = await tunnel.start(port)
        else:
            base = (public_url or f"http://127.0.0.1:{port}").rstrip("/")

        connector_url = f"{base}{mount}/mcp"
        reachable = await _wait_until_reachable(f"{base}{mount}{HEALTH_PATH}")

        print(file=sys.stderr)
        print(f"  tutut web gateway for '{server_name}'  →  {upstream_url}", file=sys.stderr)
        print(f"  Status: {'reachable from the internet ✓' if reachable else 'NOT reachable yet ✗ (check the tunnel)'}", file=sys.stderr)
        print(file=sys.stderr)
        print("  Add this URL as a custom connector on claude.ai", file=sys.stderr)
        print("  (Settings → Connectors → Add custom connector):", file=sys.stderr)
        print(f"\n    {connector_url}\n", file=sys.stderr)
        if allowed is None:
            print("  Callers: ANY IP (--allow-any-ip).", file=sys.stderr)
        else:
            print(f"  Callers: only Anthropic's servers ({', '.join(allowed)}); others get 403.", file=sys.stderr)
        if secret:
            print("  Keep the URL private: its word path is the gateway's password.", file=sys.stderr)
        if use_tunnel:
            print("  Quick-tunnel URLs change each run - re-add the connector after a restart.", file=sys.stderr)
        print("  Every tool call now shows the tutut popup on this machine. Ctrl+C to stop.\n", file=sys.stderr)

        write_gateway_state({
            "pid": os.getpid(),
            "server_name": server_name,
            "upstream": upstream_url,
            "public_url": connector_url,
            "reachable": reachable,
            "allowlist": allowed,
            "tunnel": "cloudflare-quick" if use_tunnel else "external",
            "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        })

        if tunnel:
            code = await tunnel.wait()
            print(f"  cloudflared exited (code {code}); gateway stopping.", file=sys.stderr)
        else:
            await asyncio.Event().wait()
    finally:
        clear_gateway_state()
        if tunnel:
            await tunnel.stop()
        await runner.cleanup()


# -- state file (read by `tutut dashboard`) -------------------------------------

GATEWAY_STATE_FILE = Path.home() / ".config" / "tutut" / "web_gateway.json"


def write_gateway_state(state: dict, path: Path | None = None) -> None:
    """Record the running gateway (owner-only: it holds the connector URL)."""
    import json

    path = path or GATEWAY_STATE_FILE
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except OSError as exc:
        logger.warning("Could not write %s: %s", path, exc)


def clear_gateway_state(path: Path | None = None) -> None:
    """Remove the state file if it belongs to this process."""
    import json

    path = path or GATEWAY_STATE_FILE
    try:
        if json.loads(path.read_text(encoding="utf-8")).get("pid") == os.getpid():
            path.unlink()
    except (OSError, ValueError):
        pass
