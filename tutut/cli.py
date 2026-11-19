"""
CLI entry point for tutut.

Provides subcommands for:
  - stdio:         Run as a stdio proxy (wraps an MCP server command)
  - http:          Run as a local HTTP proxy for a remote MCP server
  - web:           Gate a remote MCP server for claude.ai (gateway + tunnel)
  - add-remote:    Add a remote MCP server to Claude Desktop via mcp-remote
  - remove-remote: Remove such a server again
  - log:           Show / follow the audit log of intercepted calls
  - broker:        One approval window/queue for all processes (auto-started)
  - setup:         Auto-configure Claude Desktop to use tutut
  - teardown:      Remove tutut from Claude Desktop config
  - config:        Show or edit configuration
  - rules:         Manage allow/block rules
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .config import GuardianConfig, setup_logging


def main(argv: list[str] | None = None) -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="tutut",
        description="tutut — Monitor and control MCP tool calls",
    )
    parser.add_argument(
        "--version", action="version", version=f"tutut {__version__}"
    )
    parser.add_argument(
        "--config", type=Path, default=None,
        help="Path to tutut config file",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # -- stdio subcommand --
    stdio_parser = subparsers.add_parser(
        "stdio",
        help="Run as a stdio proxy wrapping an MCP server",
        description=(
            "Wraps an MCP server command, intercepting all JSON-RPC messages. "
            "Use this in claude_desktop_config.json in place of the original server command."
        ),
    )
    stdio_parser.add_argument(
        "--server-name", required=True,
        help="Name of the MCP server (for display and rule matching)",
    )
    stdio_parser.add_argument(
        "--display", default=None,
        help=(
            "X11 display for the popup, used only if DISPLAY is unset "
            "(MCP clients may start servers without it). Added automatically "
            "by the background watcher on Linux."
        ),
    )
    stdio_parser.add_argument(
        "--xauthority", default=None,
        help="X11 authority file for the popup, used only if XAUTHORITY is unset.",
    )
    stdio_parser.add_argument(
        "server_command", nargs=argparse.REMAINDER,
        help="The original MCP server command (after --)",
    )

    # -- http subcommand --
    http_parser = subparsers.add_parser(
        "http",
        help="Run as an HTTP proxy for remote MCP servers",
    )
    http_parser.add_argument(
        "--upstream", required=True,
        help="Upstream MCP server URL (e.g., https://mcp.example.com/mcp)",
    )
    http_parser.add_argument(
        "--server-name", default="remote",
        help="Name for the upstream server (for display and rules)",
    )
    http_parser.add_argument(
        "--host", default=None,
        help="Host to bind the proxy to (default: from config)",
    )
    http_parser.add_argument(
        "--port", type=int, default=None,
        help="Port to bind the proxy to (default: from config)",
    )
    http_parser.add_argument(
        "--header", action="append", default=[], metavar='"NAME: VALUE"',
        help="Header added to every upstream request, e.g. an API key (repeatable)",
    )

    # -- web subcommand (claude.ai path) --
    web_parser = subparsers.add_parser(
        "web",
        help="Gate a remote MCP server for claude.ai: local gateway + public tunnel",
        description=(
            "Starts the HTTP gateway on localhost, opens a Cloudflare quick tunnel "
            "to it and prints the URL to add as a custom connector on claude.ai. "
            "Every tool call made through that connector (from claude.ai, Claude "
            "Desktop or mobile) then needs your approval on this machine."
        ),
    )
    web_parser.add_argument(
        "--upstream", required=True,
        help="The real MCP server URL (e.g., https://mcp.example.com/mcp)",
    )
    web_parser.add_argument(
        "--server-name", default="remote",
        help="Name for the upstream server (for display and rules)",
    )
    web_parser.add_argument(
        "--port", type=int, default=None,
        help="Local port for the gateway (default: from config, 8019)",
    )
    web_parser.add_argument(
        "--header", action="append", default=[], metavar='"NAME: VALUE"',
        help=(
            "Header added to every upstream request, e.g. "
            '"Authorization: Bearer <token>" (repeatable). Kept on this machine.'
        ),
    )
    web_parser.add_argument(
        "--no-tunnel", action="store_true",
        help="Don't start cloudflared (use with --public-url for your own tunnel)",
    )
    web_parser.add_argument(
        "--public-url", default=None,
        help="Public base URL that reaches the gateway, when using --no-tunnel",
    )
    web_parser.add_argument(
        "--path-secret", action="store_true",
        help=(
            "Also require a passphrase path (/<words>/mcp). claude.ai refuses "
            "connector URLs with any secret path segment, so use this only for "
            "other clients"
        ),
    )
    web_parser.add_argument(
        "--rotate-secret", action="store_true",
        help="With --path-secret: generate a new passphrase (invalidates old URLs)",
    )
    web_parser.add_argument(
        "--allow-ip", action="append", default=[], metavar="CIDR",
        help="Also accept callers from this range, besides Anthropic's (repeatable)",
    )
    web_parser.add_argument(
        "--allow-any-ip", action="store_true",
        help="Turn off the caller IP allowlist (not recommended on a public tunnel)",
    )

    # -- add-remote / remove-remote (Claude Desktop path 2) --
    add_remote_parser = subparsers.add_parser(
        "add-remote",
        help="Add a remote MCP server to Claude Desktop via mcp-remote, guarded by tutut",
    )
    add_remote_parser.add_argument("name", help="Server name in Claude Desktop")
    add_remote_parser.add_argument("url", help="Remote MCP server URL")
    add_remote_parser.add_argument(
        "--header", action="append", default=[], metavar='"NAME: VALUE"',
        help="Header mcp-remote sends with every request (repeatable)",
    )
    add_remote_parser.add_argument(
        "--allow-http", action="store_true",
        help="Allow a plain-http URL on a non-local host",
    )
    add_remote_parser.add_argument(
        "--npx", default=None, help="npx to use (default: newest Node.js 18+ found)",
    )
    add_remote_parser.add_argument(
        "--force", action="store_true", help="Replace an existing server with this name",
    )
    add_remote_parser.add_argument(
        "--claude-config", type=Path, default=None,
        help="Path to claude_desktop_config.json (auto-detected by default)",
    )

    remove_remote_parser = subparsers.add_parser(
        "remove-remote", help="Remove a server added with add-remote",
    )
    remove_remote_parser.add_argument("name", help="Server name in Claude Desktop")
    remove_remote_parser.add_argument(
        "--claude-config", type=Path, default=None,
        help="Path to claude_desktop_config.json (auto-detected by default)",
    )

    # -- dashboard subcommand --
    dashboard_parser = subparsers.add_parser(
        "dashboard",
        help="Open a local live dashboard of intercepted tool calls",
        description=(
            "Serves a read-only dashboard on http://127.0.0.1:PORT with live "
            "decisions, stats, coverage and rules. Local only, token-protected."
        ),
    )
    dashboard_parser.add_argument(
        "--port", type=int, default=8020, help="Local port (default: 8020)",
    )
    dashboard_parser.add_argument(
        "--no-browser", action="store_true", help="Don't open a browser tab",
    )

    # -- broker subcommand (started automatically) --
    subparsers.add_parser(
        "broker",
        help="Run the approval broker (one window for every tutut process; started automatically)",
        description=(
            "Owns the approval window and one global queue for all tutut processes. "
            "Started on demand by the first process that needs a decision; exits "
            "when idle. Only one runs per user."
        ),
    )

    # -- log subcommand --
    log_parser = subparsers.add_parser(
        "log", help="Show the audit log of intercepted tool calls",
    )
    log_parser.add_argument(
        "-f", "--follow", action="store_true", help="Keep printing new entries",
    )
    log_parser.add_argument(
        "-n", "--lines", type=int, default=20, help="How many recent entries to show (0 = all)",
    )
    log_parser.add_argument(
        "--json", action="store_true", help="Print raw JSON lines",
    )

    # -- setup subcommand --
    setup_parser = subparsers.add_parser(
        "setup",
        help="Configure Claude Desktop to use tutut",
    )
    setup_parser.add_argument(
        "--claude-config", type=Path, default=None,
        help="Path to claude_desktop_config.json",
    )
    setup_parser.add_argument(
        "--servers", nargs="*", default=None,
        help="Specific server names to wrap (default: all)",
    )
    setup_parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would change without modifying files",
    )

    # -- teardown subcommand --
    teardown_parser = subparsers.add_parser(
        "teardown",
        help="Remove tutut from Claude Desktop config",
    )
    teardown_parser.add_argument(
        "--claude-config", type=Path, default=None,
        help="Path to claude_desktop_config.json",
    )
    teardown_parser.add_argument(
        "--servers", nargs="*", default=None,
        help="Specific server names to unwrap (default: all)",
    )

    # -- install / uninstall / status / watch (background service) --
    install_parser = subparsers.add_parser(
        "install",
        help="One-time setup: guard every Claude Desktop MCP server automatically",
        description=(
            "Creates a default config, starts the background watcher now and "
            "at every login, and routes all Claude Desktop MCP servers through "
            "tutut - including servers added later."
        ),
    )
    install_parser.add_argument(
        "--claude-config", type=Path, default=None,
        help="Path to claude_desktop_config.json (auto-detected by default)",
    )
    install_parser.add_argument(
        "--no-start", action="store_true",
        help="Set everything up but don't start the watcher now",
    )

    uninstall_parser = subparsers.add_parser(
        "uninstall",
        help="Stop the watcher, remove autostart, restore original server entries",
    )
    uninstall_parser.add_argument(
        "--claude-config", type=Path, default=None,
        help="Path to claude_desktop_config.json (auto-detected by default)",
    )

    status_parser = subparsers.add_parser(
        "status", help="Show watcher status and which servers are guarded",
    )
    status_parser.add_argument(
        "--claude-config", type=Path, default=None,
        help="Path to claude_desktop_config.json (auto-detected by default)",
    )

    watch_parser = subparsers.add_parser(
        "watch",
        help="Run the background watcher in the foreground (normally started by 'install')",
    )
    watch_parser.add_argument(
        "--claude-config", type=Path, default=None,
        help="Path to claude_desktop_config.json (auto-detected by default)",
    )

    # -- config subcommand --
    config_parser = subparsers.add_parser(
        "config",
        help="Show or initialize tutut configuration",
    )
    config_parser.add_argument(
        "--init", action="store_true",
        help="Create a default config file",
    )
    config_parser.add_argument(
        "--show", action="store_true",
        help="Print current configuration",
    )

    # -- rules subcommand --
    rules_parser = subparsers.add_parser(
        "rules",
        help="Manage allow/block rules",
    )
    rules_sub = rules_parser.add_subparsers(dest="rules_command")

    rules_list = rules_sub.add_parser("list", help="List all rules")

    rules_add = rules_sub.add_parser("add", help="Add a new rule")
    rules_add.add_argument("--server", default="*", help="Server pattern (glob)")
    rules_add.add_argument("--tool", default="*", help="Tool pattern (glob)")
    rules_add.add_argument(
        "--action", choices=["allow", "block", "ask"], required=True,
    )
    rules_add.add_argument("--description", default="", help="Rule description")

    rules_remove = rules_sub.add_parser("remove", help="Remove a rule by index")
    rules_remove.add_argument("index", type=int, help="Rule index (0-based)")

    # Parse arguments
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Load config
    config = GuardianConfig.load(args.config)

    # Dispatch to command handlers
    if args.command == "stdio":
        _cmd_stdio(args, config)
    elif args.command == "http":
        _cmd_http(args, config)
    elif args.command == "web":
        _cmd_web(args, config)
    elif args.command in ("add-remote", "remove-remote"):
        _cmd_remote(args)
    elif args.command == "log":
        _cmd_log(args, config)
    elif args.command == "broker":
        setup_logging(config, stderr=False)
        from .broker import run_broker, supported

        if not supported():
            print("The approval broker needs Unix sockets (Linux/macOS).", file=sys.stderr)
            sys.exit(1)
        sys.exit(run_broker())
    elif args.command == "dashboard":
        _cmd_dashboard(args, config)
    elif args.command == "setup":
        _cmd_setup(args, config)
    elif args.command == "teardown":
        _cmd_teardown(args, config)
    elif args.command in ("install", "uninstall", "status", "watch"):
        _cmd_service(args, config)
    elif args.command == "config":
        _cmd_config(args, config)
    elif args.command == "rules":
        _cmd_rules(args, config)


def _apply_gui_env(display: str | None, xauthority: str | None) -> None:
    """Fill in DISPLAY/XAUTHORITY for the popup if the client didn't pass them."""
    if display and not os.environ.get("DISPLAY"):
        os.environ["DISPLAY"] = display
    if xauthority and not os.environ.get("XAUTHORITY"):
        os.environ["XAUTHORITY"] = xauthority


def _cmd_service(args: argparse.Namespace, config: GuardianConfig) -> None:
    """Handle 'install', 'uninstall', 'status' and 'watch'."""
    from . import service

    if args.command == "watch":
        setup_logging(config)
        sys.exit(service.watch(args.claude_config, config_path=args.config))

    if args.command == "status":
        lines = service.status(claude_config=args.claude_config)
    elif args.command == "install":
        setup_logging(config, stderr=False)
        try:
            lines = service.install(
                claude_config=args.claude_config, start=not args.no_start
            )
        except service.InstallError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        setup_logging(config, stderr=False)
        lines = service.uninstall(claude_config=args.claude_config)

    for line in lines:
        print(f"  {line}")


def _cmd_stdio(args: argparse.Namespace, config: GuardianConfig) -> None:
    """Handle the 'stdio' subcommand."""
    setup_logging(config)
    _apply_gui_env(args.display, args.xauthority)

    # Strip leading "--" from server_command if present
    cmd = args.server_command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    if not cmd:
        print("Error: No server command specified.", file=sys.stderr)
        print("Usage: tutut stdio --server-name NAME -- command [args...]", file=sys.stderr)
        sys.exit(1)

    from .stdio_proxy import run_stdio_proxy

    exit_code = asyncio.run(
        run_stdio_proxy(
            server_command=cmd,
            server_name=args.server_name,
            config=config,
        )
    )
    sys.exit(exit_code)


def _cmd_http(args: argparse.Namespace, config: GuardianConfig) -> None:
    """Handle the 'http' subcommand."""
    setup_logging(config)

    if args.host:
        config.http_proxy_host = args.host
    if args.port:
        config.http_proxy_port = args.port

    from .http_proxy import run_http_proxy

    try:
        asyncio.run(
            run_http_proxy(
                upstream_url=args.upstream,
                server_name=args.server_name,
                config=config,
                upstream_headers=_parse_headers(args.header),
            )
        )
    except KeyboardInterrupt:
        print("\nShutting down...", file=sys.stderr)


def _parse_headers(values: list[str]) -> dict[str, str]:
    """["Name: value", …] → {"Name": "value"}; exits on a malformed one."""
    headers: dict[str, str] = {}
    for raw in values:
        name, sep, value = raw.partition(":")
        if not sep or not name.strip():
            print(f'Error: header must look like "Name: value", got {raw!r}', file=sys.stderr)
            sys.exit(2)
        headers[name.strip()] = value.strip()
    return headers


def _cmd_web(args: argparse.Namespace, config: GuardianConfig) -> None:
    """Handle the 'web' subcommand (claude.ai gateway + tunnel)."""
    setup_logging(config, stderr=False)  # keep the terminal for the banner
    from .web_gateway import GatewayError, run_web_gateway

    try:
        asyncio.run(
            run_web_gateway(
                upstream_url=args.upstream,
                server_name=args.server_name,
                config=config,
                port=args.port or config.http_proxy_port,
                upstream_headers=_parse_headers(args.header),
                use_tunnel=not args.no_tunnel,
                public_url=args.public_url,
                rotate_secret=args.rotate_secret,
                path_secret=args.path_secret,
                allow_any_ip=args.allow_any_ip,
                extra_allowed=args.allow_ip,
            )
        )
    except GatewayError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, asyncio.CancelledError):  # Ctrl+C / SIGTERM
        print("\nGateway stopped.", file=sys.stderr)


def _cmd_remote(args: argparse.Namespace) -> None:
    """Handle 'add-remote' and 'remove-remote'."""
    from .remote import RemoteError, add_remote, remove_remote

    try:
        if args.command == "add-remote":
            lines = add_remote(
                args.name,
                args.url,
                headers=args.header,
                claude_config=args.claude_config,
                npx=args.npx,
                allow_http=args.allow_http,
                force=args.force,
            )
        else:
            lines = remove_remote(args.name, claude_config=args.claude_config)
    except RemoteError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    for line in lines:
        print(f"  {line}")


def _cmd_dashboard(args: argparse.Namespace, config: GuardianConfig) -> None:
    """Handle the 'dashboard' subcommand."""
    setup_logging(config, stderr=False)
    try:
        from .dashboard import run_dashboard
    except ImportError:
        print("Error: the dashboard needs aiohttp: pip install 'tutut[http]'", file=sys.stderr)
        sys.exit(1)
    try:
        asyncio.run(run_dashboard(config, port=args.port, open_browser=not args.no_browser))
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\nDashboard stopped.", file=sys.stderr)


def _cmd_log(args: argparse.Namespace, config: GuardianConfig) -> None:
    """Handle the 'log' subcommand."""
    from .audit import follow, format_entry
    from .store import SQLiteStore

    path = Path(config.audit_db)
    show = (lambda e: json.dumps(e, ensure_ascii=False)) if args.json else format_entry
    # Opening the store also imports a legacy audit.jsonl the first time.
    store = SQLiteStore(path, retention_days=0, legacy_jsonl=config.audit_file)
    try:
        entries = store.recent(args.lines if args.lines > 0 else None)
    finally:
        store.close()
    if not entries and not args.follow:
        print(f"No intercepted calls recorded yet ({path}).")
    for entry in entries:
        print(show(entry))
    if args.follow:
        try:
            for entry in follow(path):
                print(show(entry), flush=True)
        except KeyboardInterrupt:
            pass


def _cmd_setup(args: argparse.Namespace, config: GuardianConfig) -> None:
    """Handle the 'setup' subcommand."""
    setup_logging(config)

    from .setup_helper import setup_claude_desktop

    results = setup_claude_desktop(
        config_path=args.claude_config,
        server_names=args.servers,
        dry_run=args.dry_run,
    )

    prefix = "[DRY RUN] " if args.dry_run else ""

    for name, status in results.items():
        if name.startswith("_"):
            print(f"{prefix}{status}")
        else:
            icon = {"wrapped": "✓", "already_wrapped": "⊘", "not_found": "✗"}.get(status, "?")
            print(f"  {icon} {name}: {status}")

    if not args.dry_run and any(s == "wrapped" for s in results.values()):
        print("\n  Restart Claude Desktop for changes to take effect.")


def _cmd_teardown(args: argparse.Namespace, config: GuardianConfig) -> None:
    """Handle the 'teardown' subcommand."""
    setup_logging(config)

    from .setup_helper import teardown_claude_desktop

    results = teardown_claude_desktop(
        config_path=args.claude_config,
        server_names=args.servers,
    )

    for name, status in results.items():
        if name.startswith("_"):
            print(status)
        else:
            icon = {"unwrapped": "✓", "not_wrapped": "⊘", "not_found": "✗"}.get(status, "?")
            print(f"  {icon} {name}: {status}")

    if any(s == "unwrapped" for s in results.values()):
        print("\n  Restart Claude Desktop for changes to take effect.")


def _cmd_config(args: argparse.Namespace, config: GuardianConfig) -> None:
    """Handle the 'config' subcommand."""
    from .config import DEFAULT_CONFIG_FILE

    if args.init:
        config.save()
        print(f"Configuration saved to {DEFAULT_CONFIG_FILE}")
    elif args.show:
        shown = config._to_dict()
        if shown.get("web_secret"):
            shown["web_secret"] = "*** (set)"
        print(json.dumps(shown, indent=2))
    else:
        print(f"Config file: {DEFAULT_CONFIG_FILE}")
        print(f"  Exists: {DEFAULT_CONFIG_FILE.exists()}")
        print(f"\nUse --init to create, or --show to display current config.")


def _cmd_rules(args: argparse.Namespace, config: GuardianConfig) -> None:
    """Handle the 'rules' subcommand."""
    from .models import Rule, RuleAction

    if args.rules_command == "list":
        if not config.rules:
            print("No rules configured. All tool calls will prompt for approval.")
            return
        for i, rule in enumerate(config.rules):
            print(
                f"  [{i}] {rule.action.value:5s}  "
                f"server={rule.server_pattern!r}  tool={rule.tool_pattern!r}"
                f"{'  # ' + rule.description if rule.description else ''}"
            )

    elif args.rules_command == "add":
        rule = Rule(
            server_pattern=args.server,
            tool_pattern=args.tool,
            action=RuleAction(args.action),
            description=args.description,
        )
        config.rules.append(rule)
        config.save()
        print(
            f"Added rule: {rule.action.value} "
            f"server={rule.server_pattern!r} tool={rule.tool_pattern!r}"
        )

    elif args.rules_command == "remove":
        if 0 <= args.index < len(config.rules):
            removed = config.rules.pop(args.index)
            config.save()
            print(f"Removed rule [{args.index}]: {removed.action.value} {removed.tool_pattern}")
        else:
            print(f"Invalid index: {args.index} (have {len(config.rules)} rules)")

    else:
        print("Usage: tutut rules {list|add|remove}")


if __name__ == "__main__":
    main()
