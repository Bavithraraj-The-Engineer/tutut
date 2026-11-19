"""
Stdio proxy for tutut.

Sits between Claude Desktop (or any MCP client using stdio transport) and
the actual MCP server process. Intercepts JSON-RPC messages on stdin/stdout,
holding tools/call requests until they are allowed or blocked.

Usage in claude_desktop_config.json:

    {
      "mcpServers": {
        "my-server": {
          "command": "tutut",
          "args": ["stdio", "--server-name", "my-server", "--", "npx", "-y", "@some/mcp-server"]
        }
      }
    }

The wrapped command can also be `npx -y mcp-remote https://…`, which turns a
remote (HTTP) MCP server into a local stdio one - so remote servers used from
Claude Desktop are intercepted the same way.

Design:
  - Each tools/call is decided in its own task. While one waits for the
    user, every other message (other calls, pings, cancellations) keeps
    flowing in both directions.
  - `notifications/cancelled` for a call still waiting for a decision
    withdraws its popup; no response is sent, as the MCP spec requires.
  - Messages up to MAX_MESSAGE_SIZE are supported; a larger request gets an
    error response instead of silently disappearing.
  - If the server exits, every request still waiting on it gets an error
    response, and the proxy exits so the client sees the disconnect.
  - stdin is read on a thread, which works on Windows too (asyncio pipes on
    a console/pipe stdin do not).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import signal
import sys
import threading
from typing import Any

from .config import GuardianConfig
from .interceptor import Interceptor, Verdict
from .models import JsonRpcMessage, blocked_response

logger = logging.getLogger(__name__)

# Largest single JSON-RPC message (one line) accepted in either direction.
MAX_MESSAGE_SIZE = 32 * 1024 * 1024
_READ_CHUNK = 64 * 1024

# Shutdown after the client closes stdin: how long calls being decided may
# still finish, and how long the server gets to answer and exit.
INFLIGHT_GRACE = 2.0
SERVER_EXIT_GRACE = 5.0

# JSON-RPC error codes used for proxy-generated errors.
_ERR_TOO_LARGE = -32600     # Invalid Request
_ERR_SERVER_GONE = -32000   # implementation-defined server error

_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_ID_RE = re.compile(rb'"id"\s*:\s*("(?:[^"\\]|\\.)*"|-?\d+)')


def describe_source(server_command: list[str]) -> str:
    """Popup/audit label: a local server, or a remote one via mcp-remote."""
    if any("mcp-remote" in part for part in server_command):
        url = next((p for p in server_command if _URL_RE.match(p)), None)
        return f"Claude Desktop → mcp-remote → {url}" if url else "Claude Desktop → mcp-remote"
    return "Claude Desktop (local server)"


def _id_key(msg_id: Any) -> str:
    """Hashable key for a JSON-RPC id (1 and "1" are different ids)."""
    return json.dumps(msg_id, sort_keys=True)


def _sniff_id(prefix: bytes) -> Any:
    """Best-effort id from the start of a message too large to parse."""
    match = _ID_RE.search(prefix[:4096])
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except ValueError:
        return None


async def read_message(reader: asyncio.StreamReader) -> tuple[bytes | None, bytes | None]:
    """
    Read one newline-delimited message.

    Returns (line, None) normally, (None, prefix) when the message exceeded
    the reader's limit (it is consumed and discarded; `prefix` is its first
    bytes), and (None, None) at end of stream.
    """
    try:
        return await reader.readuntil(b"\n"), None
    except asyncio.IncompleteReadError as exc:
        return (exc.partial + b"\n" if exc.partial else None), None
    except asyncio.LimitOverrunError as exc:
        prefix = await reader.readexactly(exc.consumed)
        while True:  # discard the rest of the oversized line
            try:
                await reader.readuntil(b"\n")
                break
            except asyncio.LimitOverrunError as more:
                await reader.readexactly(more.consumed)
            except asyncio.IncompleteReadError:
                break
        return None, prefix[:4096]


def install_sigterm_handler(loop: asyncio.AbstractEventLoop) -> None:
    """
    SIGTERM (what MCP clients send a server that doesn't exit) cancels the
    current task, so `finally` blocks run and child processes - the wrapped
    server, or cloudflared - are stopped instead of being orphaned.
    """
    task = asyncio.current_task()
    if task is None:
        return
    try:
        loop.add_signal_handler(signal.SIGTERM, task.cancel)
    except (NotImplementedError, RuntimeError, ValueError):
        pass  # Windows / not the main thread: default handling


def _feed_stdin(loop: asyncio.AbstractEventLoop, reader: asyncio.StreamReader) -> None:
    """
    Thread body: copy our stdin into an asyncio StreamReader.

    Reads the raw file descriptor, not sys.stdin.buffer: a daemon thread
    blocked inside the buffered reader holds its lock, and Python aborts
    ("could not acquire lock for <stdin> at interpreter shutdown") when the
    proxy exits because the server died while the client is still connected.
    """
    fd = sys.stdin.fileno()
    try:
        while True:
            chunk = os.read(fd, _READ_CHUNK)
            if not chunk:
                break
            loop.call_soon_threadsafe(reader.feed_data, chunk)
    except RuntimeError:
        return  # loop closed while we were blocked in read
    except Exception:
        logger.exception("Error reading stdin")
    finally:
        try:
            loop.call_soon_threadsafe(reader.feed_eof)
        except RuntimeError:
            pass  # loop already closed


class StdioProxy:
    """
    Transparent stdio proxy between an MCP client and server.

    Reads JSON-RPC messages from the client (our stdin), forwards them to
    the real MCP server's stdin, reads responses from the server's stdout,
    and forwards them back to our stdout. tools/call requests are held until
    the Interceptor allows or blocks them.
    """

    def __init__(
        self,
        server_command: list[str],
        server_name: str,
        config: GuardianConfig,
        env: dict[str, str] | None = None,
        *,
        interceptor: Interceptor | None = None,
    ) -> None:
        self._server_cmd = server_command
        self._server_name = server_name
        self._config = config
        self._env = env
        self._source = describe_source(server_command)
        self._interceptor = interceptor or Interceptor(
            config,
            server_name=server_name,
            transport="stdio",
            source=self._source,
        )
        self._process: asyncio.subprocess.Process | None = None
        self._server_write_lock: asyncio.Lock | None = None

        # tools/call requests waiting for a decision, by id key
        self._inflight: dict[str, asyncio.Task[None]] = {}
        # allowed tools/call requests waiting for the server's response:
        # id key -> original id
        self._awaiting_server: dict[str, Any] = {}
        # tools/list requests whose response carries tool annotations (risk hints)
        self._tools_list_ids: set[str] = set()

    # Kept for callers/tests that toggle these directly.
    @property
    def _gui_available(self) -> bool:
        return self._interceptor.gui_available

    @_gui_available.setter
    def _gui_available(self, value: bool) -> None:
        self._interceptor.gui_available = value

    @property
    def _rules(self) -> Any:
        return self._interceptor.rules

    # -- lifecycle ---------------------------------------------------------------

    async def run(self) -> int:
        """
        Start the proxy, run until the server exits or stdin closes.

        Returns the server process exit code.
        """
        logger.info(
            "Starting stdio proxy: server=%s cmd=%s", self._server_name, self._server_cmd
        )
        self._server_write_lock = asyncio.Lock()

        child_env = os.environ.copy()
        if self._env:
            child_env.update(self._env)

        try:
            self._process = await asyncio.create_subprocess_exec(
                *self._server_cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=child_env,
                limit=MAX_MESSAGE_SIZE,
            )
        except FileNotFoundError:
            logger.error("Server command not found: %s", self._server_cmd[0])
            return 127
        except Exception:
            logger.exception("Failed to start server process")
            return 1

        logger.info("Server process started (pid=%s)", self._process.pid)

        loop = asyncio.get_running_loop()
        install_sigterm_handler(loop)
        client_reader = asyncio.StreamReader(limit=MAX_MESSAGE_SIZE)
        threading.Thread(
            target=_feed_stdin, args=(loop, client_reader), daemon=True, name="tutut-stdin"
        ).start()

        client_task = asyncio.create_task(self._pipe_client_to_server(client_reader))
        server_task = asyncio.create_task(self._pipe_server_to_client())
        stderr_task = asyncio.create_task(self._pipe_server_stderr())
        try:
            # Whichever side closes first ends the session.
            await asyncio.wait({client_task, server_task}, return_when=asyncio.FIRST_COMPLETED)
            if server_task.done():
                await self._fail_pending("MCP server process exited")
            else:
                await self._graceful_shutdown(server_task)
        except asyncio.CancelledError:
            pass
        finally:
            for task in (client_task, stderr_task, *self._inflight.values()):
                task.cancel()
            await asyncio.gather(
                client_task, stderr_task, *self._inflight.values(), return_exceptions=True
            )
            await self._cleanup()
            if not server_task.done():
                server_task.cancel()
            await asyncio.gather(server_task, return_exceptions=True)

        exit_code = self._process.returncode or 0
        logger.info("Server process exited with code %d", exit_code)
        return exit_code

    async def _graceful_shutdown(self, server_task: asyncio.Task[None]) -> None:
        """
        The client closed our stdin (MCP stdio shutdown): let calls already
        being decided finish briefly, then close the server's stdin and give
        it time to answer and exit before it is terminated.
        """
        assert self._process and self._process.stdin
        if self._inflight:
            _, still_pending = await asyncio.wait(
                set(self._inflight.values()), timeout=INFLIGHT_GRACE
            )
            for task in still_pending:
                task.cancel()  # nobody is left to answer the popup
        if not self._process.stdin.is_closing():
            self._process.stdin.close()
        try:
            await asyncio.wait_for(asyncio.shield(server_task), timeout=SERVER_EXIT_GRACE)
        except asyncio.TimeoutError:
            logger.info("Server did not exit within %.0fs of stdin closing", SERVER_EXIT_GRACE)

    # -- client -> server ----------------------------------------------------------

    async def _pipe_client_to_server(self, reader: asyncio.StreamReader) -> None:
        """Read messages from the client and forward (or hold) them."""
        assert self._process and self._process.stdin
        try:
            while True:
                line, oversized = await read_message(reader)
                if line is None and oversized is None:
                    break  # client closed stdin

                if oversized is not None:
                    self._reject_oversized(oversized)
                    continue

                msg = JsonRpcMessage.parse(line)
                if msg is None:
                    await self._write_server(line)  # not JSON-RPC: pass through
                    continue

                if msg.is_tool_call:
                    self._start_interception(msg, line)
                    continue

                if msg.method == "notifications/cancelled":
                    self._on_client_cancel(msg)
                elif msg.method == "tools/list" and msg.id is not None:
                    self._tools_list_ids.add(_id_key(msg.id))
                elif msg.method == "initialize":
                    info = (msg.params or {}).get("clientInfo") or {}
                    if isinstance(info, dict) and info.get("name"):
                        # e.g. "claude-ai" or "local-agent-mode-demo-notes": shown
                        # in the popup so concurrent sessions can be told apart
                        self._interceptor.client_label = str(info["name"])[:60]

                await self._write_server(line)
                if self._config.log_payloads:
                    logger.debug("Client -> Server: %s", line.decode(errors="replace").strip())

        except (asyncio.CancelledError, ConnectionError):
            pass
        except Exception:
            logger.exception("Error in client->server pipe")
        # The server's stdin is closed by _graceful_shutdown/_cleanup, after
        # calls still being decided have had a chance to be forwarded.

    def _start_interception(self, msg: JsonRpcMessage, line: bytes) -> None:
        """Decide on a tools/call in the background; keep reading meanwhile."""
        key = _id_key(msg.id)
        task = asyncio.create_task(self._intercept(msg, line))
        if msg.id is not None:
            self._inflight[key] = task

            def _forget(t: asyncio.Task[None], key: str = key) -> None:
                if self._inflight.get(key) is t:
                    del self._inflight[key]

            task.add_done_callback(_forget)

    async def _intercept(self, msg: JsonRpcMessage, line: bytes) -> None:
        if await self._handle_tool_call(msg):
            if msg.id is not None:
                self._awaiting_server[_id_key(msg.id)] = msg.id
            await self._write_server(line)

    async def _handle_tool_call(self, msg: JsonRpcMessage) -> bool:
        """
        Decide on an intercepted tools/call request.

        Returns True if the request should be forwarded to the server,
        False if it was blocked (and a blocked response was sent to the client).
        Raises CancelledError if the client cancelled it while it was pending.
        """
        try:
            verdict = await self._interceptor.decide(msg)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Decision failed; blocking %s", msg.tool_name)
            verdict = Verdict(False, "error")

        if verdict.allowed:
            return True
        await self._send_blocked_response(msg, reason=verdict.decided_by)
        return False

    def _on_client_cancel(self, msg: JsonRpcMessage) -> None:
        """notifications/cancelled: withdraw the popup if still undecided."""
        params = msg.params or {}
        key = _id_key(params.get("requestId"))
        task = self._inflight.get(key)
        if task is not None and not task.done():
            logger.info(
                "Client cancelled pending request %s (%s)",
                params.get("requestId"), params.get("reason", "no reason given"),
            )
            task.cancel()

    def _reject_oversized(self, prefix: bytes) -> None:
        msg_id = _sniff_id(prefix)
        logger.warning(
            "Rejected a message larger than %d MB from the client (id=%r)",
            MAX_MESSAGE_SIZE // (1024 * 1024), msg_id,
        )
        if msg_id is not None:
            self._write_client({
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": _ERR_TOO_LARGE,
                    "message": f"Message larger than tutut's {MAX_MESSAGE_SIZE // (1024 * 1024)} MB limit",
                },
            })

    # -- server -> client ----------------------------------------------------------

    async def _pipe_server_to_client(self) -> None:
        """Read from server stdout and forward to our stdout (client)."""
        assert self._process and self._process.stdout
        try:
            while True:
                line, oversized = await read_message(self._process.stdout)
                if line is None and oversized is None:
                    break  # server stdout closed
                if oversized is not None:
                    logger.error(
                        "Server sent a message larger than %d MB; dropped (id=%r)",
                        MAX_MESSAGE_SIZE // (1024 * 1024), _sniff_id(oversized),
                    )
                    continue

                if self._awaiting_server or self._tools_list_ids:
                    msg = JsonRpcMessage.parse(line)
                    if msg is not None and msg.is_response:
                        key = _id_key(msg.id)
                        self._awaiting_server.pop(key, None)
                        if key in self._tools_list_ids:
                            self._tools_list_ids.discard(key)
                            self._interceptor.learn_tools(msg.raw.get("result"))

                if self._config.log_payloads:
                    logger.debug("Server -> Client: %s", line.decode(errors="replace").strip())
                self._write_client(line)

        except (asyncio.CancelledError, ConnectionError):
            pass
        except Exception:
            logger.exception("Error in server->client pipe")

    async def _pipe_server_stderr(self) -> None:
        """
        Pass server stderr through to ours: Claude Desktop records it in its
        per-server log (e.g. mcp-remote's login instructions end up there).
        """
        assert self._process and self._process.stderr
        err = getattr(sys.stderr, "buffer", None)
        try:
            while True:
                line, _ = await read_message(self._process.stderr)
                if line is None:
                    if _ is None:
                        break
                    continue
                logger.debug("Server stderr: %s", line.decode(errors="replace").strip())
                if err is not None:
                    try:
                        err.write(line)
                        err.flush()
                    except (OSError, ValueError):
                        err = None
        except (asyncio.CancelledError, ConnectionError):
            pass

    async def _fail_pending(self, reason: str) -> None:
        """The server is gone: answer everything still waiting on it."""
        for task in list(self._inflight.values()):
            task.cancel()
        pending_ids = [t for t in self._inflight]  # keys of undecided calls
        waiting = list(self._awaiting_server.values())
        self._awaiting_server.clear()
        for key in pending_ids:
            waiting.append(json.loads(key))
        for msg_id in waiting:
            self._write_client({
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": _ERR_SERVER_GONE, "message": reason},
            })
        if waiting:
            logger.warning("%s; failed %d pending request(s)", reason, len(waiting))

    # -- writing -------------------------------------------------------------------

    async def _write_server(self, line: bytes) -> None:
        assert self._process and self._process.stdin and self._server_write_lock
        async with self._server_write_lock:
            try:
                self._process.stdin.write(line)
                await self._process.stdin.drain()
            except (ConnectionError, BrokenPipeError):
                logger.warning("Server stdin closed; dropping message")

    def _write_client(self, data: bytes | dict[str, Any]) -> None:
        """Write one message to the client. Single write: lines never interleave."""
        if isinstance(data, dict):
            data = json.dumps(data).encode("utf-8") + b"\n"
        try:
            out = sys.stdout.buffer
            out.write(data)
            out.flush()
        except (BrokenPipeError, ValueError, OSError):
            logger.debug("Client stdout closed; dropping message")

    async def _send_blocked_response(self, msg: JsonRpcMessage, reason: str = "user") -> None:
        """Answer a blocked tools/call (notifications get no answer)."""
        if msg.id is None:
            return
        self._write_client(
            blocked_response(msg.id, msg.tool_name, self._server_name, reason)
        )

    async def _cleanup(self) -> None:
        """Terminate the server process if still running."""
        if self._process and self._process.returncode is None:
            logger.info("Terminating server process...")
            try:
                self._process.terminate()
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    self._process.kill()
                    await self._process.wait()
            except ProcessLookupError:
                pass


async def run_stdio_proxy(
    server_command: list[str],
    server_name: str,
    config: GuardianConfig,
    env: dict[str, str] | None = None,
) -> int:
    """Entry point to run the stdio proxy."""
    proxy = StdioProxy(
        server_command=server_command,
        server_name=server_name,
        config=config,
        env=env,
    )
    return await proxy.run()
