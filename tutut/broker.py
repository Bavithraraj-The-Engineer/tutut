"""
Approval broker: one inbox for every tutut process.

Each wrapped Claude Desktop server runs its own `tutut stdio` process, and
the claude.ai gateway is another. Without coordination, simultaneous
requests from different processes would each open a window - stacked on
top of each other, with countdowns running on the hidden ones. The broker
is a single per-user process that owns the window and one global queue:

    tutut stdio (filesystem) ─┐
    tutut stdio (demo-notes) ─┼─ Unix socket ─▶ broker ─▶ ONE window: active request
    tutut web   (gateway)    ─┘  (~/.config/     │        + "Also waiting (n)" with
                                   tutut/        │          each request's own countdown
                                   broker.sock)  └─ decisions back to each process

  - Started on demand by the first process that needs a decision; a lock
    file keeps it a singleton; it exits after IDLE_EXIT_S with no clients.
  - The socket is owner-only (0600): only this user can submit or answer.
  - Each request's deadline counts from its *arrival*, so queued requests
    expire on time (auto-block) even while another one is on screen.
  - "Remember" on one request also decides identical (server, tool)
    requests already waiting; "Block all" clears the queue.
  - If the broker can't be reached - or dies mid-request - pending requests
    fall back to the process's own popup, so a decision is never lost.

Wire format: newline-delimited JSON.
    client → broker  {"type": "hello", "protocol": 1, "pid": …}
                     {"type": "request", "id", "server", "tool", "arguments",
                      "source", "annotations", "client", "timeout"}
                     {"type": "cancel", "id"}
    broker → client  {"type": "welcome", "protocol": 1}
                     {"type": "decision", "id", "decision": "allow"|"block",
                      "remember": bool, "reason": "user"|"rule"|"timeout"|…}
"""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator

from .gui import PopupResult
from .models import Decision, InterceptedRequest, JsonRpcMessage
from .risk import classify

logger = logging.getLogger(__name__)

PROTOCOL = 1
IDLE_EXIT_S = 600
MAX_PENDING = 50   # more undecided requests than this are blocked at once ("queue_full")
CONNECT_WAIT_S = 4.0
MAX_ARGS_BYTES = 256 * 1024


def supported() -> bool:
    """Unix sockets + flock: Linux and macOS. Windows keeps per-process popups."""
    return hasattr(socket, "AF_UNIX") and sys.platform != "win32"


def _state_dir() -> Path:
    # Computed at call time (not import time) so it follows $HOME.
    return Path.home() / ".config" / "tutut"


def default_socket_path() -> Path:
    return _state_dir() / "broker.sock"


def default_lock_path() -> Path:
    return _state_dir() / "broker.lock"


# -- wire helpers -----------------------------------------------------------------


def _send(sock: socket.socket, lock: threading.Lock, obj: dict[str, Any]) -> None:
    data = (json.dumps(obj, ensure_ascii=False, default=str) + "\n").encode("utf-8")
    with lock:
        sock.sendall(data)


def _messages(sock: socket.socket) -> Iterator[dict[str, Any]]:
    buf = b""
    while True:
        try:
            chunk = sock.recv(65536)
        except OSError:
            return
        if not chunk:
            return
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if line.strip():
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if isinstance(obj, dict):
                    yield obj


# -- broker side ------------------------------------------------------------------------


class _Conn:
    """One connected tutut process."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.lock = threading.Lock()
        self.alive = True

    def send(self, obj: dict[str, Any]) -> None:
        if not self.alive:
            return
        try:
            _send(self.sock, self.lock, obj)
        except OSError:
            self.alive = False


class Item:
    """One pending approval in the broker's queue."""

    def __init__(self, conn: Any, request: InterceptedRequest, timeout: float, arrived: float) -> None:
        self.conn = conn
        self.request = request
        self.timeout = timeout
        self.arrived = arrived
        self.deadline = arrived + timeout if timeout > 0 else None
        self.result = PopupResult()
        self.active = False
        self.silent = False  # cancelled by its client: no reply expected

    @property
    def id(self) -> str:
        return self.request.id


UI = Callable[[Item, "Broker"], None]


def tk_ui(item: Item, broker: "Broker") -> None:
    """Show `item` in the approval window, with the rest of the queue."""
    from .popup_ui import PopupWindow

    PopupWindow(
        item.request, item.result,
        timeout=item.timeout, deadline=item.deadline,
        queue_view=lambda: broker.snapshot(exclude_id=item.id),
        on_block_all=broker.block_all,
    ).run()


class Broker:
    """The global queue: thread-safe; the UI runs on its own thread."""

    def __init__(self, *, ui: UI = tk_ui, idle_exit_s: float = IDLE_EXIT_S,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._cond = threading.Condition(threading.RLock())
        self._items: dict[str, Item] = {}      # arrival order
        self._conns: set[Any] = set()
        self._ui = ui
        self._clock = clock
        self._idle_exit_s = idle_exit_s
        self._last_activity = clock()

    # -- events from clients --

    def add_conn(self, conn: Any) -> None:
        with self._cond:
            self._conns.add(conn)
            self._last_activity = self._clock()

    def submit(self, conn: Any, msg: dict[str, Any]) -> Item:
        rid = str(msg.get("id") or "")
        tool = str(msg.get("tool") or "(unknown)")
        args = msg.get("arguments") if msg.get("arguments") is not None else {}
        request = InterceptedRequest(
            id=rid,
            message=JsonRpcMessage(raw={"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                                        "params": {"name": tool, "arguments": args}}),
            server_name=str(msg.get("server") or "?"),
            tool_name=tool,
            arguments=args,
            source=str(msg.get("source") or ""),
            annotations=msg.get("annotations") if isinstance(msg.get("annotations"), dict) else None,
            client=str(msg.get("client") or ""),
        )
        try:
            timeout = max(0.0, float(msg.get("timeout") or 0))
        except (TypeError, ValueError):
            timeout = 0.0
        item = Item(conn, request, timeout, self._clock())
        item.result.add_done_callback(lambda r, item=item: self._decided(item, r))
        with self._cond:
            full = sum(1 for i in self._items.values() if not i.result.is_set) >= MAX_PENDING
            if not full:
                self._items[rid] = item
                self._last_activity = self._clock()
                self._cond.notify_all()
        if full:  # a flood of requests can't grow the queue without bound
            logger.warning("Approval queue full (%d); blocking %s", MAX_PENDING, tool)
            item.result.set(Decision.BLOCK, reason="queue_full")
        return item

    def cancel(self, conn: Any, rid: str) -> None:
        with self._cond:
            item = self._items.get(str(rid))
            if item is None or item.conn is not conn:
                return
            item.silent = True
        item.result.set(Decision.BLOCK, reason="cancelled")

    def disconnect(self, conn: Any) -> None:
        with self._cond:
            self._conns.discard(conn)
            mine = [i for i in self._items.values() if i.conn is conn]
            for item in mine:
                item.silent = True
            self._last_activity = self._clock()
        for item in mine:
            item.result.set(Decision.BLOCK, reason="cancelled")

    # -- decisions --

    def _decided(self, item: Item, result: PopupResult) -> None:
        with self._cond:
            self._items.pop(item.id, None)
            self._last_activity = self._clock()
            self._cond.notify_all()
            twins = [
                i for i in self._items.values()
                if result.remember and result.reason == "user"
                and i.request.server_name == item.request.server_name
                and i.request.tool_name == item.request.tool_name
            ]
        if not item.silent:
            item.conn.send({
                "type": "decision", "id": item.id, "decision": result.decision.value,
                "remember": bool(result.remember), "reason": result.reason or "user",
            })
        # "Remember my choice" also answers identical requests already waiting.
        for twin in twins:
            twin.result.set(result.decision, remember=False, reason="rule")

    def block_all(self) -> None:
        with self._cond:
            pending = list(self._items.values())
        for item in pending:
            item.result.set(Decision.BLOCK, reason="user")

    def expire(self) -> int:
        """Auto-block requests whose deadline passed (including queued ones)."""
        now = self._clock()
        with self._cond:
            due = [i for i in self._items.values() if i.deadline is not None and now >= i.deadline]
        for item in due:
            item.result.set(Decision.BLOCK, reason="timeout")
        return len(due)

    # -- views --

    def snapshot(self, exclude_id: str | None = None) -> dict[str, Any]:
        now = self._clock()
        with self._cond:
            pending = [i for i in self._items.values() if not i.result.is_set]
        others = [
            {
                "id": i.id,
                "server": i.request.server_name,
                "tool": i.request.tool_name,
                "client": i.request.client,
                "risk": classify(i.request.tool_name, i.request.annotations).level,
                "remaining": None if i.deadline is None else max(0.0, i.deadline - now),
            }
            for i in pending if i.id != exclude_id
        ]
        return {"total": len(pending), "others": others}

    def next_item(self, wait: float = 0.5) -> Item | None:
        """The oldest undecided request not yet on screen (marks it active)."""
        with self._cond:
            def ready() -> Item | None:
                return next((i for i in self._items.values() if not i.active and not i.result.is_set), None)

            item = ready()
            if item is None:
                self._cond.wait(wait)
                item = ready()
            if item is not None:
                item.active = True
            return item

    def idle(self) -> bool:
        with self._cond:
            return (not self._conns and not self._items
                    and self._clock() - self._last_activity > self._idle_exit_s)

    def run_ui(self, item: Item) -> None:
        try:
            self._ui(item, self)
        except Exception:
            logger.exception("Approval window failed; blocking %s", item.request.tool_name)
            item.result.set(Decision.BLOCK, reason="error")
        item.result.set(Decision.BLOCK, reason="user")  # no-op if already decided


def serve(broker: Broker, path: Path, stop: threading.Event) -> None:
    """Listen on `path` until `stop` is set or the broker goes idle."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        path.unlink()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_umask = os.umask(0o177)  # socket file created 0600: only this user may connect
    try:
        srv.bind(str(path))
    finally:
        os.umask(old_umask)
    os.chmod(path, 0o600)
    srv.listen(16)
    srv.settimeout(0.25)

    def client_thread(sock: socket.socket) -> None:
        conn = _Conn(sock)
        broker.add_conn(conn)
        try:
            for msg in _messages(sock):
                kind = msg.get("type")
                if kind == "hello":
                    conn.send({"type": "welcome", "protocol": PROTOCOL})
                elif kind == "request":
                    broker.submit(conn, msg)
                elif kind == "cancel":
                    broker.cancel(conn, str(msg.get("id")))
        finally:
            conn.alive = False
            broker.disconnect(conn)
            try:
                sock.close()
            except OSError:
                pass

    def ui_loop() -> None:
        while not stop.is_set():
            item = broker.next_item(wait=0.25)
            if item is not None:
                broker.run_ui(item)

    def expiry_loop() -> None:
        while not stop.is_set():
            broker.expire()
            stop.wait(0.25)

    threading.Thread(target=ui_loop, name="tutut-broker-ui", daemon=True).start()
    threading.Thread(target=expiry_loop, name="tutut-broker-expiry", daemon=True).start()
    logger.info("Approval broker listening on %s", path)
    try:
        while not stop.is_set():
            try:
                sock, _ = srv.accept()
            except socket.timeout:
                if broker.idle():
                    logger.info("Approval broker idle; exiting")
                    break
                continue
            threading.Thread(target=client_thread, args=(sock,), daemon=True).start()
    finally:
        stop.set()
        srv.close()
        try:
            path.unlink()
        except OSError:
            pass


def acquire_singleton(lock_path: Path) -> int | None:
    """Hold an exclusive lock for the broker's lifetime; None if one is running."""
    import fcntl

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    os.ftruncate(fd, 0)
    os.write(fd, str(os.getpid()).encode())
    return fd


def run_broker(*, socket_path: Path | None = None, lock_path: Path | None = None) -> int:
    """`tutut broker`: run the singleton approval broker until idle."""
    lock = acquire_singleton(lock_path or default_lock_path())
    if lock is None:
        logger.info("An approval broker is already running")
        return 0
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    try:
        serve(Broker(), socket_path or default_socket_path(), stop)
    finally:
        os.close(lock)
    return 0


# -- client side (inside each tutut process) ------------------------------------------


class BrokerClient:
    """
    Drop-in for PopupManager (request_decision / cancel) that routes every
    request to the shared broker, starting it if needed, and falls back to
    the local popup manager whenever the broker is unavailable.
    """

    def __init__(
        self,
        *,
        timeout: float,
        fallback: Any,
        socket_path: Path | None = None,
        spawn: bool = True,
        config_path: Path | None = None,
        connect_wait: float = CONNECT_WAIT_S,
    ) -> None:
        self._timeout = float(timeout or 0)
        self._fallback = fallback
        self._path = socket_path or default_socket_path()
        self._spawn = spawn
        self._config_path = config_path
        self._connect_wait = connect_wait
        self._lock = threading.RLock()
        self._send_lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._pending: dict[str, tuple[InterceptedRequest, PopupResult]] = {}
        self._via_fallback: set[str] = set()
        self.client_label = ""

    # -- PopupManager interface --

    def request_decision(self, request: InterceptedRequest) -> PopupResult:
        result = PopupResult()
        with self._lock:
            sock = self._connect()
            if sock is not None:
                self._pending[request.id] = (request, result)
        if sock is None:
            return self._to_fallback(request, result)
        try:
            _send(sock, self._send_lock, self._payload(request))
        except OSError:
            self._connection_lost(sock)
        return result

    def cancel(self, request_id: str) -> bool:
        with self._lock:
            entry = self._pending.pop(request_id, None)
            sock = self._sock
            fallback = request_id in self._via_fallback
        if entry is not None:
            if sock is not None:
                try:
                    _send(sock, self._send_lock, {"type": "cancel", "id": request_id})
                except OSError:
                    pass
            return entry[1].set(Decision.BLOCK, reason="cancelled")
        if fallback:
            return bool(self._fallback.cancel(request_id))
        return False

    # -- internals --

    def _payload(self, request: InterceptedRequest) -> dict[str, Any]:
        args: Any = request.arguments
        try:
            text = json.dumps(args, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            text, args = str(args), {"_preview": str(args)[:12000]}
        if len(text) > MAX_ARGS_BYTES:
            args = {"_preview": text[:12000] + "…"}
        return {
            "type": "request", "id": request.id, "server": request.server_name,
            "tool": request.tool_name, "arguments": args, "source": request.source,
            "annotations": request.annotations, "client": request.client or self.client_label,
            "timeout": self._timeout,
        }

    def _connect(self) -> socket.socket | None:
        """Connected socket to the broker (starting it if needed), or None."""
        if self._sock is not None:
            return self._sock
        sock = self._try_connect()
        if sock is None and self._spawn:
            self._spawn_broker()
            deadline = time.monotonic() + self._connect_wait
            while sock is None and time.monotonic() < deadline:
                time.sleep(0.1)
                sock = self._try_connect()
        if sock is None:
            logger.warning("Approval broker unavailable; using this process's own popup")
            return None
        try:
            _send(sock, self._send_lock, {"type": "hello", "protocol": PROTOCOL, "pid": os.getpid()})
        except OSError:
            return None
        self._sock = sock
        threading.Thread(target=self._reader, args=(sock,), daemon=True, name="tutut-broker-client").start()
        return sock

    def _try_connect(self) -> socket.socket | None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(str(self._path))
            return sock
        except OSError:
            sock.close()
            return None

    def _spawn_broker(self) -> None:
        cmd = [sys.executable, "-m", "tutut"]
        if self._config_path is not None:
            cmd += ["--config", str(self._config_path)]
        cmd.append("broker")
        try:
            # Own session, no inherited stdio: a stdio proxy's stdin/stdout are
            # Claude's MCP pipes and must never be shared with the broker.
            subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
                             cwd=str(Path.home()))
            logger.info("Started the approval broker")
        except OSError as exc:
            logger.warning("Could not start the approval broker: %s", exc)

    def _reader(self, sock: socket.socket) -> None:
        for msg in _messages(sock):
            if msg.get("type") != "decision":
                continue
            with self._lock:
                entry = self._pending.pop(str(msg.get("id")), None)
            if entry is None:
                continue
            try:
                decision = Decision(msg.get("decision"))
            except ValueError:
                decision = Decision.BLOCK
            entry[1].set(decision, remember=bool(msg.get("remember")), reason=str(msg.get("reason") or "user"))
        self._connection_lost(sock)

    def _connection_lost(self, sock: socket.socket) -> None:
        """Broker gone: re-ask every undecided request with the local popup."""
        with self._lock:
            if self._sock is not sock:
                return
            self._sock = None
            pending, self._pending = self._pending, {}
        try:
            sock.close()
        except OSError:
            pass
        for request, result in pending.values():
            if not result.is_set:
                logger.warning("Approval broker went away; asking locally for %s", request.tool_name)
                self._to_fallback(request, result)

    def _to_fallback(self, request: InterceptedRequest, result: PopupResult) -> PopupResult:
        with self._lock:
            self._via_fallback.add(request.id)
        local = self._fallback.request_decision(request)

        def relay(r: PopupResult) -> None:
            result.set(r.decision, remember=r.remember, reason=r.reason or "user")
            with self._lock:
                self._via_fallback.discard(request.id)

        local.add_done_callback(relay)
        return result
