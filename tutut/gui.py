"""
GUI confirmation popup for tutut.

Displays a cross-platform popup using tkinter that appears on top of all
other windows when an MCP tool call is intercepted. The user can Allow
or Block the request, and optionally create a persistent rule.

This module is the thread-safe layer (PopupResult, PopupManager, show_popup);
the window itself lives in popup_ui.py:
  - Always-on-top window: source, server, tool, risk badge, highlighted arguments
  - Block is the keyboard default; Allow is armed after a short delay
  - Keys: Y = Allow, N / Esc = Block
  - Queue counter for concurrent pending requests
  - Optional auto-block countdown
  - "Remember my choice" switch for persistent rules
"""

from __future__ import annotations

import logging
import queue
import threading
from typing import Any

from .models import Decision, InterceptedRequest

logger = logging.getLogger(__name__)

# Whether tkinter is available on this system.
_TK_AVAILABLE = False
try:
    import tkinter as tk
    from tkinter import ttk

    _TK_AVAILABLE = True
except ImportError:
    tk = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]


def is_gui_available() -> bool:
    """Check whether a GUI can be displayed."""
    if not _TK_AVAILABLE:
        return False
    try:
        root = tk.Tk()
        root.withdraw()
        root.destroy()
        return True
    except Exception:
        return False


class PopupResult:
    """
    Thread-safe container for popup result.

    The first `set()` wins; later calls are ignored. That lets the popup,
    its timeout and an external cancel race safely.

    `reason` says who decided: "user", "timeout", "cancelled" (the client
    gave up on the request) or "queue_full".
    """

    def __init__(self) -> None:
        self.decision: Decision = Decision.PENDING
        self.remember: bool = False
        self.reason: str = ""
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._callbacks: list[Any] = []

    def set(self, decision: Decision, remember: bool = False, reason: str = "user") -> bool:
        """Record the decision. Returns False if one was already recorded."""
        with self._lock:
            if self._event.is_set():
                return False
            self.decision = decision
            self.remember = remember
            self.reason = reason
            self._event.set()
            callbacks, self._callbacks = self._callbacks, []
        for cb in callbacks:
            try:
                cb(self)
            except Exception:
                logger.exception("PopupResult callback failed")
        return True

    def add_done_callback(self, cb: Any) -> None:
        """Call `cb(result)` once decided (immediately if already decided)."""
        with self._lock:
            if not self._event.is_set():
                self._callbacks.append(cb)
                return
        cb(self)

    def wait(self, timeout: float | None = None) -> Decision:
        self._event.wait(timeout=timeout)
        return self.decision

    @property
    def is_set(self) -> bool:
        return self._event.is_set()


def show_popup(
    request: InterceptedRequest,
    timeout: float = 0,
    queue_position: int = 0,
    queue_total: int = 0,
    result: PopupResult | None = None,
) -> PopupResult:
    """
    Show a confirmation popup for an intercepted tool call.

    This function is thread-safe and can be called from any thread.
    It spawns the tkinter window in a dedicated thread since tkinter
    must run on a consistent thread.

    Args:
        request: The intercepted MCP request to display.
        timeout: Seconds to wait before auto-blocking (0 = no timeout).
        queue_position: 1-based position in the pending queue (0 = not shown).
        queue_total: Total items in the queue.
        result: Result container to fill (a new one if omitted). If someone
            else sets it while the window is open (e.g. the request was
            cancelled), the window closes itself.

    Returns:
        A PopupResult with the user's decision.
    """
    result = result if result is not None else PopupResult()

    if not _TK_AVAILABLE:
        logger.warning("tkinter not available; cannot show popup")
        result.set(Decision.BLOCK, remember=False, reason="headless")
        return result

    def _run_popup() -> None:
        try:
            _create_popup_window(request, result, timeout, queue_position, queue_total)
        except Exception:
            logger.exception("Error showing popup")
            # Fail closed: a popup that can't be shown must not hang the call.
            result.set(Decision.BLOCK, remember=False, reason="error")

    thread = threading.Thread(target=_run_popup, daemon=True)
    thread.start()
    return result


def _create_popup_window(
    request: InterceptedRequest,
    result: PopupResult,
    timeout: float,
    queue_position: int,
    queue_total: int,
) -> None:
    """Build and run the approval window (see popup_ui.py)."""
    from .popup_ui import PopupWindow

    PopupWindow(
        request,
        result,
        timeout=timeout,
        queue_position=queue_position,
        queue_total=queue_total,
    ).run()


class PopupManager:
    """
    Manages popup display, ensuring they are serialized and thread-safe.

    Only one popup is shown at a time; additional requests queue up.
    Tracks queue depth so each popup can display "N of M pending".
    """

    MAX_PENDING = 10

    def __init__(self, timeout: float = 0) -> None:
        self._timeout = timeout
        self._lock = threading.Lock()
        self._queue: queue.Queue[tuple[InterceptedRequest, PopupResult]] = queue.Queue(
            maxsize=self.MAX_PENDING
        )
        self._pending_count = 0
        self._count_lock = threading.Lock()
        self._results: dict[str, PopupResult] = {}  # undecided, by request id
        self._worker = threading.Thread(target=self._process_queue, daemon=True)
        self._worker.start()

    def request_decision(self, request: InterceptedRequest) -> PopupResult:
        """
        Queue a request for user decision and return the result container.

        The caller should wait on the result (wait() or add_done_callback).
        If the queue is full, returns an immediate BLOCK decision.
        """
        popup_result = PopupResult()

        with self._count_lock:
            self._pending_count += 1
            self._results[request.id] = popup_result

        try:
            self._queue.put_nowait((request, popup_result))
        except queue.Full:
            logger.warning(
                "Popup queue full (%d); auto-blocking %s",
                self.MAX_PENDING,
                request.tool_name,
            )
            with self._count_lock:
                self._pending_count -= 1
                self._results.pop(request.id, None)
            popup_result.set(Decision.BLOCK, remember=False, reason="queue_full")

        return popup_result

    def cancel(self, request_id: str) -> bool:
        """
        Withdraw a request (the client gave up on it).

        A queued request is skipped; an open popup closes itself. Returns
        True if the request was still undecided.
        """
        with self._count_lock:
            popup_result = self._results.get(request_id)
        if popup_result is None:
            return False
        return popup_result.set(Decision.BLOCK, remember=False, reason="cancelled")

    def _process_queue(self) -> None:
        """Worker thread that processes popup requests one at a time."""
        position = 0
        while True:
            try:
                request, popup_result = self._queue.get()
                position += 1

                with self._count_lock:
                    total = self._pending_count

                if not popup_result.is_set:  # skip requests cancelled while queued
                    show_popup(
                        request,
                        timeout=self._timeout,
                        queue_position=position if total > 1 else 0,
                        queue_total=total if total > 1 else 0,
                        result=popup_result,
                    )
                    # Wait for the popup to complete (or be cancelled)
                    popup_result.wait()

                with self._count_lock:
                    self._pending_count -= 1
                    self._results.pop(request.id, None)
                    if self._pending_count == 0:
                        position = 0

            except Exception:
                logger.exception("Error processing popup queue")
