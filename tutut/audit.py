"""
Audit trail for tutut.

Every intercepted tools/call becomes one record in the SQLite database
~/.config/tutut/audit.db (see store.py), so there is a durable, queryable
record of what Claude tried to do and what was decided:

    {"ts": "2026-11-19T10:02:11.481+00:00", "transport": "stdio",
     "source": "Claude Desktop (local)", "server": "filesystem",
     "tool": "write_file", "arguments": {"path": "...", "content": "..."},
     "decision": "block", "decided_by": "user", "wait_ms": 4210, "risk": "medium"}

Several tutut processes (one per wrapped server, plus the web gateway) write
to the same database. Argument values whose key looks secret are masked, and
long values are truncated, so the log never becomes a second copy of your
data. A failed write is logged and never breaks proxying.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import re
import threading
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger(__name__)

# Keys whose values are masked in the audit log (matched case-insensitively
# as a substring of the key, e.g. "api_key", "Authorization", "db_password").
_SECRET_KEY = re.compile(
    r"pass(word|wd)?|secret|token|api[-_]?key|auth|credential|cookie|private[-_]?key",
    re.IGNORECASE,
)
MAX_VALUE_CHARS = 300      # per string value
MAX_ARGS_CHARS = 4000      # whole arguments object, after per-value truncation
MAX_DEPTH = 6


def redact(value: Any, *, _depth: int = 0) -> Any:
    """Copy of `value` with secret-looking keys masked and long strings cut."""
    if _depth > MAX_DEPTH:
        return "…"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key = str(k)
            if _SECRET_KEY.search(key) and v not in (None, "", [], {}):
                out[key] = "***"
            else:
                out[key] = redact(v, _depth=_depth + 1)
        return out
    if isinstance(value, list):
        items = [redact(v, _depth=_depth + 1) for v in value[:50]]
        if len(value) > 50:
            items.append(f"… (+{len(value) - 50} more)")
        return items
    if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
        return value[:MAX_VALUE_CHARS] + f"… (+{len(value) - MAX_VALUE_CHARS} chars)"
    return value


def _owner_only(fd: int) -> None:
    """chmod 600 an open file (POSIX; Windows has no fchmod before 3.13)."""
    if hasattr(os, "fchmod"):
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass


def ensure_private_file(path: Path) -> None:
    """Create `path` if missing, owner-only either way."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        _owner_only(fd)
    finally:
        os.close(fd)


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds")


class AuditLog:
    """Writes audit records to the SQLite store (or nowhere, if path is None)."""

    def __init__(
        self,
        path: str | os.PathLike[str] | None,
        *,
        retention_days: int = 90,
        legacy_jsonl: str | os.PathLike[str] | None = None,
    ) -> None:
        self.path = Path(path) if path else None
        self._retention_days = retention_days
        self._legacy = legacy_jsonl
        self._store: Any = None  # opened on first write
        self._lock = threading.Lock()

    @property
    def store(self) -> Any:
        if self._store is None and self.path is not None:
            from .store import SQLiteStore

            self._store = SQLiteStore(self.path, retention_days=self._retention_days,
                                      legacy_jsonl=self._legacy)
        return self._store

    def record(
        self,
        *,
        transport: str,
        source: str,
        server: str,
        tool: str,
        arguments: Any,
        decision: str,
        decided_by: str,
        wait_ms: int | None = None,
        request_id: Any = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Write one record; never raises (auditing must not break proxying)."""
        entry: dict[str, Any] = {
            "ts": _now_iso(),
            "transport": transport,
            "source": source,
            "server": server,
            "tool": tool,
            "arguments": self._safe_arguments(arguments),
            "decision": decision,
            "decided_by": decided_by,
        }
        if wait_ms is not None:
            entry["wait_ms"] = wait_ms
        if request_id is not None:
            entry["request_id"] = request_id
        if extra:
            entry.update(extra)

        if self.path is None:
            return entry
        try:
            with self._lock:
                entry["id"] = self.store.record(entry)
        except Exception as exc:  # sqlite3.Error, OSError, ...
            logger.warning("Could not write audit record to %s: %s", self.path, exc)
        return entry

    @staticmethod
    def _safe_arguments(arguments: Any) -> Any:
        cleaned = redact(arguments if arguments is not None else {})
        text = json.dumps(cleaned, ensure_ascii=False, default=str)
        if len(text) <= MAX_ARGS_CHARS:
            return cleaned
        return {"_truncated": text[:MAX_ARGS_CHARS] + "…"}


# -- reading (for `tutut log`) -------------------------------------------------


def format_entry(entry: dict[str, Any]) -> str:
    """One human-readable line for an audit record (times in local time)."""
    raw_ts = str(entry.get("ts", ""))
    try:
        ts = _dt.datetime.fromisoformat(raw_ts).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        ts = raw_ts[:19].replace("T", " ")
    decision = str(entry.get("decision", "?")).upper()
    by = entry.get("decided_by", "?")
    wait = entry.get("wait_ms")
    wait_s = f" {wait / 1000:.1f}s" if isinstance(wait, (int, float)) else ""
    args = json.dumps(entry.get("arguments", {}), ensure_ascii=False, default=str)
    if len(args) > 120:
        args = args[:117] + "..."
    return (
        f"{ts}  {decision:<9} by {by:<10}{wait_s:>7}  "
        f"{entry.get('server', '?')}/{entry.get('tool', '?')}  "
        f"[{entry.get('source') or entry.get('transport', '?')}]  {args}"
    )


def _open_store(path: Path) -> Any:
    from .store import SQLiteStore

    return SQLiteStore(path, retention_days=0)  # readers never prune


def read_entries(path: Path, last: int | None = None) -> list[dict[str, Any]]:
    """
    Audit records, oldest first (the last `last` if given). Reads the SQLite
    database, or a legacy/exported JSON-lines file if `path` ends in .jsonl.
    """
    path = Path(path)
    if path.suffix == ".jsonl":
        from .store import _read_jsonl

        entries = _read_jsonl(path) if path.exists() else []
        return entries[-last:] if last else entries
    if not path.exists():
        return []
    store = _open_store(path)
    try:
        return store.recent(last)
    finally:
        store.close()


def follow(path: Path, poll: float = 0.5) -> Iterator[dict[str, Any]]:
    """Yield records added to the audit database from now on (like tail -f)."""
    import time

    store = _open_store(Path(path))
    try:
        last = store.max_id()
        while True:
            fresh = store.since_id(last)
            if not fresh:
                time.sleep(poll)
                continue
            for entry in fresh:
                last = entry["id"]
                yield entry
    finally:
        store.close()
