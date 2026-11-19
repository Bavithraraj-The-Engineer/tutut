"""
SQLite storage for tutut's audit trail.

Why SQLite: standard library (tutut stays dependency-free), no server, and
it fits the workload - several tutut processes on one machine (one per
wrapped Desktop server, plus the web gateway) each appending a few records
at human pace, and a dashboard querying them. With WAL mode readers never
block writers, writers queue briefly on a busy timeout, and indexed queries
stay fast at millions of rows.

    events(id, ts, ts_ms, transport, path, source, server, tool, decision,
           decided_by, risk, wait_ms, request_id, user_agent, arguments, extra)

  - `ts_ms` (UTC epoch ms) drives range queries; `ts` keeps the ISO text.
  - `arguments` is the redacted, truncated JSON the audit layer produces.
  - Every statement is parameterised: tool names and arguments can be
    attacker-controlled (prompt injection), so nothing is formatted into SQL.
  - The file (and its -wal/-shm companions) is owner-only.
  - Old rows are pruned after `retention_days`; space is reclaimed
    incrementally (auto_vacuum=INCREMENTAL).
  - An existing audit.jsonl (the previous format) is imported when the
    store is opened and renamed to audit.jsonl.migrated; records already
    present are skipped, and the rename happens under the write lock, so
    concurrent processes never import a file twice.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
PRUNE_EVERY_S = 3600
_COLUMNS = ("ts", "ts_ms", "transport", "path", "source", "server", "tool", "decision",
            "decided_by", "risk", "wait_ms", "request_id", "user_agent", "arguments", "extra")
_KNOWN = {"ts", "transport", "path", "source", "server", "tool", "decision", "decided_by",
          "risk", "wait_ms", "request_id", "user_agent", "arguments", "id"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    ts_ms       INTEGER NOT NULL,
    transport   TEXT    NOT NULL DEFAULT '',
    path        TEXT    NOT NULL DEFAULT '',
    source      TEXT    NOT NULL DEFAULT '',
    server      TEXT    NOT NULL DEFAULT '',
    tool        TEXT    NOT NULL DEFAULT '',
    decision    TEXT    NOT NULL DEFAULT '',
    decided_by  TEXT    NOT NULL DEFAULT '',
    risk        TEXT,
    wait_ms     INTEGER,
    request_id  TEXT,
    user_agent  TEXT,
    arguments   TEXT    NOT NULL DEFAULT '{}',
    extra       TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_ts          ON events(ts_ms);
CREATE INDEX IF NOT EXISTS ix_events_decision_ts ON events(decision, ts_ms);
CREATE INDEX IF NOT EXISTS ix_events_server_tool ON events(server, tool, ts_ms);
CREATE INDEX IF NOT EXISTS ix_events_path_ts     ON events(path, ts_ms);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def path_of(entry: dict[str, Any]) -> str:
    """Which interception path produced a record: local, remote or web."""
    if entry.get("path") in ("local", "remote", "web"):
        return entry["path"]
    if entry.get("transport") == "http":
        return "web"
    return "remote" if "mcp-remote" in str(entry.get("source", "")) else "local"


def parse_ts_ms(value: Any) -> int | None:
    try:
        ts = dt.datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    return int(ts.timestamp() * 1000)


def _private(path: Path) -> None:
    """Create `path` owner-only (0600) if missing, and tighten it if not."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


class SQLiteStore:
    """Audit events in SQLite. Safe across threads (one connection each) and processes."""

    def __init__(self, path: str | os.PathLike[str], *, retention_days: int = 90,
                 legacy_jsonl: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(path)
        self.retention_days = retention_days
        self.legacy_jsonl = Path(legacy_jsonl) if legacy_jsonl else None
        self._local = threading.local()
        self._last_prune = 0.0

    # -- connection & schema ----------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            new_db = not self.path.exists() or self.path.stat().st_size == 0
            _private(self.path)
            # isolation_level=None: autocommit; batches use explicit transactions.
            conn = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None,
                                   check_same_thread=True)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=5000")
            if new_db:
                conn.execute("PRAGMA auto_vacuum=INCREMENTAL")  # must precede the first table
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._migrate(conn)
            self._local.conn = conn
            self._import_legacy(conn)
        return conn

    def _migrate(self, conn: sqlite3.Connection) -> None:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version >= SCHEMA_VERSION:
            return
        # One statement at a time: executescript() would COMMIT the
        # IMMEDIATE transaction that keeps concurrent processes out.
        conn.execute("BEGIN IMMEDIATE")
        try:
            for statement in _SCHEMA.split(";"):
                if statement.strip():
                    conn.execute(statement)
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def _import_legacy(self, conn: sqlite3.Connection) -> None:
        """
        Import an audit.jsonl if one exists, then rename it.

        Not a one-time flag: tutut processes still running the old version
        keep appending to (re-creating) audit.jsonl until they restart, and
        those records must not be stranded. Rows already in the database
        are skipped, and the file is renamed while the write lock is held,
        so two processes can never import the same file.
        """
        src = self.legacy_jsonl
        if src is None or not src.exists():
            return
        conn.execute("BEGIN IMMEDIATE")
        target = None
        try:
            if not src.exists():  # another process took it while we waited
                conn.execute("COMMIT")
                return
            fresh = [e for e in _read_jsonl(src) if not self._already_stored(conn, e)]
            count = self._insert_many(conn, fresh)
            target = _unique_name(src.with_name(src.name + ".migrated"))
            src.replace(target)
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            if target is not None and target.exists() and not src.exists():
                target.replace(src)  # put it back: nothing was imported
            logger.exception("Could not import %s", src)
            return
        logger.info("Imported %d audit records from %s (renamed to %s)", count, src, target.name)

    @staticmethod
    def _already_stored(conn: sqlite3.Connection, entry: dict[str, Any]) -> bool:
        ts = str(entry.get("ts", ""))
        ts_ms = parse_ts_ms(ts)
        if ts_ms is None:
            return False
        return conn.execute(
            "SELECT 1 FROM events WHERE ts_ms = ? AND ts = ? AND server = ? AND tool = ? AND decision = ? LIMIT 1",
            (ts_ms, ts, str(entry.get("server", "")), str(entry.get("tool", "")), str(entry.get("decision", ""))),
        ).fetchone() is not None

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # -- writing ------------------------------------------------------------------

    @staticmethod
    def _row(entry: dict[str, Any]) -> tuple[Any, ...]:
        ts = str(entry.get("ts") or dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"))
        ts_ms = parse_ts_ms(ts) or int(time.time() * 1000)
        extra = {k: v for k, v in entry.items() if k not in _KNOWN}
        rid = entry.get("request_id")
        return (
            ts, ts_ms, str(entry.get("transport", "")), path_of(entry), str(entry.get("source", "")),
            str(entry.get("server", "")), str(entry.get("tool", "")), str(entry.get("decision", "")),
            str(entry.get("decided_by", "")), entry.get("risk"),
            int(entry["wait_ms"]) if isinstance(entry.get("wait_ms"), (int, float)) else None,
            json.dumps(rid) if rid is not None else None, entry.get("user_agent"),
            json.dumps(entry.get("arguments", {}), ensure_ascii=False, default=str),
            json.dumps(extra, ensure_ascii=False, default=str) if extra else None,
        )

    def _insert_many(self, conn: sqlite3.Connection, entries: Iterable[dict[str, Any]]) -> int:
        sql = f"INSERT INTO events ({', '.join(_COLUMNS)}) VALUES ({', '.join('?' * len(_COLUMNS))})"
        rows = [self._row(e) for e in entries]
        conn.executemany(sql, rows)
        return len(rows)

    def record(self, entry: dict[str, Any]) -> int:
        """Insert one audit record; returns its id."""
        conn = self._conn()
        cur = conn.execute(
            f"INSERT INTO events ({', '.join(_COLUMNS)}) VALUES ({', '.join('?' * len(_COLUMNS))})",
            self._row(entry),
        )
        if time.monotonic() - self._last_prune > PRUNE_EVERY_S:
            self.prune()
        return int(cur.lastrowid)

    def insert_many(self, entries: Iterable[dict[str, Any]]) -> int:
        """Insert records in one transaction (imports, tests)."""
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            n = self._insert_many(conn, entries)
            conn.execute("COMMIT")
            return n
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def prune(self, *, now_ms: int | None = None) -> int:
        """Delete records older than retention_days (0 = keep forever)."""
        self._last_prune = time.monotonic()
        if not self.retention_days:
            return 0
        cutoff = (now_ms or int(time.time() * 1000)) - self.retention_days * 86_400_000
        conn = self._conn()
        deleted = conn.execute("DELETE FROM events WHERE ts_ms < ?", (cutoff,)).rowcount
        if deleted:
            conn.execute("PRAGMA incremental_vacuum")
            logger.info("Pruned %d audit records older than %d days", deleted, self.retention_days)
        return deleted

    # -- reading ------------------------------------------------------------------

    @staticmethod
    def to_entry(row: sqlite3.Row) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "id": row["id"], "ts": row["ts"], "transport": row["transport"], "path": row["path"],
            "source": row["source"], "server": row["server"], "tool": row["tool"],
            "arguments": _loads(row["arguments"], {}), "decision": row["decision"],
            "decided_by": row["decided_by"],
        }
        for key in ("risk", "wait_ms", "user_agent"):
            if row[key] is not None:
                entry[key] = row[key]
        if row["request_id"] is not None:
            entry["request_id"] = _loads(row["request_id"], row["request_id"])
        if row["extra"]:
            extra = _loads(row["extra"], {})
            if isinstance(extra, dict):
                entry.update({k: v for k, v in extra.items() if k not in entry})
        return entry

    @staticmethod
    def _where(*, since_ms: int | None = None, decision: str = "", path: str = "",
               server: str = "", q: str = "", before_id: int | None = None) -> tuple[str, list[Any]]:
        clauses, params = [], []
        if since_ms is not None:
            clauses.append("ts_ms >= ?"); params.append(since_ms)
        if decision:
            clauses.append("decision = ?"); params.append(decision)
        if path:
            clauses.append("path = ?"); params.append(path)
        if server:
            clauses.append("server = ?"); params.append(server)
        if q.strip():
            needle = "%" + q.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            clauses.append(
                "(lower(server) LIKE ? ESCAPE '\\' OR lower(tool) LIKE ? ESCAPE '\\' "
                "OR lower(source) LIKE ? ESCAPE '\\' OR lower(arguments) LIKE ? ESCAPE '\\')")
            params += [needle] * 4
        if before_id is not None:
            clauses.append("id < ?"); params.append(before_id)
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", params

    def events(self, *, limit: int = 200, **filters: Any) -> tuple[int, list[dict[str, Any]]]:
        """(total matching, newest-first page of up to `limit`)."""
        conn = self._conn()
        count_where, count_params = self._where(**{k: v for k, v in filters.items() if k != "before_id"})
        total = conn.execute(f"SELECT COUNT(*) FROM events{count_where}", count_params).fetchone()[0]
        where, params = self._where(**filters)
        rows = conn.execute(f"SELECT * FROM events{where} ORDER BY id DESC LIMIT ?",
                            [*params, int(limit)]).fetchall()
        return total, [self.to_entry(r) for r in rows]

    def recent(self, n: int | None = None) -> list[dict[str, Any]]:
        """The last `n` records (all if None), oldest first."""
        conn = self._conn()
        if n is None:
            rows = conn.execute("SELECT * FROM events ORDER BY id").fetchall()
        else:
            rows = conn.execute("SELECT * FROM (SELECT * FROM events ORDER BY id DESC LIMIT ?) ORDER BY id",
                                (int(n),)).fetchall()
        return [self.to_entry(r) for r in rows]

    def since_id(self, last_id: int, limit: int = 500) -> list[dict[str, Any]]:
        rows = self._conn().execute("SELECT * FROM events WHERE id > ? ORDER BY id LIMIT ?",
                                    (int(last_id), int(limit))).fetchall()
        return [self.to_entry(r) for r in rows]

    def max_id(self) -> int:
        return int(self._conn().execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0])

    def count(self) -> int:
        return int(self._conn().execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(self.path) + suffix)
            if p.exists():
                total += p.stat().st_size
        return total

    # -- aggregates (dashboard) ---------------------------------------------------

    def stats(self, *, since_ms: int | None, start_ms: int, bucket_ms: int, buckets: int) -> dict[str, Any]:
        """All dashboard aggregates for one window, computed in SQL."""
        conn = self._conn()
        where, params = self._where(since_ms=since_ms)

        def grouped(column: str) -> dict[str, int]:
            return {str(k): int(v) for k, v in conn.execute(
                f"SELECT {column}, COUNT(*) FROM events{where} GROUP BY {column}", params)}

        totals = grouped("decision")
        top_tools = [
            {"server": r[0], "tool": r[1], "total": r[2], "allow": r[3], "block": r[4], "cancelled": r[5]}
            for r in conn.execute(
                "SELECT server, tool, COUNT(*), SUM(decision='allow'), SUM(decision='block'), "
                f"SUM(decision='cancelled') FROM events{where} GROUP BY server, tool "
                "ORDER BY COUNT(*) DESC, server, tool LIMIT 8", params)
        ]

        uw_where, uw_params = self._where(since_ms=since_ms)
        uw_where += (" AND " if uw_where else " WHERE ") + "decided_by = 'user' AND wait_ms IS NOT NULL"
        n_wait, max_wait = conn.execute(f"SELECT COUNT(*), MAX(wait_ms) FROM events{uw_where}", uw_params).fetchone()

        def nth_wait(pct: float) -> int | None:
            if not n_wait:
                return None
            k = max(0, min(n_wait - 1, round(pct / 100 * (n_wait - 1))))
            row = conn.execute(f"SELECT wait_ms FROM events{uw_where} ORDER BY wait_ms LIMIT 1 OFFSET ?",
                               [*uw_params, k]).fetchone()
            return int(row[0]) if row else None

        timeline = [{"allow": 0, "block": 0, "cancelled": 0} for _ in range(buckets)]
        for b, decision, n in conn.execute(
                "SELECT MIN(MAX((ts_ms - ?) / ?, 0), ?) AS b, decision, COUNT(*) FROM events "
                "WHERE ts_ms >= ? GROUP BY b, decision", (start_ms, bucket_ms, buckets - 1, start_ms)):
            if buckets and decision in timeline[0]:
                timeline[int(b)][decision] += int(n)

        return {
            "totals": totals,
            "by_path": grouped("path"),
            "decided_by": grouped("decided_by"),
            "servers": grouped("server"),
            "top_tools": top_tools,
            "user_wait_ms": {"count": int(n_wait), "median": nth_wait(50), "p95": nth_wait(95),
                             "max": int(max_wait) if max_wait is not None else None},
            "timeline": timeline,
        }

    def first_ts_ms(self) -> int | None:
        row = self._conn().execute("SELECT MIN(ts_ms) FROM events").fetchone()
        return int(row[0]) if row and row[0] is not None else None


def _unique_name(path: Path) -> Path:
    """path, or path.2, path.3, ... - whichever doesn't exist yet."""
    if not path.exists():
        return path
    n = 2
    while path.with_name(f"{path.name}.{n}").exists():
        n += 1
    return path.with_name(f"{path.name}.{n}")


def _loads(text: Any, default: Any) -> Any:
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    out = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for raw in f:
            raw = raw.strip()
            if raw:
                try:
                    obj = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(obj, dict):
                    out.append(obj)
    return out
