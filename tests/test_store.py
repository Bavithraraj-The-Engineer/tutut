"""
Tests for the SQLite audit store (tutut/store.py).

Run with: python -m pytest tests/test_store.py -v
"""

from __future__ import annotations

import datetime as dt
import json
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from tutut.audit import AuditLog, read_entries  # noqa: E402
from tutut.config import rotate_log_if_large  # noqa: E402
from tutut.store import SQLiteStore  # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc)


def rec(i=0, *, days_ago=0.0, server="notes", tool="list_notes", decision="allow", **more):
    return {"ts": (NOW - dt.timedelta(days=days_ago, seconds=i)).isoformat(timespec="milliseconds"),
            "transport": "stdio", "source": "Claude Desktop (local server)", "server": server,
            "tool": tool, "arguments": {"i": i}, "decision": decision, "decided_by": "user",
            "wait_ms": 1000 + i, **more}


def test_schema_wal_and_owner_only_files(tmp_path):
    store = SQLiteStore(tmp_path / "audit.db")
    store.record(rec())
    conn = store._conn()
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
    assert conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2  # incremental
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(tmp_path / "audit.db") + suffix)
        if p.exists():
            assert stat.S_IMODE(p.stat().st_mode) == 0o600, p.name


def test_roundtrip_keeps_every_field(tmp_path):
    store = SQLiteStore(tmp_path / "audit.db")
    entry = rec(transport="http", source="claude.ai / Anthropic cloud (via tunnel)",
                request_id="abc-1", risk="high", user_agent="Claude-User", custom_field={"k": [1, 2]},
                arguments={"title": "secrets", "nested": {"n": None, "ok": True}})
    store.record(entry)
    store.record(rec(1, request_id=7))
    got = store.recent()
    assert got[0]["path"] == "web" and got[0]["request_id"] == "abc-1" and got[1]["request_id"] == 7
    for key in ("ts", "transport", "source", "server", "tool", "arguments", "decision",
                "decided_by", "wait_ms", "risk", "user_agent", "custom_field"):
        assert got[0][key] == entry[key], key


def test_hostile_strings_are_data_not_sql(tmp_path):
    store = SQLiteStore(tmp_path / "audit.db")
    evil = "x'); DROP TABLE events; --"
    store.record(rec(server=evil, tool="t%_\\", arguments={"q": evil}))
    store.record(rec(1, tool="tXYZ"))
    assert store.count() == 2
    total, rows = store.events(server=evil)
    assert total == 1 and rows[0]["server"] == evil
    # LIKE wildcards in the search box are literal
    assert store.events(q="t%_")[0] == 1
    assert store.events(q="DROP TABLE")[0] == 1


def test_audit_log_writes_through_store(tmp_path):
    log = AuditLog(tmp_path / "audit.db")
    out = log.record(transport="stdio", source="s", server="fs", tool="write_file",
                     arguments={"api_key": "sk-123", "path": "/a"}, decision="block",
                     decided_by="user", wait_ms=5, extra={"risk": "medium"})
    assert isinstance(out["id"], int)
    [stored] = read_entries(tmp_path / "audit.db")
    assert stored["arguments"] == {"api_key": "***", "path": "/a"} and stored["risk"] == "medium"
    # a broken database never breaks proxying
    (tmp_path / "broken.db").write_text("not a database at all " * 100)
    AuditLog(tmp_path / "broken.db").record(transport="stdio", source="", server="s", tool="t",
                                            arguments={}, decision="allow", decided_by="rule")


def test_legacy_jsonl_import_without_duplicates_or_stranding(tmp_path):
    legacy = tmp_path / "audit.jsonl"
    legacy.write_text("".join(json.dumps(rec(i)) + "\n" for i in range(5)) + "garbage line\n")
    a = SQLiteStore(tmp_path / "audit.db", legacy_jsonl=legacy)
    assert a.count() == 5
    assert not legacy.exists() and (tmp_path / "audit.jsonl.migrated").exists()
    # The same records showing up again (e.g. a restored backup) aren't duplicated.
    (tmp_path / "audit.jsonl.migrated").rename(legacy)
    assert SQLiteStore(tmp_path / "audit.db", legacy_jsonl=legacy).count() == 5
    # A not-yet-restarted old tutut process re-creates audit.jsonl with new
    # records: they are picked up on the next open, not stranded.
    legacy.write_text(json.dumps(rec(100, tool="late_call")) + "\n")
    c = SQLiteStore(tmp_path / "audit.db", legacy_jsonl=legacy)
    assert c.count() == 6 and c.recent(1)[0]["tool"] == "late_call"
    assert sorted(p.name for p in tmp_path.glob("audit.jsonl*")) == [
        "audit.jsonl.migrated", "audit.jsonl.migrated.2"]


def test_concurrent_first_open_imports_once(tmp_path):
    legacy = tmp_path / "audit.jsonl"
    legacy.write_text("".join(json.dumps(rec(i)) + "\n" for i in range(50)))
    code = ("import sys; sys.path.insert(0, sys.argv[1]); from tutut.store import SQLiteStore; "
            "s = SQLiteStore(sys.argv[2], legacy_jsonl=sys.argv[3]); print(s.count())")
    procs = [subprocess.Popen([sys.executable, "-c", code, str(ROOT), str(tmp_path / "audit.db"), str(legacy)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(4)]
    outs = [p.communicate(timeout=60) for p in procs]
    assert all(p.returncode == 0 for p in procs), [o[1].decode()[-500:] for o in outs]
    assert SQLiteStore(tmp_path / "audit.db").count() == 50


def test_many_processes_writing_at_once(tmp_path):
    """Like several wrapped Desktop servers + the gateway: no lost or failed writes."""
    code = ("import sys; sys.path.insert(0, sys.argv[1]); from tutut.audit import AuditLog\n"
            "log = AuditLog(sys.argv[2])\n"
            "for i in range(250):\n"
            "    out = log.record(transport='stdio', source='p', server='s' + sys.argv[3], tool='t',"
            " arguments={'i': i}, decision='allow', decided_by='rule')\n"
            "    assert 'id' in out, 'write failed'\n")
    procs = [subprocess.Popen([sys.executable, "-c", code, str(ROOT), str(tmp_path / "audit.db"), str(n)],
                              stderr=subprocess.PIPE) for n in range(4)]
    errs = [p.communicate(timeout=120)[1] for p in procs]
    assert all(p.returncode == 0 for p in procs), [e.decode()[-500:] for e in errs]
    store = SQLiteStore(tmp_path / "audit.db")
    assert store.count() == 1000
    assert len({e["id"] for e in store.recent()}) == 1000


def test_retention_prunes_old_records(tmp_path):
    store = SQLiteStore(tmp_path / "audit.db", retention_days=90)
    store.insert_many([rec(0, days_ago=120), rec(1, days_ago=91), rec(2, days_ago=10), rec(3)])
    assert store.prune() == 2 and store.count() == 2
    keep = SQLiteStore(tmp_path / "keep.db", retention_days=0)
    keep.insert_many([rec(0, days_ago=4000)])
    assert keep.prune() == 0 and keep.count() == 1


def test_queries_stay_fast_at_100k_records(tmp_path):
    from tutut.dashboard import compute_stats, query_events

    store = SQLiteStore(tmp_path / "audit.db", retention_days=0)
    tools = ["list_notes", "read_note", "add_note", "delete_note", "write_file", "list_directory"]
    rows = [rec(i, days_ago=(i % 60) + (i % 997) / 1000, tool=tools[i % 6],
                decision=("allow", "block", "cancelled")[i % 3]) for i in range(100_000)]
    t0 = time.perf_counter()
    store.insert_many(rows)
    insert_s = time.perf_counter() - t0
    now = dt.datetime.now().astimezone()
    timings = {}
    for window in ("24h", "7d", "all"):
        t0 = time.perf_counter()
        s = compute_stats(store, now=now, window=window)
        timings[window] = time.perf_counter() - t0
    t0 = time.perf_counter()
    total, page = query_events(store, now=now, window="all", q="delete", limit=200)
    timings["search"] = time.perf_counter() - t0
    print(f"\n100k insert {insert_s:.2f}s; queries: " + ", ".join(f"{k} {v * 1000:.0f} ms" for k, v in timings.items()))
    assert s["totals"]["total"] == 100_000 and total > 0 and len(page) == 200
    assert max(timings.values()) < 2.0  # generous: CI machines vary


def test_log_rotation(tmp_path):
    log = tmp_path / "tutut.log"
    log.write_text("x" * 100)
    assert not rotate_log_if_large(log, max_bytes=1000)
    for n in range(3):
        log.write_text(f"run {n} " + "x" * 2000)
        assert rotate_log_if_large(log, max_bytes=1000, backups=2)
    assert not log.exists()
    assert (tmp_path / "tutut.log.1").read_text().startswith("run 2")
    assert (tmp_path / "tutut.log.2").read_text().startswith("run 1")
    assert not (tmp_path / "tutut.log.3").exists()  # oldest dropped
