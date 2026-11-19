"""
Test-suite safety net: never touch the real ~/.config/tutut.

Several tests start real `tutut` processes, and tutut computes its default
paths (audit database, legacy audit file, logs, gateway state) from $HOME
*when it is imported*. So HOME is redirected here, at conftest import time -
before any test module imports tutut - and again per test.

As a tripwire, the real ~/.config/tutut is fingerprinted before the run and
the session fails if anything in it changed.
"""

import os
import tempfile
from pathlib import Path

import pytest

_REAL_TUTUT_DIR = Path(os.path.expanduser("~")) / ".config" / "tutut"
_FAKE_HOME = tempfile.mkdtemp(prefix="tutut-test-home-")
os.environ["HOME"] = _FAKE_HOME
os.environ["XDG_CONFIG_HOME"] = os.path.join(_FAKE_HOME, ".config")


def _fingerprint(directory: Path) -> dict:
    if not directory.is_dir():
        return {}
    out = {}
    for p in sorted(directory.iterdir()):
        try:
            st = p.stat()
            out[p.name] = (st.st_size, st.st_mtime_ns)
        except OSError:
            pass
    return out


_BEFORE = _fingerprint(_REAL_TUTUT_DIR)


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path_factory, monkeypatch):
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    yield home


def pytest_sessionfinish(session, exitstatus):
    after = _fingerprint(_REAL_TUTUT_DIR)
    if after != _BEFORE:
        changed = sorted(set(after) ^ set(_BEFORE) | {k for k in after if after.get(k) != _BEFORE.get(k)})
        session.exitstatus = 1
        print(f"\n\nTEST SUITE TOUCHED THE REAL {_REAL_TUTUT_DIR}: {changed}\n")
