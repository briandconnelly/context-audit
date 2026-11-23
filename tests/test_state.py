import os
import subprocess
import sys
from pathlib import Path

import pytest

from context_audit import state
from context_audit.state import (
    StateError,
    append_event,
    bump,
    ensure_state,
    read_counters,
    read_events,
    span_digest,
    state_dir,
)

REPO = Path(__file__).resolve().parent.parent


def test_state_dir_precedence(tmp_path):
    env = {
        "CONTEXT_AUDIT_HOME": str(tmp_path / "a"),
        "XDG_STATE_HOME": str(tmp_path / "x"),
        "HOME": str(tmp_path / "h"),
    }
    assert state_dir(env) == tmp_path / "a"
    del env["CONTEXT_AUDIT_HOME"]
    assert state_dir(env) == tmp_path / "x" / "context-audit"
    del env["XDG_STATE_HOME"]
    assert state_dir(env) == tmp_path / "h" / ".local" / "state" / "context-audit"
    assert not (tmp_path / "h").exists()


def test_state_dir_ignores_empty_values(tmp_path):
    env = {"CONTEXT_AUDIT_HOME": "", "XDG_STATE_HOME": "", "HOME": str(tmp_path)}
    assert state_dir(env) == tmp_path / ".local" / "state" / "context-audit"


def test_ensure_state_is_owner_only(tmp_path):
    root = ensure_state(tmp_path / "s")
    span_digest(root, "x")
    assert root.stat().st_mode & 0o077 == 0
    assert (root / "key").stat().st_mode & 0o077 == 0
    assert len((root / "key").read_bytes()) == 32


def test_digest_is_keyed_and_stable(tmp_path):
    a = ensure_state(tmp_path / "a")
    b = ensure_state(tmp_path / "b")
    d = span_digest(a, "ignore previous instructions")
    assert d == span_digest(a, "ignore previous instructions")
    assert d != span_digest(b, "ignore previous instructions")
    assert len(d) == 16
    int(d, 16)


_WORKER = """
import sys
from pathlib import Path
from context_audit.state import append_event, bump
root = Path(sys.argv[1]); n = int(sys.argv[2]); wid = sys.argv[3]
for i in range(n):
    append_event(root, {"w": wid, "i": i, "pad": "x" * 200})
    bump(root, calls_requested=1)
"""


def test_parallel_appends_lose_nothing(tmp_path):
    root = ensure_state(tmp_path / "s")
    env = {**os.environ, "PYTHONPATH": str(REPO)}
    procs = [
        subprocess.Popen([sys.executable, "-c", _WORKER, str(root), "200", str(w)], env=env)
        for w in range(8)
    ]
    assert all(p.wait() == 0 for p in procs)
    events = read_events(root)
    assert len(events) == 1600
    assert len({(e["w"], e["i"]) for e in events}) == 1600
    assert read_counters(root)["calls_requested"] == 1600


def test_reader_skips_a_partial_line(tmp_path):
    root = ensure_state(tmp_path / "s")
    append_event(root, {"n": 1})
    with open(root / "events.jsonl", "a") as f:
        f.write('{"n": 2, "trunc')
    assert read_events(root) == [{"n": 1}]


def test_read_on_missing_files_is_empty(tmp_path):
    root = ensure_state(tmp_path / "s")
    assert read_events(root) == []
    assert read_counters(root) == {}


def test_bump_accumulates(tmp_path):
    root = ensure_state(tmp_path / "s")
    bump(root, calls_requested=2, not_scanned=1)
    bump(root, calls_requested=3)
    assert read_counters(root) == {"calls_requested": 5, "not_scanned": 1}


def test_bump_rejects_unknown_counter(tmp_path):
    root = ensure_state(tmp_path / "s")
    with pytest.raises(ValueError):
        bump(root, bogus=1)


def test_quota_trims_and_marks(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "EVENTS_CAP_BYTES", 4096)
    root = ensure_state(tmp_path / "s")
    for i in range(200):
        append_event(root, {"i": i, "pad": "y" * 40})
    assert (root / "events.jsonl").stat().st_size <= 4096
    events = read_events(root)
    assert events[-1]["i"] == 199
    assert [e["i"] for e in events] == list(range(events[0]["i"], 200))
    assert events[0]["i"] > 0
    assert (root / "trimmed").exists()
    assert (root / "trimmed").read_text().strip()


def test_read_only_state_raises_state_error(tmp_path):
    root = ensure_state(tmp_path / "s")
    root.chmod(0o500)
    try:
        with pytest.raises(StateError, match=str(root)):
            append_event(root, {"n": 1})
        with pytest.raises(StateError, match=str(root)):
            ensure_state(root / "child")
    finally:
        root.chmod(0o700)


def test_version_constants():
    import context_audit

    assert isinstance(context_audit.__version__, str)
    assert context_audit.RULE_VERSION == 1
