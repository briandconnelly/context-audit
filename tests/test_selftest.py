import json
import time
from dataclasses import replace
from pathlib import Path

from context_audit import rules, scan, state
from context_audit.features import Detection
from context_audit.selftest import SelfTest, run_selftest

ROOT = Path(__file__).resolve().parent.parent
SHIPPED = ROOT / "context_audit" / "corpus"
FROZEN = ROOT / "evaluation" / "corpus"


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _ids(name: str, expected: str | None = None) -> set[str]:
    items = [json.loads(line) for line in _lines(SHIPPED / name)]
    return {i["id"] for i in items if expected is None or i["expected"] == expected}


def test_selftest_passes_on_the_shipped_corpus(tmp_path):
    results = run_selftest(tmp_path)
    assert [r.entry for r in results] == ["hook", "scan"]
    for r in results:
        assert r == SelfTest(r.entry, True, (), ())


def test_a_broken_detector_fails_the_selftest(tmp_path, monkeypatch):
    monkeypatch.setattr(scan, "detect", lambda *a, **k: Detection())
    results = run_selftest(tmp_path)
    assert not any(r.passed for r in results)
    missed = {i for r in results for i in r.missed}
    assert _ids("canaries.jsonl", "high") <= missed
    assert _ids("canaries.jsonl", "review") <= missed
    assert not missed & _ids("canaries.jsonl", "none")


def test_an_overeager_detector_fails_the_selftest(tmp_path, monkeypatch):
    real = rules.judge

    def all_high(*a, **k):
        return [replace(f, severity="high") for f in real(*a, **k)]

    monkeypatch.setattr(scan, "judge", all_high)
    results = run_selftest(tmp_path)
    assert not any(r.passed for r in results)
    assert all(r.flagged for r in results)


def test_selftest_writes_no_events_or_counters(tmp_path):
    run_selftest(tmp_path)
    assert state.read_events(tmp_path) == []
    assert state.read_counters(tmp_path) == {}
    assert not (tmp_path / "events.jsonl").exists()
    assert not (tmp_path / "counters.json").exists()


def test_shipped_corpus_matches_the_frozen_one():
    assert _lines(SHIPPED / "canaries.jsonl") == _lines(FROZEN / "canaries.jsonl")
    frozen = set(_lines(FROZEN / "controls.jsonl"))
    shipped = _lines(SHIPPED / "controls.jsonl")
    assert len(shipped) == len(set(shipped)) == 20
    assert set(shipped) <= frozen
    # Controls that are known strict xfails in test_scan.py are not shipped.
    assert not _ids("controls.jsonl") & {"ctl-011", "ctl-082", "ctl-086"}


def test_every_entry_point_is_exercised():
    canaries = [json.loads(line) for line in _lines(SHIPPED / "canaries.jsonl")]
    controls = [json.loads(line) for line in _lines(SHIPPED / "controls.jsonl")]
    for items in (canaries, controls):
        assert {i["entry"] for i in items} == {"hook", "scan"}
    assert any("blocks" in i for i in controls)


def test_selftest_is_fast(tmp_path):
    run_selftest(tmp_path)  # warm the key file and imports
    t = time.perf_counter()
    run_selftest(tmp_path)
    assert time.perf_counter() - t < 0.15
